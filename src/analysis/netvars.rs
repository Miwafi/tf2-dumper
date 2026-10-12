//! Netvar analysis: walks the Source 1 `ClientClass` -> `RecvTable` -> `RecvProp`
//! hierarchy in `client.dll` (the client-side equivalent of CS2's schema system).
//!
//! Strategy (no byte patterns, robust across game updates):
//!
//! 1. Single pass over the module's writable data: any pointer slot whose target
//!    validates as a `RecvTable` (via its `DT_*` name at +0x18) yields a
//!    candidate `ClientClass` at `slot - 0x18`.
//! 2. `ClientClass` structs are validated via create function pointers, the
//!    network class name and the class id.
//! 3. The longest `ClientClass::next` chain is the `g_pClientClassHead` list;
//!    the global slot pointing at its head is `dwGetAllClasses`.

use std::collections::BTreeMap;

use anyhow::Result;

use log::{debug, warn};

use memflow::prelude::v1::*;

use pelite::pe64::{Pe, PeView};

use serde::{Deserialize, Serialize};

use crate::source1::SendPropType;

pub type NetVarMap = BTreeMap<String, Vec<Class>>;

const MAX_PROP_COUNT: i32 = 1024;
const MAX_CLASS_ID: i32 = 4096;
const RECV_PROP_SIZE: u32 = 0x60;
const CLIENT_CLASS_SIZE: u32 = 0x30;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Class {
    pub name: String,
    pub module_name: String,
    pub parent_name: Option<String>,
    pub fields: Vec<ClassField>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClassField {
    pub name: String,
    pub type_name: String,
    pub offset: u32,
}

/// Result of the netvar analysis, including the discovered list head.
#[derive(Debug, Default)]
pub struct NetVars {
    pub map: NetVarMap,
    /// RVA of the global holding `g_pClientClassHead` (`dwGetAllClasses`).
    pub head_rva: Option<u32>,
}

/// Section ranges needed for pointer classification.
struct PeInfo {
    /// Readable + writable + initialized data sections (`.data`).
    data_ranges: Vec<(u32, u32)>,
    /// Readable + executable sections (`.text`).
    code_range: Option<(u32, u32)>,
}

/// Module image with base-relative pointer resolution.
struct ModuleImage {
    buf: Vec<u8>,
    base: u64,
}

impl ModuleImage {
    fn read_u64(&self, rva: u32) -> Option<u64> {
        let start = rva as usize;
        let end = start.checked_add(8)?;

        if end > self.buf.len() {
            return None;
        }

        Some(u64::from_le_bytes(self.buf[start..end].try_into().ok()?))
    }

    fn read_i32(&self, rva: u32) -> Option<i32> {
        let start = rva as usize;
        let end = start.checked_add(4)?;

        if end > self.buf.len() {
            return None;
        }

        Some(i32::from_le_bytes(self.buf[start..end].try_into().ok()?))
    }

    /// Reads a pointer field and converts it to an RVA within this module.
    fn read_ptr(&self, rva: u32) -> Option<u32> {
        let value = self.read_u64(rva)?;

        if value < self.base {
            return None;
        }

        let rva = (value - self.base) as u32;

        if rva as usize >= self.buf.len() {
            return None;
        }

        Some(rva)
    }

    fn read_cstr(&self, rva: u32, max: usize) -> Option<String> {
        let start = rva as usize;

        if start >= self.buf.len() {
            return None;
        }

        let end = (start + max).min(self.buf.len());
        let slice = &self.buf[start..end];

        let nul = slice.iter().position(|&b| b == 0)?;
        let bytes = &slice[..nul];

        if bytes.is_empty() || bytes.len() >= max {
            return None;
        }

        if !bytes.iter().all(|&b| (0x20..0x7F).contains(&b)) {
            return None;
        }

        Some(String::from_utf8_lossy(bytes).into_owned())
    }
}

/// Read accessor serving the static module image directly and falling back to
/// remote process reads for runtime-allocated (heap) structures.
///
/// Array netvars (`RecvPropArray`) build their element tables on the heap at
/// static init time, so field expansion must be able to leave the module.
struct AddressSpace<'a, P: Process + MemoryView> {
    module: &'a ModuleImage,
    process: &'a mut P,
}

impl<P: Process + MemoryView> AddressSpace<'_, P> {
    fn in_module(&self, addr: u64) -> bool {
        addr >= self.module.base && addr - self.module.base < self.module.buf.len() as u64
    }

    fn read_bytes(&mut self, addr: u64, len: usize) -> Option<Vec<u8>> {
        if self.in_module(addr) {
            let start = (addr - self.module.base) as usize;
            let end = start.checked_add(len)?;

            return self.module.buf.get(start..end).map(|slice| slice.to_vec());
        }

        let data = self
            .process
            .read_raw(Address::from(addr), len)
            .data_part()
            .ok()?;

        if data.len() < len {
            return None;
        }

        Some(data.to_vec())
    }

    fn read_u64(&mut self, addr: u64) -> Option<u64> {
        let bytes = self.read_bytes(addr, 8)?;

        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    }

    fn read_i32(&mut self, addr: u64) -> Option<i32> {
        let bytes = self.read_bytes(addr, 4)?;

        Some(i32::from_le_bytes(bytes.try_into().ok()?))
    }

    fn read_cstr(&mut self, addr: u64, max: usize) -> Option<String> {
        let bytes = self.read_bytes(addr, max)?;

        let nul = bytes.iter().position(|&b| b == 0)?;
        let slice = &bytes[..nul];

        if slice.is_empty() || !slice.iter().all(|&b| (0x20..0x7F).contains(&b)) {
            return None;
        }

        Some(String::from_utf8_lossy(slice).into_owned())
    }
}

pub fn netvars<P: Process + MemoryView>(process: &mut P) -> Result<NetVars> {
    let module = process.module_by_name("client.dll")?;

    let buf = process
        .read_raw(module.base, module.size as _)
        .data_part()?;

    let info = {
        let view = PeView::from_bytes(&buf)?;
        section_info(&view)
    };

    if info.data_ranges.is_empty() {
        anyhow::bail!("no writable data sections found in client.dll");
    }

    let mem = ModuleImage {
        buf,
        base: module.base.to_umem(),
    };

    // Phase 1: any pointer slot referencing a `DT_*` name string anchors a
    // RecvTable at `slot - 0x18` (RecvTable::net_table_name is at +0x18).
    let mut tables: BTreeMap<u32, String> = BTreeMap::new();

    for &(start, end) in &info.data_ranges {
        let mut rva = start & !0x7;

        while rva + 8 <= end {
            if let Some(name_rva) = mem.read_ptr(rva) {
                if let Some(name) = mem.read_cstr(name_rva, 64) {
                    if is_dt_name(&name) {
                        if let Some(table_rva) = rva.checked_sub(0x18) {
                            if validate_recv_table(&mem, table_rva) {
                                tables.insert(table_rva, name);
                            }
                        }
                    }
                }
            }

            rva += 8;
        }
    }

    // Phase 2: any pointer slot referencing a known RecvTable anchors a
    // ClientClass at `slot - 0x18` (ClientClass::recv_table is at +0x18).
    let mut classes: BTreeMap<u32, (String, u32)> = BTreeMap::new();
    let mut table_owners: BTreeMap<u32, u32> = BTreeMap::new();

    for &(start, end) in &info.data_ranges {
        let mut rva = start & !0x7;

        while rva + 8 <= end {
            if let Some(table_rva) = mem.read_ptr(rva) {
                if tables.contains_key(&table_rva) {
                    if let Some(class_rva) = rva.checked_sub(0x18) {
                        if try_class(&mem, &info, class_rva, table_rva, &mut classes) {
                            table_owners.entry(table_rva).or_insert(class_rva);
                        }
                    }
                }
            }

            rva += 8;
        }
    }

    debug!("found {} recv tables in client.dll", tables.len());
    debug!("found {} client classes in client.dll", classes.len());

    if classes.is_empty() {
        anyhow::bail!("no ClientClass structures found in client.dll");
    }

    // Locate the head of the longest chain and its global slot.
    let head_rva = find_head_rva(&mem, &info, &classes);

    match head_rva {
        Some(rva) => debug!("g_pClientClassHead found at client.dll + {:#X}", rva),
        None => warn!("unable to locate g_pClientClassHead global"),
    }

    let list = {
        let mut space = AddressSpace {
            module: &mem,
            process: &mut *process,
        };

        build_classes(&mut space, &classes, &table_owners)
    };

    let mut map = NetVarMap::new();
    map.insert(module.name.to_string(), list);

    Ok(NetVars { map, head_rva })
}

fn section_info(view: &PeView<'_>) -> PeInfo {
    let mut data_ranges = Vec::new();
    let mut code_range = None;

    for section in view.section_headers() {
        let chars = section.Characteristics;
        let start = section.VirtualAddress;
        let end = start + section.VirtualSize;

        if chars & 0x2000_0000 != 0 && chars & 0x4000_0000 != 0 {
            // Executable + readable -> code.
            code_range = code_range.or(Some((start, end)));
        }

        if chars & 0x8000_0000 != 0 && chars & 0x0000_0040 != 0 {
            // Writable + initialized data.
            data_ranges.push((start, end));
        }
    }

    PeInfo {
        data_ranges,
        code_range,
    }
}

fn is_dt_name(name: &str) -> bool {
    name.starts_with("DT_") && name.len() > 3
}

fn validate_recv_table(mem: &ModuleImage, rva: u32) -> bool {
    // props pointer must be valid...
    let Some(props) = mem.read_ptr(rva) else {
        return false;
    };

    let Some(prop_count) = mem.read_i32(rva + 0x8) else {
        return false;
    };

    if prop_count <= 0 || prop_count > MAX_PROP_COUNT {
        return false;
    }

    // ...and the props array must fit into the module image.
    let end = props.checked_add((prop_count as u32) * RECV_PROP_SIZE);

    match end {
        Some(end) => (end as usize) <= mem.buf.len(),
        None => false,
    }
}

#[allow(clippy::too_many_arguments)]
fn try_class(
    mem: &ModuleImage,
    info: &PeInfo,
    class_rva: u32,
    table_rva: u32,
    classes: &mut BTreeMap<u32, (String, u32)>,
) -> bool {
    if classes.contains_key(&class_rva) {
        return true;
    }

    // create_fn / create_event_fn must be code pointers or null.
    for offset in [0x0, 0x8] {
        match mem.read_ptr(class_rva + offset) {
            Some(fn_rva) => {
                let in_code = info
                    .code_range
                    .map(|(start, end)| start <= fn_rva && fn_rva < end)
                    .unwrap_or(false);

                if !in_code {
                    return false;
                }
            }
            None => {
                // read_ptr fails for null pointers, which is allowed here.
                if mem.read_u64(class_rva + offset) != Some(0) {
                    return false;
                }
            }
        }
    }

    let Some(name_ptr) = mem.read_ptr(class_rva + 0x10) else {
        return false;
    };

    let Some(network_name) = mem.read_cstr(name_ptr, 128) else {
        return false;
    };

    // Network names are C++ class names (e.g. "CTFPlayer", "CBaseEntity").
    let valid = network_name.starts_with('C')
        && network_name
            .chars()
            .nth(1)
            .map(|c| c.is_ascii_alphabetic() || c == '_')
            .unwrap_or(false);

    if !valid {
        return false;
    }

    let Some(class_id) = mem.read_i32(class_rva + 0x28) else {
        return false;
    };

    if !(0..MAX_CLASS_ID).contains(&class_id) {
        return false;
    }

    // next must be null or point into this module.
    match mem.read_u64(class_rva + 0x20) {
        Some(0) => {}
        Some(_) => {
            if mem.read_ptr(class_rva + 0x20).is_none() {
                return false;
            }
        }
        None => return false,
    }

    classes.insert(class_rva, (network_name, table_rva));

    true
}

fn find_head_rva(
    mem: &ModuleImage,
    info: &PeInfo,
    classes: &BTreeMap<u32, (String, u32)>,
) -> Option<u32> {
    // Build the set of all `next` targets.
    let next_targets: std::collections::BTreeSet<u32> = classes
        .keys()
        .filter_map(|&rva| mem.read_ptr(rva + 0x20))
        .collect();

    // Heads are classes never referenced by another class.
    let mut heads: Vec<u32> = classes
        .keys()
        .copied()
        .filter(|rva| !next_targets.contains(rva))
        .collect();

    if heads.is_empty() {
        return None;
    }

    // Walk each head and keep the longest chain.
    let chain_len = |head: u32| -> usize {
        let mut len = 0usize;
        let mut cur = Some(head);
        let mut seen = std::collections::BTreeSet::new();

        while let Some(rva) = cur {
            if !classes.contains_key(&rva) || !seen.insert(rva) {
                break;
            }

            len += 1;
            cur = mem.read_ptr(rva + 0x20);
        }

        len
    };

    heads.sort_by_key(|&head| chain_len(head));

    let head = *heads.last().unwrap();

    // Find the global slot pointing to the head, excluding slots that belong to
    // other ClientClass structs.
    for &(start, end) in &info.data_ranges {
        let mut rva = start & !0x7;

        while rva + 8 <= end {
            if mem.read_u64(rva)
                == Some(mem.base + u64::from(head))
                && !classes.keys().any(|&class_rva| {
                    class_rva <= rva && rva < class_rva + CLIENT_CLASS_SIZE
                })
            {
                return Some(rva);
            }

            rva += 8;
        }
    }

    None
}

fn build_classes<P: Process + MemoryView>(
    mem: &mut AddressSpace<'_, P>,
    classes: &BTreeMap<u32, (String, u32)>,
    table_owners: &BTreeMap<u32, u32>,
) -> Vec<Class> {
    let mut list = Vec::with_capacity(classes.len());

    for (name, table_rva) in classes.values() {
        let mut parent_name = None;
        let mut fields = Vec::new();
        let mut seen_names = std::collections::BTreeSet::new();
        let mut visited = std::collections::BTreeSet::new();

        walk_table(
            mem,
            mem.module.base + u64::from(*table_rva),
            0,
            "",
            0,
            table_owners,
            classes,
            &mut visited,
            &mut seen_names,
            &mut fields,
            &mut parent_name,
        );

        list.push(Class {
            name: name.clone(),
            module_name: "client.dll".to_string(),
            parent_name,
            fields,
        });
    }

    list.sort_by(|a, b| a.name.cmp(&b.name));

    list
}

/// Maximum recursion depth for nested (anonymous) recv tables and inline
/// baseclass chains.
const MAX_TABLE_DEPTH: u32 = 8;

/// Walks a recv table and collects its fields into `fields`.
///
/// `table_addr` is absolute. Following Source 1 netvar semantics, prop offsets
/// inside a table are relative to the offset of the prop that references the
/// table (`base_offset`); the top-level call uses `base_offset = 0` so its
/// props resolve to entity-absolute offsets.
///
/// Composite props (`DataTable` / `Array`) reference a child table: tables
/// owned by a ClientClass are emitted as separate classes, while anonymous
/// tables (arrays, local data aggregates) are flattened into the current class
/// with the prop name as prefix. Child tables may live on the heap (arrays are
/// runtime-built), hence the remote read fallback.
#[allow(clippy::too_many_arguments)]
fn walk_table<P: Process + MemoryView>(
    mem: &mut AddressSpace<'_, P>,
    table_addr: u64,
    base_offset: u32,
    prefix: &str,
    depth: u32,
    table_owners: &BTreeMap<u32, u32>,
    classes: &BTreeMap<u32, (String, u32)>,
    visited: &mut std::collections::BTreeSet<u64>,
    seen_names: &mut std::collections::BTreeSet<String>,
    fields: &mut Vec<ClassField>,
    parent_name: &mut Option<String>,
) {
    if depth > MAX_TABLE_DEPTH || !visited.insert(table_addr) {
        return;
    }

    let Some(props) = mem.read_u64(table_addr) else {
        return;
    };

    let Some(prop_count) = mem
        .read_i32(table_addr + 0x8)
        .filter(|&count| count > 0 && count <= MAX_PROP_COUNT)
    else {
        return;
    };

    for i in 0..prop_count {
        let prop_addr = props.wrapping_add((i as u64) * u64::from(RECV_PROP_SIZE));

        let Some(var_name_ptr) = mem.read_u64(prop_addr) else {
            continue;
        };

        if var_name_ptr == 0 {
            continue;
        }

        let Some(name) = mem.read_cstr(var_name_ptr, 128) else {
            continue;
        };

        // Some proxy-defined props are named with surrounding quotes.
        let name = if name.starts_with('"') && name.ends_with('"') && name.len() > 2 {
            name[1..name.len() - 1].to_string()
        } else {
            name
        };

        let raw_type = mem.read_i32(prop_addr + 0x8).unwrap_or(-1);
        let type_name = SendPropType::from_i32(raw_type)
            .map(|t| t.type_name().to_string())
            .unwrap_or_else(|| format!("unknown_{}", raw_type));

        let Some(rel_offset) = mem.read_i32(prop_addr + 0x48).filter(|&off| off >= 0) else {
            continue;
        };

        let offset = base_offset.wrapping_add(rel_offset as u32);

        // Arrays and data tables reference a child table via +0x40.
        let is_composite = raw_type == SendPropType::DataTable as i32
            || raw_type == SendPropType::Array as i32;

        if is_composite {
            if let Some(child_table) = mem.read_u64(prop_addr + 0x40).filter(|&t| t != 0) {
                let owned = mem.in_module(child_table)
                    && table_owners.contains_key(&((child_table - mem.module.base) as u32));

                if name == "baseclass" {
                    // The datatable prop named "baseclass" links to the parent
                    // class. When its table belongs to a ClientClass the parent
                    // link is recorded and inherited fields are resolved through
                    // the class hierarchy. Abstract intermediates (e.g. CNextBot)
                    // have no ClientClass; their tables are flattened inline so
                    // their props are not lost.
                    if owned && parent_name.is_none() {
                        let table_rva = (child_table - mem.module.base) as u32;

                        if let Some(&owner) = table_owners.get(&table_rva) {
                            *parent_name = classes.get(&owner).map(|(n, _)| n.clone());
                        }
                    } else if !owned {
                        walk_table(
                            mem,
                            child_table,
                            offset,
                            prefix,
                            depth + 1,
                            table_owners,
                            classes,
                            visited,
                            seen_names,
                            fields,
                            parent_name,
                        );
                    }

                    continue;
                }

                // Tables owned by a ClientClass are separate classes.
                if !owned {
                    let child_prefix = format!("{prefix}{}_", sanitize_name(&name));

                    walk_table(
                        mem,
                        child_table,
                        offset,
                        &child_prefix,
                        depth + 1,
                        table_owners,
                        classes,
                        visited,
                        seen_names,
                        fields,
                        parent_name,
                    );
                }
            }
        }

        let full_name = format!("{prefix}{}", sanitize_name(&name));

        if !seen_names.insert(full_name.clone()) {
            continue;
        }

        fields.push(ClassField {
            name: full_name,
            type_name,
            offset,
        });
    }
}

/// Replaces characters that are invalid in generated identifiers.
#[inline]
fn sanitize_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();

    // Array element props are literally named `m_x[0]`; keep a single clean
    // separator instead of a dangling trailing underscore.
    let sanitized = sanitized.trim_end_matches('_');

    match sanitized.chars().next() {
        Some(c) if c.is_ascii_digit() => format!("_{sanitized}"),
        _ => sanitized.to_string(),
    }
}
