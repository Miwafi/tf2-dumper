use std::collections::BTreeMap;

use anyhow::Result;

use log::{debug, warn};

use memflow::prelude::v1::*;

use pelite::pe64::{Pe, PeView};

use super::{InterfaceMap, NetVars};

pub type OffsetMap = BTreeMap<String, BTreeMap<String, u32>>;

/// `interval_per_tick` for TF2 (66.67 tickrate), used to anchor the static
/// `CGlobalVarsBase` object inside `engine.dll`.
const TICK_INTERVAL: u32 = 0x3C75_C28F; // 0.015f32

const ENTITY_LIST_INTERFACE: &str = "VClientEntityList003";

pub fn offsets<P: Process + MemoryView>(
    process: &mut P,
    ctx: &(&NetVars, &InterfaceMap),
) -> Result<OffsetMap> {
    let (netvars, interfaces) = *ctx;

    let mut result: OffsetMap = BTreeMap::new();

    // dwGetAllClasses: the global slot holding g_pClientClassHead, discovered
    // while walking the netvar tree.
    match netvars.head_rva {
        Some(rva) => insert(&mut result, "client.dll", "dwGetAllClasses", rva),
        None => warn!("dwGetAllClasses unavailable (g_pClientClassHead not found)"),
    }

    // dwEntityList: the static IClientEntityList instance exposed through the
    // VClientEntityList003 interface.
    if let Some(rva) = interfaces
        .get("client.dll")
        .and_then(|ifaces| ifaces.get(ENTITY_LIST_INTERFACE))
    {
        insert(
            &mut result,
            "client.dll",
            "dwEntityList",
            *rva as u32,
        );
    } else {
        warn!("dwEntityList unavailable ({} not found)", ENTITY_LIST_INTERFACE);
    }

    // dwGlobalVars: the static CGlobalVarsBase object in engine.dll.
    match find_global_vars(process) {
        Ok(Some(rva)) => insert(&mut result, "engine.dll", "dwGlobalVars", rva),
        Ok(None) => warn!("dwGlobalVars unavailable (no CGlobalVarsBase found)"),
        Err(err) => warn!("dwGlobalVars unavailable: {}", err),
    }

    Ok(result)
}

fn insert(map: &mut OffsetMap, module_name: &str, name: &str, value: u32) {
    debug!("{}: {} = {:#X}", module_name, name, value);

    map.entry(module_name.to_string())
        .or_default()
        .insert(name.to_string(), value);
}

/// Scans `engine.dll` for the static `CGlobalVarsBase` object.
///
/// Layout (TF2 x64, verified at runtime):
///
/// ```text
/// +0x00 float realtime
/// +0x04 int   framecount
/// +0x08 float absoluteFrameTime
/// +0x0C float curtime
/// +0x10 float frameTime
/// +0x14 int   maxClients
/// +0x18 int   tickcount
/// +0x1C float interval_per_tick  (always 0.015)
/// +0x20 float interpolation_amount
/// +0x24 int   simTicksThisFrame
/// +0x28 int   network_protocol
/// ```
///
/// Strategy: find every occurrence of 0.015f in the writable data sections,
/// then validate the surrounding structure. The runtime invariant
/// `curtime == tickcount * interval_per_tick` (and both being live) filters
/// out static copies and unrelated float constants.
fn find_global_vars<P: Process + MemoryView>(process: &mut P) -> Result<Option<u32>> {
    let module = process.module_by_name("engine.dll")?;

    let buf = process
        .read_raw(module.base, module.size as _)
        .data_part()?;

    let data_ranges = {
        let view = PeView::from_bytes(&buf)?;

        view.section_headers()
            .iter()
            .filter(|s| s.Characteristics & 0x8000_0000 != 0 && s.Characteristics & 0x0000_0040 != 0)
            .map(|s| (s.VirtualAddress, s.VirtualAddress + s.VirtualSize))
            .collect::<Vec<_>>()
    };

    let read_u32 = |rva: u32| -> Option<u32> {
        let start = rva as usize;
        let end = start.checked_add(4)?;

        buf.get(start..end)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
    };

    for &(start, end) in &data_ranges {
        let mut rva = start & !0x3;

        while rva + 4 <= end {
            if read_u32(rva) == Some(TICK_INTERVAL) && rva >= 0x1C {
                let base = rva - 0x1C;

                if validate_global_vars(&read_u32, base) {
                    return Ok(Some(base));
                }
            }

            rva += 4;
        }
    }

    Ok(None)
}

fn validate_global_vars(read_u32: &impl Fn(u32) -> Option<u32>, base: u32) -> bool {
    let f32_at = |rva: u32| read_u32(rva).map(f32::from_bits);
    let i32_at = |rva: u32| read_u32(rva).map(|v| v as i32);

    let Some(realtime) = f32_at(base) else {
        return false;
    };

    let Some(frame_count) = i32_at(base + 0x04) else {
        return false;
    };

    let Some(absolute_frame_time) = f32_at(base + 0x08) else {
        return false;
    };

    let Some(curtime) = f32_at(base + 0x0C) else {
        return false;
    };

    let Some(frame_time) = f32_at(base + 0x10) else {
        return false;
    };

    let Some(max_clients) = i32_at(base + 0x14) else {
        return false;
    };

    let Some(tick_count) = i32_at(base + 0x18) else {
        return false;
    };

    let Some(interpolation_amount) = f32_at(base + 0x20) else {
        return false;
    };

    let floats_ok = (0.0..1.0e7).contains(&realtime)
        && (0.0..=1.0).contains(&absolute_frame_time)
        && (0.0..1.0e7).contains(&curtime)
        && (0.0..=1.0).contains(&frame_time)
        && (0.0..=1.0).contains(&interpolation_amount);

    let ints_ok = (1..(1 << 26)).contains(&frame_count)
        && (0..=256).contains(&max_clients)
        && (0..(1 << 26)).contains(&tick_count);

    if !(floats_ok && ints_ok) {
        return false;
    }

    // Live globals: the simulation has advanced and curtime tracks tickcount.
    tick_count > 0 && curtime > 0.0 && (curtime - tick_count as f32 * 0.015).abs() < 1.0
}
