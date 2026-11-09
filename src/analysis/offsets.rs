use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};

use log::{debug, warn};

use memflow::prelude::v1::*;

use pelite::pe64::{Pe, PeView};

use super::{InterfaceMap, NetVars};

pub type OffsetMap = BTreeMap<String, BTreeMap<String, u32>>;

/// `interval_per_tick` for TF2 (66.67 tickrate), used to anchor the static
/// `CGlobalVarsBase` object inside `engine.dll`.
const TICK_INTERVAL: u32 = 0x3C75_C28F; // 0.015f32

const ENTITY_LIST_INTERFACE: &str = "VClientEntityList003";

const ENGINE_CLIENT_INTERFACE: &str = "VEngineClient014";

/// `IVEngineClient::SetViewAngles` vtable slot (Valve SDK, `public/cdll_int.h`).
const ENGINE_SETVIEWANGLES_VTABLE_INDEX: usize = 20;

/// MSVC decorated type_info name of `class CInput` in `client.dll`.
const CLIENT_INPUT_RTTI_NAME: &[u8] = b".?AVCInput@@";

/// `IInput::CreateMove` vtable slot (Valve SDK, `game/client/iinput.h`).
const CLIENT_CREATEMOVE_VTABLE_INDEX: usize = 3;

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

    // dwCreateMove: CInput::CreateMove, resolved through the CInput RTTI
    // type descriptor -> complete object locator -> vtable.
    match find_create_move(process) {
        Ok(Some(rva)) => insert(&mut result, "client.dll", "dwCreateMove", rva),
        Ok(None) => warn!("dwCreateMove unavailable (CInput vtable not found)"),
        Err(err) => warn!("dwCreateMove unavailable: {}", err),
    }

    // dwSetViewAngles: IVEngineClient::SetViewAngles, taken from the
    // VEngineClient014 interface instance's vtable.
    match find_set_view_angles(process, interfaces) {
        Ok(Some(rva)) => insert(&mut result, "engine.dll", "dwSetViewAngles", rva),
        Ok(None) => warn!("dwSetViewAngles unavailable ({} not found)", ENGINE_CLIENT_INTERFACE),
        Err(err) => warn!("dwSetViewAngles unavailable: {}", err),
    }

    Ok(result)
}

fn insert(map: &mut OffsetMap, module_name: &str, name: &str, value: u32) {
    debug!("{}: {} = {:#X}", module_name, name, value);

    map.entry(module_name.to_string())
        .or_default()
        .insert(name.to_string(), value);
}

/// Resolves `CInput::CreateMove` inside `client.dll`.
///
/// `CInput` is not exported through the interface registry, so its vtable is
/// located through the module's MSVC RTTI metadata instead: the type
/// descriptor named `.?AVCInput@@`, the complete object locator referencing
/// it, and finally the vtable whose `[-1]` slot points back at that locator.
fn find_create_move<P: Process + MemoryView>(process: &mut P) -> Result<Option<u32>> {
    let module = process.module_by_name("client.dll")?;

    let buf = process
        .read_raw(module.base, module.size as _)
        .data_part()?;

    let base = module.base.to_umem();

    // Type descriptor: {vfptr, spare, name[]}, so the name sits 0x10 bytes in.
    let name_pos = find_bytes(&buf, CLIENT_INPUT_RTTI_NAME)
        .context("CInput type descriptor not found")?;
    let type_descriptor_rva = name_pos as u64 - 0x10;

    // The x64 complete object locator references the type descriptor by its
    // image-relative offset and starts with a signature of 1 and a zero
    // member offset (CInput uses single, full-object inheritance).
    let mut col_rva = None;
    let mut pos = 0;

    while let Some(found) = find_dword(&buf, type_descriptor_rva as u32, pos) {
        pos = found + 1;

        let Some(candidate) = found.checked_sub(12) else {
            continue;
        };

        if read_u32(&buf, candidate) == Some(1) && read_u32(&buf, candidate + 4) == Some(0) {
            col_rva = Some(candidate as u64);

            break;
        }
    }

    let Some(col_rva) = col_rva else {
        return Ok(None);
    };

    // The vtable's [-1] slot holds the locator's absolute runtime address.
    let locator_va = (base + col_rva).to_le_bytes();
    let Some(vtable_pos) = find_bytes(&buf, &locator_va) else {
        return Ok(None);
    };

    read_vtable_function(
        &buf,
        base,
        module.size as u64,
        vtable_pos + size_of::<u64>(),
        CLIENT_CREATEMOVE_VTABLE_INDEX,
    )
}

/// Resolves `IVEngineClient::SetViewAngles` inside `engine.dll` by taking the
/// vtable of the `VEngineClient014` interface instance.
fn find_set_view_angles<P: Process + MemoryView>(
    process: &mut P,
    interfaces: &InterfaceMap,
) -> Result<Option<u32>> {
    let Some(&instance_rva) = interfaces
        .get("engine.dll")
        .and_then(|ifaces| ifaces.get(ENGINE_CLIENT_INTERFACE))
    else {
        return Ok(None);
    };

    let module = process.module_by_name("engine.dll")?;

    let buf = process
        .read_raw(module.base, module.size as _)
        .data_part()?;

    let base = module.base.to_umem();

    // The interface instance's first member is its vtable pointer.
    let vtable_rva = read_u64(&buf, instance_rva as usize)
        .context("failed to read VEngineClient014 vtable pointer")?
        - base;

    read_vtable_function(
        &buf,
        base,
        module.size as u64,
        vtable_rva as usize,
        ENGINE_SETVIEWANGLES_VTABLE_INDEX,
    )
}

/// Reads a virtual function address from a vtable and converts it to a
/// module-relative offset.
fn read_vtable_function(
    buf: &[u8],
    base: u64,
    size: u64,
    vtable_rva: usize,
    index: usize,
) -> Result<Option<u32>> {
    let function = read_u64(buf, vtable_rva + index * size_of::<u64>())
        .context("vtable entry out of bounds")?;
    let rva = function.checked_sub(base).context("vtable entry outside module")?;

    if rva >= size {
        bail!("vtable entry outside module");
    }

    Ok(Some(rva as u32))
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn find_dword(buf: &[u8], value: u32, start: usize) -> Option<usize> {
    find_bytes(&buf[start..], &value.to_le_bytes()).map(|pos| pos + start)
}

fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    buf.get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u64(buf: &[u8], offset: usize) -> Option<u64> {
    buf.get(offset..offset + 8)
        .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
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
