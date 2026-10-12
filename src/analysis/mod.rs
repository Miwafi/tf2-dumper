pub use interfaces::*;
pub use netvars::*;
pub use offsets::*;

use std::any::type_name;

use anyhow::Result;

use log::{error, info};

use memflow::prelude::v1::*;

mod interfaces;
mod netvars;
mod offsets;

#[derive(Debug)]
pub struct AnalysisResult {
    pub interfaces: InterfaceMap,
    pub netvars: NetVars,
    pub offsets: OffsetMap,
}

pub fn analyze_all<P: Process + MemoryView>(process: &mut P) -> Result<AnalysisResult> {
    let interfaces = analyze(process, interfaces);

    info!(
        "found {} interfaces across {} modules",
        interfaces
            .iter()
            .map(|(_, ifaces)| ifaces.len())
            .sum::<usize>(),
        interfaces.len()
    );

    let netvars = analyze(process, netvars);

    let class_count = netvars.map.values().map(|classes| classes.len()).sum::<usize>();

    info!(
        "found {} netvar classes across {} modules",
        class_count,
        netvars.map.len()
    );

    let offsets = analyze_with(process, offsets, (&netvars, &interfaces));

    info!(
        "found {} offsets across {} modules",
        offsets
            .iter()
            .map(|(_, offsets)| offsets.len())
            .sum::<usize>(),
        offsets.len()
    );

    Ok(AnalysisResult {
        interfaces,
        netvars,
        offsets,
    })
}

fn analyze<P, F, T>(process: &mut P, f: F) -> T
where
    P: Process + MemoryView,
    F: FnOnce(&mut P) -> Result<T>,
    T: Default,
{
    let name = type_name::<F>();

    match f(process) {
        Ok(result) => result,
        Err(err) => {
            error!("failed to read {}: {}", name, err);

            T::default()
        }
    }
}

fn analyze_with<P, F, T, C>(process: &mut P, f: F, ctx: C) -> T
where
    P: Process + MemoryView,
    F: FnOnce(&mut P, &C) -> Result<T>,
    T: Default,
{
    let name = type_name::<F>();

    match f(process, &ctx) {
        Ok(result) => result,
        Err(err) => {
            error!("failed to read {}: {}", name, err);

            T::default()
        }
    }
}
