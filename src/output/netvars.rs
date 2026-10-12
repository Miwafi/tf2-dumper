use std::collections::BTreeMap;
use std::fmt::{self, Write};

use heck::{AsPascalCase, AsSnakeCase};

use serde_json::json;

use super::{CodeWriter, Formatter, NetVarMap, slugify, zig_ident};

impl CodeWriter for NetVarMap {
    fn write_cs(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        fmt.block("namespace TF2Dumper.Netvars", false, |fmt| {
            for (module_name, classes) in self {
                writeln!(fmt, "// Module: {}", module_name)?;
                writeln!(fmt, "// Class count: {}", classes.len())?;

                fmt.block(
                    &format!("public static class {}", AsPascalCase(slugify(module_name))),
                    false,
                    |fmt| {
                        for class in classes {
                            let parent_name = class
                                .parent_name
                                .as_deref()
                                .map(slugify)
                                .unwrap_or("None".to_string());

                            writeln!(fmt, "// Parent: {}", parent_name)?;
                            writeln!(fmt, "// Field count: {}", class.fields.len())?;

                            fmt.block(
                                &format!("public static class {}", slugify(&class.name)),
                                false,
                                |fmt| {
                                    for field in &class.fields {
                                        writeln!(
                                            fmt,
                                            "public const nint {} = {:#X}; // {}",
                                            sanitize_ident(&field.name),
                                            field.offset,
                                            field.type_name
                                        )?;
                                    }

                                    Ok(())
                                },
                            )?;
                        }

                        Ok(())
                    },
                )?;
            }

            Ok(())
        })
    }

    fn write_hpp(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        writeln!(fmt, "#pragma once\n")?;
        writeln!(fmt, "#include <cstddef>")?;
        writeln!(fmt, "#include <cstdint>\n")?;

        fmt.block("namespace tf2_dumper", false, |fmt| {
            fmt.block("namespace netvars", false, |fmt| {
                for (module_name, classes) in self {
                    writeln!(fmt, "// Module: {}", module_name)?;
                    writeln!(fmt, "// Class count: {}", classes.len())?;

                    fmt.block(
                        &format!("namespace {}", AsSnakeCase(slugify(module_name))),
                        false,
                        |fmt| {
                            for class in classes {
                                let parent_name = class
                                    .parent_name
                                    .as_deref()
                                    .map(slugify)
                                    .unwrap_or("None".to_string());

                                writeln!(fmt, "// Parent: {}", parent_name)?;
                                writeln!(fmt, "// Field count: {}", class.fields.len())?;

                                fmt.block(
                                    &format!("namespace {}", slugify(&class.name)),
                                    false,
                                    |fmt| {
                                        for field in &class.fields {
                                            writeln!(
                                                fmt,
                                                "constexpr std::ptrdiff_t {} = {:#X}; // {}",
                                                sanitize_ident(&field.name),
                                                field.offset,
                                                field.type_name
                                            )?;
                                        }

                                        Ok(())
                                    },
                                )?;
                            }

                            Ok(())
                        },
                    )?;
                }

                Ok(())
            })
        })
    }

    fn write_json(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        let content: BTreeMap<_, _> = self
            .iter()
            .map(|(module_name, classes)| {
                let classes: BTreeMap<_, _> = classes
                    .iter()
                    .map(|class| {
                        let fields: BTreeMap<_, _> = class
                            .fields
                            .iter()
                            .map(|field| {
                                let entry =
                                    json!({ "type_name": field.type_name, "offset": field.offset });

                                (field.name.clone(), entry)
                            })
                            .collect();

                        (class.name.clone(), fields)
                    })
                    .collect();

                (module_name.clone(), classes)
            })
            .collect();

        fmt.write_str(&serde_json::to_string_pretty(&content).unwrap())
    }

    fn write_rs(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        writeln!(
            fmt,
            "#![allow(non_snake_case, non_upper_case_globals, unused)]\n"
        )?;

        fmt.block("pub mod tf2_dumper", false, |fmt| {
            fmt.block("pub mod netvars", false, |fmt| {
                for (module_name, classes) in self {
                    writeln!(fmt, "// Module: {}", module_name)?;
                    writeln!(fmt, "// Class count: {}", classes.len())?;

                    fmt.block(
                        &format!("pub mod {}", AsSnakeCase(slugify(module_name))),
                        false,
                        |fmt| {
                            for class in classes {
                                fmt.block(
                                    &format!("pub mod {}", slugify(&class.name)),
                                    false,
                                    |fmt| {
                                        for field in &class.fields {
                                            writeln!(
                                                fmt,
                                                "pub const {}: usize = {:#X}; // {}",
                                                sanitize_ident(&field.name),
                                                field.offset,
                                                field.type_name
                                            )?;
                                        }

                                        Ok(())
                                    },
                                )?;
                            }

                            Ok(())
                        },
                    )?;
                }

                Ok(())
            })
        })
    }

    fn write_zig(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        fmt.block("pub const tf2_dumper = struct", true, |fmt| {
            fmt.block("pub const netvars = struct", true, |fmt| {
                for (module_name, classes) in self {
                    writeln!(fmt, "// Module: {}", module_name)?;
                    writeln!(fmt, "// Class count: {}", classes.len())?;

                    let module_name = zig_ident(&AsSnakeCase(slugify(module_name)).to_string());

                    fmt.block(
                        &format!("pub const {} = struct", module_name),
                        true,
                        |fmt| {
                            for class in classes {
                                fmt.block(
                                    &format!("pub const {} = struct", zig_ident(&class.name)),
                                    true,
                                    |fmt| {
                                        for field in &class.fields {
                                            writeln!(
                                                fmt,
                                                "pub const {}: usize = {:#X}; // {}",
                                                zig_ident(&sanitize_ident(&field.name)),
                                                field.offset,
                                                field.type_name
                                            )?;
                                        }

                                        Ok(())
                                    },
                                )?;
                            }

                            Ok(())
                        },
                    )?;
                }

                Ok(())
            })
        })
    }
}

/// Netvar array element props are named like "0000"; prefix an underscore so
/// they form valid identifiers in the generated code files.
#[inline]
fn sanitize_ident(name: &str) -> String {
    if name.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(true) {
        format!("_{}", name)
    } else {
        name.to_string()
    }
}
