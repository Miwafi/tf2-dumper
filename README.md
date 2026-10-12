# tf2-dumper

An external offset/interface dumper for the 64-bit (2024+) version of Team
Fortress 2. Powered by [memflow](https://github.com/memflow/memflow).

## Acknowledgements

This project is based on [a2x/cs2-dumper](https://github.com/a2x/cs2-dumper),
an external dumper for Counter-Strike 2. The project layout, command-line
interface, memflow integration and multi-language code generators are
inherited from the original project.

Counter-Strike 2 runs on Source 2, which exposes a reflection (schema) system,
while the 2024 x64 build of Team Fortress 2 still runs on the original Source
1 engine and only provides the classic
`ClientClass` -> `RecvTable` -> `RecvProp` netvar system. The analysis core
was therefore rewritten for Source 1:

- The schema and buttons analysis of the original project was removed
  (Source 1 has no schema system, and TF2 does not expose usable button
  (`kbutton_t`) name data in memory on x64).
- Netvar analysis was rebuilt around the Source 1 netvar hierarchy.
- Global offset discovery was replaced with algorithms appropriate for
  Source 1.

## Features

- **Signature-free.** Everything is reconstructed by walking runtime data
  structures in the game's memory. No byte patterns are used anywhere, so the
  dump should keep working across game updates as long as Valve does not
  change the `ClientClass` / `RecvTable` / `RecvProp` layouts.
- **Full netvar hierarchy.** Discovers all client classes through a two-phase
  scan of the module's data sections, resolves inheritance via `baseclass`
  links (including abstract intermediates that have no `ClientClass`, such as
  `CNextBot`), follows Source 1 relative-offset semantics, and expands both
  statically built and heap-allocated array element tables.
- **Algorithmic globals.**
  - `dwGetAllClasses` — the data slot holding the head of the longest
    `ClientClass::next` linked list.
  - `dwEntityList` — the `IClientEntityList` instance exposed via the
    `VClientEntityList003` interface.
  - `dwGlobalVars` — the static `CGlobalVarsBase` object in `engine.dll`,
    located by its runtime invariant
    `curtime == tickcount * interval_per_tick` (TF2's fixed 0.015 tick
    interval).
- **Multi-language output.** Generates C# (`.cs`), C++ (`.hpp`), JSON,
  Rust (`.rs`) and Zig files, with netvars written per module
  (e.g. `client_dll.cs`).

## What It Produces

- `interfaces` — interface versions and their instance addresses per module.
- `netvars` — every `ClientClass` (e.g. `CTFPlayer`) with the name, type and
  relative offset of each netvar property.
- `offsets` — module-relative globals (see above).

## Usage

1. Ensure the game is running (being in the main menu should suffice).
2. Run the `tf2-dumper` executable.

_Note:_ If you run the executable without specifying an optional memflow
connector name, it will automatically use the
[memflow-native](https://github.com/memflow/memflow-native) OS layer to read
the memory of the game process. If you wish to use an existing memflow
connector instead, such as **pcileech** or **kvm**, you can pass the
`connector` and optional `connector-args` arguments to the program.

E.g (for pcileech). `tf2-dumper -c pcileech -a :device=FPGA -vv`

Certain connectors require elevated privileges, so run the executable as an
administrator on Windows when using them.

### Available Arguments

- `-c, --connector <connector>`: The name of the memflow connector to use.
- `-a, --connector-args <connector-args>`: Additional arguments to pass to the memflow connector.
- `-f, --file-types <file-types>`: The types of files to generate. Default: `cs`, `hpp`, `json`, `rs`, `zig`.
- `-i, --indent-size <indent-size>`: The number of spaces to use per indentation level. Default: `4`.
- `-o, --output <output>`: The output directory to write the generated files to. Default: `output`.
- `-p, --process-name <process-name>`: The name of the game process. Default: `tf_win64.exe`.
- `-v...`: Increase logging verbosity. Can be specified multiple times.
- `-h, --help`: Print help.
- `-V, --version`: Print version.

## License

Licensed under the MIT license ([LICENSE](./LICENSE)). Based on
[a2x/cs2-dumper](https://github.com/a2x/cs2-dumper).
