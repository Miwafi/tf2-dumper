//! Source 1 (Team Fortress 2, 64-bit) datatable structures.
//!
//! Layouts verified against a live `tf_win64.exe` process (build 25738890):
//!
//! - `ClientClass` (size 0x30)
//! - `RecvTable`   (fields at 0x00..0x18)
//! - `RecvProp`    (size 0x60)

use memflow::prelude::v1::*;

#[rustfmt::skip]
#[derive(Pod)]
#[repr(C)]
pub struct ClientClass {
    pub create_fn: Pointer64<()>,       // 0x0000
    pub create_event_fn: Pointer64<()>, // 0x0008
    pub network_name: Pointer64<ReprCString>, // 0x0010
    pub recv_table: Pointer64<RecvTable>,     // 0x0018
    pub next: Pointer64<ClientClass>,         // 0x0020
    pub class_id: i32,                        // 0x0028
    pad_0: [u8; 0x4],                         // 0x002C
}

#[rustfmt::skip]
#[derive(Pod)]
#[repr(C)]
pub struct RecvTable {
    pub props: Pointer64<[RecvProp]>, // 0x0000
    pub prop_count: i32,              // 0x0008
    pad_0: [u8; 0x4],                 // 0x000C
    pub decoder: Pointer64<()>,       // 0x0010
    pub net_table_name: Pointer64<ReprCString>, // 0x0018
}

#[rustfmt::skip]
#[derive(Pod)]
#[repr(C)]
pub struct RecvProp {
    pub var_name: Pointer64<ReprCString>, // 0x0000
    pub recv_type: i32,                   // 0x0008
    pub flags: i32,                       // 0x000C
    pub string_buffer_size: i32,          // 0x0010
    pad_0: [u8; 0x4],                     // 0x0014
    pub extra_data: Pointer64<()>,        // 0x0018
    pad_1: [u8; 0x18],                    // 0x0020
    pub proxy_fn: Pointer64<()>,          // 0x0038
    pub data_table: Pointer64<RecvTable>, // 0x0040
    pub offset: i32,                      // 0x0048
    pub element_stride: i32,              // 0x004C
    pub element_count: i32,               // 0x0050
    pad_2: [u8; 0xC],                     // 0x0054
}
