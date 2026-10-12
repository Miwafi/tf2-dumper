//! `SendPropType` values as used by Team Fortress 2 (Source 1).
//!
//! Verified empirically against a live process: `m_iHealth` is `DPT_Int`,
//! `m_vecOrigin` is `DPT_VecXY`, string props (`m_isz*`) are `DPT_String`,
//! array props (`m_flPoseParameter`) are `DPT_Array`.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum SendPropType {
    Int = 0,
    Float = 1,
    Vec = 2,
    VecXY = 3,
    String = 4,
    Array = 5,
    DataTable = 6,
}

impl SendPropType {
    pub fn from_i32(value: i32) -> Option<Self> {
        Some(match value {
            0 => Self::Int,
            1 => Self::Float,
            2 => Self::Vec,
            3 => Self::VecXY,
            4 => Self::String,
            5 => Self::Array,
            6 => Self::DataTable,
            _ => return None,
        })
    }

    /// Human-readable type name used in generated files.
    pub fn type_name(self) -> &'static str {
        match self {
            Self::Int => "int",
            Self::Float => "float",
            Self::Vec => "vector",
            Self::VecXY => "vector2d",
            Self::String => "string",
            Self::Array => "array",
            Self::DataTable => "datatable",
        }
    }
}
