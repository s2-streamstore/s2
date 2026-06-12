use s2_common::{self, location::LocationName};
use serde::{Deserialize, Serialize};

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct LocationInfo {
    /// Location name.
    pub name: LocationName,
    /// Location represents a private placement, limited by account.
    pub is_private: bool,
}

impl From<s2_common::location::LocationInfo> for LocationInfo {
    fn from(value: s2_common::location::LocationInfo) -> Self {
        let s2_common::location::LocationInfo { name, is_private } = value;

        Self { name, is_private }
    }
}

pub type GetDefaultLocationResponse = LocationInfo;

pub type SetDefaultLocationRequest = LocationName;
