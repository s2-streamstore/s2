use compact_str::CompactString;
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
    /// Storage classes available to the account in this location.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<Vec<String>>))]
    pub storage_classes: Option<Vec<CompactString>>,
    /// Default storage class for this location.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    pub default_storage_class: Option<CompactString>,
}

impl From<s2_common::location::LocationInfo> for LocationInfo {
    fn from(value: s2_common::location::LocationInfo) -> Self {
        let s2_common::location::LocationInfo {
            name,
            is_private,
            storage_classes,
            default_storage_class,
        } = value;

        Self {
            name,
            is_private,
            storage_classes: Some(storage_classes),
            default_storage_class: Some(default_storage_class),
        }
    }
}

pub type GetDefaultLocationResponse = LocationInfo;

pub type SetDefaultLocationRequest = LocationName;
