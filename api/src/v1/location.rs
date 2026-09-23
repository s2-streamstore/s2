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
    pub storage_classes: Option<Vec<String>>,
    /// Default storage class for this location.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_storage_class: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::LocationInfo;

    #[test]
    fn common_location_serializes_future_storage_classes() {
        let location = LocationInfo::from(s2_common::location::LocationInfo {
            name: "aws:us-east-1".parse().unwrap(),
            is_private: false,
            storage_classes: vec!["express".into(), "future".into()],
            default_storage_class: "future".into(),
        });
        assert_eq!(
            serde_json::to_value(location).unwrap(),
            serde_json::json!({
                "name": "aws:us-east-1",
                "is_private": false,
                "storage_classes": ["express", "future"],
                "default_storage_class": "future",
            }),
        );
    }
}
