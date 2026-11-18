use compact_str::CompactString;
use s2_common::{self, location::LocationName};
use serde::{Deserialize, Serialize};

use super::MaybeKnown;

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct AwsPrivateNet {
    /// AWS PrivateLink endpoint service name, for creating a VPC endpoint.
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    pub service_name: CompactString,
}

/// How the account can reach a location over a private network. Exactly one kind applies.
#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum PrivateNet {
    /// AWS PrivateLink.
    Aws(AwsPrivateNet),
}

impl From<s2_common::location::PrivateNet> for PrivateNet {
    fn from(value: s2_common::location::PrivateNet) -> Self {
        match value {
            s2_common::location::PrivateNet::Aws(aws) => Self::Aws(AwsPrivateNet {
                service_name: aws.service_name,
            }),
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct LocationInfo {
    /// Location name.
    pub name: LocationName,
    /// Location represents a private placement, limited by account.
    pub is_private: bool,
    /// [Storage classes](https://s2.dev/docs/storage-classes) available to the account in this location.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<Vec<String>>))]
    pub storage_classes: Option<Vec<CompactString>>,
    /// Default [storage class](https://s2.dev/docs/storage-classes) for this location.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    pub default_storage_class: Option<CompactString>,
    /// [Private networking](https://s2.dev/docs/platform/private-networking) details for the
    /// account in this location, which can differ between accounts.
    /// Omitted until the account has a basin in this location, and when the location cannot be
    /// reached over a private network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<PrivateNet>))]
    pub private_net: Option<MaybeKnown<PrivateNet>>,
}

impl From<s2_common::location::LocationInfo> for LocationInfo {
    fn from(value: s2_common::location::LocationInfo) -> Self {
        let s2_common::location::LocationInfo {
            name,
            is_private,
            storage_classes,
            default_storage_class,
            private_net,
        } = value;

        Self {
            name,
            is_private,
            storage_classes: Some(storage_classes),
            default_storage_class: Some(default_storage_class),
            private_net: private_net.map(|private_net| MaybeKnown::Known(private_net.into())),
        }
    }
}

pub type GetDefaultLocationResponse = LocationInfo;

pub type SetDefaultLocationRequest = LocationName;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_net_kind_added_later_still_parses() {
        let parse = |private_net: &str| {
            serde_json::from_str::<LocationInfo>(&format!(
                r#"{{"name":"aws:us-east-1","is_private":false,"private_net":{private_net}}}"#
            ))
            .unwrap()
            .private_net
        };
        assert!(matches!(
            parse(r#"{"aws":{"service_name":"com.amazonaws.vpce.us-east-1.vpce-svc-0"}}"#),
            Some(MaybeKnown::Known(PrivateNet::Aws(aws))) if aws.service_name.ends_with("vpce-svc-0")
        ));
        assert_eq!(
            parse(r#"{"gcp":{"service_attachment":"x"}}"#)
                .map(|p| matches!(p, MaybeKnown::Unknown(kind) if kind == "gcp")),
            Some(true)
        );
    }
}
