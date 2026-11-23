pub mod access;
pub mod basin;
pub mod config;
pub mod error;
pub mod location;
mod maybe_known;
pub mod metrics;
pub mod network_policy;
pub mod stream;

pub(crate) mod rfc3339 {
    use jiff::Timestamp;
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser};

    const RFC3339_MIN: Timestamp = Timestamp::constant(-62_167_219_200, 0);

    fn parse_rfc3339(s: &str) -> Result<Timestamp, String> {
        // RFC 3339 requires a 4-digit non-negative year (`0000`–`9999`) with no Temporal
        // `[TimeZone]` annotation suffix.
        if s.len() < 20 || !s.as_bytes()[..4].iter().all(u8::is_ascii_digit) || s.contains('[') {
            return Err(format!("invalid RFC 3339 timestamp: `{s}`"));
        }
        let ts: Timestamp = s
            .parse()
            .map_err(|e| format!("invalid RFC 3339 timestamp: {e}"))?;
        if ts < RFC3339_MIN {
            return Err(format!("timestamp `{s}` is outside RFC 3339 year range"));
        }
        Ok(ts)
    }

    pub(crate) mod option {
        use super::*;

        pub fn serialize<S>(value: &Option<Timestamp>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if let Some(ts) = value
                && *ts < RFC3339_MIN
            {
                return Err(ser::Error::custom(format!(
                    "timestamp `{ts}` is outside RFC 3339 year range"
                )));
            }
            value.serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Timestamp>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let opt = Option::<String>::deserialize(deserializer)?;
            opt.map(|s| parse_rfc3339(&s).map_err(de::Error::custom))
                .transpose()
        }
    }
}

pub use maybe_known::MaybeKnown;
use s2_common::{
    access::AccessTokenId, basin::BasinName, resources::RequestToken, stream::StreamName,
};

#[rustfmt::skip]
#[derive(Debug)]
#[cfg_attr(feature = "utoipa", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "utoipa", into_params(parameter_in = Header))]
pub struct S2RequestTokenHeader {
    /// Client-specified request token for idempotent retries.
    #[cfg_attr(feature = "utoipa", param(required = false, rename = "s2-request-token"))]
    pub s2_request_token: RequestToken,
}

/// Outcome of a create or ensure operation, reported in the `s2-provision-result` response header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::IntoStaticStr)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "utoipa", schema(rename_all = "snake_case"))]
#[strum(serialize_all = "snake_case")]
pub enum ProvisionResult {
    /// The resource was created.
    Created,
    /// The resource already existed and its configuration was updated.
    Updated,
    /// The resource already existed and no changes were made.
    Noop,
}

#[rustfmt::skip]
#[derive(Debug)]
#[cfg_attr(feature = "utoipa", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "utoipa", into_params(parameter_in = Path))]
pub struct AccessTokenIdPathSegment {
    /// Access token ID.
    pub id: AccessTokenId,
}

#[rustfmt::skip]
#[derive(Debug)]
#[cfg_attr(feature = "utoipa", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "utoipa", into_params(parameter_in = Path))]
pub struct BasinNamePathSegment {
    /// Basin name.
    pub basin: BasinName,
}

#[rustfmt::skip]
#[derive(Debug)]
#[cfg_attr(feature = "utoipa", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "utoipa", into_params(parameter_in = Path))]
pub struct StreamNamePathSegment {
    /// Stream name.
    pub stream: StreamName,
}

macro_rules! impl_list_request_conversions {
    ($name:ident, $prefix:ty, $start_after:ty) => {
        impl TryFrom<$name> for s2_common::resources::ListItemsRequest<$prefix, $start_after> {
            type Error = s2_common::ValidationError;

            fn try_from(value: $name) -> Result<Self, Self::Error> {
                let $name {
                    prefix,
                    start_after,
                    limit,
                } = value;

                Ok(Self {
                    prefix: prefix.unwrap_or_default(),
                    start_after: start_after.unwrap_or_default(),
                    limit: limit.map(Into::into).unwrap_or_default(),
                })
            }
        }
    };
}

pub(crate) use impl_list_request_conversions;
