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

    fn is_valid_rfc3339_syntax(s: &str) -> bool {
        // RFC 3339 §5.6: YYYY-MM-DD[T|t| ]HH:MM:SS(.digits)?(Z|z|[+-]HH:MM)
        let b = s.as_bytes();
        if b.len() < 20 {
            return false;
        }
        if !(b[0..4].iter().all(u8::is_ascii_digit)
            && b[4] == b'-'
            && b[5..7].iter().all(u8::is_ascii_digit)
            && b[7] == b'-'
            && b[8..10].iter().all(u8::is_ascii_digit)
            && matches!(b[10], b'T' | b't' | b' ')
            && b[11..13].iter().all(u8::is_ascii_digit)
            && b[13] == b':'
            && b[14..16].iter().all(u8::is_ascii_digit)
            && b[16] == b':'
            && b[17..19].iter().all(u8::is_ascii_digit))
        {
            return false;
        }
        let mut i = 19;
        if b[i] == b'.' {
            i += 1;
            let frac_start = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if i == frac_start || i >= b.len() {
                return false;
            }
        }
        match b[i] {
            b'Z' | b'z' => i + 1 == b.len(),
            b'+' | b'-' => {
                i + 6 == b.len()
                    && b[i + 1..i + 3].iter().all(u8::is_ascii_digit)
                    && b[i + 3] == b':'
                    && b[i + 4..i + 6].iter().all(u8::is_ascii_digit)
            }
            _ => false,
        }
    }

    fn parse_rfc3339(s: &str) -> Result<Timestamp, String> {
        if !is_valid_rfc3339_syntax(s) {
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
