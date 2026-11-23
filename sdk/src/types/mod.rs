//! Types relevant to [`S2`](crate::S2), [`S2Basin`](crate::S2Basin), and
//! [`S2Stream`](crate::S2Stream).

mod access;
mod config;
mod metrics;
mod network_policy;
mod records;
mod resources;
#[cfg(test)]
mod tests;

use std::time::Duration;

/// Contiguous byte buffer.
pub use bytes::Bytes;
/// Wall-clock UTC timestamp.
pub use jiff::Timestamp;
/// Rustls cryptographic provider for [`S2Config::with_rustls_crypto_provider`].
pub use rustls::crypto::CryptoProvider;
/// Access token ID.
///
/// **Note:** It must be unique to the account and between 1 and 96 bytes in length, and must
/// not contain NUL bytes.
pub use s2_common::access::AccessTokenId;
/// Prefix filter for [`ListAccessTokensInput::with_prefix`]. Must not contain NUL bytes.
pub use s2_common::access::AccessTokenIdPrefix;
/// Cursor for [`ListAccessTokensInput::with_start_after`]. Must not contain NUL bytes.
pub use s2_common::access::AccessTokenIdStartAfter;
/// Basin name.
///
/// **Note:** It must be globally unique and between 8 and 48 bytes in length. It can only
/// comprise lowercase letters, numbers, and hyphens. It cannot begin or end with a hyphen.
pub use s2_common::basin::BasinName;
/// Prefix filter for [`ListBasinsInput::with_prefix`].
pub use s2_common::basin::BasinNamePrefix;
/// Cursor for [`ListBasinsInput::with_start_after`].
pub use s2_common::basin::BasinNameStartAfter;
/// Location name.
///
/// **Note:** It must be between 1 and 64 characters in length and can only comprise ASCII
/// letters, numbers, colons, hyphens, and periods.
pub use s2_common::location::LocationName;
/// IP network in CIDR notation, e.g. `203.0.113.0/24`. Host bits must be zero.
pub use s2_common::network_policy::Cidr;
/// Random suffix distinguishing successive network policies created under the same slug.
pub use s2_common::network_policy::NetworkPolicyNonce;
/// Full network policy reference, `<slug>.<nonce>`, which access tokens are bound to.
pub use s2_common::network_policy::NetworkPolicyRef;
/// Network policy slug or full reference, used when getting or deleting a policy or binding an
/// access token.
pub use s2_common::network_policy::NetworkPolicySelector;
/// Network policy slug.
///
/// **Note:** It must be unique to the account and between 1 and 96 bytes in length, and can
/// only comprise ASCII letters, numbers, hyphens, and underscores.
pub use s2_common::network_policy::NetworkPolicySlug;
/// Prefix filter for [`ListNetworkPoliciesInput::with_prefix`].
pub use s2_common::network_policy::NetworkPolicySlugPrefix;
/// Cursor for [`ListNetworkPoliciesInput::with_start_after`].
pub use s2_common::network_policy::NetworkPolicySlugStartAfter;
/// AWS VPC endpoint ID, e.g. `vpce-0a1b2c3d4e5f67890`.
pub use s2_common::network_policy::VpcEndpointId;
/// Stream name.
///
/// **Note:** It must be unique to the basin and between 1 and 253 bytes in length, and must
/// not contain NUL bytes.
pub use s2_common::stream::StreamName;
/// Prefix filter for [`ListStreamsInput::with_prefix`]. Must not contain NUL bytes.
pub use s2_common::stream::StreamNamePrefix;
/// Cursor for [`ListStreamsInput::with_start_after`]. Must not contain NUL bytes.
pub use s2_common::stream::StreamNameStartAfter;

pub(crate) use self::config::AccessToken;
pub use self::{access::*, config::*, metrics::*, network_policy::*, records::*, resources::*};
use crate::error::ValidationError;

/// Record count and metered byte limits for a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BatchLimits {
    /// Maximum number of records in a batch (`1000`).
    pub count: usize,
    /// Maximum metered bytes in a batch (`1 MiB`).
    pub bytes: usize,
}

/// Maximum record batch limits (count and metered bytes).
pub const RECORD_BATCH_MAX: BatchLimits = BatchLimits {
    count: s2_common::caps::RECORD_BATCH_MAX.count,
    bytes: s2_common::caps::RECORD_BATCH_MAX.bytes,
};

pub(crate) const ONE_MIB: usize = 1024 * 1024;
pub(crate) const RFC3339_MIN: Timestamp = Timestamp::constant(-62_167_219_200, 0);

pub(crate) fn whole_seconds(duration: Duration, field: &str) -> Result<u64, ValidationError> {
    if duration.subsec_nanos() != 0 {
        return Err(ValidationError(format!(
            "{field} must be a whole number of seconds"
        )));
    }
    Ok(duration.as_secs())
}

pub(crate) fn validate_rfc3339_timestamp(ts: Timestamp) -> Result<Timestamp, ValidationError> {
    if ts < RFC3339_MIN {
        return Err(ValidationError(format!(
            "timestamp ({ts}) year must be between 0000 and 9999 for RFC 3339"
        )));
    }
    Ok(ts)
}

pub(crate) fn timestamp_from_epoch_secs(secs: u32) -> Timestamp {
    Timestamp::from_second(i64::from(secs)).expect("u32 Unix epoch seconds fits in Timestamp")
}

pub(crate) fn validate_metrics_timestamp(
    ts: Timestamp,
    field: &str,
) -> Result<u32, ValidationError> {
    let err = || {
        ValidationError(format!(
            "{field} ({ts}) must be between 0 and {} Unix epoch seconds",
            u32::MAX
        ))
    };
    if ts < Timestamp::UNIX_EPOCH {
        return Err(err());
    }
    u32::try_from(ts.as_second()).map_err(|_| err())
}

pub(crate) fn request_token() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}
