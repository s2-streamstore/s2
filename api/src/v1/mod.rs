pub mod access;
pub mod basin;
pub mod config;
pub mod error;
pub mod location;
mod maybe_known;
pub mod metrics;
pub mod network_policy;
pub mod stream;

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

/// What a create or ensure did, as the `s2-provision-result` response header reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::IntoStaticStr)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "utoipa", schema(rename_all = "snake_case"))]
#[strum(serialize_all = "snake_case")]
pub enum ProvisionResult {
    /// The resource was created.
    Created,
    /// The resource existed, and its configuration was changed.
    Updated,
    /// The resource existed, and nothing was written.
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
