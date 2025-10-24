pub mod access;
pub mod basin;
pub mod config;
pub mod metrics;
pub mod stream;

use s2_common::types;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

#[rustfmt::skip]
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Header)]
pub struct S2RequestTokenHeader {
    /// Client-specified request token for idempotent retries.
    #[param(required = false, rename = "s2-request-token")]
    pub s2_request_token: String,
}

#[rustfmt::skip]
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Path)]
pub struct AccessTokenIdPathSegment {
    /// Access token ID.
    #[param(value_type = String, minimum = 1, maximum = 96)]
    pub id: types::access::AccessTokenId,
}

#[rustfmt::skip]
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Path)]
pub struct BasinNamePathSegment {
    /// Basin name.
    #[param(value_type = String, minimum = 8, maximum = 48, pattern = "^(?!-)[a-z0-9-]{8,48}(?<!-)$")]
    pub basin: types::basin::BasinName,
}

#[rustfmt::skip]
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Path)]
pub struct StreamNamePathSegment {
    /// Stream name.
    #[param(value_type = String, minimum = 1, maximum = 512)]
    pub stream: types::stream::StreamName,
}

macro_rules! impl_list_request_try_from {
    ($name:ident, $prefix:ty, $start_after:ty) => {
        impl TryFrom<$name>
            for s2_common::types::resources::ListItemsRequest<$prefix, $start_after>
        {
            type Error = s2_common::types::ValidationError;

            fn try_from(value: $name) -> Result<Self, Self::Error> {
                let $name {
                    prefix,
                    start_after,
                    limit,
                } = value;

                Ok(Self::try_from(
                    s2_common::types::resources::ListItemsRequestParts {
                        prefix: prefix.unwrap_or_default(),
                        start_after: start_after.unwrap_or_default(),
                        limit: limit.map(Into::into).unwrap_or_default(),
                    },
                )?)
            }
        }
    };
}

pub(crate) use impl_list_request_try_from;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<&'static str>,
    pub message: String,
}
