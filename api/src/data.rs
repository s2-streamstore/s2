use std::str::FromStr;

use base64ct::{Base64, Encoding as _};
use bytes::Bytes;
use s2_common::types::ValidationError;

#[derive(Debug)]
pub struct Json<T>(pub T);

#[cfg(feature = "axum")]
impl<T> axum::response::IntoResponse for Json<T>
where
    T: serde::Serialize,
{
    fn into_response(self) -> axum::response::Response {
        let Self(value) = self;
        axum::Json(value).into_response()
    }
}

#[derive(Debug)]
pub struct Proto<T>(pub T);

#[cfg(feature = "axum")]
impl<T> axum::response::IntoResponse for Proto<T>
where
    T: prost::Message,
{
    fn into_response(self) -> axum::response::Response {
        let headers = [(
            http::header::CONTENT_TYPE,
            http::header::HeaderValue::from_static("application/protobuf"),
        )];
        let body = self.0.encode_to_vec();
        (headers, body).into_response()
    }
}

#[rustfmt::skip]
#[derive(Debug, Default, Clone, Copy)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum Format {
    #[default]
    #[cfg_attr(feature = "utoipa", schema(rename = "raw"))]
    Raw,
    #[cfg_attr(feature = "utoipa", schema(rename = "base64"))]
    Base64,
}

impl s2_common::http::ParseableHeader for Format {
    fn name() -> &'static http::HeaderName {
        &FORMAT_HEADER
    }
}

impl Format {
    pub fn encode(self, bytes: &[u8]) -> String {
        match self {
            Format::Raw => String::from_utf8_lossy(bytes).into_owned(),
            Format::Base64 => Base64::encode_string(bytes),
        }
    }

    pub fn decode(self, s: String) -> Result<Bytes, ValidationError> {
        Ok(match self {
            Format::Raw => s.into_bytes().into(),
            Format::Base64 => Base64::decode_vec(&s)
                .map_err(|_| ValidationError("invalid Base64 encoding".to_owned()))?
                .into(),
        })
    }
}

impl FromStr for Format {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "raw" | "json" => Ok(Self::Raw),
            "base64" | "json-binsafe" => Ok(Self::Base64),
            _ => Err(ValidationError(s.to_string())),
        }
    }
}

pub static FORMAT_HEADER: http::HeaderName = http::HeaderName::from_static("s2-format");

#[rustfmt::skip]
#[cfg_attr(feature = "utoipa", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "utoipa", into_params(parameter_in = Header))]
pub struct S2FormatHeader {
    /// Defines the interpretation of record data (header name, header value, and body) with the JSON content type.
    /// Use `raw` (default) for efficient transmission and storage of Unicode data — storage will be in UTF-8.
    /// Use `base64` for safe transmission with efficient storage of binary data.
    #[cfg_attr(feature = "utoipa", param(required = false, rename = "s2-format"))]
    pub s2_format: Format,
}

#[cfg(feature = "axum")]
pub mod extract {
    use axum::{
        extract::{
            FromRequest, OptionalFromRequest, Request,
            rejection::{BytesRejection, JsonRejection},
        },
        response::{IntoResponse, Response},
    };
    use bytes::Bytes;
    use serde::de::DeserializeOwned;

    impl<S, T> FromRequest<S> for super::Json<T>
    where
        S: Send + Sync,
        T: DeserializeOwned,
    {
        type Rejection = JsonRejection;

        async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
            let axum::Json(value) =
                <axum::Json<T> as FromRequest<S>>::from_request(req, state).await?;
            Ok(Self(value))
        }
    }

    impl<S, T> OptionalFromRequest<S> for super::Json<T>
    where
        S: Send + Sync,
        T: DeserializeOwned,
    {
        type Rejection = JsonRejection;

        async fn from_request(req: Request, state: &S) -> Result<Option<Self>, Self::Rejection> {
            let Some(ctype) = req.headers().get(http::header::CONTENT_TYPE) else {
                return Ok(None);
            };
            if !crate::mime::parse(ctype)
                .as_ref()
                .is_some_and(crate::mime::is_json)
            {
                Err(JsonRejection::MissingJsonContentType(Default::default()))?;
            }
            let bytes = Bytes::from_request(req, state)
                .await
                .map_err(JsonRejection::BytesRejection)?;
            if bytes.is_empty() {
                return Ok(None);
            }
            let value = axum::Json::<T>::from_bytes(&bytes)?.0;
            Ok(Some(Self(value)))
        }
    }

    /// Workaround for https://github.com/tokio-rs/axum/issues/3623
    #[derive(Debug)]
    pub struct JsonOpt<T>(pub Option<T>);

    impl<S, T> FromRequest<S> for JsonOpt<T>
    where
        S: Send + Sync,
        T: DeserializeOwned,
    {
        type Rejection = JsonRejection;

        async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
            match <super::Json<T> as OptionalFromRequest<S>>::from_request(req, state).await {
                Ok(Some(super::Json(value))) => Ok(Self(Some(value))),
                Ok(None) => Ok(Self(None)),
                Err(e) => Err(e),
            }
        }
    }

    #[derive(Debug, thiserror::Error)]
    pub enum ProtoRejection {
        #[error(transparent)]
        BytesRejection(#[from] BytesRejection),
        #[error(transparent)]
        Decode(#[from] prost::DecodeError),
    }

    impl IntoResponse for ProtoRejection {
        fn into_response(self) -> Response {
            match self {
                ProtoRejection::BytesRejection(e) => e.into_response(),
                ProtoRejection::Decode(e) => (
                    http::StatusCode::BAD_REQUEST,
                    format!("Invalid protobuf body: {e}"),
                )
                    .into_response(),
            }
        }
    }

    impl<S, T> FromRequest<S> for super::Proto<T>
    where
        S: Send + Sync,
        T: prost::Message + Default,
    {
        type Rejection = ProtoRejection;

        async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
            let bytes = Bytes::from_request(req, state).await?;
            Ok(super::Proto(T::decode(bytes)?))
        }
    }
}
