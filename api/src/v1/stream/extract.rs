use axum::{
    extract::{FromRequest, FromRequestParts, Request},
    response::{IntoResponse, Response},
};
use futures::StreamExt as _;
use http::{StatusCode, request::Parts};
use s2_common::{
    encryption::EncryptionKey,
    http::{ParseableHeader, extract::HeaderRejection},
    types,
};
use tokio_util::{codec::FramedRead, io::StreamReader};

use super::{AppendInput, AppendInputStreamError, AppendRequest, ReadRequest, proto, s2s};
use crate::{
    data::{
        Format, Json, Proto,
        extract::{JsonExtractionRejection, ProtoRejection},
    },
    mime::JsonOrProto,
    v1::stream::sse::LastEventId,
};

#[derive(Debug, thiserror::Error)]
pub enum AppendRequestRejection {
    #[error(transparent)]
    HeaderRejection(#[from] HeaderRejection),
    #[error(transparent)]
    JsonRejection(#[from] JsonExtractionRejection),
    #[error(transparent)]
    ProtoRejection(#[from] ProtoRejection),
    #[error(transparent)]
    Validation(#[from] types::ValidationError),
}

impl IntoResponse for AppendRequestRejection {
    fn into_response(self) -> Response {
        match self {
            AppendRequestRejection::HeaderRejection(e) => e.into_response(),
            AppendRequestRejection::JsonRejection(e) => e.into_response(),
            AppendRequestRejection::ProtoRejection(e) => e.into_response(),
            AppendRequestRejection::Validation(e) => {
                (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()).into_response()
            }
        }
    }
}

impl<S> FromRequest<S> for AppendRequest
where
    S: Send + Sync,
{
    type Rejection = AppendRequestRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let content_type = crate::mime::content_type(req.headers());
        let encryption_key = parse_header_opt::<EncryptionKey>(req.headers())?;

        if content_type.as_ref().is_some_and(crate::mime::is_s2s_proto) {
            let response_compression =
                s2s::CompressionAlgorithm::from_accept_encoding(req.headers());

            let body_reader = StreamReader::new(
                req.into_body()
                    .into_data_stream()
                    .map(|result| result.map_err(std::io::Error::other)),
            );

            let framed = FramedRead::new(body_reader, s2s::FrameDecoder);

            let inputs = futures::stream::try_unfold(framed, |mut framed| async move {
                let Some(msg) = framed.next().await else {
                    return Ok(None);
                };
                match msg? {
                    s2s::SessionMessage::Regular(data) => {
                        let input = data.try_into_proto::<proto::AppendInput>()?;
                        let input = types::stream::AppendInput::try_from(input)?;
                        Ok(Some((input, framed)))
                    }
                    s2s::SessionMessage::Terminal(_) => {
                        Err(AppendInputStreamError::FrameDecode(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Unexpected terminal frame as input",
                        )))
                    }
                }
            });

            return Ok(Self::S2s {
                encryption_key,
                inputs: Box::pin(inputs),
                response_compression,
            });
        }

        let request_mime = content_type
            .as_ref()
            .and_then(JsonOrProto::from_mime)
            .unwrap_or(JsonOrProto::Json);

        let response_mime = crate::mime::accept(req.headers())
            .as_ref()
            .and_then(JsonOrProto::from_mime)
            .unwrap_or(JsonOrProto::Json);

        let input = match request_mime {
            JsonOrProto::Proto => {
                let Proto(input) = Proto::<proto::AppendInput>::from_request(req, state).await?;
                input.try_into()?
            }
            JsonOrProto::Json => {
                let format = parse_header_opt::<Format>(req.headers())?.unwrap_or_default();
                let Json(input) = Json::<AppendInput>::from_request(req, state).await?;
                input.decode(format)?
            }
        };

        Ok(Self::Unary {
            encryption_key,
            input,
            response_mime,
        })
    }
}

impl<S> FromRequestParts<S> for ReadRequest
where
    S: Send + Sync,
{
    type Rejection = HeaderRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let content_type = crate::mime::content_type(&parts.headers);
        let encryption_key = parse_header_opt::<EncryptionKey>(&parts.headers)?;

        if content_type.as_ref().is_some_and(crate::mime::is_s2s_proto) {
            let response_compression =
                s2s::CompressionAlgorithm::from_accept_encoding(&parts.headers);
            return Ok(Self::S2s {
                encryption_key,
                response_compression,
            });
        }

        let format = parse_header_opt::<Format>(&parts.headers)?.unwrap_or_default();

        let accept = crate::mime::accept(&parts.headers);

        if accept.as_ref().is_some_and(crate::mime::is_event_stream) {
            let last_event_id = parse_header_opt::<LastEventId>(&parts.headers)?;
            return Ok(Self::EventStream {
                encryption_key,
                format,
                last_event_id,
            });
        }

        let response_mime = accept
            .as_ref()
            .and_then(JsonOrProto::from_mime)
            .unwrap_or(JsonOrProto::Json);

        Ok(Self::Unary {
            encryption_key,
            format,
            response_mime,
        })
    }
}

fn parse_header_opt<T>(headers: &http::HeaderMap) -> Result<Option<T>, HeaderRejection>
where
    T: ParseableHeader,
    T::Err: std::fmt::Display,
{
    match s2_common::http::extract::parse_header(headers) {
        Ok(value) => Ok(Some(value)),
        Err(HeaderRejection::MissingHeader(_)) => Ok(None),
        Err(e) => Err(e)?,
    }
}
