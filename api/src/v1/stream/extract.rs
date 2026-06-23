use std::{io, pin::Pin, time::Duration};

use axum::{
    body::Bytes,
    extract::{FromRequest, FromRequestParts, Request},
    response::{IntoResponse, Response},
};
use bytes::BytesMut;
use futures_core::Stream;
use futures_util::StreamExt as _;
use http::{StatusCode, request::Parts};
use s2_common::{
    encryption::EncryptionKey,
    http::{ParseableHeader, extract::HeaderRejection},
};
use tokio::time::{Instant, timeout_at};
use tokio_util::codec::Decoder as _;

use super::{AppendInput, AppendInputStreamError, AppendRequest, ReadRequest, proto, s2s};
use crate::{
    data::{
        Format, Json, Proto,
        extract::{JsonExtractionRejection, ProtoRejection},
    },
    mime::JsonOrProto,
    v1::stream::sse::LastEventId,
};

const S2S_FRAME_READ_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, thiserror::Error)]
pub enum AppendRequestRejection {
    #[error(transparent)]
    HeaderRejection(#[from] HeaderRejection),
    #[error(transparent)]
    JsonRejection(#[from] JsonExtractionRejection),
    #[error(transparent)]
    ProtoRejection(#[from] ProtoRejection),
    #[error(transparent)]
    Validation(#[from] s2_common::ValidationError),
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

            let inputs = decode_s2s_append_inputs(
                req.into_body()
                    .into_data_stream()
                    .map(|result| result.map_err(io::Error::other)),
                S2S_FRAME_READ_TIMEOUT,
            );

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

type S2sBodyStream = Pin<Box<dyn Stream<Item = Result<Bytes, io::Error>> + Send>>;

struct S2sAppendDecodeState {
    body: S2sBodyStream,
    decoder: s2s::FrameDecoder,
    buffer: BytesMut,
    frame_deadline: Option<Instant>,
    frame_timeout: Duration,
}

fn decode_s2s_append_inputs(
    body: impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static,
    frame_timeout: Duration,
) -> impl Stream<Item = Result<s2_common::stream::AppendInput, AppendInputStreamError>> {
    let state = S2sAppendDecodeState {
        body: Box::pin(body),
        decoder: s2s::FrameDecoder,
        buffer: BytesMut::new(),
        frame_deadline: None,
        frame_timeout,
    };

    futures_util::stream::try_unfold(state, |mut state| async move {
        loop {
            match state.decoder.decode(&mut state.buffer) {
                Ok(Some(s2s::SessionMessage::Regular(data))) => {
                    state.frame_deadline = if state.buffer.is_empty() {
                        None
                    } else {
                        Some(Instant::now() + state.frame_timeout)
                    };
                    let input = data.try_into_proto::<proto::AppendInput>()?;
                    let input = s2_common::stream::AppendInput::try_from(input)?;
                    return Ok(Some((input, state)));
                }
                Ok(Some(s2s::SessionMessage::Terminal(_))) => {
                    return Err(AppendInputStreamError::FrameDecode(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Unexpected terminal frame as input",
                    )));
                }
                Ok(None) => {
                    if !state.buffer.is_empty() && state.frame_deadline.is_none() {
                        state.frame_deadline = Some(Instant::now() + state.frame_timeout);
                    }
                }
                Err(err) => return Err(err.into()),
            }

            let next = match state.frame_deadline {
                Some(deadline) => timeout_at(deadline, state.body.as_mut().next())
                    .await
                    .map_err(|_| s2s_frame_timeout())?,
                None => state.body.as_mut().next().await,
            };

            match next {
                Some(Ok(chunk)) => state.buffer.extend_from_slice(&chunk),
                Some(Err(err)) => return Err(err.into()),
                None if state.buffer.is_empty() => return Ok(None),
                None => {
                    return Err(AppendInputStreamError::FrameDecode(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "not all bytes were consumed from the buffer, {} remaining",
                            state.buffer.len()
                        ),
                    )));
                }
            }
        }
    })
}

fn s2s_frame_timeout() -> AppendInputStreamError {
    AppendInputStreamError::FrameDecode(io::Error::new(
        io::ErrorKind::TimedOut,
        "S2S frame read timed out",
    ))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;
    use futures_util::{StreamExt as _, pin_mut, stream};

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn s2s_append_decode_does_not_timeout_before_frame_starts() {
        let body = stream::pending::<Result<Bytes, io::Error>>();
        let inputs = decode_s2s_append_inputs(body, Duration::from_secs(20));
        pin_mut!(inputs);

        let next = inputs.next();
        pin_mut!(next);
        tokio::select! {
            result = &mut next => panic!("unexpected decode result: {result:?}"),
            _ = tokio::task::yield_now() => {}
        }

        tokio::time::advance(Duration::from_secs(40)).await;
        tokio::select! {
            result = &mut next => panic!("unexpected decode result: {result:?}"),
            _ = tokio::task::yield_now() => {}
        }
    }

    #[tokio::test(start_paused = true)]
    async fn s2s_append_decode_times_out_incomplete_frame() {
        let body = stream::once(async { Ok::<_, io::Error>(Bytes::from_static(&[0, 0, 2])) })
            .chain(stream::pending());
        let inputs = decode_s2s_append_inputs(body, Duration::from_secs(20));
        pin_mut!(inputs);

        let next = inputs.next();
        pin_mut!(next);
        tokio::select! {
            result = &mut next => panic!("unexpected decode result: {result:?}"),
            _ = tokio::task::yield_now() => {}
        }

        tokio::time::advance(Duration::from_secs(20)).await;
        let err = next.await.expect("stream item").expect_err("timeout");
        match err {
            AppendInputStreamError::FrameDecode(err) => {
                assert_eq!(err.kind(), io::ErrorKind::TimedOut);
                assert_eq!(err.to_string(), "S2S frame read timed out");
            }
            AppendInputStreamError::Validation(err) => {
                panic!("unexpected validation error: {err}");
            }
        }
    }
}
