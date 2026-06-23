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

const DEFAULT_S2S_FRAME_READ_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S2sFrameReadTimeout(Duration);

impl S2sFrameReadTimeout {
    pub const fn new(timeout: Duration) -> Self {
        Self(timeout)
    }

    pub const fn get(self) -> Duration {
        self.0
    }
}

impl Default for S2sFrameReadTimeout {
    fn default() -> Self {
        Self(DEFAULT_S2S_FRAME_READ_TIMEOUT)
    }
}

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
            let frame_timeout = req
                .extensions()
                .get::<S2sFrameReadTimeout>()
                .copied()
                .unwrap_or_default()
                .get();

            let inputs = decode_s2s_append_inputs(
                req.into_body()
                    .into_data_stream()
                    .map(|result| result.map_err(io::Error::other)),
                frame_timeout,
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
    frame_started_at: Option<Instant>,
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
        frame_started_at: None,
        frame_deadline: None,
        frame_timeout,
    };

    futures_util::stream::try_unfold(state, |mut state| async move {
        loop {
            match state.decoder.decode(&mut state.buffer) {
                Ok(Some(s2s::SessionMessage::Regular(data))) => {
                    state.arm_or_clear_frame_deadline();
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
                    state.arm_frame_deadline_if_unset();
                }
                Err(err) => return Err(err.into()),
            }

            let next = match state.frame_deadline {
                Some(deadline) => timeout_at(deadline, state.body.as_mut().next())
                    .await
                    .map_err(|_| state.s2s_frame_timeout())?,
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

impl S2sAppendDecodeState {
    fn arm_or_clear_frame_deadline(&mut self) {
        if self.buffer.is_empty() {
            self.frame_started_at = None;
            self.frame_deadline = None;
        } else {
            self.arm_frame_deadline();
        }
    }

    fn arm_frame_deadline_if_unset(&mut self) {
        if !self.buffer.is_empty() && self.frame_deadline.is_none() {
            self.arm_frame_deadline();
        }
    }

    fn arm_frame_deadline(&mut self) {
        let now = Instant::now();
        // Buffered trailing bytes start the next frame's deadline.
        self.frame_started_at = Some(now);
        self.frame_deadline = Some(now + self.frame_timeout);
    }

    fn s2s_frame_timeout(&self) -> AppendInputStreamError {
        AppendInputStreamError::FrameTimeout {
            buffered_bytes: self.buffer.len(),
            elapsed: self
                .frame_started_at
                .map_or(self.frame_timeout, |started_at| started_at.elapsed()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;
    use futures_util::{StreamExt as _, pin_mut, stream};

    use super::*;

    fn encoded_append_frame() -> Bytes {
        s2s::SessionMessage::regular(
            s2s::CompressionAlgorithm::None,
            &proto::AppendInput {
                records: vec![proto::AppendRecord {
                    timestamp: None,
                    headers: vec![],
                    body: Bytes::from_static(b"x"),
                }],
                match_seq_num: None,
                fencing_token: None,
            },
        )
        .unwrap()
        .encode()
    }

    #[test]
    fn s2s_frame_read_timeout_defaults_to_request_timeout() {
        assert_eq!(S2sFrameReadTimeout::default().get(), Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn s2s_append_decode_does_not_timeout_before_frame_starts() {
        let body = stream::pending::<Result<Bytes, io::Error>>();
        let inputs = decode_s2s_append_inputs(body, S2sFrameReadTimeout::default().get());
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
        let inputs = decode_s2s_append_inputs(body, S2sFrameReadTimeout::default().get());
        pin_mut!(inputs);

        let next = inputs.next();
        pin_mut!(next);
        tokio::select! {
            result = &mut next => panic!("unexpected decode result: {result:?}"),
            _ = tokio::task::yield_now() => {}
        }

        tokio::time::advance(Duration::from_secs(5)).await;
        let err = next.await.expect("stream item").expect_err("timeout");
        match err {
            AppendInputStreamError::FrameTimeout {
                buffered_bytes,
                elapsed,
            } => {
                assert_eq!(buffered_bytes, 3);
                assert_eq!(elapsed, Duration::from_secs(5));
            }
            AppendInputStreamError::FrameDecode(err) => panic!("unexpected decode error: {err}"),
            AppendInputStreamError::Validation(err) => {
                panic!("unexpected validation error: {err}");
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn s2s_append_decode_times_out_buffered_next_frame() {
        let mut chunk = BytesMut::from(encoded_append_frame().as_ref());
        chunk.extend_from_slice(&[0, 0, 2]);
        let body =
            stream::once(async { Ok::<_, io::Error>(chunk.freeze()) }).chain(stream::pending());
        let inputs = decode_s2s_append_inputs(body, S2sFrameReadTimeout::default().get());
        pin_mut!(inputs);

        inputs
            .next()
            .await
            .expect("first stream item")
            .expect("first frame");

        tokio::time::advance(Duration::from_secs(5)).await;
        let err = inputs
            .next()
            .await
            .expect("second stream item")
            .expect_err("timeout");
        match err {
            AppendInputStreamError::FrameTimeout {
                buffered_bytes,
                elapsed,
            } => {
                assert_eq!(buffered_bytes, 3);
                assert_eq!(elapsed, Duration::from_secs(5));
            }
            AppendInputStreamError::FrameDecode(err) => panic!("unexpected decode error: {err}"),
            AppendInputStreamError::Validation(err) => {
                panic!("unexpected validation error: {err}");
            }
        }
    }
}
