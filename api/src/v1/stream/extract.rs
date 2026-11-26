use axum::{
    extract::{FromRequest, FromRequestParts, Request},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use futures_util::StreamExt as _;
use http::{StatusCode, request::Parts};
use s2_common::{
    encryption::EncryptionKey,
    http::{ParseableHeader, extract::HeaderRejection},
};

use super::{AppendInput, AppendInputStreamError, AppendRequest, ReadRequest, proto, s2s};
use crate::{
    data::{
        Format, Json, Proto,
        extract::{JsonExtractionRejection, ProtoRejection},
    },
    mime::JsonOrProto,
    v1::{config::StreamConfigHeader, stream::sse::LastEventId},
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
        let create_stream_config_patch = parse_header_opt::<StreamConfigHeader>(req.headers())?
            .map(|header| header.0)
            .unwrap_or_default();

        if content_type.as_ref().is_some_and(crate::mime::is_s2s_proto) {
            let response_compression =
                s2s::CompressionAlgorithm::from_accept_encoding(req.headers());

            let body_stream = req.into_body().into_data_stream();

            let inputs = futures_util::stream::try_unfold(
                (body_stream, s2s::ChunkFrameDecoder::new(), Bytes::new()),
                |(mut body_stream, mut decoder, mut current_chunk)| async move {
                    loop {
                        if let Some(msg) = decoder.decode_next(&mut current_chunk)? {
                            return match msg {
                                s2s::SessionMessage::Regular(data) => {
                                    let input = data.try_into_proto::<proto::AppendInput>()?;
                                    let input = s2_common::stream::AppendInput::try_from(input)?;
                                    Ok(Some((input, (body_stream, decoder, current_chunk))))
                                }
                                s2s::SessionMessage::Terminal(_) => {
                                    Err(AppendInputStreamError::FrameDecode(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        "Unexpected terminal frame as input",
                                    )))
                                }
                            };
                        }
                        match body_stream.next().await {
                            Some(Ok(chunk)) => {
                                current_chunk = chunk;
                            }
                            Some(Err(err)) => {
                                // Wrap with `io::Error::other` to preserve the underlying
                                // `axum::Error` / `hyper::Error` source chain for callers that
                                // classify transport body read disconnects.
                                return Err(AppendInputStreamError::FrameDecode(
                                    std::io::Error::other(err),
                                ));
                            }
                            None => {
                                if decoder.remaining_len() > 0 {
                                    return Err(AppendInputStreamError::FrameDecode(
                                        std::io::Error::new(
                                            std::io::ErrorKind::UnexpectedEof,
                                            format!(
                                                "truncated s2s frame at end of stream ({} bytes remaining)",
                                                decoder.remaining_len()
                                            ),
                                        ),
                                    ));
                                }
                                return Ok(None);
                            }
                        }
                    }
                },
            );

            return Ok(Self::S2s {
                encryption_key,
                create_stream_config_patch,
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
            create_stream_config_patch,
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
        let create_stream_config_patch = parse_header_opt::<StreamConfigHeader>(&parts.headers)?
            .map(|header| header.0)
            .unwrap_or_default();

        if content_type.as_ref().is_some_and(crate::mime::is_s2s_proto) {
            let response_compression =
                s2s::CompressionAlgorithm::from_accept_encoding(&parts.headers);
            return Ok(Self::S2s {
                encryption_key,
                create_stream_config_patch,
                response_compression,
            });
        }

        let format = parse_header_opt::<Format>(&parts.headers)?.unwrap_or_default();

        let accept = crate::mime::accept(&parts.headers);

        if accept.as_ref().is_some_and(crate::mime::is_event_stream) {
            let last_event_id = parse_header_opt::<LastEventId>(&parts.headers)?;
            return Ok(Self::EventStream {
                encryption_key,
                create_stream_config_patch,
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
            create_stream_config_patch,
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

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use futures_util::stream;

    use super::*;

    fn make_append_frame(body: &[u8]) -> Bytes {
        let input = proto::AppendInput {
            records: vec![proto::AppendRecord {
                timestamp: None,
                headers: vec![],
                body: Bytes::copy_from_slice(body),
            }],
            match_seq_num: None,
            fencing_token: None,
        };
        s2s::SessionMessage::regular(s2s::CompressionAlgorithm::None, &input)
            .unwrap()
            .encode()
    }

    async fn extract_s2s_inputs(
        chunks: Vec<Result<Bytes, std::io::Error>>,
    ) -> Vec<Result<Vec<u8>, AppendInputStreamError>> {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/streams/test/records")
            .header(http::header::CONTENT_TYPE, "s2s/proto")
            .body(Body::from_stream(stream::iter(chunks)))
            .unwrap();
        let AppendRequest::S2s { mut inputs, .. } =
            AppendRequest::from_request(req, &()).await.unwrap()
        else {
            panic!("expected s2s append request");
        };
        let mut out = Vec::new();
        while let Some(item) = inputs.next().await {
            out.push(item.map(|input| {
                let record = input.records.into_iter().next().unwrap();
                let (_, body) = record.into_parts().record.into_inner().into_parts();
                body.to_vec()
            }));
        }
        out
    }

    #[test]
    fn s2s_append_extractor_handles_straddled_multi_frame_and_eof_truncation() {
        futures::executor::block_on(async {
            let f0 = make_append_frame(b"first");
            let f1 = make_append_frame(b"second");
            let f2 = make_append_frame(b"third");

            // Split 3-byte prefix of f0, empty chunk, combined rest of f0 + full f1 + prefix of f2,
            // then rest of f2.
            let mut combined = Vec::new();
            combined.extend_from_slice(&f0[2..]);
            combined.extend_from_slice(&f1);
            combined.extend_from_slice(&f2[..2]);
            let results = extract_s2s_inputs(vec![
                Ok(Bytes::copy_from_slice(&f0[..1])),
                Ok(Bytes::copy_from_slice(&f0[1..2])),
                Ok(Bytes::new()),
                Ok(Bytes::from(combined)),
                Ok(Bytes::copy_from_slice(&f2[2..])),
            ])
            .await;
            assert_eq!(results.len(), 3);
            assert_eq!(results[0].as_ref().unwrap(), b"first");
            assert_eq!(results[1].as_ref().unwrap(), b"second");
            assert_eq!(results[2].as_ref().unwrap(), b"third");

            // Truncated trailing bytes at EOF must return FrameDecode(UnexpectedEof).
            let truncated = extract_s2s_inputs(vec![
                Ok(f0.clone()),
                Ok(Bytes::copy_from_slice(&f1[..f1.len() - 2])),
            ])
            .await;
            assert_eq!(truncated.len(), 2);
            assert_eq!(truncated[0].as_ref().unwrap(), b"first");
            assert!(matches!(
                truncated[1],
                Err(AppendInputStreamError::FrameDecode(ref e))
                    if e.kind() == std::io::ErrorKind::UnexpectedEof
            ));

            // Terminal frame on input stream must be rejected as FrameDecode(InvalidData).
            let terminal = s2s::SessionMessage::Terminal(s2s::TerminalMessage {
                status: 400,
                body: Bytes::from_static(b"{}"),
            })
            .encode();
            let term_res = extract_s2s_inputs(vec![Ok(terminal)]).await;
            assert_eq!(term_res.len(), 1);
            assert!(matches!(
                term_res[0],
                Err(AppendInputStreamError::FrameDecode(ref e))
                    if e.kind() == std::io::ErrorKind::InvalidData
            ));

            // Underlying body transport error must remain reachable via `Error::source()`.
            let err_res = extract_s2s_inputs(vec![Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "peer reset",
            ))])
            .await;
            assert_eq!(err_res.len(), 1);
            let Err(AppendInputStreamError::FrameDecode(ref err)) = err_res[0] else {
                panic!("expected FrameDecode");
            };
            assert!(std::error::Error::source(err).is_some());
        });
    }
}
