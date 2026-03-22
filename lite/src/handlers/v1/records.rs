use std::time::Duration;

use axum::{
    body::Body,
    extract::{FromRequest, Path, Query, State},
    response::{IntoResponse, Response},
};
use futures::{Stream, StreamExt, TryStreamExt};
use http::StatusCode;
use s2_api::{
    data::{Json, Proto},
    mime::JsonOrProto,
    v1::{self as v1t, stream::s2s},
};
use s2_common::{
    caps::RECORD_BATCH_MAX,
    encryption::{
        self, EncryptionDirective, EncryptionError, parse_s2_encryption_header, stream_aad,
    },
    http::extract::Header,
    read_extent::{CountOrBytes, ReadLimit},
    record::{Metered, MeteredSize as _},
    types::{
        ValidationError,
        basin::BasinName,
        stream::{ReadBatch, ReadEnd, ReadFrom, ReadSessionOutput, ReadStart, StreamName},
    },
};

use crate::{
    backend::{AppendEncryption, Backend, error::ReadError},
    handlers::v1::error::ServiceError,
};

pub fn router() -> axum::Router<Backend> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route(super::paths::streams::records::CHECK_TAIL, get(check_tail))
        .route(super::paths::streams::records::READ, get(read))
        .route(super::paths::streams::records::APPEND, post(append))
}

struct EncryptionContext {
    aad: Vec<u8>,
    directive: Option<EncryptionDirective>,
}

impl EncryptionContext {
    fn resolve(
        headers: &http::HeaderMap,
        basin: &BasinName,
        stream: &StreamName,
    ) -> Result<Self, ServiceError> {
        let directive = parse_s2_encryption_header(headers)
            .map_err(|e| ServiceError::Validation(ValidationError(e.to_string())))?;
        Ok(Self {
            aad: stream_aad(basin, stream).into_bytes(),
            directive,
        })
    }

    fn into_append_encryption(self) -> Option<AppendEncryption> {
        self.directive.map(|directive| AppendEncryption {
            directive,
            aad: self.aad,
        })
    }

    fn decrypt_batch(&self, batch: ReadBatch) -> Result<ReadBatch, EncryptionError> {
        encryption::decrypt_read_batch(batch, self.directive.as_ref(), &self.aad)
    }
}

fn validate_read_until(start: ReadStart, end: ReadEnd) -> Result<(), ServiceError> {
    if let ReadFrom::Timestamp(ts) = start.from
        && end.until.deny(ts)
    {
        return Err(ServiceError::Validation(ValidationError(
            "start `timestamp` exceeds or equal to `until`".to_owned(),
        )));
    }
    Ok(())
}

fn apply_last_event_id(
    mut start: ReadStart,
    mut end: v1t::stream::ReadEnd,
    last_event_id: Option<v1t::stream::sse::LastEventId>,
) -> (ReadStart, v1t::stream::ReadEnd) {
    if let Some(v1t::stream::sse::LastEventId {
        seq_num,
        count,
        bytes,
    }) = last_event_id
    {
        start.from = ReadFrom::SeqNum(seq_num + 1);
        end.count = end.count.map(|c| c.saturating_sub(count));
        end.bytes = end.bytes.map(|c| c.saturating_sub(bytes));
    }
    (start, end)
}

enum ReadMode {
    Unary,
    Streaming,
}

fn prepare_read(
    start: ReadStart,
    end: v1t::stream::ReadEnd,
    mode: ReadMode,
) -> Result<(ReadStart, ReadEnd), ServiceError> {
    let mut end: ReadEnd = end.into();
    if matches!(mode, ReadMode::Unary) {
        end.limit = ReadLimit::CountOrBytes(end.limit.into_allowance(RECORD_BATCH_MAX));
        end.wait = end.wait.map(|d| d.min(super::MAX_UNARY_READ_WAIT));
    }
    validate_read_until(start, end)?;
    Ok((start, end))
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct CheckTailArgs {
    #[from_request(via(Header))]
    basin: BasinName,
    #[from_request(via(Path))]
    stream: StreamName,
}

/// Check the tail.
#[cfg_attr(feature = "utoipa", utoipa::path(
    get,
    path = super::paths::streams::records::CHECK_TAIL,
    tag = super::paths::streams::records::TAG,
    responses(
        (status = StatusCode::OK, body = v1t::stream::TailResponse),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::CONFLICT, body = v1t::error::ErrorInfo),
        (status = StatusCode::NOT_FOUND, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(v1t::StreamNamePathSegment),
    servers(
        (url = super::paths::cloud_endpoints::BASIN, variables(
            ("basin" = (
                description = "Basin name",
            ))
        ), description = "Endpoint for the basin"),
    )
))]
pub async fn check_tail(
    State(backend): State<Backend>,
    CheckTailArgs { basin, stream }: CheckTailArgs,
) -> Result<Json<v1t::stream::TailResponse>, ServiceError> {
    let tail = backend.check_tail(basin, stream).await?;
    Ok(Json(v1t::stream::TailResponse { tail: tail.into() }))
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct ReadArgs {
    headers: http::HeaderMap,
    #[from_request(via(Header))]
    basin: BasinName,
    #[from_request(via(Path))]
    stream: StreamName,
    #[from_request(via(Query))]
    start: v1t::stream::ReadStart,
    #[from_request(via(Query))]
    end: v1t::stream::ReadEnd,
    request: v1t::stream::ReadRequest,
}

/// Read records.
#[cfg_attr(feature = "utoipa", utoipa::path(
    get,
    path = super::paths::streams::records::READ,
    tag = super::paths::streams::records::TAG,
    responses(
        (status = StatusCode::OK, content(
            (v1t::stream::ReadBatch = "application/json"),
            (v1t::stream::sse::ReadEvent = "text/event-stream"),
        )),
        (status = StatusCode::RANGE_NOT_SATISFIABLE, body = v1t::stream::TailResponse),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::CONFLICT, body = v1t::error::ErrorInfo),
        (status = StatusCode::NOT_FOUND, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(
        v1t::StreamNamePathSegment,
        s2_api::data::S2FormatHeader,
        v1t::stream::ReadStart,
        v1t::stream::ReadEnd,
    ),
    servers(
        (url = super::paths::cloud_endpoints::BASIN, variables(
            ("basin" = (
                description = "Basin name",
            ))
        ), description = "Endpoint for the basin"),
    )
))]
pub async fn read(
    State(backend): State<Backend>,
    ReadArgs {
        headers,
        basin,
        stream,
        start,
        end,
        request,
    }: ReadArgs,
) -> Result<Response, ServiceError> {
    let enc = EncryptionContext::resolve(&headers, &basin, &stream)?;

    let start: ReadStart = start.try_into()?;
    match request {
        v1t::stream::ReadRequest::Unary {
            format,
            response_mime,
        } => {
            let (start, end) = prepare_read(start, end, ReadMode::Unary)?;
            let session = backend
                .read(basin.clone(), stream.clone(), start, end)
                .await?;
            let batch = merge_read_session(session, end.wait).await?;
            let batch = enc.decrypt_batch(batch).map_err(ReadError::Encryption)?;
            match response_mime {
                JsonOrProto::Json => Ok(Json(v1t::stream::json::serialize_read_batch(
                    format, &batch,
                ))
                .into_response()),
                JsonOrProto::Proto => {
                    let batch: v1t::stream::proto::ReadBatch = batch.into();
                    Ok(Proto(batch).into_response())
                }
            }
        }
        v1t::stream::ReadRequest::EventStream {
            format,
            last_event_id,
        } => {
            let (start, end) = apply_last_event_id(start, end, last_event_id);
            let (start, end) = prepare_read(start, end, ReadMode::Streaming)?;
            let session = backend
                .read(basin.clone(), stream.clone(), start, end)
                .await?;
            let events = async_stream::stream! {
                let mut processed = CountOrBytes::ZERO;
                tokio::pin!(session);
                let mut errored = false;
                while let Some(output) = session.next().await {
                    match output {
                        Ok(ReadSessionOutput::Heartbeat(_tail)) => {
                            yield v1t::stream::sse::ping_event();
                        },
                        Ok(ReadSessionOutput::Batch(batch)) => {
                            let batch = match enc.decrypt_batch(batch) {
                                Ok(batch) => batch,
                                Err(err) => {
                                    let (_, body) = ServiceError::from(ReadError::Encryption(err)).to_response().to_parts();
                                    yield v1t::stream::sse::error_event(body);
                                    errored = true;
                                    break;
                                }
                            };
                            let Some(last_record) = batch.records.last() else {
                                continue;
                            };
                            processed.count += batch.records.len();
                            processed.bytes += batch.records.metered_size();
                            let id = v1t::stream::sse::LastEventId {
                                seq_num: last_record.position.seq_num,
                                count: processed.count,
                                bytes: processed.bytes,
                            };
                            yield v1t::stream::sse::read_batch_event(format, &batch, id);
                        },
                        Err(err) => {
                            let (_, body) = ServiceError::from(err).to_response().to_parts();
                            yield v1t::stream::sse::error_event(body);
                            errored = true;
                        }
                    }
                }
                if !errored {
                    yield v1t::stream::sse::done_event();
                }
            };

            Ok(axum::response::Sse::new(events).into_response())
        }
        v1t::stream::ReadRequest::S2s {
            response_compression,
        } => {
            let (start, end) = prepare_read(start, end, ReadMode::Streaming)?;
            let s2s_stream = backend
                .read(basin.clone(), stream.clone(), start, end)
                .await?
                .map(move |msg| match msg {
                    Ok(ReadSessionOutput::Heartbeat(tail)) => Ok(v1t::stream::proto::ReadBatch {
                        records: vec![],
                        tail: Some(tail.into()),
                    }),
                    Ok(ReadSessionOutput::Batch(batch)) => {
                        let batch = enc.decrypt_batch(batch).map_err(ReadError::Encryption)?;
                        Ok(v1t::stream::proto::ReadBatch::from(batch))
                    }
                    Err(e) => Err(e),
                });
            let response_stream = s2s::FramedMessageStream::<_>::new(
                response_compression,
                Box::pin(s2s_stream.map_err(ServiceError::from)),
            );
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "s2s/proto")
                .body(Body::from_stream(response_stream))
                .expect("valid response builder"))
        }
    }
}

async fn merge_read_session(
    session: impl Stream<Item = Result<ReadSessionOutput, ReadError>>,
    wait: Option<Duration>,
) -> Result<ReadBatch, ReadError> {
    let mut acc = ReadBatch {
        records: Metered::with_capacity(RECORD_BATCH_MAX.count),
        tail: None,
    };
    let mut wait_mode = false;
    tokio::pin!(session);
    while let Some(output) = session.next().await {
        match output? {
            ReadSessionOutput::Batch(batch) => {
                assert!(!batch.records.is_empty(), "unexpected empty batch");
                assert!(
                    (acc.records.metered_size() + batch.records.metered_size())
                        <= RECORD_BATCH_MAX.bytes
                        && acc.records.len() + batch.records.len() <= RECORD_BATCH_MAX.count,
                    "cannot accumulate more than limit"
                );
                acc.records.append(batch.records);
                acc.tail = batch.tail;
                if wait_mode {
                    break;
                }
            }
            ReadSessionOutput::Heartbeat(pos) => {
                assert!(
                    wait.is_some_and(|d| d > Duration::ZERO),
                    "heartbeat {pos} only if non-zero wait"
                );
                if !acc.records.is_empty() {
                    break;
                }
                wait_mode = true;
            }
        }
    }
    Ok(acc)
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct AppendArgs {
    headers: http::HeaderMap,
    #[from_request(via(Header))]
    basin: BasinName,
    #[from_request(via(Path))]
    stream: StreamName,
    request: v1t::stream::AppendRequest,
}

/// Append records.
#[cfg_attr(feature = "utoipa", utoipa::path(
    post,
    path = super::paths::streams::records::APPEND,
    tag = super::paths::streams::records::TAG,
    request_body(content = v1t::stream::AppendInput, content_type = "application/json"),
    responses(
        (status = StatusCode::OK, body = v1t::stream::AppendAck),
        (status = StatusCode::PRECONDITION_FAILED, body = v1t::stream::AppendConditionFailed),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::CONFLICT, body = v1t::error::ErrorInfo),
        (status = StatusCode::NOT_FOUND, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(v1t::StreamNamePathSegment, s2_api::data::S2FormatHeader),
    servers(
        (url = super::paths::cloud_endpoints::BASIN, variables(
            ("basin" = (
                description = "Basin name",
            ))
        ), description = "Endpoint for the basin"),
    )
))]
pub async fn append(
    State(backend): State<Backend>,
    AppendArgs {
        headers,
        basin,
        stream,
        request,
    }: AppendArgs,
) -> Result<Response, ServiceError> {
    let enc = EncryptionContext::resolve(&headers, &basin, &stream)?;
    let append_enc = enc.into_append_encryption();

    match request {
        v1t::stream::AppendRequest::Unary {
            input,
            response_mime,
        } => {
            let ack = backend.append(basin, stream, input, append_enc).await?;
            match response_mime {
                JsonOrProto::Json => {
                    let ack: v1t::stream::AppendAck = ack.into();
                    Ok(Json(ack).into_response())
                }
                JsonOrProto::Proto => {
                    let ack: v1t::stream::proto::AppendAck = ack.into();
                    Ok(Proto(ack).into_response())
                }
            }
        }
        v1t::stream::AppendRequest::S2s {
            inputs,
            response_compression,
        } => {
            let (err_tx, err_rx) = tokio::sync::oneshot::channel::<ServiceError>();

            let inputs = async_stream::stream! {
                tokio::pin!(inputs);
                let mut err_tx = Some(err_tx);
                while let Some(input) = inputs.next().await {
                    match input {
                        Ok(input) => yield input,
                        Err(e) => {
                            if let Some(tx) = err_tx.take() {
                                let _ = tx.send(e.into());
                            }
                            break;
                        }
                    }
                }
            };

            let ack_stream = backend
                .append_session(basin, stream, inputs, append_enc)
                .await?
                .map(|res| {
                    res.map(v1t::stream::proto::AppendAck::from)
                        .map_err(ServiceError::from)
                });

            let input_err_stream = futures::stream::once(err_rx).filter_map(|res| async move {
                match res {
                    Ok(err) => Some(Err(err.into())),
                    Err(_) => None,
                }
            });

            let response_stream = s2s::FramedMessageStream::<_>::new(
                response_compression,
                Box::pin(ack_stream.chain(input_err_stream)),
            );

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "s2s/proto")
                .body(Body::from_stream(response_stream))
                .expect("valid response builder"))
        }
    }
}
