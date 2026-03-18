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
        EncryptionDirective, EncryptionError, check_encryption_directive, decode_record_plaintext,
        decrypt_record, encode_record_plaintext, encrypt_record, parse_s2_encryption_header,
    },
    http::extract::Header,
    read_extent::{CountOrBytes, ReadLimit},
    record::{Metered, MeteredSize as _, Record, SequencedRecord},
    types::{
        ValidationError,
        basin::BasinName,
        config::EncryptionAlgorithm,
        stream::{
            AppendInput, AppendRecordBatch, AppendRecordParts, ReadBatch, ReadEnd, ReadFrom,
            ReadSessionOutput, ReadStart, StreamName,
        },
    },
};

use crate::{
    backend::{Backend, error::ReadError},
    handlers::v1::error::ServiceError,
};

pub fn router() -> axum::Router<Backend> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route(super::paths::streams::records::CHECK_TAIL, get(check_tail))
        .route(super::paths::streams::records::READ, get(read))
        .route(super::paths::streams::records::APPEND, post(append))
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
    let directive = parse_s2_encryption_header(&headers)
        .map_err(|e| ServiceError::Validation(ValidationError(e.to_string())))?;

    let config = backend
        .get_stream_config(basin.clone(), stream.clone())
        .await?;

    // On reads, EncryptionRequired is OK — return opaque bytes without decryption.
    let decrypt_directive =
        match check_encryption_directive(config.encryption_algorithm, directive.as_ref()) {
            Ok(checked) => checked.cloned(),
            Err(EncryptionError::EncryptionRequired(_)) => None,
            Err(e) => return Err(ServiceError::Validation(ValidationError(e.to_string()))),
        };

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
            let batch = decrypt_read_batch(batch, decrypt_directive.as_ref(), &basin, &stream)
                .map_err(ReadError::Encryption)?;
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
                            let batch = match decrypt_read_batch(batch, decrypt_directive.as_ref(), &basin, &stream) {
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
                        let batch =
                            decrypt_read_batch(batch, decrypt_directive.as_ref(), &basin, &stream)
                                .map_err(ReadError::Encryption)?;
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

fn decrypt_read_batch(
    batch: ReadBatch,
    directive: Option<&EncryptionDirective>,
    basin: &BasinName,
    stream: &StreamName,
) -> Result<ReadBatch, EncryptionError> {
    let Some(EncryptionDirective::Key { key, .. }) = directive else {
        return Ok(batch);
    };
    let aad = format!("{basin}/{stream}");
    let records: Vec<SequencedRecord> = batch
        .records
        .into_inner()
        .into_iter()
        .map(|sr| {
            let Record::Envelope(ref env) = sr.record else {
                return Ok(sr);
            };
            match decrypt_record(env.body(), key, aad.as_bytes())? {
                None => Ok(sr),
                Some(plaintext) => {
                    let (headers, body) = decode_record_plaintext(plaintext)?;
                    let record = Record::try_from_parts(headers, body)
                        .map_err(|e| EncryptionError::EncodingFailed(e.to_string()))?;
                    Ok(SequencedRecord {
                        position: sr.position,
                        record,
                    })
                }
            }
        })
        .collect::<Result<_, EncryptionError>>()?;
    Ok(ReadBatch {
        records: Metered::from(records),
        tail: batch.tail,
    })
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
    let directive = parse_s2_encryption_header(&headers)
        .map_err(|e| ServiceError::Validation(ValidationError(e.to_string())))?;

    let config = backend
        .get_stream_config(basin.clone(), stream.clone())
        .await?;

    check_encryption_directive(config.encryption_algorithm, directive.as_ref())
        .map_err(|e| ServiceError::Validation(ValidationError(e.to_string())))?;

    match request {
        v1t::stream::AppendRequest::Unary {
            input,
            response_mime,
        } => {
            let input = encrypt_append_input(
                input,
                config.encryption_algorithm,
                directive.as_ref(),
                &basin,
                &stream,
            )
            .map_err(crate::backend::error::AppendError::Encryption)?;
            let ack = backend.append(basin, stream, input).await?;
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
            let (err_tx, err_rx) = tokio::sync::oneshot::channel();

            let stream_alg = config.encryption_algorithm;
            let enc_basin = basin.clone();
            let enc_stream = stream.clone();
            let inputs = async_stream::stream! {
                tokio::pin!(inputs);
                let mut err_tx = Some(err_tx);
                while let Some(input) = inputs.next().await {
                    match input {
                        Ok(input) => {
                            match encrypt_append_input(input, stream_alg, directive.as_ref(), &enc_basin, &enc_stream) {
                                Ok(encrypted) => yield encrypted,
                                Err(e) => {
                                    if let Some(tx) = err_tx.take() {
                                        let _ = tx.send(ServiceError::Append(e.into()));
                                    }
                                    break;
                                }
                            }
                        }
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
                .append_session(basin, stream, inputs)
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

fn encrypt_append_input(
    input: AppendInput,
    stream_alg: Option<EncryptionAlgorithm>,
    directive: Option<&EncryptionDirective>,
    basin: &BasinName,
    stream: &StreamName,
) -> Result<AppendInput, EncryptionError> {
    let Some(EncryptionDirective::Key { alg, key }) = directive else {
        return Ok(input);
    };
    if stream_alg.is_none() {
        return Ok(input);
    }
    let aad = format!("{basin}/{stream}");
    let mut encrypted_records = Vec::with_capacity(input.records.len());
    for record in input.records.into_iter() {
        let AppendRecordParts { timestamp, record } = record.into();
        let encrypted = match &*record {
            Record::Envelope(env) => {
                let plaintext =
                    encode_record_plaintext(env.headers().to_vec(), env.body().clone())?;
                let enc_body = encrypt_record(&plaintext, *alg, key, aad.as_bytes())?;
                let enc_record = Record::try_from_parts(vec![], enc_body)
                    .map_err(|e| EncryptionError::EncodingFailed(e.to_string()))?;
                Metered::from(enc_record)
            }
            Record::Command(_) => record,
        };
        encrypted_records.push(
            AppendRecordParts {
                timestamp,
                record: encrypted,
            }
            .try_into()
            .map_err(|e: &str| EncryptionError::EncodingFailed(e.to_string()))?,
        );
    }
    let records: AppendRecordBatch = encrypted_records
        .try_into()
        .map_err(|e: &str| EncryptionError::EncodingFailed(e.to_string()))?;
    Ok(AppendInput {
        records,
        match_seq_num: input.match_seq_num,
        fencing_token: input.fencing_token,
    })
}
