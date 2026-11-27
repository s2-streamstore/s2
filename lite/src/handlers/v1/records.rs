use axum::{
    body::Body,
    extract::{FromRequest, Path, Query, State},
    response::{IntoResponse, Response},
};
use futures::{Stream, StreamExt, TryStreamExt};
use http::{HeaderValue, StatusCode, header};
use s2_api::{
    data::{Json, Proto},
    mime::JsonOrProto,
    v1::{self as v1t, stream::s2s},
};
use s2_common::{
    ValidationError,
    basin::BasinName,
    caps::RECORD_BATCH_MAX,
    http::extract::Header,
    read_extent::ReadLimit,
    record::{Metered, MeteredSize as _},
    stream::{ReadBatch, ReadEnd, ReadFrom, ReadSessionOutput, ReadStart, StreamName},
};

use crate::{
    backend::{
        Backend,
        error::{ReadError, UnwrittenError},
    },
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

#[derive(Default, Clone, Copy)]
struct SseDelivered {
    count: u64,
    bytes: u64,
}

/// Adjusts the read bounds to resume after `last_event_id`, and returns the
/// count/bytes already delivered so emitted event ids stay cumulative across
/// reconnects.
fn apply_last_event_id(
    mut start: ReadStart,
    mut end: v1t::stream::ReadEnd,
    last_event_id: Option<v1t::stream::sse::LastEventId>,
) -> (ReadStart, v1t::stream::ReadEnd, SseDelivered) {
    let mut delivered = SseDelivered::default();
    if let Some(v1t::stream::sse::LastEventId {
        seq_num,
        count,
        bytes,
    }) = last_event_id
    {
        start.from = ReadFrom::SeqNum(seq_num.saturating_add(1));
        end.count = end.count.map(|c| c.saturating_sub(count));
        end.bytes = end.bytes.map(|c| c.saturating_sub(bytes));
        delivered = SseDelivered { count, bytes };
    }
    (start, end, delivered)
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
    let tail = backend
        .open_for_check_tail(&basin, &stream)
        .await?
        .check_tail()
        .await?;
    Ok(Json(v1t::stream::TailResponse { tail: tail.into() }))
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct ReadArgs {
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
///
/// Starts at the tail when `seq_num`, `timestamp`, and `tail_offset` are all omitted.
#[cfg_attr(feature = "utoipa", utoipa::path(
    get,
    path = super::paths::streams::records::READ,
    tag = super::paths::streams::records::TAG,
    responses(
        (status = StatusCode::OK, content(
            (v1t::stream::ReadBatch = "application/json"),
            (v1t::stream::sse::ReadEvent = "text/event-stream"),
        )),
        (
            status = StatusCode::RANGE_NOT_SATISFIABLE,
            description = "Requested starting position is beyond the tail without `clamp` (`seq_num > tail.seq_num` or `timestamp > tail.timestamp`), or a unary read with `wait` of `0` reached the tail with no records to return.",
            body = v1t::stream::TailResponse,
        ),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::CONFLICT, body = v1t::error::ErrorInfo),
        (status = StatusCode::NOT_FOUND, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(
        v1t::StreamNamePathSegment,
        s2_api::data::S2FormatHeader,
        s2_api::data::S2EncryptionKeyHeader,
        s2_api::data::S2StreamConfigHeader,
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
        basin,
        stream,
        start,
        end,
        request,
    }: ReadArgs,
) -> Result<Response, ServiceError> {
    let start: ReadStart = start.try_into()?;
    match request {
        v1t::stream::ReadRequest::Unary {
            encryption_key,
            create_stream_config_patch,
            format,
            response_mime,
        } => {
            let (start, end) = prepare_read(start, end, ReadMode::Unary)?;
            let may_follow = end.may_follow();
            let session = backend
                .open_for_read(&basin, &stream, encryption_key, create_stream_config_patch)
                .await?
                .read(start, end)
                .await?;
            let batch = merge_read_session(session, may_follow).await?;
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
            encryption_key,
            create_stream_config_patch,
            format,
            last_event_id,
        } => {
            let (start, end, delivered) = apply_last_event_id(start, end, last_event_id);
            let (start, end) = prepare_read(start, end, ReadMode::Streaming)?;
            let session = backend
                .open_for_read(&basin, &stream, encryption_key, create_stream_config_patch)
                .await?
                .read(start, end)
                .await?;
            let events = async_stream::stream! {
                let mut processed = delivered;
                tokio::pin!(session);
                let mut errored = false;
                while let Some(output) = session.next().await {
                    match output {
                        Ok(ReadSessionOutput::Heartbeat(tail)) => {
                            yield v1t::stream::sse::ping_event(tail);
                        },
                        Ok(ReadSessionOutput::Batch(batch)) => {
                            let Some(last_record) = batch.records.last() else {
                                continue;
                            };
                            processed.count =
                                processed.count.saturating_add(batch.records.len() as u64);
                            processed.bytes = processed
                                .bytes
                                .saturating_add(batch.records.metered_size() as u64);
                            let id = v1t::stream::sse::LastEventId {
                                seq_num: last_record.position().seq_num,
                                count: processed.count,
                                bytes: processed.bytes,
                            };
                            yield v1t::stream::sse::read_batch_event(format, &batch, id);
                        },
                        Err(err) => {
                            let error = match ServiceError::from(err).to_response() {
                                v1t::error::ErrorResponse::Standard(err) => err,
                                other => {
                                    unreachable!(
                                        "unexpected non-standard mid-stream read error: {other:?}"
                                    )
                                }
                            };
                            yield v1t::stream::sse::error_event(error);
                            errored = true;
                        }
                    }
                }
                if !errored {
                    yield v1t::stream::sse::done_event();
                }
            };

            let mut response = axum::response::Sse::new(events).into_response();
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("no-cache, no-transform"),
            );
            response
                .headers_mut()
                .insert("x-accel-buffering", HeaderValue::from_static("no"));
            Ok(response)
        }
        v1t::stream::ReadRequest::S2s {
            encryption_key,
            create_stream_config_patch,
            response_compression,
        } => {
            let (start, end) = prepare_read(start, end, ReadMode::Streaming)?;
            let s2s_stream = backend
                .open_for_read(&basin, &stream, encryption_key, create_stream_config_patch)
                .await?
                .read(start, end)
                .await?
                .map_ok(|msg| match msg {
                    ReadSessionOutput::Heartbeat(tail) => v1t::stream::proto::ReadBatch {
                        records: vec![],
                        tail: Some(tail.into()),
                    },
                    ReadSessionOutput::Batch(batch) => v1t::stream::proto::ReadBatch::from(batch),
                })
                .map_err(ServiceError::from);
            let response_stream =
                s2s::FramedMessageStream::<_>::new(response_compression, Box::pin(s2s_stream));
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "s2s/proto")
                .header(http::header::CACHE_CONTROL, "no-cache, no-transform")
                .header("x-accel-buffering", "no")
                .body(Body::from_stream(response_stream))
                .expect("valid response builder"))
        }
    }
}

async fn merge_read_session(
    session: impl Stream<Item = Result<ReadSessionOutput, ReadError>>,
    may_follow: bool,
) -> Result<ReadBatch, ServiceError> {
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
                acc.tail = Some(pos);
                if !acc.records.is_empty() {
                    break;
                }
                if !may_follow {
                    return Err(ReadError::Unwritten(UnwrittenError(pos)).into());
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
        (
            status = StatusCode::TOO_MANY_REQUESTS,
            description = "Append rate limit exceeded (`rate_limited`). No records were appended.",
            body = v1t::error::ErrorInfo,
            headers(("retry-after-ms" = u64, description = "Milliseconds to wait before retrying.")),
        ),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::CONFLICT, body = v1t::error::ErrorInfo),
        (status = StatusCode::NOT_FOUND, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(
        v1t::StreamNamePathSegment,
        s2_api::data::S2FormatHeader,
        s2_api::data::S2EncryptionKeyHeader,
        s2_api::data::S2StreamConfigHeader,
    ),
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
        basin,
        stream,
        request,
    }: AppendArgs,
) -> Result<Response, ServiceError> {
    match request {
        v1t::stream::AppendRequest::Unary {
            encryption_key,
            create_stream_config_patch,
            input,
            response_mime,
        } => {
            let handle = backend
                .open_for_append(&basin, &stream, encryption_key, create_stream_config_patch)
                .await?;
            let ack = handle.append(input).await?;
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
            encryption_key,
            create_stream_config_patch,
            inputs,
            response_compression,
        } => {
            let handle = backend
                .open_for_append(&basin, &stream, encryption_key, create_stream_config_patch)
                .await?;
            let (err_tx, err_rx) = tokio::sync::oneshot::channel();

            let inputs = async_stream::stream! {
                tokio::pin!(inputs);
                let mut err_tx = Some(err_tx);
                while let Some(input) = inputs.next().await {
                    match input {
                        Ok(input) => yield input,
                        Err(e) => {
                            if let Some(tx) = err_tx.take() {
                                let _ = tx.send(e);
                            }
                            break;
                        }
                    }
                }
            };

            let ack_stream = handle.append_session(inputs).map(|res| {
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
                .header(http::header::CACHE_CONTROL, "no-cache, no-transform")
                .header("x-accel-buffering", "no")
                .body(Body::from_stream(response_stream))
                .expect("valid response builder"))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use axum::{
        body::{self, Body},
        http::{Request, StatusCode, header},
        response::Response,
    };
    use bytes::{Bytes, BytesMut};
    use bytesize::ByteSize;
    use futures::TryStreamExt as _;
    use prost::Message as _;
    use s2_api::v1::{
        config::STREAM_CONFIG_HEADER,
        stream::{
            proto,
            s2s::{self, FrameDecoder, SessionMessage},
            sse::LastEventId,
        },
    };
    use s2_common::{
        basin::{BASIN_HEADER, BasinName},
        config::{
            BasinConfig, DeleteOnEmptyConfig, OptionalStreamConfig, RetentionPolicy, StreamConfig,
        },
        encryption::{EncryptionAlgorithm, EncryptionKey, S2_ENCRYPTION_KEY_HEADER},
        read_extent::{ReadLimit, ReadUntil},
        record::{
            CommandRecord, EnvelopeRecord, Metered, MeteredSize as _, Record, StreamPosition,
        },
        resources::ProvisionMode,
        stream::{
            AppendInput, AppendRecord, AppendRecordBatch, AppendRecordParts, ListStreamsRequest,
            ReadEnd, ReadFrom, ReadSessionOutput, ReadStart, StreamName,
        },
    };
    use slatedb::{Db, config::Settings, object_store::memory::InMemory};
    use tokio_util::codec::Decoder as _;
    use tower::ServiceExt as _;
    use uuid::Uuid;

    use crate::{backend::Backend, handlers};

    fn basin_config_with_stream_cipher(stream_cipher: EncryptionAlgorithm) -> BasinConfig {
        BasinConfig {
            default_stream_config: OptionalStreamConfig::default(),
            stream_cipher: Some(stream_cipher),
            ..Default::default()
        }
    }

    fn aegis_key(byte: u8) -> EncryptionKey {
        EncryptionKey::new([byte; 32])
    }

    async fn create_backend() -> Backend {
        let object_store = Arc::new(InMemory::new());
        let db_path = format!("/tmp/records-handler-test-{}", Uuid::new_v4());
        let db = Db::builder(db_path, object_store)
            .with_settings(Settings {
                flush_interval: Some(Duration::from_millis(5)),
                ..Default::default()
            })
            .build()
            .await
            .expect("create in-memory db");
        Backend::new(db, ByteSize::mib(10))
    }

    async fn setup_app_with_config(
        test_suffix: &str,
        basin_config: BasinConfig,
        stream_config: OptionalStreamConfig,
    ) -> (axum::Router, Backend, BasinName, StreamName) {
        let backend = create_backend().await;
        let basin: BasinName = format!("test-basin-{test_suffix}").parse().unwrap();
        backend
            .provision_basin(
                basin.clone(),
                basin_config,
                ProvisionMode::CreateOnly {
                    request_token: None,
                },
            )
            .await
            .expect("create basin");
        let stream: StreamName = format!("test-stream-{test_suffix}").parse().unwrap();
        backend
            .provision_stream(
                basin.clone(),
                stream.clone(),
                stream_config,
                ProvisionMode::CreateOnly {
                    request_token: None,
                },
            )
            .await
            .expect("create stream");
        let app = handlers::router().with_state(backend.clone());
        (app, backend, basin, stream)
    }

    async fn setup_app_without_stream(
        test_suffix: &str,
        basin_config: BasinConfig,
    ) -> (axum::Router, Backend, BasinName, StreamName) {
        let backend = create_backend().await;
        let basin: BasinName = format!("test-basin-{test_suffix}").parse().unwrap();
        backend
            .provision_basin(
                basin.clone(),
                basin_config,
                ProvisionMode::CreateOnly {
                    request_token: None,
                },
            )
            .await
            .expect("create basin");
        let stream: StreamName = format!("test-stream-{test_suffix}").parse().unwrap();
        let app = handlers::router().with_state(backend.clone());
        (app, backend, basin, stream)
    }

    fn envelope_record(body: &'static [u8], timestamp: Option<u64>) -> AppendRecord {
        let record = Metered::from(Record::Envelope(
            EnvelopeRecord::try_from_parts(vec![], Bytes::from_static(body)).unwrap(),
        ));
        AppendRecord::try_from(AppendRecordParts { timestamp, record }).unwrap()
    }

    fn trim_record(trim_point: u64, timestamp: Option<u64>) -> AppendRecord {
        let record = Metered::from(Record::Command(CommandRecord::Trim(trim_point)));
        AppendRecord::try_from(AppendRecordParts { timestamp, record }).unwrap()
    }

    fn append_input(body: &'static [u8]) -> AppendInput {
        AppendInput {
            records: AppendRecordBatch::try_from(vec![envelope_record(body, None)]).unwrap(),
            match_seq_num: None,
            fencing_token: None,
        }
    }

    async fn append_encrypted_payload(
        backend: &Backend,
        basin: &BasinName,
        stream: &StreamName,
        body: &'static [u8],
        encryption_key: EncryptionKey,
    ) {
        backend
            .open_for_append(
                basin,
                stream,
                Some(encryption_key),
                OptionalStreamConfig::default(),
            )
            .await
            .expect("open append handle")
            .append(append_input(body))
            .await
            .expect("append encrypted payload");
    }

    async fn append_records(
        backend: &Backend,
        basin: &BasinName,
        stream: &StreamName,
        records: Vec<AppendRecord>,
    ) -> s2_common::stream::AppendAck {
        let input = AppendInput {
            records: AppendRecordBatch::try_from(records).unwrap(),
            match_seq_num: None,
            fencing_token: None,
        };
        backend
            .open_for_append(basin, stream, None, OptionalStreamConfig::default())
            .await
            .expect("open append handle")
            .append(input)
            .await
            .expect("append records")
    }

    async fn append_payload(
        backend: &Backend,
        basin: &BasinName,
        stream: &StreamName,
        body: &'static [u8],
    ) {
        append_records(backend, basin, stream, vec![envelope_record(body, None)]).await;
    }

    struct SseBatches {
        seq_nums: Vec<u64>,
        last_id: Option<LastEventId>,
        pings: Vec<StreamPosition>,
    }

    async fn sse_read(
        app: &axum::Router,
        basin: &BasinName,
        stream: &StreamName,
        bounds: &str,
        last_event_id: Option<LastEventId>,
    ) -> SseBatches {
        sse_read_query(
            app,
            basin,
            stream,
            &format!("seq_num=0&wait=0&{bounds}"),
            last_event_id,
        )
        .await
    }

    async fn sse_read_query(
        app: &axum::Router,
        basin: &BasinName,
        stream: &StreamName,
        query: &str,
        last_event_id: Option<LastEventId>,
    ) -> SseBatches {
        let uri = records_uri(stream, query);
        let mut request =
            request_builder("GET", uri, basin).header(header::ACCEPT, "text/event-stream");
        if let Some(id) = last_event_id {
            request = request.header("last-event-id", id.to_string());
        }
        let response = send(app, request.body(Body::empty()).unwrap()).await;
        assert_eq!(response.status(), StatusCode::OK, "query={query}");
        let body =
            tokio::time::timeout(Duration::from_secs(5), response_bytes(response, "sse body"))
                .await
                .expect("SSE read should terminate");
        let body = std::str::from_utf8(&body).expect("utf8 sse body");

        let mut batches = SseBatches {
            seq_nums: Vec::new(),
            last_id: None,
            pings: Vec::new(),
        };
        let mut done = false;
        for event in body.split("\n\n").filter(|e| !e.trim().is_empty()) {
            let field = |name: &str| {
                event
                    .lines()
                    .find_map(|line| line.strip_prefix(name))
                    .map(str::trim)
            };
            match field("event:") {
                Some("batch") => {
                    let id: LastEventId = field("id:")
                        .expect("batch event id")
                        .parse()
                        .expect("parse batch event id");
                    let data: serde_json::Value =
                        serde_json::from_str(field("data:").expect("batch event data"))
                            .expect("batch event json");
                    let records = data["records"].as_array().expect("records array");
                    batches.seq_nums.extend(
                        records
                            .iter()
                            .map(|r| r["seq_num"].as_u64().expect("seq_num")),
                    );
                    assert_eq!(
                        id.seq_num,
                        *batches.seq_nums.last().expect("non-empty batch")
                    );
                    batches.last_id = Some(id);
                }
                Some("ping") => {
                    let data: serde_json::Value =
                        serde_json::from_str(field("data:").expect("ping event data"))
                            .expect("ping event json");
                    let tail = StreamPosition {
                        seq_num: data["tail"]["seq_num"].as_u64().expect("ping tail seq_num"),
                        timestamp: data["tail"]["timestamp"]
                            .as_u64()
                            .expect("ping tail timestamp"),
                    };
                    batches.pings.push(tail);
                }
                Some("error") => panic!("unexpected sse error event: {event}"),
                Some(other) => panic!("unexpected sse event `{other}`: {event}"),
                None => {
                    assert_eq!(field("data:"), Some("[DONE]"), "unexpected event: {event}");
                    done = true;
                }
            }
        }
        assert!(done, "SSE read should end with [DONE]");
        batches
    }

    fn records_uri(stream: &StreamName, query: &str) -> String {
        if query.is_empty() {
            format!("/v1/streams/{stream}/records")
        } else {
            format!("/v1/streams/{stream}/records?{query}")
        }
    }

    fn decode_all_frames(body: Bytes) -> Vec<SessionMessage> {
        let mut decoder = FrameDecoder;
        let mut buf = BytesMut::from(body.as_ref());
        let mut frames = Vec::new();
        while let Some(frame) = decoder.decode(&mut buf).expect("frame decode") {
            frames.push(frame);
        }
        assert!(buf.is_empty(), "trailing unparsed frame bytes");
        frames
    }

    async fn s2s_read_batches(
        app: &axum::Router,
        basin: &BasinName,
        stream: &StreamName,
        query: &str,
    ) -> Vec<proto::ReadBatch> {
        let uri = records_uri(stream, query);
        let response = send(
            app,
            request_builder("GET", uri, basin)
                .header(header::CONTENT_TYPE, "s2s/proto")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "query={query}");
        let body =
            tokio::time::timeout(Duration::from_secs(5), response_bytes(response, "s2s body"))
                .await
                .expect("S2S read should terminate");
        decode_all_frames(body)
            .into_iter()
            .map(|frame| match frame {
                SessionMessage::Regular(data) => data
                    .try_into_proto::<proto::ReadBatch>()
                    .expect("decode read batch proto"),
                SessionMessage::Terminal(term) => {
                    panic!("unexpected terminal frame for query `{query}`: {term:?}")
                }
            })
            .collect()
    }

    fn read_uri(stream: &StreamName) -> String {
        format!("/v1/streams/{stream}/records?seq_num=0&wait=0")
    }

    fn request_builder(
        method: &str,
        uri: impl Into<String>,
        basin: &BasinName,
    ) -> axum::http::request::Builder {
        Request::builder()
            .method(method)
            .uri(uri.into())
            .header(BASIN_HEADER.as_str(), basin.as_ref())
    }

    async fn send(app: &axum::Router, request: Request<Body>) -> Response {
        app.clone()
            .oneshot(request)
            .await
            .expect("request should complete")
    }

    async fn response_bytes(response: Response, context: &str) -> Bytes {
        body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect(context)
    }

    async fn response_json(response: Response, context: &str) -> serde_json::Value {
        let body = response_bytes(response, context).await;
        serde_json::from_slice(&body).expect("json body")
    }

    async fn assert_no_streams(backend: &Backend, basin: &BasinName) {
        let stream_list = backend
            .list_streams(basin.clone(), ListStreamsRequest::default())
            .await
            .expect("list streams");
        assert!(stream_list.values.is_empty());
    }

    #[tokio::test]
    async fn unary_append_with_encryption_header_persists_encrypted_record() {
        let encryption_key = aegis_key(0x42);
        let (app, backend, basin, stream) = setup_app_with_config(
            "append-unary-encrypted",
            basin_config_with_stream_cipher(EncryptionAlgorithm::Aegis256),
            OptionalStreamConfig::default(),
        )
        .await;

        let input = proto::AppendInput {
            records: vec![proto::AppendRecord {
                timestamp: None,
                headers: vec![],
                body: Bytes::from_static(b"secret"),
            }],
            match_seq_num: None,
            fencing_token: None,
        };

        let response = send(
            &app,
            request_builder("POST", format!("/v1/streams/{stream}/records"), &basin)
                .header(header::CONTENT_TYPE, "application/protobuf")
                .header(header::ACCEPT, "application/protobuf")
                .header(
                    S2_ENCRYPTION_KEY_HEADER.as_str(),
                    encryption_key.to_header_value(),
                )
                .body(Body::from(input.encode_to_vec()))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_bytes(response, "append ack body").await;
        let ack = proto::AppendAck::decode(body).expect("append ack");
        assert_eq!(ack.end.as_ref().map(|pos| pos.seq_num), Some(1));

        let records = backend
            .open_for_read(
                &basin,
                &stream,
                Some(encryption_key.clone()),
                OptionalStreamConfig::default(),
            )
            .await
            .expect("open read handle")
            .read(
                ReadStart {
                    from: ReadFrom::SeqNum(0),
                    clamp: false,
                },
                ReadEnd {
                    limit: ReadLimit::Unbounded,
                    until: ReadUntil::Unbounded,
                    wait: Some(Duration::ZERO),
                },
            )
            .await
            .expect("create read session")
            .try_filter_map(|output| async move {
                match output {
                    ReadSessionOutput::Batch(batch) => Ok(Some(batch)),
                    ReadSessionOutput::Heartbeat(_) => Ok(None),
                }
            })
            .try_collect::<Vec<_>>()
            .await
            .expect("read encrypted record");
        let batch = records.into_iter().next().expect("batch");
        assert_eq!(batch.records.len(), 1);
        let record = batch.records.first().expect("record");
        let Record::Envelope(record) = record.inner() else {
            panic!("expected envelope record");
        };
        assert_eq!(record.body().as_ref(), b"secret");
    }

    fn basin_config_with_create_stream_on_append() -> BasinConfig {
        BasinConfig {
            create_stream_on_append: true,
            default_stream_config: OptionalStreamConfig {
                storage_class: Some("standard".into()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn expected_auto_created_config() -> StreamConfig {
        StreamConfig {
            storage_class: Some("standard".into()),
            retention_policy: RetentionPolicy::Age(Duration::from_secs(3600)),
            timestamping: Default::default(),
            delete_on_empty: DeleteOnEmptyConfig {
                min_age: Duration::from_secs(300),
            },
        }
    }

    const STREAM_CONFIG_HEADER_VALUE: &str =
        r#"{"retention_policy":{"age":3600},"delete_on_empty":{"min_age_secs":300}}"#;

    fn append_record_input(body: &'static [u8]) -> proto::AppendInput {
        proto::AppendInput {
            records: vec![proto::AppendRecord {
                timestamp: None,
                headers: vec![],
                body: Bytes::from_static(body),
            }],
            match_seq_num: None,
            fencing_token: None,
        }
    }

    #[tokio::test]
    async fn json_append_auto_creates_stream_with_stream_config_header() {
        let (app, backend, basin, stream) = setup_app_without_stream(
            "append-json-create-config",
            basin_config_with_create_stream_on_append(),
        )
        .await;

        let body = serde_json::json!({"records": [{"body": "hello"}]});
        let response = send(
            &app,
            request_builder("POST", format!("/v1/streams/{stream}/records"), &basin)
                .header(header::CONTENT_TYPE, "application/json")
                .header(STREAM_CONFIG_HEADER.as_str(), STREAM_CONFIG_HEADER_VALUE)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let ack = response_json(response, "append ack body").await;
        assert_eq!(ack["end"]["seq_num"], 1);
        let config = backend
            .get_stream_config(basin, stream)
            .await
            .expect("get stream config");
        assert_eq!(config, expected_auto_created_config());
    }

    #[tokio::test]
    async fn append_with_invalid_stream_config_header_is_rejected_without_creating() {
        let (app, backend, basin, stream) = setup_app_without_stream(
            "append-create-config-invalid",
            basin_config_with_create_stream_on_append(),
        )
        .await;

        for (value, expected_message) in [
            (
                r#"{"retention_policy":{"age":0}}"#,
                "age must be greater than 0 seconds",
            ),
            ("not json", "invalid JSON"),
        ] {
            let body = serde_json::json!({"records": [{"body": "hello"}]});
            let response = send(
                &app,
                request_builder("POST", format!("/v1/streams/{stream}/records"), &basin)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(STREAM_CONFIG_HEADER.as_str(), value)
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await;

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let info = response_json(response, "append error body").await;
            assert_eq!(info["code"], "bad_header");
            let message = info["message"].as_str().expect("error message string");
            assert!(
                message.contains("s2-stream-config") && message.contains(expected_message),
                "{message}"
            );
        }
        assert_no_streams(&backend, &basin).await;
    }

    #[tokio::test]
    async fn s2s_append_session_auto_creates_stream_with_stream_config_header() {
        let (app, backend, basin, stream) = setup_app_without_stream(
            "append-s2s-create-config",
            basin_config_with_create_stream_on_append(),
        )
        .await;

        let frame = |body: &'static [u8]| {
            SessionMessage::regular(s2s::CompressionAlgorithm::None, &append_record_input(body))
                .expect("encode frame")
                .encode()
        };
        let mut body = BytesMut::new();
        body.extend_from_slice(&frame(b"first"));
        body.extend_from_slice(&frame(b"second"));

        let response = send(
            &app,
            request_builder("POST", format!("/v1/streams/{stream}/records"), &basin)
                .header(header::CONTENT_TYPE, "s2s/proto")
                .header(STREAM_CONFIG_HEADER.as_str(), STREAM_CONFIG_HEADER_VALUE)
                .body(Body::from(body.freeze()))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_bytes(response, "s2s body").await;
        let mut decoder = FrameDecoder;
        let mut buf = BytesMut::from(body.as_ref());
        let mut acks = Vec::new();
        while let Some(frame) = decoder.decode(&mut buf).expect("frame decode") {
            let SessionMessage::Regular(ack) = frame else {
                panic!("expected regular frame");
            };
            acks.push(
                ack.try_into_proto::<proto::AppendAck>()
                    .expect("decode append ack"),
            );
        }
        assert_eq!(acks.len(), 2);
        assert_eq!(acks[1].end.as_ref().map(|pos| pos.seq_num), Some(2));

        let config = backend
            .get_stream_config(basin, stream)
            .await
            .expect("get stream config");
        assert_eq!(config, expected_auto_created_config());
    }

    #[rstest::rstest]
    #[case::count("count=0")]
    #[case::bytes("bytes=0")]
    #[tokio::test]
    async fn unary_read_with_zero_limit_returns_empty(
        #[case] bound: &str,
        #[values(
            "timestamp=0",
            "seq_num=0",
            "tail_offset=0",
            "timestamp=1",
            "seq_num=1"
        )]
        start: &str,
        #[values(0, 60)] wait: u32,
    ) {
        let (app, _backend, basin, stream) = setup_app_with_config(
            "read-zero-limit",
            BasinConfig::default(),
            OptionalStreamConfig::default(),
        )
        .await;

        let response = tokio::time::timeout(
            Duration::from_secs(2),
            send(
                &app,
                request_builder(
                    "GET",
                    format!("/v1/streams/{stream}/records?{start}&{bound}&wait={wait}"),
                    &basin,
                )
                .body(Body::empty())
                .unwrap(),
            ),
        )
        .await
        .expect("a zero limit should complete without waiting for records");

        let status = response.status();
        let body = response_json(response, "read zero-limit response").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{start}&{bound}&wait={wait}: {body}"
        );
        assert_eq!(body["records"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn read_auto_creates_stream_with_stream_config_header() {
        let basin_config = BasinConfig {
            create_stream_on_append: false,
            create_stream_on_read: true,
            ..basin_config_with_create_stream_on_append()
        };
        let (app, backend, basin, stream) =
            setup_app_without_stream("read-create-config", basin_config).await;

        let response = send(
            &app,
            request_builder(
                "GET",
                format!("/v1/streams/{stream}/records?seq_num=0"),
                &basin,
            )
            .header(STREAM_CONFIG_HEADER.as_str(), STREAM_CONFIG_HEADER_VALUE)
            .body(Body::empty())
            .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        let config = backend
            .get_stream_config(basin, stream)
            .await
            .expect("get stream config");
        assert_eq!(config, expected_auto_created_config());
    }

    #[tokio::test]
    async fn invalid_read_bounds_do_not_auto_create_stream() {
        let basin_config = BasinConfig {
            create_stream_on_read: true,
            ..Default::default()
        };
        let (app, backend, basin, stream) =
            setup_app_without_stream("read-invalid-bounds-no-create", basin_config).await;

        let response = send(
            &app,
            request_builder(
                "GET",
                format!("/v1/streams/{stream}/records?timestamp=5&until=5"),
                &basin,
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let info = response_json(response, "read error body").await;
        assert_eq!(info["code"], "invalid");
        assert!(
            info["message"]
                .as_str()
                .expect("error message string")
                .contains("start `timestamp` exceeds or equal to `until`")
        );
        assert_no_streams(&backend, &basin).await;
    }

    #[tokio::test]
    async fn unary_read_with_wrong_key_returns_decryption_failed_error() {
        let encryption_key = aegis_key(0x42);
        let wrong_key = aegis_key(0x24);
        let (app, backend, basin, stream) = setup_app_with_config(
            "read-unary-bad-key",
            basin_config_with_stream_cipher(EncryptionAlgorithm::Aegis256),
            OptionalStreamConfig::default(),
        )
        .await;
        append_encrypted_payload(&backend, &basin, &stream, b"secret", encryption_key).await;

        let response = send(
            &app,
            request_builder("GET", read_uri(&stream), &basin)
                .header(
                    S2_ENCRYPTION_KEY_HEADER.as_str(),
                    wrong_key.to_header_value(),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let info = response_json(response, "read error body").await;
        assert_eq!(info["code"], "decryption_failed");
        assert!(
            info["message"]
                .as_str()
                .expect("error message string")
                .contains("record decryption failed")
        );
    }

    #[tokio::test]
    async fn sse_read_with_wrong_key_ends_with_error_event() {
        let encryption_key = aegis_key(0x42);
        let wrong_key = aegis_key(0x24);
        let (app, backend, basin, stream) = setup_app_with_config(
            "read-sse-bad-key",
            basin_config_with_stream_cipher(EncryptionAlgorithm::Aegis256),
            OptionalStreamConfig::default(),
        )
        .await;
        append_encrypted_payload(&backend, &basin, &stream, b"secret", encryption_key).await;

        let response = send(
            &app,
            request_builder("GET", read_uri(&stream), &basin)
                .header(header::ACCEPT, "text/event-stream")
                .header(
                    S2_ENCRYPTION_KEY_HEADER.as_str(),
                    wrong_key.to_header_value(),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_bytes(response, "sse body").await;
        let body = std::str::from_utf8(&body).expect("utf8 sse body");
        let events: Vec<_> = body
            .split("\n\n")
            .filter(|e| !e.trim().is_empty())
            .collect();
        let [event] = events.as_slice() else {
            panic!("expected only an error event: {body}");
        };
        let field = |name: &str| {
            event
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .map(str::trim)
        };
        assert_eq!(field("event:"), Some("error"));
        let data: serde_json::Value =
            serde_json::from_str(field("data:").expect("error event data")).expect("json data");
        assert_eq!(data["status"], 400);
        assert_eq!(data["code"], "decryption_failed");
        assert!(
            data["message"]
                .as_str()
                .expect("error message string")
                .contains("record decryption failed")
        );
    }

    #[tokio::test]
    async fn sse_read_without_key_header_is_rejected_before_stream_starts() {
        let encryption_key = aegis_key(0x42);
        let (app, backend, basin, stream) = setup_app_with_config(
            "read-sse-plain",
            basin_config_with_stream_cipher(EncryptionAlgorithm::Aegis256),
            OptionalStreamConfig::default(),
        )
        .await;
        append_encrypted_payload(&backend, &basin, &stream, b"secret", encryption_key).await;

        let response = send(
            &app,
            request_builder(
                "GET",
                format!("/v1/streams/{stream}/records?seq_num=0"),
                &basin,
            )
            .header(header::ACCEPT, "text/event-stream")
            .body(Body::empty())
            .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let info = response_json(response, "sse read error body").await;
        assert_eq!(info["code"], "bad_header");
        assert!(
            info["message"]
                .as_str()
                .expect("error message string")
                .contains("missing encryption key")
        );
    }

    #[rstest::rstest]
    #[case::count(Some(10), None)]
    #[case::bytes(None, Some(10))]
    #[case::count_first(Some(10), Some(15))]
    #[case::bytes_first(Some(15), Some(10))]
    #[tokio::test]
    async fn sse_resume_emits_cumulative_ids_and_honors_bounds(
        #[case] count: Option<u64>,
        #[case] bytes_in_records: Option<u64>,
    ) {
        let (app, backend, basin, stream) = setup_app_with_config(
            "read-sse-resume",
            BasinConfig::default(),
            OptionalStreamConfig::default(),
        )
        .await;
        let per_record = append_input(b"payload").records.metered_size() as u64;
        let mut bounds = String::new();
        if let Some(count) = count {
            bounds.push_str(&format!("count={count}&"));
        }
        if let Some(records) = bytes_in_records {
            bounds.push_str(&format!("bytes={}&", records * per_record));
        }

        // End two connections at the current tail, then resume with exactly
        // the same bounds and the actual id emitted by the previous connection.
        let mut last_id = None;
        let mut delivered = Vec::new();
        for (appended, expected_total, reaches_tail) in
            [(4usize, 4u64, true), (3, 7, true), (13, 10, false)]
        {
            for _ in 0..appended {
                append_payload(&backend, &basin, &stream, b"payload").await;
            }
            let resumed = sse_read(&app, &basin, &stream, &bounds, last_id).await;
            delivered.extend(resumed.seq_nums);
            assert_eq!(delivered, (0..expected_total).collect::<Vec<_>>());
            if reaches_tail {
                assert_eq!(resumed.pings.len(), 1);
                assert_eq!(resumed.pings[0].seq_num, expected_total);
            } else {
                assert!(resumed.pings.is_empty(), "{:?}", resumed.pings);
            }
            let id = resumed.last_id.expect("last id");
            assert_eq!(id.seq_num, expected_total - 1);
            assert_eq!(id.count, expected_total);
            assert_eq!(id.bytes, expected_total * per_record);
            last_id = Some(id);
        }

        // The same read without reconnects produces the same records and id.
        let full = sse_read(&app, &basin, &stream, &bounds, None).await;
        assert_eq!(full.seq_nums, delivered);
        assert!(full.pings.is_empty(), "{:?}", full.pings);
        assert_eq!(
            full.last_id.expect("full id").to_string(),
            last_id.expect("resumed id").to_string(),
        );

        let exhausted = sse_read(&app, &basin, &stream, &bounds, last_id).await;
        assert!(exhausted.seq_nums.is_empty(), "{:?}", exhausted.seq_nums);
        assert!(exhausted.last_id.is_none());
        assert!(exhausted.pings.is_empty(), "{:?}", exhausted.pings);
    }

    #[rstest::rstest]
    #[case::unbounded("", (u64::MAX - 1, u64::MAX - 1), (u64::MAX, u64::MAX), 3)]
    #[case::count_bound("count=2", (0, u64::MAX), (2, u64::MAX), 2)]
    #[case::bytes_bound("bytes=30", (u64::MAX, 0), (u64::MAX, 30), 2)]
    #[tokio::test]
    async fn sse_resume_saturates_client_supplied_counters(
        #[case] bounds: &str,
        #[case] (count, bytes): (u64, u64),
        #[case] expected_totals: (u64, u64),
        #[case] expected_records: usize,
    ) {
        let (app, backend, basin, stream) = setup_app_with_config(
            "read-sse-saturation",
            BasinConfig::default(),
            OptionalStreamConfig::default(),
        )
        .await;
        // Each "payload" record occupies 15 metered bytes.
        for _ in 0..4 {
            append_payload(&backend, &basin, &stream, b"payload").await;
        }
        let resumed = sse_read(
            &app,
            &basin,
            &stream,
            bounds,
            Some(LastEventId {
                seq_num: 0,
                count,
                bytes,
            }),
        )
        .await;
        assert_eq!(
            resumed.seq_nums,
            (1..=expected_records as u64).collect::<Vec<_>>()
        );
        let id = resumed.last_id.expect("last id");
        assert_eq!((id.count, id.bytes), expected_totals);
    }

    #[tokio::test]
    async fn s2s_read_without_key_header_is_rejected_before_stream_starts() {
        let encryption_key = aegis_key(0x42);
        let (app, backend, basin, stream) = setup_app_with_config(
            "read-s2s-plain",
            basin_config_with_stream_cipher(EncryptionAlgorithm::Aegis256),
            OptionalStreamConfig::default(),
        )
        .await;
        append_encrypted_payload(&backend, &basin, &stream, b"secret", encryption_key).await;

        let response = send(
            &app,
            request_builder("GET", read_uri(&stream), &basin)
                .header(header::CONTENT_TYPE, "s2s/proto")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let info = response_json(response, "s2s read error body").await;
        assert_eq!(info["code"], "bad_header");
        assert!(
            info["message"]
                .as_str()
                .expect("error message string")
                .contains("missing encryption key")
        );
    }

    #[tokio::test]
    async fn s2s_read_with_correct_encryption_returns_batch_frame() {
        let encryption_key = aegis_key(0x42);
        let (app, backend, basin, stream) = setup_app_with_config(
            "read-s2s-ok",
            basin_config_with_stream_cipher(EncryptionAlgorithm::Aegis256),
            OptionalStreamConfig::default(),
        )
        .await;
        append_encrypted_payload(&backend, &basin, &stream, b"secret", encryption_key.clone())
            .await;

        let response = send(
            &app,
            request_builder("GET", read_uri(&stream), &basin)
                .header(header::CONTENT_TYPE, "s2s/proto")
                .header(
                    S2_ENCRYPTION_KEY_HEADER.as_str(),
                    encryption_key.to_header_value(),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_bytes(response, "s2s body").await;
        let frames = decode_all_frames(body);
        assert_eq!(frames.len(), 2, "expected batch frame + tail heartbeat");
        let SessionMessage::Regular(batch) = frames[0].clone() else {
            panic!("expected regular batch frame");
        };
        let batch = batch
            .try_into_proto::<proto::ReadBatch>()
            .expect("decode read batch proto");
        assert_eq!(batch.records.len(), 1);
        assert_eq!(batch.records[0].body.as_ref(), b"secret");

        let SessionMessage::Regular(hb) = frames[1].clone() else {
            panic!("expected regular heartbeat frame");
        };
        let hb = hb
            .try_into_proto::<proto::ReadBatch>()
            .expect("decode heartbeat proto");
        assert!(hb.records.is_empty());
        assert_eq!(hb.tail.as_ref().map(|pos| pos.seq_num), Some(1));
    }

    async fn assert_streaming_tail_heartbeat(
        app: &axum::Router,
        basin: &BasinName,
        stream: &StreamName,
        query: &str,
        expected_tail: StreamPosition,
    ) {
        // S2S: 200 OK, single empty ReadBatch carrying tail, clean EOF (no terminal frame).
        let s2s_batches = s2s_read_batches(app, basin, stream, query).await;
        assert_eq!(
            s2s_batches.len(),
            1,
            "S2S query `{query}` should emit a single tail heartbeat, got {s2s_batches:?}"
        );
        assert!(
            s2s_batches[0].records.is_empty(),
            "S2S query `{query}` heartbeat should have no records"
        );
        let s2s_tail = s2s_batches[0]
            .tail
            .as_ref()
            .expect("S2S heartbeat must carry tail");
        assert_eq!(
            (s2s_tail.seq_num, s2s_tail.timestamp),
            (expected_tail.seq_num, expected_tail.timestamp),
            "S2S query `{query}` tail mismatch"
        );

        // SSE: 200 OK, single ping event carrying tail, followed by [DONE].
        let sse = sse_read_query(app, basin, stream, query, None).await;
        assert!(
            sse.seq_nums.is_empty(),
            "SSE query `{query}` should have no records"
        );
        assert_eq!(
            sse.pings,
            vec![expected_tail],
            "SSE query `{query}` should emit a single tail ping"
        );
    }

    async fn assert_416(response: Response, expected_tail: StreamPosition, context: &str) {
        assert_eq!(
            response.status(),
            StatusCode::RANGE_NOT_SATISFIABLE,
            "{context}: expected 416"
        );
        let body = response_json(response, "416 tail body").await;
        assert_eq!(
            (
                body["tail"]["seq_num"].as_u64(),
                body["tail"]["timestamp"].as_u64()
            ),
            (Some(expected_tail.seq_num), Some(expected_tail.timestamp)),
            "{context}: tail mismatch"
        );
    }

    #[tokio::test]
    async fn streaming_no_wait_at_tail_emits_heartbeat_over_s2s_and_sse() {
        // Empty stream.
        let (app, _backend, basin, stream) = setup_app_with_config(
            "stream-empty-tail-hb",
            BasinConfig::default(),
            OptionalStreamConfig::default(),
        )
        .await;
        for query in ["wait=0", "count=10", "seq_num=10&clamp=true&count=10"] {
            assert_streaming_tail_heartbeat(&app, &basin, &stream, query, StreamPosition::MIN)
                .await;
        }

        // Non-empty stream.
        let (app, backend, basin, stream) = setup_app_with_config(
            "stream-nonempty-tail-hb",
            BasinConfig::default(),
            OptionalStreamConfig::default(),
        )
        .await;
        let ack = append_records(
            &backend,
            &basin,
            &stream,
            vec![
                envelope_record(b"a", Some(1000)),
                envelope_record(b"b", Some(2000)),
            ],
        )
        .await;
        for query in ["wait=0", "count=10", "seq_num=10&clamp=true&count=10"] {
            assert_streaming_tail_heartbeat(&app, &basin, &stream, query, ack.end).await;
        }

        // Fully trimmed stream.
        let trim_ack = append_records(
            &backend,
            &basin,
            &stream,
            vec![trim_record(u64::MAX, Some(3000))],
        )
        .await;
        while backend.clone().tick_stream_trim().await.expect("trim tick") {}
        for query in [
            "seq_num=0&wait=0",
            "seq_num=0&count=10",
            "seq_num=10&clamp=true&count=10",
        ] {
            assert_streaming_tail_heartbeat(&app, &basin, &stream, query, trim_ack.end).await;
        }
    }

    #[tokio::test]
    async fn streaming_no_wait_before_tail_returns_records_then_trailing_heartbeat() {
        let (app, backend, basin, stream) = setup_app_with_config(
            "stream-records-then-hb",
            BasinConfig::default(),
            OptionalStreamConfig::default(),
        )
        .await;
        let ack = append_records(
            &backend,
            &basin,
            &stream,
            vec![
                envelope_record(b"a", Some(1000)),
                envelope_record(b"b", Some(2000)),
            ],
        )
        .await;

        for query in [
            "seq_num=0&count=10",
            "seq_num=0&wait=0",
            "seq_num=0&until=5000",
        ] {
            // S2S: non-empty record batch(es), then a single trailing tail heartbeat and clean EOF.
            let s2s_batches = s2s_read_batches(&app, &basin, &stream, query).await;
            let (last, record_batches) = s2s_batches
                .split_last()
                .expect("S2S catch-up read should emit records and trailing heartbeat");
            assert!(
                !record_batches.is_empty(),
                "S2S query `{query}` should emit records before trailing heartbeat"
            );
            let mut s2s_seq_nums = Vec::new();
            for batch in record_batches {
                assert!(
                    !batch.records.is_empty(),
                    "S2S query `{query}` emitted unexpected intermediate heartbeat: {s2s_batches:?}"
                );
                s2s_seq_nums.extend(batch.records.iter().map(|r| r.seq_num));
            }
            assert_eq!(s2s_seq_nums, vec![0, 1], "S2S query `{query}`");
            assert!(
                last.records.is_empty(),
                "S2S query `{query}` final frame should be trailing heartbeat: {s2s_batches:?}"
            );
            let tail = last
                .tail
                .as_ref()
                .expect("S2S trailing heartbeat must carry tail");
            assert_eq!(
                (tail.seq_num, tail.timestamp),
                (ack.end.seq_num, ack.end.timestamp),
                "S2S query `{query}` tail mismatch"
            );

            // SSE: batch event(s) for [0, 1], then a single ping carrying tail before [DONE].
            let sse = sse_read_query(&app, &basin, &stream, query, None).await;
            assert_eq!(sse.seq_nums, vec![0, 1], "SSE query `{query}`");
            assert_eq!(sse.pings, vec![ack.end], "SSE query `{query}`");
        }
    }

    #[tokio::test]
    async fn streaming_beyond_tail_without_clamp_returns_416_before_stream_starts() {
        let (app, backend, basin, stream) = setup_app_with_config(
            "stream-beyond-416",
            BasinConfig::default(),
            OptionalStreamConfig::default(),
        )
        .await;
        let ack = append_records(
            &backend,
            &basin,
            &stream,
            vec![
                envelope_record(b"a", Some(1000)),
                envelope_record(b"b", Some(2000)),
            ],
        )
        .await;

        let s2s_resp = send(
            &app,
            request_builder("GET", records_uri(&stream, "seq_num=3&count=10"), &basin)
                .header(header::CONTENT_TYPE, "s2s/proto")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_416(s2s_resp, ack.end, "S2S beyond tail").await;

        let sse_resp = send(
            &app,
            request_builder("GET", records_uri(&stream, "seq_num=3&count=10"), &basin)
                .header(header::ACCEPT, "text/event-stream")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_416(sse_resp, ack.end, "SSE beyond tail").await;
    }

    #[tokio::test]
    async fn sse_last_event_id_resuming_at_tail_without_wait_emits_ping_and_done() {
        let (app, backend, basin, stream) = setup_app_with_config(
            "sse-resume-at-tail",
            BasinConfig::default(),
            OptionalStreamConfig::default(),
        )
        .await;
        let per_record = append_input(b"payload").records.metered_size() as u64;
        let ack = append_records(
            &backend,
            &basin,
            &stream,
            vec![
                envelope_record(b"payload", Some(1000)),
                envelope_record(b"payload", Some(2000)),
            ],
        )
        .await;
        let at_tail_id = LastEventId {
            seq_num: 1,
            count: 2,
            bytes: per_record * 2,
        };

        for query in ["seq_num=0&wait=0", "seq_num=0&count=10"] {
            let resumed = sse_read_query(&app, &basin, &stream, query, Some(at_tail_id)).await;
            assert!(resumed.seq_nums.is_empty(), "query={query}");
            assert!(resumed.last_id.is_none(), "query={query}");
            assert_eq!(resumed.pings, vec![ack.end], "query={query}");
        }
    }

    #[tokio::test]
    async fn unary_read_no_wait_tail_and_stop_mapping() {
        // Empty stream without wait -> 416 with StreamPosition::MIN.
        let (empty_app, _empty_backend, empty_basin, empty_stream) = setup_app_with_config(
            "unary-empty-416",
            BasinConfig::default(),
            OptionalStreamConfig::default(),
        )
        .await;
        let resp = send(
            &empty_app,
            request_builder("GET", records_uri(&empty_stream, "seq_num=0"), &empty_basin)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_416(resp, StreamPosition::MIN, "unary empty stream").await;

        // Non-empty stream.
        let (app, backend, basin, stream) = setup_app_with_config(
            "unary-nonempty",
            BasinConfig::default(),
            OptionalStreamConfig::default(),
        )
        .await;
        let ack = append_records(
            &backend,
            &basin,
            &stream,
            vec![
                envelope_record(b"a", Some(1000)),
                envelope_record(b"b", Some(2000)),
            ],
        )
        .await;

        // Starting at tail with wait=0 -> 416 with tail.
        let resp = send(
            &app,
            request_builder("GET", records_uri(&stream, "seq_num=2&wait=0"), &basin)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_416(resp, ack.end, "unary at tail wait=0").await;

        // `until` cutting off before first record -> 200 OK empty.
        let resp = send(
            &app,
            request_builder("GET", records_uri(&stream, "seq_num=0&until=500"), &basin)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp, "unary empty until response").await;
        assert_eq!(body["records"], serde_json::json!([]));

        // Non-empty catch-up with wait=0 -> 200 OK with records + tail.
        let resp = send(
            &app,
            request_builder("GET", records_uri(&stream, "seq_num=0&wait=0"), &basin)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp, "unary catch-up response").await;
        assert_eq!(body["records"].as_array().map(Vec::len), Some(2));
        assert_eq!(body["tail"]["seq_num"], 2);
        assert_eq!(body["tail"]["timestamp"], 2000);

        // Count-bounded stopping before tail -> 200 OK without tail.
        let resp = send(
            &app,
            request_builder(
                "GET",
                records_uri(&stream, "seq_num=0&count=1&wait=0"),
                &basin,
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp, "unary bounded response").await;
        assert_eq!(body["records"].as_array().map(Vec::len), Some(1));
        assert!(body.get("tail").is_none());

        // Fully trimmed stream -> 416 with tail.
        let trim_ack = append_records(
            &backend,
            &basin,
            &stream,
            vec![trim_record(u64::MAX, Some(3000))],
        )
        .await;
        while backend.clone().tick_stream_trim().await.expect("trim tick") {}
        let resp = send(
            &app,
            request_builder("GET", records_uri(&stream, "seq_num=0"), &basin)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_416(resp, trim_ack.end, "unary across trimmed gap").await;
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn unary_read_with_positive_wait_at_tail_long_polls() {
        let (app, backend, basin, stream) = setup_app_with_config(
            "unary-wait-long-poll",
            BasinConfig::default(),
            OptionalStreamConfig::default(),
        )
        .await;
        let initial_ack = append_records(
            &backend,
            &basin,
            &stream,
            vec![envelope_record(b"first", Some(1000))],
        )
        .await;

        // 1. Wait expires with no new records -> 200 OK with empty records and tail (not 416).
        let resp = send(
            &app,
            request_builder("GET", records_uri(&stream, "seq_num=1&wait=1"), &basin)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp, "unary wait expiry body").await;
        assert_eq!(body["records"], serde_json::json!([]));
        assert_eq!(body["tail"]["seq_num"], initial_ack.end.seq_num);
        assert_eq!(body["tail"]["timestamp"], initial_ack.end.timestamp);

        // 2. Record appended during wait -> wakes and returns 200 OK with the new record and tail.
        let append_task = tokio::spawn({
            let backend = backend.clone();
            let basin = basin.clone();
            let stream = stream.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                append_records(
                    &backend,
                    &basin,
                    &stream,
                    vec![envelope_record(b"second", Some(2000))],
                )
                .await
            }
        });
        let resp = send(
            &app,
            request_builder("GET", records_uri(&stream, "seq_num=1&wait=5"), &basin)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let second_ack = append_task.await.expect("append task");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp, "unary wait append body").await;
        let records = body["records"].as_array().expect("records array");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["seq_num"], 1);
        assert_eq!(records[0]["body"], "second");
        assert_eq!(body["tail"]["seq_num"], second_ack.end.seq_num);
        assert_eq!(body["tail"]["timestamp"], second_ack.end.timestamp);
    }
}
