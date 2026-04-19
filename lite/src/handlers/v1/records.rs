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
        s2_api::data::S2EncryptionKeyHeader,
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
            format,
            response_mime,
        } => {
            let (start, end) = prepare_read(start, end, ReadMode::Unary)?;
            let session = backend
                .open_for_read(&basin, &stream, encryption_key)
                .await?
                .read(start, end)
                .await?;
            let batch = merge_read_session(session, end.wait).await?;
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
            format,
            last_event_id,
        } => {
            let (start, end) = apply_last_event_id(start, end, last_event_id);
            let (start, end) = prepare_read(start, end, ReadMode::Streaming)?;
            let session = backend
                .open_for_read(&basin, &stream, encryption_key)
                .await?
                .read(start, end)
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
                            let Some(last_record) = batch.records.last() else {
                                continue;
                            };
                            processed.count += batch.records.len();
                            processed.bytes += batch.records.metered_size();
                            let id = v1t::stream::sse::LastEventId {
                                seq_num: last_record.position().seq_num,
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
            encryption_key,
            response_compression,
        } => {
            let (start, end) = prepare_read(start, end, ReadMode::Streaming)?;
            let s2s_stream = backend
                .open_for_read(&basin, &stream, encryption_key)
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
                .body(Body::from_stream(response_stream))
                .expect("valid response builder"))
        }
    }
}

async fn merge_read_session(
    session: impl Stream<Item = Result<ReadSessionOutput, ReadError>>,
    wait: Option<Duration>,
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
    params(
        v1t::StreamNamePathSegment,
        s2_api::data::S2FormatHeader,
        s2_api::data::S2EncryptionKeyHeader,
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
            input,
            response_mime,
        } => {
            let handle = backend
                .open_for_append(&basin, &stream, encryption_key)
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
            inputs,
            response_compression,
        } => {
            let handle = backend
                .open_for_append(&basin, &stream, encryption_key)
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
    use s2_api::v1::stream::{
        proto,
        s2s::{FrameDecoder, SessionMessage},
    };
    use s2_common::{
        encryption::{EncryptionAlgorithm, EncryptionKey, S2_ENCRYPTION_KEY_HEADER},
        read_extent::{ReadLimit, ReadUntil},
        record::{EnvelopeRecord, Metered, Record},
        types::{
            basin::{BASIN_HEADER, BasinName},
            config::{BasinConfig, OptionalStreamConfig},
            resources::CreateMode,
            stream::{
                AppendInput, AppendRecord, AppendRecordBatch, AppendRecordParts,
                ListStreamsRequest, ReadEnd, ReadFrom, ReadSessionOutput, ReadStart, StreamName,
            },
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
            .create_basin(basin.clone(), basin_config, CreateMode::CreateOnly(None))
            .await
            .expect("create basin");
        let stream: StreamName = format!("test-stream-{test_suffix}").parse().unwrap();
        backend
            .create_stream(
                basin.clone(),
                stream.clone(),
                stream_config,
                CreateMode::CreateOnly(None),
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
            .create_basin(basin.clone(), basin_config, CreateMode::CreateOnly(None))
            .await
            .expect("create basin");
        let stream: StreamName = format!("test-stream-{test_suffix}").parse().unwrap();
        let app = handlers::router().with_state(backend.clone());
        (app, backend, basin, stream)
    }

    fn append_input(body: &'static [u8]) -> AppendInput {
        let record = Metered::from(Record::Envelope(
            EnvelopeRecord::try_from_parts(vec![], Bytes::from_static(body)).unwrap(),
        ));
        let record = AppendRecord::try_from(AppendRecordParts {
            timestamp: None,
            record,
        })
        .unwrap();
        let records = AppendRecordBatch::try_from(vec![record]).unwrap();
        AppendInput {
            records,
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
            .open_for_append(basin, stream, Some(encryption_key))
            .await
            .expect("open append handle")
            .append(append_input(body))
            .await
            .expect("append encrypted payload");
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

    fn decode_single_frame(body: Bytes, context: &str) -> SessionMessage {
        let mut decoder = FrameDecoder;
        let mut buf = BytesMut::from(body.as_ref());
        let frame = decoder
            .decode(&mut buf)
            .expect("frame decode")
            .expect(context);
        assert!(buf.is_empty(), "expected a single frame");
        frame
    }

    fn assert_invalid_error(info: &serde_json::Value, expected_message: &str) {
        assert_eq!(info["code"], "invalid");
        assert!(
            info["message"]
                .as_str()
                .expect("error message string")
                .contains(expected_message)
        );
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
            .open_for_read(&basin, &stream, Some(encryption_key.clone()))
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
        assert_invalid_error(&info, "start `timestamp` exceeds or equal to `until`");
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

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let info = response_json(response, "sse read error body").await;
        assert_invalid_error(&info, "missing encryption key");
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

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let info = response_json(response, "s2s read error body").await;
        assert_invalid_error(&info, "missing encryption key");
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
        let frame = decode_single_frame(body, "batch frame");
        let SessionMessage::Regular(batch) = frame else {
            panic!("expected regular frame");
        };
        let batch = batch
            .try_into_proto::<proto::ReadBatch>()
            .expect("decode read batch proto");
        assert_eq!(batch.records.len(), 1);
        assert_eq!(batch.records[0].body.as_ref(), b"secret");
    }
}
