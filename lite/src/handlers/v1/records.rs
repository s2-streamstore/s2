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
    encryption::EncryptionConfig,
    http::extract::Header,
    read_extent::{CountOrBytes, ReadLimit},
    record::{Metered, MeteredSize as _},
    types::{
        ValidationError,
        basin::BasinName,
        stream::{
            ReadBatch, ReadEnd, ReadFrom, ReadSessionOutput, ReadStart, StoredReadSessionOutput,
            StreamName,
        },
    },
};

use crate::{backend::Backend, handlers::v1::error::ServiceError, stream_id::StreamId};

pub fn router() -> axum::Router<Backend> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route(super::paths::streams::records::CHECK_TAIL, get(check_tail))
        .route(super::paths::streams::records::READ, get(read))
        .route(super::paths::streams::records::APPEND, post(append))
}

fn decrypt_session<S>(
    session: S,
    encryption: EncryptionConfig,
    stream_id: StreamId,
) -> impl Stream<Item = Result<ReadSessionOutput, ServiceError>>
where
    S: Stream<Item = Result<StoredReadSessionOutput, crate::backend::error::ReadError>>,
{
    async_stream::stream! {
        tokio::pin!(session);
        while let Some(output) = session.next().await {
            let output = match output {
                Ok(output) => output
                    .decrypt(&encryption, stream_id.as_bytes())
                    .map_err(ServiceError::from),
                Err(err) => Err(err.into()),
            };
            let should_stop = output.is_err();
            yield output;
            if should_stop {
                break;
            }
        }
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
        s2_api::data::S2EncryptionHeader,
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
    let stream_id = StreamId::new(&basin, &stream);
    match request {
        v1t::stream::ReadRequest::Unary {
            encryption,
            format,
            response_mime,
        } => {
            let (start, end) = prepare_read(start, end, ReadMode::Unary)?;
            let session = backend.read(basin, stream, start, end).await?;
            let session = decrypt_session(session, encryption, stream_id);
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
            encryption,
            format,
            last_event_id,
        } => {
            let (start, end) = apply_last_event_id(start, end, last_event_id);
            let (start, end) = prepare_read(start, end, ReadMode::Streaming)?;
            let session = backend.read(basin, stream, start, end).await?;
            let session = decrypt_session(session, encryption, stream_id);
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
                            let (_, body) = err.to_response().to_parts();
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
            encryption,
            response_compression,
        } => {
            let (start, end) = prepare_read(start, end, ReadMode::Streaming)?;
            let session = backend.read(basin, stream, start, end).await?;
            let s2s_stream =
                decrypt_session(session, encryption, stream_id).map_ok(|msg| match msg {
                    ReadSessionOutput::Heartbeat(tail) => v1t::stream::proto::ReadBatch {
                        records: vec![],
                        tail: Some(tail.into()),
                    },
                    ReadSessionOutput::Batch(batch) => v1t::stream::proto::ReadBatch::from(batch),
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
    session: impl Stream<Item = Result<ReadSessionOutput, ServiceError>>,
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
        s2_api::data::S2EncryptionHeader,
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
    let stream_id = StreamId::new(&basin, &stream);
    match request {
        v1t::stream::AppendRequest::Unary {
            encryption,
            input,
            response_mime,
        } => {
            let input = input.encrypt(&encryption, stream_id.as_bytes());
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
            encryption,
            inputs,
            response_compression,
        } => {
            let (err_tx, err_rx) = tokio::sync::oneshot::channel();

            let inputs = async_stream::stream! {
                tokio::pin!(inputs);
                let mut err_tx = Some(err_tx);
                while let Some(input) = inputs.next().await {
                    match input {
                        Ok(input) => yield input.encrypt(&encryption, stream_id.as_bytes()),
                        Err(e) => {
                            if let Some(tx) = err_tx.take() {
                                let _ = tx.send(e);
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
    use futures::StreamExt as _;
    use prost::Message as _;
    use s2_api::v1::stream::{
        proto,
        s2s::{FrameDecoder, SessionMessage, TerminalMessage},
    };
    use s2_common::{
        encryption::{EncryptionAlgorithm, EncryptionConfig, S2_ENCRYPTION_HEADER},
        read_extent::{ReadLimit, ReadUntil},
        record::{EnvelopeRecord, Metered, Record, RecordDecryptionError},
        types::{
            basin::{BASIN_HEADER, BasinName},
            config::{BasinConfig, OptionalStreamConfig},
            resources::CreateMode,
            stream::{
                AppendInput, AppendRecord, AppendRecordBatch, AppendRecordParts, ReadEnd, ReadFrom,
                ReadStart, StoredReadBatch, StoredReadSessionOutput, StreamName,
            },
        },
    };
    use slatedb::{Db, config::Settings, object_store::memory::InMemory};
    use tokio_util::codec::Decoder as _;
    use tower::ServiceExt as _;
    use uuid::Uuid;

    use crate::{backend::Backend, handlers, stream_id::StreamId};

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

    async fn setup_app(test_suffix: &str) -> (axum::Router, Backend, BasinName, StreamName) {
        let backend = create_backend().await;
        let basin: BasinName = format!("test-basin-{test_suffix}").parse().unwrap();
        backend
            .create_basin(
                basin.clone(),
                BasinConfig::default(),
                CreateMode::CreateOnly(None),
            )
            .await
            .expect("create basin");
        let stream: StreamName = format!("test-stream-{test_suffix}").parse().unwrap();
        backend
            .create_stream(
                basin.clone(),
                stream.clone(),
                OptionalStreamConfig::default(),
                CreateMode::CreateOnly(None),
            )
            .await
            .expect("create stream");
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
        encryption: &EncryptionConfig,
    ) {
        let stream_id = StreamId::new(basin, stream);
        let input = append_input(body).encrypt(encryption, stream_id.as_bytes());
        backend
            .append(basin.clone(), stream.clone(), input)
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

    async fn first_stored_batch(
        backend: &Backend,
        basin: &BasinName,
        stream: &StreamName,
    ) -> StoredReadBatch {
        let session = backend
            .read(
                basin.clone(),
                stream.clone(),
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
            .expect("create stored read session");
        let mut session = Box::pin(session);
        match session.next().await {
            Some(Ok(StoredReadSessionOutput::Batch(batch))) => batch,
            Some(Ok(other)) => panic!("unexpected first output: {other:?}"),
            Some(Err(err)) => panic!("unexpected read error: {err:?}"),
            None => panic!("read session ended without batch"),
        }
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

    #[tokio::test]
    async fn unary_append_with_encryption_header_persists_encrypted_record() {
        let encryption = EncryptionConfig::aegis256([0x42; 32]);
        let (app, backend, basin, stream) = setup_app("append-unary-encrypted").await;

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
                .header(S2_ENCRYPTION_HEADER.as_str(), encryption.to_header_value())
                .body(Body::from(input.encode_to_vec()))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_bytes(response, "append ack body").await;
        let ack = proto::AppendAck::decode(body).expect("append ack");
        assert_eq!(ack.end.as_ref().map(|pos| pos.seq_num), Some(1));

        let stored_batch = first_stored_batch(&backend, &basin, &stream).await;

        assert!(matches!(
            stored_batch.clone().decrypt(&EncryptionConfig::Plain, &[]),
            Err(RecordDecryptionError::AlgorithmMismatch {
                expected: None,
                actual: EncryptionAlgorithm::Aegis256,
            })
        ));

        let stream_id = StreamId::new(&basin, &stream);
        let batch = stored_batch
            .decrypt(&encryption, stream_id.as_bytes())
            .expect("decrypt stored batch");
        assert_eq!(batch.records.len(), 1);
        let record = batch.records.first().expect("record");
        let Record::Envelope(record) = record.inner() else {
            panic!("expected envelope record");
        };
        assert_eq!(record.body().as_ref(), b"secret");
    }

    #[tokio::test]
    async fn unary_read_with_wrong_key_returns_invalid_error() {
        let encryption = EncryptionConfig::aegis256([0x42; 32]);
        let wrong_key = EncryptionConfig::aegis256([0x24; 32]);
        let (app, backend, basin, stream) = setup_app("read-unary-bad-key").await;
        append_encrypted_payload(&backend, &basin, &stream, b"secret", &encryption).await;

        let response = send(
            &app,
            request_builder("GET", read_uri(&stream), &basin)
                .header(S2_ENCRYPTION_HEADER.as_str(), wrong_key.to_header_value())
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let info = response_json(response, "read error body").await;
        assert_invalid_error(&info, "record decryption failed");
    }

    #[tokio::test]
    async fn sse_read_with_plain_header_emits_error_event_and_terminates() {
        let encryption = EncryptionConfig::aegis256([0x42; 32]);
        let (app, backend, basin, stream) = setup_app("read-sse-plain").await;
        append_encrypted_payload(&backend, &basin, &stream, b"secret", &encryption).await;

        let response = send(
            &app,
            request_builder(
                "GET",
                format!("/v1/streams/{stream}/records?seq_num=0"),
                &basin,
            )
            .header(header::ACCEPT, "text/event-stream")
            .header(
                S2_ENCRYPTION_HEADER.as_str(),
                EncryptionConfig::Plain.to_header_value(),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body =
            tokio::time::timeout(Duration::from_secs(1), response_bytes(response, "sse body"))
                .await
                .expect("sse body should terminate after the first error event");
        let body = String::from_utf8(body.to_vec()).expect("utf8 sse body");
        assert!(body.contains("event: error"));
        assert!(body.contains("\"code\":\"invalid\""));
        assert!(body.contains("ciphertext algorithm mismatch"));
        assert!(!body.contains("event: ping"));
        assert!(!body.contains("[DONE]"));
    }

    #[tokio::test]
    async fn s2s_read_with_plain_header_returns_terminal_invalid_frame() {
        let encryption = EncryptionConfig::aegis256([0x42; 32]);
        let (app, backend, basin, stream) = setup_app("read-s2s-plain").await;
        append_encrypted_payload(&backend, &basin, &stream, b"secret", &encryption).await;

        let response = send(
            &app,
            request_builder("GET", read_uri(&stream), &basin)
                .header(header::CONTENT_TYPE, "s2s/proto")
                .header(
                    S2_ENCRYPTION_HEADER.as_str(),
                    EncryptionConfig::Plain.to_header_value(),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_bytes(response, "s2s body").await;
        let frame = decode_single_frame(body, "terminal frame");
        let SessionMessage::Terminal(TerminalMessage { status, body }) = frame else {
            panic!("expected terminal frame");
        };
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY.as_u16());
        let info: serde_json::Value =
            serde_json::from_str(&body).expect("terminal json error info");
        assert_invalid_error(&info, "ciphertext algorithm mismatch");
    }

    #[tokio::test]
    async fn s2s_read_with_correct_encryption_returns_batch_frame() {
        let encryption = EncryptionConfig::aegis256([0x42; 32]);
        let (app, backend, basin, stream) = setup_app("read-s2s-ok").await;
        append_encrypted_payload(&backend, &basin, &stream, b"secret", &encryption).await;

        let response = send(
            &app,
            request_builder("GET", read_uri(&stream), &basin)
                .header(header::CONTENT_TYPE, "s2s/proto")
                .header(S2_ENCRYPTION_HEADER.as_str(), encryption.to_header_value())
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
