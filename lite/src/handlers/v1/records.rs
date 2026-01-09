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
        basin::BasinName,
        stream::{ReadBatch, ReadEnd, ReadFrom, ReadSessionOutput, ReadStart, StreamName},
    },
};

use crate::{
    backend::{Backend, error::ReadError},
    handlers::v1::error::ServiceError,
};

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct CheckTailArgs {
    #[from_request(via(Header))]
    basin: BasinName,
    #[from_request(via(Path))]
    stream: StreamName,
}

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
    match request {
        v1t::stream::ReadRequest::Unary {
            format,
            response_mime,
        } => {
            let start: ReadStart = start.try_into()?;
            let mut end: ReadEnd = end.into();
            end.limit = ReadLimit::CountOrBytes(end.limit.into_allowance(RECORD_BATCH_MAX));
            end.wait = end.wait.map(|d| d.min(super::MAX_UNARY_READ_WAIT));
            let session = backend.read(basin, stream, start, end).await?;
            let batch = merge_read_session(session, end.wait).await?;
            match response_mime {
                JsonOrProto::Json => {
                    let batch = v1t::stream::ReadBatch::encode(format, batch);
                    Ok(Json(batch).into_response())
                }
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
            let mut start: ReadStart = start.try_into()?;
            let mut end = end;
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
            let session = backend.read(basin, stream, start, end.into()).await?;
            let events = async_stream::stream! {
                let mut processed = CountOrBytes::ZERO;
                tokio::pin!(session);
                let mut errored = false;
                while let Some(output) = session.next().await {
                    match output {
                        Ok(ReadSessionOutput::Heartbeat(_tail)) => {
                            yield v1t::stream::sse::ReadEvent::ping().try_into();
                        },
                        Ok(ReadSessionOutput::Batch(batch)) => {
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
                            let batch = v1t::stream::ReadBatch::encode(format, batch);
                            yield v1t::stream::sse::ReadEvent::batch(batch, id).try_into();
                        },
                        Err(err) => {
                            let (_, body) = ServiceError::from(err).to_response().to_parts();
                            yield v1t::stream::sse::ReadEvent::error(body).try_into();
                            errored = true;
                        }
                    }
                }
                if !errored {
                    yield v1t::stream::sse::ReadEvent::done().try_into();
                }
            };

            Ok(axum::response::Sse::new(events).into_response())
        }
        v1t::stream::ReadRequest::S2s {
            response_compression,
        } => {
            let s2s_stream = backend
                .read(basin, stream, start.try_into()?, end.into())
                .await?
                .map_ok(|msg| match msg {
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
    #[from_request(via(Header))]
    basin: BasinName,
    #[from_request(via(Path))]
    stream: StreamName,
    request: v1t::stream::AppendRequest,
}

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
            input,
            response_mime,
        } => {
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
