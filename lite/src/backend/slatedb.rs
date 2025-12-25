use std::sync::Arc;

use dashmap::DashMap;
use futures::stream::BoxStream;
use s2_common::{
    record::StreamPosition,
    types::{
        basin::BasinName,
        stream::{AppendAck, AppendInput, ReadBatch, ReadEnd, ReadStart, StreamName},
    },
};
use tokio::sync::{broadcast, mpsc};

use super::ops::{CheckTailError, DataOps};
use crate::backend::{
    ops::{AppendError, ReadError},
    stream_id::StreamId,
};

struct StreamTailState {
    tail: StreamPosition,
    follower_tx: broadcast::Sender<ReadBatch>,
}

struct StreamState {
    tail_state: Option<StreamTailState>,
}

impl StreamState {}

pub struct SlateDbBackend {
    db: slatedb::Db,
    streams: DashMap<StreamId, StreamState>,
}

impl SlateDbBackend {
    pub fn new(db: slatedb::Db) -> Self {
        Self {
            db,
            streams: DashMap::default(),
        }
    }
}

impl DataOps for SlateDbBackend {
    async fn check_tail(
        &self,
        basin: BasinName,
        stream: StreamName,
    ) -> Result<StreamPosition, CheckTailError> {
        todo!()
    }

    async fn read(
        &self,
        basin: BasinName,
        stream: StreamName,
        start: ReadStart,
        end: ReadEnd,
    ) -> Result<BoxStream<'static, Result<ReadBatch, ReadError>>, ReadError> {
        todo!()
    }

    async fn append(
        &self,
        basin: BasinName,
        stream: StreamName,
        input: AppendInput,
    ) -> Result<AppendAck, AppendError> {
        todo!()
    }

    async fn append_session(
        &self,
        basin: BasinName,
        stream: StreamName,
        requests: BoxStream<'static, AppendInput>,
    ) -> Result<BoxStream<'static, Result<AppendAck, AppendError>>, AppendError> {
        todo!()
    }
}
