use std::sync::Arc;

use dashmap::DashMap;
use futures::stream::BoxStream;
use s2_common::types::{
    basin::BasinName,
    stream::{AppendAck, AppendInput, ReadBatch, ReadEnd, ReadStart, StreamName, StreamPosition},
};
use tokio::sync::{broadcast, mpsc};

use crate::backend::ops::{AppendError, ReadError};

use super::ops::{CheckTailError, DataOps};

#[derive(Debug, Clone)]
enum StreamCommand {
    CheckTail {
        reply_tx: mpsc::Sender<Result<StreamPosition, CheckTailError>>,
    },
    Read {
        reply_tx: mpsc::Sender<Result<ReadBatch, ReadError>>,
    },
    Append {
        input: AppendInput,
        reply_tx: mpsc::Sender<Result<AppendAck, AppendError>>,
    },
}

pub struct ActiveStreams {
    tx: mpsc::Sender<StreamCommand>,
    // TODO: AbortOnDrop wrapper
    _handle: tokio::task::JoinHandle<()>,
}

struct StreamTailState {
    tail: StreamPosition,
    follower_tx: broadcast::Sender<ReadBatch>,
}

struct StreamState {
    db: Arc<slatedb::Db>,
    tail_state: Option<StreamTailState>,
}

impl StreamState {}

pub struct SlateDbBackend {
    db: Arc<slatedb::Db>,
    streams: DashMap<(BasinName, StreamName), ActiveStreams>,
}

impl SlateDbBackend {
    pub fn new(db: Arc<slatedb::Db>) -> Self {
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
