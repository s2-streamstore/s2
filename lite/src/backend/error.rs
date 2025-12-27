use std::sync::Arc;

use s2_common::{
    record::{FencingToken, SeqNum, StreamPosition},
    types::{basin::BasinName, stream::StreamName},
};

use crate::backend::kv;

#[derive(Debug, Clone, thiserror::Error)]
pub(super) enum StreamerError {
    #[error("Hangup")]
    Hangup,
    #[error("Stream `{stream}` not found in basin `{basin}`")]
    StreamNotFound {
        basin: BasinName,
        stream: StreamName,
    },
    #[error("Deserialization: {0}")]
    Deserialization(#[from] kv::DeserializationError),
    #[error("Slate: {0}")]
    Slate(#[from] Arc<slatedb::Error>),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum CheckTailError {
    #[error("Stream not found")]
    StreamNotFound,
}

impl From<StreamerError> for CheckTailError {
    fn from(value: StreamerError) -> Self {
        todo!()
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum AppendError {
    #[error("Stream not found")]
    StreamNotFound,
    #[error(transparent)]
    ConditionFailed(#[from] AppendConditionFailed),
    #[error("Record timestamp required but missing")]
    TimestampMissing,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum AppendConditionFailed {
    #[error("Fencing token mismatch: expected `{expected}`, actual `{actual}`")]
    FencingTokenMismatch {
        expected: FencingToken,
        actual: FencingToken,
        // Note: this is bumped on all commands not just fencing tokens.
        applied_point: SeqNum,
    },
    #[error("Sequence number mismatch: expected {match_seq_num}, actual {assigned_seq_num}")]
    SeqNumMismatch {
        assigned_seq_num: SeqNum,
        match_seq_num: SeqNum,
    },
}

impl AppendConditionFailed {
    pub fn durability_dependency(&self) -> SeqNum {
        use AppendConditionFailed::*;
        match self {
            SeqNumMismatch {
                assigned_seq_num, ..
            } => *assigned_seq_num,
            FencingTokenMismatch { applied_point, .. } => *applied_point,
        }
    }
}

impl From<StreamerError> for AppendError {
    fn from(value: StreamerError) -> Self {
        todo!()
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ReadError {
    #[error("Stream not found")]
    StreamNotFound,
    #[error("Tail position exceeded: {0}")]
    TailExceeded(StreamPosition),
}

impl From<StreamerError> for ReadError {
    fn from(value: StreamerError) -> Self {
        todo!()
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ListStreamsError {
    #[error("Database error: {0}")]
    Database(#[from] Arc<slatedb::Error>),
    #[error("Deserialization error: {0}")]
    Deserialization(#[from] kv::DeserializationError),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum CreateStreamError {
    #[error("Stream already exists")]
    AlreadyExists,
    #[error("Database error: {0}")]
    Database(#[from] Arc<slatedb::Error>),
    #[error("Deserialization error: {0}")]
    Deserialization(#[from] kv::DeserializationError),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum GetStreamConfigError {
    #[error("Stream not found")]
    StreamNotFound,
    #[error("Database error: {0}")]
    Database(#[from] Arc<slatedb::Error>),
    #[error("Deserialization error: {0}")]
    Deserialization(#[from] kv::DeserializationError),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DeleteStreamError {
    #[error("Stream not found")]
    StreamNotFound,
    #[error("Database error: {0}")]
    Database(#[from] Arc<slatedb::Error>),
    #[error("Deserialization error: {0}")]
    Deserialization(#[from] kv::DeserializationError),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ListBasinsError {
    #[error("Database error: {0}")]
    Database(#[from] Arc<slatedb::Error>),
    #[error("Deserialization error: {0}")]
    Deserialization(#[from] kv::DeserializationError),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum CreateBasinError {
    #[error("Basin already exists")]
    AlreadyExists,
    #[error("Database error: {0}")]
    Database(#[from] Arc<slatedb::Error>),
    #[error("Deserialization error: {0}")]
    Deserialization(#[from] kv::DeserializationError),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum GetBasinConfigError {
    #[error("Basin not found")]
    BasinNotFound,
    #[error("Database error: {0}")]
    Database(#[from] Arc<slatedb::Error>),
    #[error("Deserialization error: {0}")]
    Deserialization(#[from] kv::DeserializationError),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ReconfigureBasinError {}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DeleteBasinError {
    #[error("Basin not found")]
    BasinNotFound,
    #[error("Database error: {0}")]
    Database(#[from] Arc<slatedb::Error>),
    #[error("Deserialization error: {0}")]
    Deserialization(#[from] kv::DeserializationError),
}
