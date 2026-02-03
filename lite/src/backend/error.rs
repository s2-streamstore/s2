use std::{ops::RangeTo, sync::Arc};

use s2_common::{
    record::{FencingToken, SeqNum, StreamPosition},
    types::{basin::BasinName, stream::StreamName},
};

use crate::backend::kv;

#[derive(Debug, Clone, thiserror::Error)]
pub enum StorageError {
    #[error("deserialization: {0}")]
    Deserialization(#[from] kv::DeserializationError),
    #[error("database: {0}")]
    Database(Arc<slatedb::Error>),
}

impl From<slatedb::Error> for StorageError {
    fn from(error: slatedb::Error) -> Self {
        StorageError::Database(Arc::new(error))
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("basin `{basin}` not found")]
pub struct BasinNotFoundError {
    pub basin: BasinName,
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("stream `{stream}` in basin `{basin}` not found")]
pub struct StreamNotFoundError {
    pub basin: BasinName,
    pub stream: StreamName,
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("basin `{basin}` already exists")]
pub struct BasinAlreadyExistsError {
    pub basin: BasinName,
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("stream `{stream}` in basin `{basin}` already exists")]
pub struct StreamAlreadyExistsError {
    pub basin: BasinName,
    pub stream: StreamName,
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("basin `{basin}` is being deleted")]
pub struct BasinDeletionPendingError {
    pub basin: BasinName,
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("stream `{stream}` in basin `{basin}` is being deleted")]
pub struct StreamDeletionPendingError {
    pub basin: BasinName,
    pub stream: StreamName,
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("unwritten position: {0}")]
pub struct UnwrittenError(pub StreamPosition);

#[derive(Debug, Clone, thiserror::Error)]
#[error("streamer missing in action")]
pub struct StreamerMissingInActionError;

#[derive(Debug, Clone, thiserror::Error)]
#[error("request dropped")]
pub struct RequestDroppedError;

#[derive(Debug, Clone, thiserror::Error)]
#[error("record timestamp was required but was missing")]
pub struct AppendTimestampRequiredError;

#[derive(Debug, Clone, thiserror::Error)]
#[error("transaction conflict occurred – this is usually retriable")]
pub struct TransactionConflictError;

#[derive(Debug, Clone, thiserror::Error)]
pub(super) enum StreamerError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    StreamNotFound(#[from] StreamNotFoundError),
    #[error(transparent)]
    StreamDeletionPending(#[from] StreamDeletionPendingError),
}

#[derive(Debug, Clone, thiserror::Error)]
pub(super) enum AppendErrorInternal {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    StreamerMissingInActionError(#[from] StreamerMissingInActionError),
    #[error(transparent)]
    RequestDroppedError(#[from] RequestDroppedError),
    #[error(transparent)]
    ConditionFailed(#[from] AppendConditionFailedError),
    #[error(transparent)]
    TimestampMissing(#[from] AppendTimestampRequiredError),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum CheckTailError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    TransactionConflict(#[from] TransactionConflictError),
    #[error(transparent)]
    StreamerMissingInActionError(#[from] StreamerMissingInActionError),
    #[error(transparent)]
    BasinNotFound(#[from] BasinNotFoundError),
    #[error(transparent)]
    StreamNotFound(#[from] StreamNotFoundError),
    #[error(transparent)]
    BasinDeletionPending(#[from] BasinDeletionPendingError),
    #[error(transparent)]
    StreamDeletionPending(#[from] StreamDeletionPendingError),
}

impl From<StreamerError> for CheckTailError {
    fn from(e: StreamerError) -> Self {
        match e {
            StreamerError::StreamNotFound(e) => Self::StreamNotFound(e),
            StreamerError::Storage(e) => Self::Storage(e),
            StreamerError::StreamDeletionPending(e) => Self::StreamDeletionPending(e),
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum AppendError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    TransactionConflict(#[from] TransactionConflictError),
    #[error(transparent)]
    StreamerMissingInActionError(#[from] StreamerMissingInActionError),
    #[error(transparent)]
    RequestDroppedError(#[from] RequestDroppedError),
    #[error(transparent)]
    BasinNotFound(#[from] BasinNotFoundError),
    #[error(transparent)]
    StreamNotFound(#[from] StreamNotFoundError),
    #[error(transparent)]
    BasinDeletionPending(#[from] BasinDeletionPendingError),
    #[error(transparent)]
    StreamDeletionPending(#[from] StreamDeletionPendingError),
    #[error(transparent)]
    ConditionFailed(#[from] AppendConditionFailedError),
    #[error(transparent)]
    TimestampMissing(#[from] AppendTimestampRequiredError),
}

impl From<AppendErrorInternal> for AppendError {
    fn from(e: AppendErrorInternal) -> Self {
        match e {
            AppendErrorInternal::Storage(e) => AppendError::Storage(e),
            AppendErrorInternal::StreamerMissingInActionError(e) => {
                AppendError::StreamerMissingInActionError(e)
            }
            AppendErrorInternal::RequestDroppedError(e) => AppendError::RequestDroppedError(e),
            AppendErrorInternal::ConditionFailed(e) => AppendError::ConditionFailed(e),
            AppendErrorInternal::TimestampMissing(e) => AppendError::TimestampMissing(e),
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum AppendConditionFailedError {
    #[error("fencing token mismatch: expected `{expected}`, actual `{actual}`")]
    FencingTokenMismatch {
        expected: FencingToken,
        actual: FencingToken,
        applied_point: RangeTo<SeqNum>,
    },
    #[error("sequence number mismatch: expected {match_seq_num}, actual {assigned_seq_num}")]
    SeqNumMismatch {
        assigned_seq_num: SeqNum,
        match_seq_num: SeqNum,
    },
}

impl AppendConditionFailedError {
    pub fn durability_dependency(&self) -> RangeTo<SeqNum> {
        use AppendConditionFailedError::*;
        match self {
            SeqNumMismatch {
                assigned_seq_num, ..
            } => ..*assigned_seq_num,
            FencingTokenMismatch { applied_point, .. } => *applied_point,
        }
    }
}

impl From<StreamerError> for AppendError {
    fn from(e: StreamerError) -> Self {
        match e {
            StreamerError::StreamNotFound(e) => Self::StreamNotFound(e),
            StreamerError::Storage(e) => Self::Storage(e),
            StreamerError::StreamDeletionPending(e) => Self::StreamDeletionPending(e),
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ReadError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    TransactionConflict(#[from] TransactionConflictError),
    #[error(transparent)]
    StreamerMissingInActionError(#[from] StreamerMissingInActionError),
    #[error(transparent)]
    BasinNotFound(#[from] BasinNotFoundError),
    #[error(transparent)]
    StreamNotFound(#[from] StreamNotFoundError),
    #[error(transparent)]
    BasinDeletionPending(#[from] BasinDeletionPendingError),
    #[error(transparent)]
    StreamDeletionPending(#[from] StreamDeletionPendingError),
    #[error(transparent)]
    Unwritten(#[from] UnwrittenError),
}

impl From<StreamerError> for ReadError {
    fn from(e: StreamerError) -> Self {
        match e {
            StreamerError::StreamNotFound(e) => Self::StreamNotFound(e),
            StreamerError::Storage(e) => Self::Storage(e),
            StreamerError::StreamDeletionPending(e) => Self::StreamDeletionPending(e),
        }
    }
}

impl From<kv::DeserializationError> for ReadError {
    fn from(e: kv::DeserializationError) -> Self {
        Self::Storage(e.into())
    }
}

impl From<slatedb::Error> for ReadError {
    fn from(e: slatedb::Error) -> Self {
        Self::Storage(e.into())
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ListStreamsError {
    #[error(transparent)]
    Storage(#[from] StorageError),
}

impl From<slatedb::Error> for ListStreamsError {
    fn from(e: slatedb::Error) -> Self {
        Self::Storage(e.into())
    }
}

impl From<kv::DeserializationError> for ListStreamsError {
    fn from(e: kv::DeserializationError) -> Self {
        Self::Storage(e.into())
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum CreateStreamError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    TransactionConflict(#[from] TransactionConflictError),
    #[error(transparent)]
    BasinNotFound(#[from] BasinNotFoundError),
    #[error(transparent)]
    BasinDeletionPending(#[from] BasinDeletionPendingError),
    #[error(transparent)]
    StreamAlreadyExists(#[from] StreamAlreadyExistsError),
    #[error(transparent)]
    StreamDeletionPending(#[from] StreamDeletionPendingError),
}

impl From<slatedb::Error> for CreateStreamError {
    fn from(err: slatedb::Error) -> Self {
        if err.kind() == slatedb::ErrorKind::Transaction {
            Self::TransactionConflict(TransactionConflictError)
        } else {
            Self::Storage(err.into())
        }
    }
}

impl From<GetBasinConfigError> for CreateStreamError {
    fn from(err: GetBasinConfigError) -> Self {
        match err {
            GetBasinConfigError::Storage(e) => Self::Storage(e),
            GetBasinConfigError::BasinNotFound(e) => Self::BasinNotFound(e),
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum GetStreamConfigError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    StreamNotFound(#[from] StreamNotFoundError),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DeleteStreamError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    StreamerMissingInActionError(#[from] StreamerMissingInActionError),
    #[error(transparent)]
    RequestDroppedError(#[from] RequestDroppedError),
    #[error(transparent)]
    StreamNotFound(#[from] StreamNotFoundError),
}

impl From<slatedb::Error> for DeleteStreamError {
    fn from(err: slatedb::Error) -> Self {
        Self::Storage(err.into())
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum BasinDeletionError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    DeleteStream(#[from] DeleteStreamError),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ListBasinsError {
    #[error(transparent)]
    Storage(#[from] StorageError),
}

impl From<slatedb::Error> for ListBasinsError {
    fn from(err: slatedb::Error) -> Self {
        Self::Storage(err.into())
    }
}

impl From<kv::DeserializationError> for ListBasinsError {
    fn from(e: kv::DeserializationError) -> Self {
        Self::Storage(e.into())
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum CreateBasinError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    BasinAlreadyExists(#[from] BasinAlreadyExistsError),
    #[error(transparent)]
    BasinDeletionPending(#[from] BasinDeletionPendingError),
}

impl From<slatedb::Error> for CreateBasinError {
    fn from(err: slatedb::Error) -> Self {
        Self::Storage(err.into())
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum GetBasinConfigError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    BasinNotFound(#[from] BasinNotFoundError),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ReconfigureBasinError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    TransactionConflict(#[from] TransactionConflictError),
    #[error(transparent)]
    BasinNotFound(#[from] BasinNotFoundError),
    #[error(transparent)]
    BasinDeletionPending(#[from] BasinDeletionPendingError),
}

impl From<slatedb::Error> for ReconfigureBasinError {
    fn from(err: slatedb::Error) -> Self {
        if err.kind() == slatedb::ErrorKind::Transaction {
            Self::TransactionConflict(TransactionConflictError)
        } else {
            Self::Storage(err.into())
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ReconfigureStreamError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    TransactionConflict(#[from] TransactionConflictError),
    #[error(transparent)]
    StreamNotFound(#[from] StreamNotFoundError),
    #[error(transparent)]
    StreamDeletionPending(#[from] StreamDeletionPendingError),
}

impl From<slatedb::Error> for ReconfigureStreamError {
    fn from(err: slatedb::Error) -> Self {
        if err.kind() == slatedb::ErrorKind::Transaction {
            Self::TransactionConflict(TransactionConflictError)
        } else {
            Self::Storage(err.into())
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DeleteBasinError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    BasinNotFound(#[from] BasinNotFoundError),
}

impl From<slatedb::Error> for DeleteBasinError {
    fn from(err: slatedb::Error) -> Self {
        Self::Storage(err.into())
    }
}
