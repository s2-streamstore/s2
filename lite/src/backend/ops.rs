use bytes::Bytes;
use futures::stream::BoxStream;
use s2_common::{
    record::{FencingToken, SeqNum},
    types::{
        basin::{BasinInfo, BasinName, BasinScope, ListBasinsRequest},
        config::{BasinConfig, BasinReconfiguration, OptionalStreamConfig, StreamReconfiguration},
        resources::{CreateMode, Page},
        stream::{
            AppendAck, AppendInput, ListStreamsRequest, ReadBatch, ReadEnd, ReadStart, StreamInfo,
            StreamName, StreamPosition,
        },
    },
};

// TODO Create/Reconfigure/Delete Ok() variants
// TODO spec out all the errors properly

#[derive(Debug, Clone, thiserror::Error)]
pub enum CheckTailError {
    #[error("Stream not found")]
    StreamNotFound,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum AppendError {
    #[error("Stream not found")]
    StreamNotFound,
    #[error("Sequence number mismatch: expected {expected}, actual {actual}")]
    SeqNumMismatch { expected: SeqNum, actual: SeqNum },
    #[error("Fencing token mismatch: expected {expected}, actual {actual}")]
    FencingTokenMismatch {
        expected: FencingToken,
        actual: FencingToken,
    },
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ReadError {
    #[error("Stream not found")]
    StreamNotFound,
}

pub trait DataOps {
    async fn check_tail(
        &self,
        basin: BasinName,
        stream: StreamName,
    ) -> Result<StreamPosition, CheckTailError>;

    async fn read(
        &self,
        basin: BasinName,
        stream: StreamName,
        start: ReadStart,
        end: ReadEnd,
    ) -> Result<BoxStream<'static, Result<ReadBatch, ReadError>>, ReadError>;

    async fn append(
        &self,
        basin: BasinName,
        stream: StreamName,
        input: AppendInput,
    ) -> Result<AppendAck, AppendError>;

    async fn append_session(
        &self,
        basin: BasinName,
        stream: StreamName,
        requests: BoxStream<'static, AppendInput>,
    ) -> Result<BoxStream<'static, Result<AppendAck, AppendError>>, AppendError>;
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ListStreamsError {}

#[derive(Debug, Clone, thiserror::Error)]
pub enum CreateStreamError {}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ReconfigureStreamError {}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DeleteStreamError {}

pub trait StreamOps {
    async fn list_streams(
        &self,
        basin: BasinName,
        request: ListStreamsRequest,
    ) -> Result<Page<StreamInfo>, ListStreamsError>;

    async fn create_stream(
        &self,
        basin: BasinName,
        stream: StreamName,
        config: OptionalStreamConfig,
        mode: CreateMode,
        idempotence_key: Option<Bytes>,
    ) -> Result<(), CreateStreamError>;

    async fn reconfigure_stream(
        &self,
        basin: BasinName,
        stream: StreamName,
        config: StreamReconfiguration,
    ) -> Result<(), ReconfigureStreamError>;

    async fn delete_stream(
        &self,
        basin: BasinName,
        stream: StreamName,
    ) -> Result<(), DeleteStreamError>;
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ListBasinsError {}

#[derive(Debug, Clone, thiserror::Error)]
pub enum CreateBasinError {}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ReconfigureBasinError {}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DeleteBasinError {}

pub trait BasinOps {
    async fn list_basins(
        &self,
        request: ListBasinsRequest,
    ) -> Result<Page<BasinInfo>, ListBasinsError>;

    async fn create_basin(
        &self,
        basin: BasinName,
        scope: BasinScope,
        config: BasinConfig,
        mode: CreateMode,
        idempotence_key: Option<Bytes>,
    ) -> Result<(), CreateBasinError>;

    async fn reconfigure_basin(
        &self,
        basin: BasinName,
        config: BasinReconfiguration,
    ) -> Result<(), ReconfigureBasinError>;

    async fn delete_basin(&self, basin: BasinName) -> Result<(), DeleteBasinError>;
}
