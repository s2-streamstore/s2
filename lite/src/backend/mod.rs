pub mod inmem;

// TODO this should be feature-gated
pub mod slatedb;

use async_trait::async_trait;
use bytes::Bytes;
use compact_str::CompactString;
use futures::stream::BoxStream;
use s2_common::types::{
    basin::{BasinInfo, BasinName, BasinScope, ListBasinsRequest},
    config::{BasinConfig, BasinReconfiguration, OptionalStreamConfig, StreamReconfiguration},
    resources::{CreateMode, Page},
    stream::{
        AppendAck, AppendInput, ListStreamsRequest, ReadBatch, ReadRequest, StreamInfo, StreamName,
        StreamPosition,
    },
};

pub struct InternalError {
    pub code: CompactString,
    pub message: CompactString,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ListBasinsError {}

#[derive(Debug, Clone, thiserror::Error)]
pub enum CreateBasinError {}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ReconfigureBasinError {}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DeleteBasinError {}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ListStreamsError {}

#[derive(Debug, Clone, thiserror::Error)]
pub enum CreateStreamError {}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ReconfigureStreamError {}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DeleteStreamError {}

#[derive(Debug, Clone, thiserror::Error)]
pub enum CheckTailError {}

#[derive(Debug, Clone, thiserror::Error)]
pub enum AppendError {}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ReadError {}

// TODO spec out all the errors properly
// TODO Create/Reconfigure/Delete Ok() variants
#[async_trait]
pub trait Backend {
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

    async fn check_tail(
        &self,
        basin: BasinName,
        stream: StreamName,
    ) -> Result<StreamPosition, CheckTailError>;

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

    async fn read(
        &self,
        basin: BasinName,
        stream: StreamName,
        request: ReadRequest,
    ) -> Result<BoxStream<'static, Result<ReadBatch, ReadError>>, ReadError>;
}
