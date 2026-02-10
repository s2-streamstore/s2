use axum::{
    extract::rejection::{JsonRejection, PathRejection, QueryRejection},
    response::{IntoResponse, Response},
};
use s2_api::{
    data::extract::ProtoRejection,
    v1::{
        self as v1t,
        error::{ErrorCode, ErrorInfo, ErrorResponse, StandardError},
        stream::{AppendInputStreamError, extract::AppendRequestRejection, s2s},
    },
};
use s2_common::{http::extract::HeaderRejection, types::ValidationError};

use crate::backend::error::{
    AppendConditionFailedError, AppendError, CheckTailError, CreateBasinError, CreateStreamError,
    DeleteBasinError, DeleteStreamError, GetBasinConfigError, GetStreamConfigError,
    ListBasinsError, ListStreamsError, ReadError, ReconfigureBasinError, ReconfigureStreamError,
};

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error(transparent)]
    HeaderRejection(#[from] HeaderRejection),
    #[error(transparent)]
    PathRejection(#[from] PathRejection),
    #[error(transparent)]
    QueryRejection(#[from] QueryRejection),
    #[error(transparent)]
    JsonRejection(#[from] JsonRejection),
    #[error(transparent)]
    ProtoRejection(#[from] ProtoRejection),
    #[error(transparent)]
    AppendInputStream(#[from] AppendInputStreamError),
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    ListBasins(#[from] ListBasinsError),
    #[error(transparent)]
    CreateBasin(#[from] CreateBasinError),
    #[error(transparent)]
    GetBasinConfig(#[from] GetBasinConfigError),
    #[error(transparent)]
    DeleteBasin(#[from] DeleteBasinError),
    #[error(transparent)]
    ReconfigureBasin(#[from] ReconfigureBasinError),
    #[error(transparent)]
    ListStreams(#[from] ListStreamsError),
    #[error(transparent)]
    CreateStream(#[from] CreateStreamError),
    #[error(transparent)]
    GetStreamConfig(#[from] GetStreamConfigError),
    #[error(transparent)]
    DeleteStream(#[from] DeleteStreamError),
    #[error(transparent)]
    ReconfigureStream(#[from] ReconfigureStreamError),
    #[error(transparent)]
    CheckTail(#[from] CheckTailError),
    #[error(transparent)]
    Append(#[from] AppendError),
    #[error(transparent)]
    Read(#[from] ReadError),
    #[error("Not implemented")]
    NotImplemented,
}

impl From<AppendRequestRejection> for ServiceError {
    fn from(value: AppendRequestRejection) -> Self {
        match value {
            AppendRequestRejection::HeaderRejection(e) => ServiceError::from(e),
            AppendRequestRejection::JsonRejection(e) => ServiceError::from(e),
            AppendRequestRejection::ProtoRejection(e) => ServiceError::from(e),
            AppendRequestRejection::Validation(e) => ServiceError::Validation(e),
        }
    }
}

impl ServiceError {
    pub fn to_response(&self) -> ErrorResponse {
        match self {
            ServiceError::HeaderRejection(e) => standard(ErrorCode::BadHeader, e.to_string()),
            ServiceError::PathRejection(e) => standard(ErrorCode::BadPath, e.body_text()),
            ServiceError::QueryRejection(e) => standard(ErrorCode::BadQuery, e.body_text()),
            ServiceError::JsonRejection(e) => standard(ErrorCode::BadJson, e.body_text()),
            ServiceError::ProtoRejection(e) => standard(ErrorCode::BadProto, e.to_string()),
            ServiceError::AppendInputStream(e) => match e {
                AppendInputStreamError::FrameDecode(e) => {
                    standard(ErrorCode::BadFrame, e.to_string())
                }
                AppendInputStreamError::Validation(e) => {
                    standard(ErrorCode::Invalid, e.to_string())
                }
            },
            ServiceError::Validation(e) => standard(ErrorCode::Invalid, e.to_string()),
            ServiceError::ListBasins(e) => match e {
                ListBasinsError::Storage(e) => standard(ErrorCode::Storage, e.to_string()),
            },
            ServiceError::CreateBasin(e) => match e {
                CreateBasinError::Storage(e) => standard(ErrorCode::Storage, e.to_string()),
                CreateBasinError::BasinAlreadyExists(e) => {
                    standard(ErrorCode::ResourceAlreadyExists, e.to_string())
                }
                CreateBasinError::BasinDeletionPending(e) => {
                    standard(ErrorCode::BasinDeletionPending, e.to_string())
                }
            },
            ServiceError::GetBasinConfig(e) => match e {
                GetBasinConfigError::Storage(e) => standard(ErrorCode::Storage, e.to_string()),
                GetBasinConfigError::BasinNotFound(e) => {
                    standard(ErrorCode::BasinNotFound, e.to_string())
                }
            },
            ServiceError::DeleteBasin(e) => match e {
                DeleteBasinError::Storage(e) => standard(ErrorCode::Storage, e.to_string()),
                DeleteBasinError::BasinNotFound(e) => {
                    standard(ErrorCode::BasinNotFound, e.to_string())
                }
            },
            ServiceError::ReconfigureBasin(e) => match e {
                ReconfigureBasinError::Storage(e) => standard(ErrorCode::Storage, e.to_string()),
                ReconfigureBasinError::TransactionConflict(e) => {
                    standard(ErrorCode::TransactionConflict, e.to_string())
                }
                ReconfigureBasinError::BasinNotFound(e) => {
                    standard(ErrorCode::BasinNotFound, e.to_string())
                }
                ReconfigureBasinError::BasinDeletionPending(e) => {
                    standard(ErrorCode::BasinDeletionPending, e.to_string())
                }
            },
            ServiceError::ListStreams(e) => match e {
                ListStreamsError::Storage(e) => standard(ErrorCode::Storage, e.to_string()),
            },
            ServiceError::CreateStream(e) => match e {
                CreateStreamError::Storage(e) => standard(ErrorCode::Storage, e.to_string()),
                CreateStreamError::TransactionConflict(e) => {
                    standard(ErrorCode::TransactionConflict, e.to_string())
                }
                CreateStreamError::BasinNotFound(e) => {
                    standard(ErrorCode::BasinNotFound, e.to_string())
                }
                CreateStreamError::BasinDeletionPending(e) => {
                    standard(ErrorCode::BasinDeletionPending, e.to_string())
                }
                CreateStreamError::StreamAlreadyExists(e) => {
                    standard(ErrorCode::ResourceAlreadyExists, e.to_string())
                }
                CreateStreamError::StreamDeletionPending(e) => {
                    standard(ErrorCode::StreamDeletionPending, e.to_string())
                }
            },
            ServiceError::GetStreamConfig(e) => match e {
                GetStreamConfigError::Storage(e) => standard(ErrorCode::Storage, e.to_string()),
                GetStreamConfigError::StreamNotFound(e) => {
                    standard(ErrorCode::StreamNotFound, e.to_string())
                }
                GetStreamConfigError::StreamDeletionPending(e) => {
                    standard(ErrorCode::StreamDeletionPending, e.to_string())
                }
            },
            ServiceError::DeleteStream(e) => match e {
                DeleteStreamError::Storage(e) => standard(ErrorCode::Storage, e.to_string()),
                DeleteStreamError::StreamerMissingInActionError(e) => {
                    standard(ErrorCode::Unavailable, e.to_string())
                }
                DeleteStreamError::RequestDroppedError(e) => {
                    // Unavailable error code promised to be side-effect free,
                    // AppendType::Terminal may have become durable prior to drop.
                    standard(ErrorCode::Other, e.to_string())
                }
                DeleteStreamError::StreamNotFound(e) => {
                    standard(ErrorCode::StreamNotFound, e.to_string())
                }
            },
            ServiceError::ReconfigureStream(e) => match e {
                ReconfigureStreamError::Storage(e) => standard(ErrorCode::Storage, e.to_string()),
                ReconfigureStreamError::TransactionConflict(e) => {
                    standard(ErrorCode::TransactionConflict, e.to_string())
                }
                ReconfigureStreamError::StreamNotFound(e) => {
                    standard(ErrorCode::StreamNotFound, e.to_string())
                }
                ReconfigureStreamError::StreamDeletionPending(e) => {
                    standard(ErrorCode::StreamDeletionPending, e.to_string())
                }
            },
            ServiceError::CheckTail(e) => match e {
                CheckTailError::Storage(e) => standard(ErrorCode::Storage, e.to_string()),
                CheckTailError::TransactionConflict(e) => {
                    standard(ErrorCode::TransactionConflict, e.to_string())
                }
                CheckTailError::StreamerMissingInActionError(_) => {
                    standard(ErrorCode::Unavailable, e.to_string())
                }
                CheckTailError::BasinNotFound(e) => {
                    standard(ErrorCode::BasinNotFound, e.to_string())
                }
                CheckTailError::StreamNotFound(e) => {
                    standard(ErrorCode::StreamNotFound, e.to_string())
                }
                CheckTailError::BasinDeletionPending(e) => {
                    standard(ErrorCode::BasinDeletionPending, e.to_string())
                }
                CheckTailError::StreamDeletionPending(e) => {
                    standard(ErrorCode::StreamDeletionPending, e.to_string())
                }
            },
            ServiceError::Append(e) => match e {
                AppendError::Storage(e) => standard(ErrorCode::Storage, e.to_string()),
                AppendError::TransactionConflict(e) => {
                    standard(ErrorCode::TransactionConflict, e.to_string())
                }
                AppendError::StreamerMissingInActionError(e) => {
                    standard(ErrorCode::Unavailable, e.to_string())
                }
                AppendError::RequestDroppedError(e) => {
                    // Unavailable error code promised to be side-effect free,
                    // AppendType::Regular may have become durable prior to drop.
                    standard(ErrorCode::Other, e.to_string())
                }
                AppendError::BasinNotFound(e) => standard(ErrorCode::BasinNotFound, e.to_string()),
                AppendError::StreamNotFound(e) => {
                    standard(ErrorCode::StreamNotFound, e.to_string())
                }
                AppendError::BasinDeletionPending(e) => {
                    standard(ErrorCode::BasinDeletionPending, e.to_string())
                }
                AppendError::StreamDeletionPending(e) => {
                    standard(ErrorCode::StreamDeletionPending, e.to_string())
                }
                AppendError::ConditionFailed(e) => ErrorResponse::AppendConditionFailed(match e {
                    AppendConditionFailedError::FencingTokenMismatch { actual, .. } => {
                        v1t::stream::AppendConditionFailed::FencingTokenMismatch(actual.clone())
                    }
                    AppendConditionFailedError::SeqNumMismatch {
                        assigned_seq_num, ..
                    } => v1t::stream::AppendConditionFailed::SeqNumMismatch(*assigned_seq_num),
                }),
                AppendError::TimestampMissing(e) => standard(ErrorCode::Invalid, e.to_string()),
            },
            ServiceError::Read(e) => match e {
                ReadError::Storage(e) => standard(ErrorCode::Storage, e.to_string()),
                ReadError::TransactionConflict(e) => {
                    standard(ErrorCode::TransactionConflict, e.to_string())
                }
                ReadError::StreamerMissingInActionError(_) => {
                    standard(ErrorCode::Unavailable, e.to_string())
                }
                ReadError::BasinNotFound(e) => standard(ErrorCode::BasinNotFound, e.to_string()),
                ReadError::StreamNotFound(e) => standard(ErrorCode::StreamNotFound, e.to_string()),
                ReadError::BasinDeletionPending(e) => {
                    standard(ErrorCode::BasinDeletionPending, e.to_string())
                }
                ReadError::StreamDeletionPending(e) => {
                    standard(ErrorCode::StreamDeletionPending, e.to_string())
                }
                ReadError::Unwritten(tail) => ErrorResponse::Unwritten(v1t::stream::TailResponse {
                    tail: tail.0.into(),
                }),
            },
            ServiceError::NotImplemented => {
                standard(ErrorCode::PermissionDenied, "Not implemented".to_string())
            }
        }
    }
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        self.to_response().into_response()
    }
}

impl From<ServiceError> for s2s::TerminalMessage {
    fn from(value: ServiceError) -> Self {
        let (status, body) = value.to_response().to_parts();
        s2s::TerminalMessage {
            status: status.as_u16(),
            body,
        }
    }
}

fn standard(code: ErrorCode, message: impl Into<String>) -> ErrorResponse {
    ErrorResponse::Standard(StandardError {
        status: code.status(),
        info: ErrorInfo {
            code: code.into(),
            message: message.into(),
        },
    })
}
