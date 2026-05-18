use std::pin::Pin;

use futures::Stream;
use s2_common::{
    encryption::EncryptionSpec,
    record::StreamPosition,
    types::{
        basin::BasinName,
        stream::{AppendAck, AppendInput, StreamName},
    },
};
use s2_lite::backend::{
    Backend,
    error::{AppendError, CheckTailError},
};

mod read;
mod setup;

pub use read::*;
pub use setup::*;

pub async fn append(
    backend: &Backend,
    basin: BasinName,
    stream: StreamName,
    input: AppendInput,
    encryption: Option<&EncryptionSpec>,
) -> Result<AppendAck, AppendError> {
    backend
        .open_for_append(
            &basin,
            &stream,
            encryption.and_then(encryption_key_for_spec),
        )
        .await?
        .append(input)
        .await
}

pub async fn append_session<S>(
    backend: &Backend,
    basin: BasinName,
    stream: StreamName,
    encryption: Option<&EncryptionSpec>,
    inputs: S,
) -> Result<Pin<Box<dyn Stream<Item = Result<AppendAck, AppendError>>>>, AppendError>
where
    S: Stream<Item = AppendInput> + 'static,
{
    let session = backend
        .open_for_append(
            &basin,
            &stream,
            encryption.and_then(encryption_key_for_spec),
        )
        .await?
        .append_session(inputs);
    Ok(Box::pin(session))
}

pub async fn check_tail(
    backend: &Backend,
    basin: BasinName,
    stream: StreamName,
) -> Result<StreamPosition, CheckTailError> {
    backend
        .open_for_check_tail(&basin, &stream)
        .await?
        .check_tail()
        .await
}
