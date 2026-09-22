//! Transactional scheduling shared by configuration changes, trims, and migration.
//! Appends only postpone eligibility and do not need to update the schedule.

use std::time::Duration;

use slatedb::DbTransaction;

use super::{
    error::StorageError,
    kv::{
        self,
        stream_doe_state::{Check, State},
        timestamp::TimestampSecs,
    },
    store::db_txn_get,
};
use crate::stream_id::StreamId;

/// Bound polling on active streams, while allowing known expirations to defer
/// checks much farther into the future.
pub(super) const RETRY_INTERVAL: Duration = Duration::from_secs(600);

pub(super) async fn state(
    txn: &DbTransaction,
    stream_id: StreamId,
) -> Result<Option<State>, StorageError> {
    db_txn_get(
        txn,
        kv::stream_doe_state::ser_key(stream_id),
        kv::stream_doe_state::deser_value,
    )
    .await
}

/// Request a check without adding a second ticket. Even when keeping an earlier
/// ticket, rewrite the state to advance its commit sequence: an in-flight worker
/// must not park or postpone the stream after a concurrent trim/configuration wake.
pub(super) async fn schedule(
    txn: &DbTransaction,
    stream_id: StreamId,
    at: TimestampSecs,
) -> Result<(), StorageError> {
    let previous = state(txn, stream_id).await?;
    let next = match previous {
        Some(State::Scheduled(check)) if check.at <= at => State::Scheduled(check),
        _ => State::Scheduled(Check {
            at,
            id: rand::random(),
        }),
    };
    replace(txn, stream_id, previous, Some(next))?;
    Ok(())
}

pub(super) async fn clear(txn: &DbTransaction, stream_id: StreamId) -> Result<(), StorageError> {
    let previous = state(txn, stream_id).await?;
    replace(txn, stream_id, previous, None)?;
    Ok(())
}

/// The caller must have read the state in this serializable transaction.
pub(super) fn replace(
    txn: &DbTransaction,
    stream_id: StreamId,
    previous: Option<State>,
    next: Option<State>,
) -> Result<(), slatedb::Error> {
    if previous != next {
        if let Some(State::Scheduled(check)) = previous {
            txn.delete(kv::stream_doe_check::ser_key(stream_id, check))?;
        }
        if let Some(State::Scheduled(check)) = next {
            txn.put(kv::stream_doe_check::ser_key(stream_id, check), [])?;
        }
    }
    let key = kv::stream_doe_state::ser_key(stream_id);
    match next {
        Some(next) => txn.put(key, kv::stream_doe_state::ser_value(next))?,
        None if previous.is_some() => txn.delete(key)?,
        None => (),
    }
    Ok(())
}
