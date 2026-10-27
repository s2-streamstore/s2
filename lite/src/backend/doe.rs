//! Transactional scheduling shared by configuration changes, trims, and migration.
//! Appends only postpone eligibility and do not need to update the schedule.

use std::time::Duration;

use slatedb::DbTransaction;

use super::{error::StorageError, kv, store::db_txn_get, timestamp::TimestampSecs};
use crate::stream_id::StreamId;

/// Bound polling on active streams, while allowing known expirations to defer
/// checks much farther into the future.
pub(super) const RETRY_INTERVAL: Duration = Duration::from_secs(600);

pub(super) async fn state(
    txn: &DbTransaction,
    stream_id: StreamId,
) -> Result<Option<kv::stream_doe_state::State>, StorageError> {
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
    schedule_observed(txn, stream_id, previous, at)?;
    Ok(())
}

/// Most trims need only the state row. A full trim also restores scheduling for
/// older enabled streams whose last legacy deadline was already consumed.
pub(super) async fn wake_after_trim(
    txn: &DbTransaction,
    stream_id: StreamId,
    has_remaining_records: bool,
) -> Result<(), StorageError> {
    let previous = state(txn, stream_id).await?;
    if previous.is_none() {
        if has_remaining_records {
            return Ok(());
        }
        let Some((basin, stream)) = db_txn_get(
            txn,
            kv::stream_id_mapping::ser_key(stream_id),
            kv::stream_id_mapping::deser_value,
        )
        .await?
        else {
            return Ok(());
        };
        let Some(meta) = db_txn_get(
            txn,
            kv::stream_meta::ser_key(&basin, &stream),
            kv::stream_meta::deser_value,
        )
        .await?
        else {
            return Ok(());
        };
        if meta.deleted_at.is_some() || meta.config.delete_on_empty.min_age().is_none() {
            return Ok(());
        }
    }
    schedule_observed(txn, stream_id, previous, TimestampSecs::now())?;
    Ok(())
}

fn schedule_observed(
    txn: &DbTransaction,
    stream_id: StreamId,
    previous: Option<kv::stream_doe_state::State>,
    at: TimestampSecs,
) -> Result<(), slatedb::Error> {
    let next = match previous {
        Some(kv::stream_doe_state::State::Scheduled(check)) if check.at <= at => {
            kv::stream_doe_state::State::Scheduled(check)
        }
        _ => kv::stream_doe_state::State::Scheduled(kv::stream_doe_state::Check {
            at,
            id: rand::random(),
        }),
    };
    replace(txn, stream_id, previous, Some(next))
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
    previous: Option<kv::stream_doe_state::State>,
    next: Option<kv::stream_doe_state::State>,
) -> Result<(), slatedb::Error> {
    if previous != next {
        if let Some(kv::stream_doe_state::State::Scheduled(check)) = previous {
            txn.delete(kv::stream_doe_check::ser_key(stream_id, check))?;
        }
        if let Some(kv::stream_doe_state::State::Scheduled(check)) = next {
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
