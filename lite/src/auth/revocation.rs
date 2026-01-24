//! Token revocation storage using SlateDB.
//!
//! Revocation IDs are stored with a dedicated prefix to avoid conflicts
//! with the main KV store (which uses numeric ordinals 1-8).

use slatedb::config::{ReadOptions, ScanOptions};

/// Prefix for revocation keys.
/// Starts with 'r' (114) which won't conflict with main KV ordinals (1-8).
const REVOCATION_PREFIX: &[u8] = b"revocations/";

/// Check if any of the revocation IDs are revoked.
///
/// Returns `true` if any ID in the list has been revoked.
pub async fn is_revoked(
    db: &slatedb::Db,
    revocation_ids: &[Vec<u8>],
) -> Result<bool, RevocationError> {
    static READ_OPTS: ReadOptions = ReadOptions {
        durability_filter: slatedb::config::DurabilityLevel::Remote,
        dirty: false,
        cache_blocks: true,
    };

    for id in revocation_ids {
        let key = revocation_key(id);
        if db.get_with_options(&key, &READ_OPTS).await?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Revoke a token by adding its revocation ID to the store.
pub async fn revoke(db: &slatedb::Db, revocation_id: &[u8]) -> Result<(), RevocationError> {
    let key = revocation_key(revocation_id);
    // Empty value - we only need key existence
    db.put(&key, &[]).await?;
    Ok(())
}

/// List all revoked token IDs (hex-encoded).
pub async fn list_revocations(db: &slatedb::Db) -> Result<Vec<String>, RevocationError> {
    static SCAN_OPTS: ScanOptions = ScanOptions {
        durability_filter: slatedb::config::DurabilityLevel::Remote,
        dirty: false,
        read_ahead_bytes: 4096,
        cache_blocks: true,
        max_fetch_tasks: 1,
    };

    let mut ids = Vec::new();

    // Scan from prefix to end of prefix range
    let start = REVOCATION_PREFIX.to_vec();
    let mut end = start.clone();
    // Increment last byte to get exclusive end (revocations0 > revocations/)
    if let Some(last) = end.last_mut() {
        *last += 1;
    }

    let mut iter = db.scan_with_options(start..end, &SCAN_OPTS).await?;
    while let Some(kv) = iter.next().await? {
        // Extract the hex-encoded ID portion after prefix
        if kv.key.starts_with(REVOCATION_PREFIX) {
            let hex_id = &kv.key[REVOCATION_PREFIX.len()..];
            if let Ok(s) = std::str::from_utf8(hex_id) {
                ids.push(s.to_string());
            }
        }
    }

    Ok(ids)
}

/// Build a revocation key from a revocation ID.
/// Format: "revocations/<hex-encoded-id>"
fn revocation_key(id: &[u8]) -> Vec<u8> {
    let mut key = REVOCATION_PREFIX.to_vec();
    key.extend_from_slice(hex::encode(id).as_bytes());
    key
}

#[derive(Debug, thiserror::Error)]
pub enum RevocationError {
    #[error("storage error: {0}")]
    Storage(#[from] slatedb::Error),
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use slatedb::object_store::memory::InMemory;

    use super::*;

    async fn test_db() -> slatedb::Db {
        let object_store = Arc::new(InMemory::new());
        slatedb::Db::builder("/test", object_store)
            .build()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_revoke_and_check() {
        let db = test_db().await;

        let id1 = vec![1, 2, 3, 4];
        let id2 = vec![5, 6, 7, 8];

        // Initially not revoked
        assert!(!is_revoked(&db, &[id1.clone()]).await.unwrap());
        assert!(!is_revoked(&db, &[id2.clone()]).await.unwrap());

        // Revoke id1
        revoke(&db, &id1).await.unwrap();

        // Now id1 is revoked, id2 is not
        assert!(is_revoked(&db, &[id1.clone()]).await.unwrap());
        assert!(!is_revoked(&db, &[id2.clone()]).await.unwrap());

        // Check with multiple IDs - should be true if any is revoked
        assert!(is_revoked(&db, &[id1.clone(), id2.clone()]).await.unwrap());
    }

    #[tokio::test]
    async fn test_list_revocations() {
        let db = test_db().await;

        let id1 = vec![1, 2, 3, 4];
        let id2 = vec![5, 6, 7, 8];

        // Initially empty
        let list = list_revocations(&db).await.unwrap();
        assert!(list.is_empty());

        // Add some revocations
        revoke(&db, &id1).await.unwrap();
        revoke(&db, &id2).await.unwrap();

        // List should contain both (hex-encoded)
        let list = list_revocations(&db).await.unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.contains(&hex::encode(&id1)));
        assert!(list.contains(&hex::encode(&id2)));
    }

    #[tokio::test]
    async fn test_empty_revocation_list() {
        let db = test_db().await;
        // Check with empty list returns false
        assert!(!is_revoked(&db, &[]).await.unwrap());
    }
}
