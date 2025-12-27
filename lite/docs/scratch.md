Q: does `{basin}.whatever` work in general or do we need to rely on `S2-Basin` header

Explicit trim:
- STP key used for trawling, deleted when processed.
- Background task (process-level) processes trims concurrently by deleting data.
- Stream deletion: set SM deleted_at set + explicit trim to SeqNum::MAX, when that is complete, delete all stream-level keys.
  - Stream stays in tombstoned state (SM's deleted_at field) while pending.

Delete-on-empty:
- Probably some kinda deadline key that is trawled by a process-level background task, but only set it for first batch in N minutes (in-mem state).

Creation:
Transactionally write SM if it does not already exist

Reconfiguration:
SM write (transactionally if it is a patch)

```
# Granular access tokens will be supported by storing them in the same DB.
AccessTokenOps /access-tokens
  list_access_tokens # (id)
  issue_access_token # (id)
  revoke_access_token # (id)

# Not supported
MetricOps /metrics
  get_account_metrics # ()
  get_basin_metrics # (basin)
  get_stream_metrics # (basin, stream)
```
