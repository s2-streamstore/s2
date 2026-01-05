# TODO

## bgtasks

### Explicit trim

- STP key used for trawling, deleted when processed
- bgtask processes trims concurrently by deleting data
- Stream deletion: explicit trim to SeqNum::MAX, which when complete deletes *all* stream-level keys including metadata
  - Stream stays in tombstoned state while pending.
  - N.B. Stream meta `deleted_at` is not set transactionally with STP, but as a subsequent step in initiating deletion, so may be temporarily out of sync

### Basin deletion

- BDP key used for trawling for basin deletions
- BDP value used for keeping track of streams to be deleted for each basin as it is a `start_after` cursor for listing streams
- bgtask initiates stream deletion for every stream in the basin, completes and deletes *all* basin-level keys when all streams have been deleted

### Delete-on-empty

TODO. Probably some kinda deadline key that is trawled by a process-level bgtask, only set it for first batch in N minutes (in-mem state).
