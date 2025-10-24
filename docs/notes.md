s2-cloud: scale horizontally
s2-lite: scale vertically

Pluggable backends, to start:
- InMemory { embedded }
    Data tied to process lifetime
- SlateDB  { embedded, diskless, durable, bottomless }
    Configured with:
      an object storage URI

Backend responsibilities:
- fencing zombies

Following live updates is easy because it'd be a single node that is aware of what's being written on a stream, so always just publish to a tailer broadcast channel.

Basins supported via `S2-Basin` header.

Q: what do we do if a basin is lost
  Streams, well, it's the nature of the beast

Granular access tokens supported by storing them in the same DB.
  Background tasks may be required by certain backends, while others have built-in TTL support.

/records
  append # (basin, stream)
  read # (basin, stream)
  check_tail # (basin, stream)
/streams
  list_streams  # (basin)
  create_stream  # (basin, stream)
  get_stream_config # (basin, stream)
  reconfigure_stream # (basin, stream)
  delete_stream # (basin, stream)

/basins
  list_basins # ()
  create_basin # (basin)
  get_basin_config # (basin)
  reconfigure_basin # (basin)
  delete_basin # (basin)

/access-tokens # not initially supported
  list_access_tokens
  issue_access_token
  revoke_access_token

/metrics # not initially supported
  get_account_metrics
  get_basin_metrics
  get_stream_metrics
