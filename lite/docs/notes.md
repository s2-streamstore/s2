s2-cloud: scale horizontally
s2-lite: scale vertically, slatedb

Following live updates is easy because it'd be a single node that is aware of what's being written on a stream, so always just publish to a tailer broadcast channel.

TBD: Task per stream and communicate over a channel, or shared state?

Basins supported via `S2-Basin` header. If missing, `default` basin used.

Granular access tokens supported by storing them in the same DB.

## Data model

`StreamID = Blake3(BasinName, StreamName)`

1 byte prefix for each key identifying the type of data:
```
BC  Basin config              upd   per-basin
SC  Stream config             upd   per-stream
SD  Stream data               imm   per-record
ST  Stream timestamp          imm   per-record
SP  Stream tail position      upd   per-stream
```

Mappings
```
BC  "{BasinName}"                 ->    BasinConfig
SC  "{BasinName}#{StreamName}"    ->    StreamConfig
SD  StreamID.SeqNum               ->    Record
ST  StreamID.Timestamp            ->    SeqNum
SP  StreamID                      ->    SeqNum.Timestamp
```

Appends: Every AppendInput maps to a WriteBatch, with per-record SR and ST key-value pairs, and an SP update

Reads:
- By seq num – straightforward, scan >= SD key
- By timestamp – find first record >= ST key, and then look by seq num
- If no record found, figure out the tail if possible to follow

Figuring out the tail:
- Init SP if it isn't already

Retention:
- TTL set on each SD & ST row if configured

## API surface

DataOps /records
  append # (basin, stream)
  read # (basin, stream)
  check_tail # (basin, stream)

StreamOps /streams
  list_streams  # (basin)
  create_stream  # (basin, stream)
  get_stream_config # (basin, stream)
  reconfigure_stream # (basin, stream)
  delete_stream # (basin, stream)

BasinOps /basins
  list_basins # ()
  create_basin # (basin)
  get_basin_config # (basin)
  reconfigure_basin # (basin)
  delete_basin # (basin)

AccessTokenOps /access-tokens # not initially supported
  list_access_tokens
  issue_access_token
  revoke_access_token

MetricOps /metrics # not initially supported
  get_account_metrics
  get_basin_metrics
  get_stream_metrics
