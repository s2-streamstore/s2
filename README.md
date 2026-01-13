# S2, the durable streams API

[s2.dev](https://s2.dev) is a serverless datastore for real-time, streaming data.

S2 reimagines streams as an unlimited and access-controlled web resource. _Like if Kafka and S3 had a baby._

## s2-lite

`s2-lite` is an open source, self-hostable server implementation of the [S2 API](https://s2.dev/docs/rest/protocol).

It uses [SlateDB](https://slatedb.io) as its storage engine, which relies entirely on object storage for durability.

It is easy to run `s2-lite` against object stores like AWS S3, GCP GCS, and Cloudflare R2. It is a single-node binary with no other external dependencies. Just like [s2.dev](https://s2.dev), data is always durable on object storage before being acknowledged or returned to readers.

You can also simply not specify a `--bucket`, which makes it operate entirely in-memory. This is great for integration tests involving S2.

### Try it out

_TODO: `docker run` cmd_

### Design

[Concepts](https://s2.dev/docs/concepts)

- HTTP API is implemented using [axum](https://github.com/tokio-rs/axum).
- Each stream maps to a [Tokio task](lite/src/backend/streamer.rs) that owns the current tail position, serializes appends, and broadcasts acknowledged records to followers.
- Appends are pipelined to improve performance against high-latency object storage.
- [`lite::backend::kv::Key`](lite/src/backend/kv/mod.rs) documents the data model in sl8.

### SlateDB settings

[Settings reference](https://docs.rs/slatedb/latest/slatedb/config/struct.Settings.html#fields)

Use `SL8_` prefixed environment variables, e.g.:

```bash
SL8_FLUSH_INTERVAL=10ms
```

### API Coverage

> [!TIP]
> S2 has a REST-ful HTTP API with an [OpenAPI spec](api/specs/s2/v1/openapi.json).
> The data plane additionally supports [Protobuf messages](api/specs/s2/v1/s2.proto) and a minimal binary protocol over HTTP/2 called `S2S`, to support streaming requirements efficiently. This is fully documented [here](http://s2.dev/docs/rest/records/overview).

**Fully supported**
- `/basins`
- `/streams`
- `/streams/{stream}/records`

Unlike the cloud service where the basin is implicit as a subdomain, `/streams/*` requests **must** specify the basin using the `S2-Basin` header. S2 SDKs take care of this automatically.

**Not supported**
- `/access-tokens` (but will be supported https://github.com/s2-streamstore/s2/issues/28)
- `/metrics`

### Current limitations

- Deletion is not fully plumbed up yet
  - basins https://github.com/s2-streamstore/s2/issues/53
  - streams https://github.com/s2-streamstore/s2/issues/52
  - records https://github.com/s2-streamstore/s2/issues/51
- Pipelining needs to be made safe and default https://github.com/s2-streamstore/s2/issues/48

**Compatibility**
- CLI ✅ v0.23+
- TypeScript SDK ✅ v0.22+
- Go SDK ✅ v0.11+
- Rust SDK ✅ v0.22+
- Python 🚧 _needs to be migrated to v1 API_
- Java 🚧 _needs to be migrated to v1 API_
