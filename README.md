<div align="center">
  <p>
    <!-- Light mode logo -->
    <a href="https://s2.dev#gh-light-mode-only">
      <img src="./assets/s2-black.png" height="60">
    </a>
    <!-- Dark mode logo -->
    <a href="https://s2.dev#gh-dark-mode-only">
      <img src="./assets/s2-white.png" height="60">
    </a>
  </p>

  <h1>S2, the durable streams API</h1>

  <p>
    <!-- Github Actions (CI) -->
    <a href="https://github.com/s2-streamstore/s2/actions?query=branch%3Amain++"><img src="https://github.com/s2-streamstore/s2/actions/workflows/ci.yml/badge.svg" /></a>
    <!-- Discord (chat) -->
    <a href="https://discord.gg/vTCs7kMkAf"><img src="https://img.shields.io/discord/1209937852528599092?logo=discord" /></a>
    <!-- LICENSE -->
    <a href="./LICENSE"><img src="https://img.shields.io/github/license/s2-streamstore/s2" /></a>
  </p>
</div>

[s2.dev](https://s2.dev) is a serverless datastore for real-time, streaming data.

## s2-lite

`s2-lite` is an open source, self-hostable server implementation of the [S2 API](https://s2.dev/docs/api).

It uses [SlateDB](https://slatedb.io) as its storage engine, which relies entirely on object storage for durability.

It is easy to run `s2-lite` against object stores like AWS S3 and Tigris. It is a single-node binary with no other external dependencies. Just like [s2.dev](https://s2.dev), data is always durable on object storage before being acknowledged or returned to readers.

You can also simply not specify a `--bucket`, which makes it operate entirely in-memory. This is great for integration tests involving S2.

### Quickstart

> [!NOTE]
> Point CLI or SDKs at your lite instance like this:
> ```bash
> export S2_ACCOUNT_ENDPOINT="http://localhost:8080"
> export S2_BASIN_ENDPOINT="http://localhost:8080"
> export S2_ACCESS_TOKEN="redundant"
> ```

Here's how you can run in-memory without any external dependency:
```bash
docker run -p 8080:80 ghcr.io/s2-streamstore/s2-lite
```

<details>
<summary>AWS S3 bucket example</summary>

```bash
docker run -p 8080:80 \
  -e AWS_PROFILE=${AWS_PROFILE} \
  -v ~/.aws:/root/.aws:ro \
  ghcr.io/s2-streamstore/s2-lite \
  --bucket ${S3_BUCKET} \
  --path s2lite
```
</details>

<details>
<summary>Static credentials example (Tigris, R2 etc)</summary>

```bash
docker run -p 8080:80 \
  -e AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID} \
  -e AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY} \
  -e AWS_ENDPOINT_URL_S3=${AWS_ENDPOINT_URL_S3} \
  ghcr.io/s2-streamstore/s2-lite \
  --bucket ${S3_BUCKET} \
  --path s2lite
```
</details>

Let's make sure the server is ready:
```bash
while ! curl -sf ${S2_ACCOUNT_ENDPOINT}/ping -o /dev/null; do echo Waiting...; sleep 2; done && echo Up!
```

[Install the CLI](https://github.com/s2-streamstore/s2-cli?tab=readme-ov-file#installation) or upgrade it if `s2 --version` is older than `0.23`

Let's create a [basin](https://s2.dev/docs/concepts) with auto-creation of streams enabled:
```bash
s2 create-basin liteness --create-stream-on-append --create-stream-on-read
```

Test your latencies:
```bash
s2 ping s2://liteness/pinger
```

Now let's try streaming sessions. In one or more new terminals (make sure you re-export the env vars noted above),
```bash
s2 read s2://liteness/starwars 2> /dev/null
```

Now back from your original terminal, let's write to the stream:
```bash
nc starwars.s2.dev 23 | s2 append s2://liteness/starwars
```

### Monitoring

*Readiness* `/ping` will `pong`

*Metrics* `/metrics` returns Prometheus text format

### Internals

#### SlateDB settings

[Settings reference](https://docs.rs/slatedb/latest/slatedb/config/struct.Settings.html#fields)

Use `SL8_` prefixed environment variables, e.g.:

```bash
# defaults to 40ms
SL8_FLUSH_INTERVAL=10ms
```

#### Design

[Concepts](https://s2.dev/docs/concepts)

- HTTP serving is implemented using [axum](https://github.com/tokio-rs/axum)
- Each stream corresponds to a Tokio task called [`streamer`](lite/src/backend/streamer.rs) that owns the current `tail` position, serializes appends, and broadcasts acknowledged records to followers
- Appends are pipelined to improve performance against high-latency object storage
  - **Temporary** [disabled by default](https://github.com/s2-streamstore/s2/issues/48), you can try it with `S2LITE_PIPELINE=true`
- [`lite::backend::kv::Key`](lite/src/backend/kv/mod.rs) documents the data modeling in SlateDB

### Caveats

- Deletion is not fully plumbed up yet
  - basins https://github.com/s2-streamstore/s2/issues/53
  - streams https://github.com/s2-streamstore/s2/issues/52
  - records https://github.com/s2-streamstore/s2/issues/51
- Pipelining needs to be made safe and default https://github.com/s2-streamstore/s2/issues/48

### Compatibility

- [CLI](https://github.com/s2-streamstore/s2-cli) ✅ v0.23+
- [TypeScript SDK](https://github.com/s2-streamstore/s2-sdk-typescript) ✅ v0.22+
- [Go SDK](https://github.com/s2-streamstore/s2-sdk-go) ✅ v0.11+
- [Rust SDK](https://github.com/s2-streamstore/s2-sdk-rust) ✅ v0.22+
- [Python](https://github.com/s2-streamstore/s2-sdk-python) 🚧 _needs to be migrated to v1 API_
- [Java](https://github.com/s2-streamstore/s2-sdk-java) 🚧 _needs to be migrated to v1 API_

### API Coverage

> [!TIP]
> Complete [specs](api/specs/s2/v1) are available: [OpenAPI](https://s2.dev/docs/api) for the REST-ful core, [Protobuf](https://buf.build/streamstore/s2/docs/main:s2.v1) definitions, and [S2S](https://s2.dev/docs/api/records/overview#s2s-spec) which is the streaming session protocol.

**Fully supported**
- `/basins`
- `/streams`
- `/streams/{stream}/records`

> [!IMPORTANT]
> Unlike the cloud service where the basin is implicit as a subdomain, `/streams/*` requests **must** specify the basin using the `S2-Basin` header. The SDKs take care of this automatically.

**Not supported**
- `/access-tokens` https://github.com/s2-streamstore/s2/issues/28
- `/metrics`
