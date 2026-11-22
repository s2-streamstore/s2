//! Spec conformance vector runner and rule-tagged tests for Revision 1 (Draft).
//!
//! Runs the shared JSON test vectors from `api/specs/sdk/vectors/` and
//! `api/specs/s2/v1/error-codes.json` against `s2-sdk` and `s2-api`.

mod support;

use std::{
    collections::{BTreeMap, BTreeSet},
    env::VarError,
    error::Error as StdError,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt as _;
use http::Response;
use prost::Message as _;
use s2_api::v1::{
    self as api,
    error::ErrorCode,
    stream::{
        proto::{
            AppendAck as ProtoAppendAck, ReadBatch as ProtoReadBatch,
            SequencedRecord as ProtoSequencedRecord, StreamPosition as ProtoStreamPosition,
        },
        s2s::{FrameDecoder, SessionMessage},
    },
};
use s2_common::resources::ProvisionResult;
use s2_sdk::{
    S2, S2Basin, S2Stream,
    append_session::{AppendSession, AppendSessionConfig},
    batching::{Batcher, BatcherConfig, TryBatchError},
    error::{AppendError, AppendSessionError, ReadError, ReadSessionError, RequestError, S2Error},
    producer::{Producer, ProducerConfig},
    read_session::{ReadBatchSession, ReadSession, ReadSessionState},
    types::{
        AccessTokenId, AccessTokenMatcher, AccessTokenScopeInput, AccountEndpoint,
        AccountMetricSet, AppendInput, AppendRecord, AppendRecordBatch, AppendRetryPolicy,
        BasinEndpoint, BasinMatcher, BasinMetricSet, BasinName, BasinReconfiguration,
        CommandRecord, Compression, CreateBasinInput, CreateNetworkPolicyInput, CreateStreamInput,
        DeleteOnEmptyConfig, DeleteOnEmptyReconfiguration, EncryptionAlgorithm, EncryptionKey,
        EnsureBasinInput, EnsureOutput, EnsureStreamInput, FencingToken, Header, Http2Config,
        IssueAccessTokenInput, ListAllBasinsInput, ListAllStreamsInput, ListBasinsInput,
        ListStreamsInput, Maybe, MeteredBytes, Metric, MetricUnit, NetworkPolicy, Operation,
        OperationGroupPermissions, PrivateNet, PrivateNetPolicy, PublicNetPolicy, ReadFrom,
        ReadInput, ReadLimits, ReadSessionConfig, ReadSessionRetryPolicy, ReadStart, ReadStop,
        RetentionPolicy, RetryConfig, S2Config, S2Endpoints, SequencedRecord, StreamMatcher,
        StreamMetricSet, StreamName, StreamReconfiguration, TimeRange, TimeRangeAndInterval,
        TimeseriesInterval, Timestamp, TimestampingMode, TimestampingReconfiguration,
    },
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use support::{CannedResponse, MockH2Server, gzip_bytes, zstd_bytes};
use tokio_util::codec::Decoder;

fn specs_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../api/specs")
        .join(rel)
}

fn read_json<T: for<'de> Deserialize<'de>>(rel: &str) -> T {
    let path = specs_path(rel);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()))
}

fn decode_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "hex string must have even length: {hex}");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex byte"))
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

// ---------------------------------------------------------------------------
// E4a: error-codes.json parity
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ErrorCodesFile {
    codes: Vec<ErrorCodeEntry>,
}

#[derive(Deserialize)]
struct ErrorCodeEntry {
    code: String,
    status: u16,
    retryable: bool,
    side_effects: String,
}

// spec: r1 E4a
#[test]
fn spec_error_codes_parity() {
    let file: ErrorCodesFile = read_json("s2/v1/error-codes.json");
    let mut seen = BTreeSet::new();

    for entry in &file.codes {
        let code = ErrorCode::from_str(&entry.code)
            .unwrap_or_else(|_| panic!("missing ErrorCode variant for {:?}", entry.code));
        assert!(
            seen.insert(code.to_string()),
            "duplicate code in error-codes.json: {}",
            entry.code
        );
        assert_eq!(
            code.status().as_u16(),
            entry.status,
            "status mismatch for {}",
            entry.code
        );
        assert_eq!(
            code.is_retryable(),
            entry.retryable,
            "retryable mismatch for {}",
            entry.code
        );
        let expected_no_side_effects = match entry.side_effects.as_str() {
            "none" => true,
            "maybe" => false,
            other => panic!("unexpected side_effects {other:?} for {}", entry.code),
        };
        assert_eq!(
            code.has_no_side_effects(),
            expected_no_side_effects,
            "side_effects mismatch for {}",
            entry.code
        );
        let serialized = serde_json::to_string(&code).expect("ErrorCode serializes");
        assert_eq!(
            serialized,
            format!("\"{}\"", entry.code),
            "serde snake_case mismatch for {}",
            entry.code
        );
        let deserialized: ErrorCode =
            serde_json::from_str(&serialized).expect("ErrorCode deserializes");
        assert_eq!(deserialized, code);
    }

    let sdk_codes: BTreeSet<String> = ErrorCode::ALL.iter().map(ToString::to_string).collect();
    assert_eq!(
        sdk_codes, seen,
        "ErrorCode variants must match error-codes.json 1:1"
    );
}

// ---------------------------------------------------------------------------
// C1, C3: endpoints.json
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct EndpointsFile {
    cases: Vec<EndpointCase>,
}

#[derive(Deserialize)]
struct EndpointCase {
    rule: String,
    name: String,
    endpoints: Option<EndpointsInput>,
    env: Option<BTreeMap<String, String>>,
    access_token: Option<String>,
    basin: String,
    expect: EndpointExpect,
}

#[derive(Deserialize)]
struct EndpointsInput {
    account: Option<String>,
    basin: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum EndpointExpect {
    Error {
        error: String,
    },
    Ok {
        account_origin: String,
        basin_origin: String,
        s2_basin_header: bool,
    },
}

// spec: r1 C1, C3
#[tokio::test]
async fn spec_vectors_endpoints() {
    let file: EndpointsFile = read_json("sdk/vectors/endpoints.json");
    assert!(!file.cases.is_empty());

    for case in &file.cases {
        let label = format!("[{}] {}", case.rule, case.name);
        let basin: BasinName = case.basin.parse().expect("valid basin in vector");

        if let Some(env) = &case.env {
            let result =
                S2Config::from_env_with(|key| env.get(key).cloned().ok_or(VarError::NotPresent))
                    .map_err(RequestError::Validation)
                    .and_then(|config| {
                        let endpoints = config.endpoints().clone();
                        S2::new(config)?;
                        Ok(endpoints)
                    });

            assert_endpoint_expect(&label, &basin, result, &case.expect);
        } else if let Some(token) = &case.access_token {
            let result = S2::new(S2Config::new(token.clone())).map(|_| S2Endpoints::for_cloud());
            assert_endpoint_expect(&label, &basin, result, &case.expect);
        } else if let Some(endpoints) = &case.endpoints {
            let result: Result<S2Endpoints, RequestError> =
                match (&endpoints.account, &endpoints.basin) {
                    (Some(account), Some(basin_ep)) => AccountEndpoint::new(account)
                        .and_then(|a| BasinEndpoint::new(basin_ep).map(|b| (a, b)))
                        .and_then(|(a, b)| S2Endpoints::new(a, b))
                        .map_err(RequestError::Validation),
                    (Some(account), None) => S2Endpoints::from_env_with(|key| match key {
                        "S2_ACCOUNT_ENDPOINT" => Ok(account.clone()),
                        _ => Err(VarError::NotPresent),
                    })
                    .map_err(RequestError::Validation),
                    (None, Some(basin_ep)) => S2Endpoints::from_env_with(|key| match key {
                        "S2_BASIN_ENDPOINT" => Ok(basin_ep.clone()),
                        _ => Err(VarError::NotPresent),
                    })
                    .map_err(RequestError::Validation),
                    (None, None) => Ok(S2Endpoints::for_cloud()),
                }
                .and_then(|ep| {
                    S2::new(S2Config::new("token").with_endpoints(ep.clone()))?;
                    Ok(ep)
                });
            assert_endpoint_expect(&label, &basin, result, &case.expect);
        } else {
            let config = S2Config::new("token");
            let ep = config.endpoints().clone();
            let result = S2::new(config).map(|_| ep);
            assert_endpoint_expect(&label, &basin, result, &case.expect);
        }
    }
}

fn assert_endpoint_expect(
    label: &str,
    basin: &BasinName,
    result: Result<S2Endpoints, RequestError>,
    expect: &EndpointExpect,
) {
    match expect {
        EndpointExpect::Error { error } => {
            assert_eq!(error, "ValidationError", "{label}");
            let err = result.expect_err(&format!("{label}: expected ValidationError"));
            assert!(
                matches!(err, RequestError::Validation(_)),
                "{label}: expected ValidationError, got {err:?}"
            );
        }
        EndpointExpect::Ok {
            account_origin,
            basin_origin,
            s2_basin_header,
        } => {
            let ep = result.unwrap_or_else(|e| panic!("{label}: unexpected error {e}"));
            assert_eq!(ep.account_origin(), *account_origin, "{label}");
            assert_eq!(ep.basin_origin(basin), *basin_origin, "{label}");
            assert_eq!(ep.uses_basin_header(), *s2_basin_header, "{label}");
        }
    }
}

// ---------------------------------------------------------------------------
// C9: names.json
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct NamesFile {
    cases: Vec<NameCase>,
}

#[derive(Deserialize)]
struct NameCase {
    rule: String,
    basin: String,
    expect: String,
}

// spec: r1 C9
#[test]
fn spec_vectors_names() {
    let file: NamesFile = read_json("sdk/vectors/names.json");
    assert!(!file.cases.is_empty());

    for case in &file.cases {
        let parsed = case.basin.parse::<BasinName>();
        match case.expect.as_str() {
            "valid" => assert!(
                parsed.is_ok(),
                "[{}] expected valid basin name {:?}, got {:?}",
                case.rule,
                case.basin,
                parsed
            ),
            "ValidationError" => assert!(
                parsed.is_err(),
                "[{}] expected ValidationError for basin name {:?}",
                case.rule,
                case.basin
            ),
            other => panic!("unexpected expect value {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// C4: keys.json
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct KeysFile {
    cases: Vec<KeyCase>,
}

#[derive(Deserialize)]
struct KeyCase {
    rule: String,
    name: String,
    text: Option<String>,
    bytes_hex: Option<String>,
    expect: KeyExpect,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum KeyExpect {
    Header { header: String },
    Error { error: String },
}

// spec: r1 C4
#[test]
fn spec_vectors_keys() {
    let file: KeysFile = read_json("sdk/vectors/keys.json");
    assert!(!file.cases.is_empty());

    for case in &file.cases {
        let label = format!("[{}] {}", case.rule, case.name);
        let result = match (&case.text, &case.bytes_hex) {
            (Some(text), None) => text.parse::<EncryptionKey>(),
            (None, Some(hex)) => EncryptionKey::new(decode_hex(hex)),
            _ => panic!("{label}: case must set exactly one of text or bytes_hex"),
        };

        match &case.expect {
            KeyExpect::Header { header } => {
                let key = result.unwrap_or_else(|e| panic!("{label}: unexpected error {e}"));
                let value = key.to_header_value();
                assert!(value.is_sensitive(), "{label}: header must be sensitive");
                assert_eq!(value.to_str().unwrap(), header, "{label}");
            }
            KeyExpect::Error { error } => {
                assert_eq!(error, "ValidationError", "{label}");
                assert!(result.is_err(), "{label}: expected ValidationError");
            }
        }
    }

    // Empty key cases (aligned with s2-specs#33).
    assert!("".parse::<EncryptionKey>().is_err());
    assert!("   \n\t ".parse::<EncryptionKey>().is_err());
    assert!(EncryptionKey::new([]).is_err());
}

// ---------------------------------------------------------------------------
// A2d, C2, D5: numbers.json
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct NumbersFile {
    cases: Vec<NumberCase>,
}

#[derive(Deserialize)]
struct NumberCase {
    rule: String,
    field: String,
    value: Option<String>,
    millis: Option<String>,
    expect: String,
}

// spec: r1 A2d, C2, D5
#[tokio::test]
async fn spec_vectors_numbers() {
    let file: NumbersFile = read_json("sdk/vectors/numbers.json");
    assert!(!file.cases.is_empty());

    let dummy_batch = AppendRecordBatch::try_from_iter([AppendRecord::new("").unwrap()]).unwrap();

    for case in &file.cases {
        let label = format!(
            "[{}] {} = {:?}",
            case.rule,
            case.field,
            case.value.as_deref().or(case.millis.as_deref())
        );

        let expect_valid = match case.expect.as_str() {
            "valid" | "valid_if_representable" => true,
            "ValidationError" => false,
            other => panic!("{label}: unexpected expect {other:?}"),
        };

        if let Some(raw) = &case.value {
            match case.field.as_str() {
                "record.timestamp" => match raw.parse::<u64>() {
                    Ok(v) => {
                        assert!(expect_valid, "{label}");
                        let rec = AppendRecord::new("").unwrap().with_timestamp(v);
                        assert_eq!(rec.timestamp(), Some(v), "{label}");
                    }
                    Err(_) => assert!(!expect_valid, "{label}: expected valid u64"),
                },
                "append.match_seq_num" => match raw.parse::<u64>() {
                    Ok(v) => {
                        assert!(expect_valid, "{label}");
                        let input = AppendInput::new(dummy_batch.clone()).with_match_seq_num(v);
                        assert_eq!(input.match_seq_num, Some(v), "{label}");
                    }
                    Err(_) => assert!(!expect_valid, "{label}: expected valid u64"),
                },
                "read.start.seq_num" => match raw.parse::<u64>() {
                    Ok(v) => {
                        assert!(expect_valid, "{label}");
                        let start: api::stream::ReadStart =
                            ReadStart::new().with_from(ReadFrom::SeqNum(v)).into();
                        assert_eq!(start.seq_num, Some(v), "{label}");
                    }
                    Err(_) => assert!(!expect_valid, "{label}: expected valid u64"),
                },
                "read.start.timestamp" => match raw.parse::<u64>() {
                    Ok(v) => {
                        assert!(expect_valid, "{label}");
                        let start: api::stream::ReadStart =
                            ReadStart::new().with_from(ReadFrom::Timestamp(v)).into();
                        assert_eq!(start.timestamp, Some(v), "{label}");
                    }
                    Err(_) => assert!(!expect_valid, "{label}: expected valid u64"),
                },
                "read.stop.count" => match raw.parse::<u64>() {
                    Ok(v) => {
                        assert!(expect_valid, "{label}");
                        let end: api::stream::ReadEnd = ReadStop::new()
                            .with_limits(ReadLimits::new().with_count(v))
                            .into();
                        assert_eq!(end.count, Some(v), "{label}");
                    }
                    Err(_) => assert!(!expect_valid, "{label}: expected valid u64"),
                },
                "read.stop.bytes" => match raw.parse::<u64>() {
                    Ok(v) => {
                        assert!(expect_valid, "{label}");
                        let end: api::stream::ReadEnd = ReadStop::new()
                            .with_limits(ReadLimits::new().with_bytes(v))
                            .into();
                        assert_eq!(end.bytes, Some(v), "{label}");
                    }
                    Err(_) => assert!(!expect_valid, "{label}: expected valid u64"),
                },
                "read.stop.until" => match raw.parse::<u64>() {
                    Ok(v) => {
                        assert!(expect_valid, "{label}");
                        let end: api::stream::ReadEnd = ReadStop::new().with_until(..v).into();
                        assert_eq!(end.until, Some(v), "{label}");
                    }
                    Err(_) => assert!(!expect_valid, "{label}: expected valid u64"),
                },
                "trim.seq_num" => match raw.parse::<u64>() {
                    Ok(v) => {
                        assert!(expect_valid, "{label}");
                        let rec: AppendRecord = CommandRecord::trim(v).into();
                        assert_eq!(rec.body(), &v.to_be_bytes(), "{label}");
                    }
                    Err(_) => assert!(!expect_valid, "{label}: expected valid u64"),
                },
                "client.max_attempts" => match raw.parse::<u32>() {
                    Ok(v) => {
                        let res = RetryConfig::new().with_max_attempts(v);
                        assert_eq!(res.is_ok(), expect_valid, "{label}");
                    }
                    Err(_) => assert!(!expect_valid, "{label}"),
                },
                "session.max_unacked_bytes" => match raw.parse::<u32>() {
                    Ok(v) => {
                        let sess = AppendSessionConfig::new().with_max_unacked_bytes(v);
                        let prod = ProducerConfig::new().with_max_unacked_bytes(v);
                        assert_eq!(sess.is_ok(), expect_valid, "{label}");
                        assert_eq!(prod.is_ok(), expect_valid, "{label}");
                    }
                    Err(_) => assert!(!expect_valid, "{label}"),
                },
                "session.max_unacked_batches" => match raw.parse::<u32>() {
                    Ok(v) => {
                        let res = AppendSessionConfig::new().with_max_unacked_batches(v);
                        assert_eq!(res.is_ok(), expect_valid, "{label}");
                    }
                    Err(_) => assert!(!expect_valid, "{label}"),
                },
                "batching.max_batch_records" => match raw.parse::<usize>() {
                    Ok(v) => {
                        let batcher = BatcherConfig::new().with_max_batch_records(v);
                        let prod = ProducerConfig::new().with_max_batch_records(v);
                        assert_eq!(batcher.is_ok(), expect_valid, "{label}");
                        assert_eq!(prod.is_ok(), expect_valid, "{label}");
                    }
                    Err(_) => assert!(!expect_valid, "{label}"),
                },
                "batching.max_batch_bytes" => match raw.parse::<usize>() {
                    Ok(v) => {
                        let batcher = BatcherConfig::new().with_max_batch_bytes(v);
                        let prod = ProducerConfig::new().with_max_batch_bytes(v);
                        assert_eq!(batcher.is_ok(), expect_valid, "{label}");
                        assert_eq!(prod.is_ok(), expect_valid, "{label}");
                    }
                    Err(_) => assert!(!expect_valid, "{label}"),
                },
                other => panic!("unhandled value field {other:?}"),
            }
        } else if let Some(raw_ms) = &case.millis {
            match raw_ms.parse::<u64>() {
                Ok(ms) => {
                    let dur = Duration::from_millis(ms);
                    match case.field.as_str() {
                        "read.stop.wait" => {
                            let res = ReadStop::new().with_wait(dur);
                            assert_eq!(res.is_ok(), expect_valid, "{label}");
                        }
                        "stream_config.retention_age" => {
                            let res = RetentionPolicy::age(dur);
                            assert_eq!(res.is_ok(), expect_valid, "{label}");
                        }
                        "stream_config.delete_on_empty.min_age" => {
                            let cfg = DeleteOnEmptyConfig::new().with_min_age(dur);
                            let rec = DeleteOnEmptyReconfiguration::new().with_min_age(dur);
                            assert_eq!(cfg.is_ok(), expect_valid, "{label}");
                            assert_eq!(rec.is_ok(), expect_valid, "{label}");
                        }
                        "client.connection_timeout" => {
                            let res = S2Config::new("token").with_connection_timeout(dur);
                            assert_eq!(res.is_ok(), expect_valid, "{label}");
                        }
                        "client.request_timeout" => {
                            let res = S2Config::new("token").with_request_timeout(dur);
                            assert_eq!(res.is_ok(), expect_valid, "{label}");
                        }
                        "client.min_base_delay" => {
                            assert!(expect_valid, "{label}");
                            let _ = RetryConfig::new().with_min_base_delay(dur);
                        }
                        "client.max_base_delay" => {
                            assert!(expect_valid, "{label}");
                            let _ = RetryConfig::new().with_max_base_delay(dur);
                        }
                        "batching.linger" => {
                            assert!(expect_valid, "{label}");
                            let _ = BatcherConfig::new().with_linger(dur);
                            let _ = ProducerConfig::new().with_linger(dur);
                        }
                        other => panic!("unhandled millis field {other:?}"),
                    }
                }
                Err(_) => assert!(
                    !expect_valid,
                    "{label}: negative or non-integer millis is unrepresentable in Duration"
                ),
            }
        } else {
            panic!("{label}: case must have value or millis");
        }
    }

    // Cross-field constraint (C2): min_base_delay <= max_base_delay checked at S2::new().
    let bad_retry = RetryConfig::new()
        .with_min_base_delay(Duration::from_secs(2))
        .with_max_base_delay(Duration::from_secs(1));
    let err = S2::new(S2Config::new("token").with_retry(bad_retry))
        .expect_err("min_base_delay > max_base_delay must fail S2::new");
    assert!(matches!(err, RequestError::Validation(_)));

    let equal_retry = RetryConfig::new()
        .with_min_base_delay(Duration::ZERO)
        .with_max_base_delay(Duration::ZERO);
    assert!(S2::new(S2Config::new("token").with_retry(equal_retry)).is_ok());
}

// ---------------------------------------------------------------------------
// A2a, A2b, A2c, D2, D3: records.json
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RecordsFile {
    cases: Vec<serde_json::Value>,
}

// spec: r1 A2a, A2b, A2c, D2, D3
#[test]
fn spec_vectors_records() {
    let file: RecordsFile = read_json("sdk/vectors/records.json");
    assert!(!file.cases.is_empty());

    for case in &file.cases {
        let rule = case["rule"].as_str().unwrap();
        let name = case["name"].as_str().unwrap();
        let label = format!("[{rule}] {name}");

        if let Some(rec) = case.get("record") {
            if let Some(body_hex) = rec.get("body_hex").and_then(|v| v.as_str()) {
                let body = decode_hex(body_hex);
                let headers: Vec<Header> = rec["headers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|pair| {
                        Header::new(
                            decode_hex(pair[0].as_str().unwrap()),
                            decode_hex(pair[1].as_str().unwrap()),
                        )
                    })
                    .collect();
                let expected = case["expect"]["metered_bytes"].as_u64().unwrap() as usize;
                let append_rec = AppendRecord::new(body.clone())
                    .unwrap()
                    .with_headers(headers.clone())
                    .unwrap();
                assert_eq!(append_rec.metered_bytes(), expected, "{label}");
                let seq_rec = SequencedRecord::from_parts(0, 0, headers, body);
                assert_eq!(seq_rec.metered_bytes(), expected, "{label}");
            } else {
                let body_len = rec["body_len"].as_u64().unwrap() as usize;
                let res = AppendRecord::new(vec![0u8; body_len]);
                match case["expect"].as_str().unwrap() {
                    "valid" => assert!(res.is_ok(), "{label}"),
                    "ValidationError" => assert!(res.is_err(), "{label}"),
                    other => panic!("{label}: unexpected expect {other:?}"),
                }
            }
        } else if let Some(batch) = case.get("batch") {
            let count = batch["count"].as_u64().unwrap() as usize;
            let body_len = batch["body_len"].as_u64().unwrap() as usize;
            let records: Vec<AppendRecord> = (0..count)
                .map(|_| AppendRecord::new(vec![0u8; body_len]).unwrap())
                .collect();
            let res = AppendRecordBatch::try_from_iter(records);
            match case["expect"].as_str().unwrap() {
                "valid" => assert!(res.is_ok(), "{label}"),
                "ValidationError" => assert!(res.is_err(), "{label}"),
                other => panic!("{label}: unexpected expect {other:?}"),
            }
        } else if let Some(ft) = case.get("fencing_token").and_then(|v| v.as_str()) {
            let res = ft.parse::<FencingToken>();
            match case["expect"].as_str().unwrap() {
                "valid" => assert!(res.is_ok(), "{label}"),
                "ValidationError" => assert!(res.is_err(), "{label}"),
                other => panic!("{label}: unexpected expect {other:?}"),
            }
        } else if let Some(fence) = case.get("fence") {
            let token: FencingToken = fence["token"].as_str().unwrap().parse().unwrap();
            let mut cmd = CommandRecord::fence(token);
            if let Some(ts) = fence.get("timestamp").and_then(|v| v.as_str()) {
                cmd = cmd.with_timestamp(ts.parse().unwrap());
            }
            let rec: AppendRecord = cmd.into();
            assert_command_record(&label, &rec, &case["expect"]);
        } else if let Some(trim) = case.get("trim") {
            let seq_num: u64 = trim["seq_num"].as_str().unwrap().parse().unwrap();
            let mut cmd = CommandRecord::trim(seq_num);
            if let Some(ts) = trim.get("timestamp").and_then(|v| v.as_str()) {
                cmd = cmd.with_timestamp(ts.parse().unwrap());
            }
            let rec: AppendRecord = cmd.into();
            let expect = case["expect"]
                .get("if_representable")
                .unwrap_or(&case["expect"]);
            assert_command_record(&label, &rec, expect);
        } else if let Some(is_cmd) = case.get("is_command_record") {
            let headers: Vec<Header> = is_cmd["headers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|pair| {
                    Header::new(
                        decode_hex(pair[0].as_str().unwrap()),
                        decode_hex(pair[1].as_str().unwrap()),
                    )
                })
                .collect();
            let rec = SequencedRecord::from_parts(0, 0, headers, Bytes::new());
            assert_eq!(
                rec.is_command_record(),
                case["expect"].as_bool().unwrap(),
                "{label}"
            );
        } else {
            panic!("{label}: unhandled record vector shape");
        }
    }
}

fn assert_command_record(label: &str, rec: &AppendRecord, expect: &serde_json::Value) {
    let expected_headers: Vec<(Vec<u8>, Vec<u8>)> = expect["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| {
            (
                decode_hex(pair[0].as_str().unwrap()),
                decode_hex(pair[1].as_str().unwrap()),
            )
        })
        .collect();
    let actual_headers: Vec<(Vec<u8>, Vec<u8>)> = rec
        .headers()
        .iter()
        .map(|h| (h.name.to_vec(), h.value.to_vec()))
        .collect();
    assert_eq!(actual_headers, expected_headers, "{label}: headers");
    assert_eq!(
        encode_hex(rec.body()),
        expect["body_hex"].as_str().unwrap(),
        "{label}: body"
    );
    let expected_ts = expect
        .get("timestamp")
        .and_then(|v| v.as_str())
        .map(|s| s.parse::<u64>().unwrap());
    assert_eq!(rec.timestamp(), expected_ts, "{label}: timestamp");
}

// ---------------------------------------------------------------------------
// C6, F1, T9: s2s-frames.json
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct S2sFramesFile {
    cases: Vec<S2sFrameCase>,
}

#[derive(Deserialize)]
struct S2sFrameCase {
    rule: String,
    name: String,
    bytes: Vec<BytePiece>,
    expect: S2sFrameExpect,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum BytePiece {
    Hex { hex: String },
    Zeros { zeros: usize },
}

#[derive(Deserialize)]
struct S2sFrameExpect {
    messages: Vec<ExpectedMessage>,
    end: ExpectedEnd,
}

#[derive(Deserialize)]
struct ExpectedMessage {
    payload_hex: Option<String>,
    payload_len: Option<usize>,
    payload_sha256: Option<String>,
    reconnect_advised: bool,
}

#[derive(Deserialize)]
struct ExpectedEnd {
    #[serde(rename = "type")]
    kind: String,
    status: Option<u16>,
    code: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum DecodedEnd {
    Clean,
    ServerError { status: u16, code: Option<String> },
    ProtocolError,
    ConnectionLostError,
}

fn decode_s2s_stream(wire: &[u8]) -> (Vec<(Bytes, bool)>, DecodedEnd) {
    let mut decoder = FrameDecoder;
    let mut buf = BytesMut::from(wire);
    let mut messages = Vec::new();

    loop {
        match decoder.decode(&mut buf) {
            Ok(Some(SessionMessage::Regular(data))) => {
                let reconnect_advised = data.reconnect_advised();
                match data.decompressed() {
                    Ok(payload) => messages.push((payload, reconnect_advised)),
                    Err(_) => return (messages, DecodedEnd::ProtocolError),
                }
            }
            Ok(Some(SessionMessage::Terminal(term))) => {
                let code = serde_json::from_slice::<serde_json::Value>(&term.body)
                    .ok()
                    .and_then(|v| v.get("code")?.as_str().map(str::to_owned));
                return (
                    messages,
                    DecodedEnd::ServerError {
                        status: term.status,
                        code,
                    },
                );
            }
            Ok(None) => {
                if !buf.is_empty() {
                    return (messages, DecodedEnd::ConnectionLostError);
                }
                return (messages, DecodedEnd::Clean);
            }
            Err(_) => return (messages, DecodedEnd::ProtocolError),
        }
    }
}

// spec: r1 C6, F1, T9
#[test]
fn spec_vectors_s2s_frames() {
    let file: S2sFramesFile = read_json("sdk/vectors/s2s-frames.json");
    assert!(!file.cases.is_empty());

    for case in &file.cases {
        let label = format!("[{}] {}", case.rule, case.name);
        let mut wire = Vec::new();
        for piece in &case.bytes {
            match piece {
                BytePiece::Hex { hex } => wire.extend_from_slice(&decode_hex(hex)),
                BytePiece::Zeros { zeros } => wire.resize(wire.len() + *zeros, 0),
            }
        }

        let (messages, end) = decode_s2s_stream(&wire);
        assert_eq!(
            messages.len(),
            case.expect.messages.len(),
            "{label}: message count mismatch (end={end:?})"
        );
        for (idx, ((payload, advised), expected)) in
            messages.iter().zip(&case.expect.messages).enumerate()
        {
            assert_eq!(
                *advised, expected.reconnect_advised,
                "{label}: msg[{idx}] reconnect_advised"
            );
            if let Some(hex) = &expected.payload_hex {
                assert_eq!(encode_hex(payload), *hex, "{label}: msg[{idx}] payload_hex");
            }
            if let Some(len) = expected.payload_len {
                assert_eq!(payload.len(), len, "{label}: msg[{idx}] payload_len");
            }
            if let Some(expected_sha) = &expected.payload_sha256 {
                let digest = Sha256::digest(payload);
                assert_eq!(
                    encode_hex(&digest),
                    *expected_sha,
                    "{label}: msg[{idx}] payload_sha256"
                );
            }
        }

        let expected_end = match case.expect.end.kind.as_str() {
            "clean" => DecodedEnd::Clean,
            "ServerError" => DecodedEnd::ServerError {
                status: case.expect.end.status.unwrap(),
                code: case.expect.end.code.clone(),
            },
            "ProtocolError" => DecodedEnd::ProtocolError,
            "ConnectionLostError" => DecodedEnd::ConnectionLostError,
            other => panic!("{label}: unexpected end type {other:?}"),
        };
        assert_eq!(end, expected_end, "{label}: end mismatch");
    }

    // Terminal frame edge cases (aligned with s2-specs#33): empty body and non-UTF-8 body.
    let (msgs, end) = decode_s2s_stream(&decode_hex("0000038001f7"));
    assert!(msgs.is_empty());
    assert_eq!(
        end,
        DecodedEnd::ServerError {
            status: 503,
            code: None,
        }
    );

    let (msgs, end) = decode_s2s_stream(&decode_hex("0000058001f4fffe"));
    assert!(msgs.is_empty());
    assert_eq!(
        end,
        DecodedEnd::ServerError {
            status: 500,
            code: None,
        }
    );
}

// ---------------------------------------------------------------------------
// Additional PR 1 rule-tagged conformance checks: D4, M2, M3, R1, T5b
// ---------------------------------------------------------------------------

// spec: r1 D4
#[test]
fn spec_d4_wall_clock_and_metrics_timestamps() {
    let start = Timestamp::new(1_700_000_000, 999_999_999).unwrap();
    let end = Timestamp::new(1_700_003_600, 123_456_789).unwrap();

    let range = TimeRange::new(start, end).unwrap();
    assert_eq!(
        range.start(),
        Timestamp::from_second(1_700_000_000).unwrap()
    );
    assert_eq!(range.end(), Timestamp::from_second(1_700_003_600).unwrap());

    let tri = TimeRangeAndInterval::new(start, end).unwrap();
    assert_eq!(tri.start(), Timestamp::from_second(1_700_000_000).unwrap());
    assert_eq!(tri.end(), Timestamp::from_second(1_700_003_600).unwrap());

    // Negative and > u32::MAX fail ValidationError.
    let neg = Timestamp::new(-1, 500_000_000).unwrap();
    assert!(TimeRange::new(neg, end).is_err());
    assert!(TimeRangeAndInterval::new(neg, end).is_err());

    let overflow = Timestamp::from_second(i64::from(u32::MAX) + 1).unwrap();
    assert!(TimeRange::new(start, overflow).is_err());
    assert!(TimeRangeAndInterval::new(start, overflow).is_err());
}

// spec: r1 M2
#[tokio::test]
async fn spec_m2_ensure_output_variants() {
    assert_eq!(
        EnsureOutput::from(ProvisionResult::Created(1)),
        EnsureOutput::Created(1)
    );
    assert_eq!(
        EnsureOutput::from(ProvisionResult::Updated(2)),
        EnsureOutput::Updated(2)
    );
    assert_eq!(
        EnsureOutput::from(ProvisionResult::Noop(3)),
        EnsureOutput::Noop(3)
    );

    let (basin_name, stream_name) = test_basin_and_stream();
    let basin_json = r#"{"name":"test-basin","scope":"aws:us-east-1","state":"active","created_at":"2026-01-01T00:00:00Z"}"#;
    let stream_json = r#"{"name":"test-stream","created_at":"2026-01-01T00:00:00Z"}"#;

    // Verify `s2-provision-result` header handling AND status-code fallback (201 -> Created,
    // 200 -> Updated) over HTTP for both ensure_basin and ensure_stream.
    let server = MockH2Server::from_responses([
        CannedResponse::new(201, basin_json).with_header("s2-provision-result", "created"),
        CannedResponse::new(200, basin_json).with_header("s2-provision-result", "updated"),
        CannedResponse::new(200, basin_json).with_header("s2-provision-result", "noop"),
        CannedResponse::new(201, basin_json),
        CannedResponse::new(200, basin_json),
        CannedResponse::new(201, stream_json).with_header("s2-provision-result", "created"),
        CannedResponse::new(200, stream_json).with_header("s2-provision-result", "noop"),
        CannedResponse::new(200, stream_json),
    ])
    .await;
    let s2 = server.client(no_retry_config());

    assert!(matches!(
        s2.ensure_basin(EnsureBasinInput::new(basin_name.clone()))
            .await
            .unwrap(),
        EnsureOutput::Created(_)
    ));
    assert!(matches!(
        s2.ensure_basin(EnsureBasinInput::new(basin_name.clone()))
            .await
            .unwrap(),
        EnsureOutput::Updated(_)
    ));
    assert!(matches!(
        s2.ensure_basin(EnsureBasinInput::new(basin_name.clone()))
            .await
            .unwrap(),
        EnsureOutput::Noop(_)
    ));
    assert!(matches!(
        s2.ensure_basin(EnsureBasinInput::new(basin_name.clone()))
            .await
            .unwrap(),
        EnsureOutput::Created(_)
    ));
    assert!(matches!(
        s2.ensure_basin(EnsureBasinInput::new(basin_name.clone()))
            .await
            .unwrap(),
        EnsureOutput::Updated(_)
    ));

    let basin = s2.basin(basin_name);
    assert!(matches!(
        basin
            .ensure_stream(EnsureStreamInput::new(stream_name.clone()))
            .await
            .unwrap(),
        EnsureOutput::Created(_)
    ));
    assert!(matches!(
        basin
            .ensure_stream(EnsureStreamInput::new(stream_name.clone()))
            .await
            .unwrap(),
        EnsureOutput::Noop(_)
    ));
    assert!(matches!(
        basin
            .ensure_stream(EnsureStreamInput::new(stream_name))
            .await
            .unwrap(),
        EnsureOutput::Updated(_)
    ));
}

// spec: r1 M3
#[test]
fn spec_m3_reconfiguration_three_states() {
    // Unchanged (default): fields omitted in serialized JSON.
    let unchanged: api::config::StreamReconfiguration = StreamReconfiguration::new().into();
    assert_eq!(
        serde_json::to_value(&unchanged).unwrap(),
        serde_json::json!({})
    );

    // Set to a new value.
    let updated: api::config::StreamReconfiguration = StreamReconfiguration::new()
        .with_storage_class("express")
        .with_retention_policy(RetentionPolicy::Infinite)
        .with_timestamping(
            TimestampingReconfiguration::new()
                .with_mode(TimestampingMode::Arrival)
                .with_uncapped(true),
        )
        .with_delete_on_empty(
            DeleteOnEmptyReconfiguration::new()
                .with_min_age(Duration::from_secs(60))
                .unwrap(),
        )
        .into();
    let updated_json = serde_json::to_value(&updated).unwrap();
    assert_eq!(updated_json["storage_class"], "express");
    assert_eq!(updated_json["timestamping"]["mode"], "arrival");
    assert_eq!(updated_json["timestamping"]["uncapped"], true);
    assert_eq!(updated_json["delete_on_empty"]["min_age_secs"], 60);

    // Reset to server default: serialized as explicit JSON null.
    let reset: api::config::StreamReconfiguration = StreamReconfiguration::new()
        .reset_storage_class()
        .reset_retention_policy()
        .reset_timestamping()
        .reset_delete_on_empty()
        .into();
    assert_eq!(
        serde_json::to_value(&reset).unwrap(),
        serde_json::json!({
            "storage_class": null,
            "retention_policy": null,
            "timestamping": null,
            "delete_on_empty": null,
        })
    );

    // Nested reset helpers and direct Maybe usage.
    let nested_reset: api::config::StreamReconfiguration = StreamReconfiguration::new()
        .with_timestamping(
            TimestampingReconfiguration::new()
                .reset_mode()
                .reset_uncapped(),
        )
        .with_delete_on_empty(DeleteOnEmptyReconfiguration::new().reset_min_age())
        .into();
    assert_eq!(
        serde_json::to_value(&nested_reset).unwrap(),
        serde_json::json!({
            "timestamping": { "mode": null, "uncapped": null },
            "delete_on_empty": { "min_age_secs": null },
        })
    );

    let basin_reset = BasinReconfiguration::new()
        .reset_default_stream_config()
        .reset_stream_cipher();
    assert!(matches!(
        basin_reset.default_stream_config,
        Maybe::Specified(None)
    ));
    assert!(matches!(basin_reset.stream_cipher, Maybe::Specified(None)));
    let basin_api: api::config::BasinReconfiguration = basin_reset.into();
    assert_eq!(
        serde_json::to_value(&basin_api).unwrap(),
        serde_json::json!({
            "default_stream_config": null,
            "stream_cipher": null,
        })
    );
}

// spec: r1 R1
#[test]
fn spec_r1_read_start_defaults_to_omitted() {
    let start: api::stream::ReadStart = ReadStart::new().into();
    assert_eq!(start.seq_num, None);
    assert_eq!(start.timestamp, None);
    assert_eq!(start.tail_offset, None);
    assert_eq!(start.clamp, None);
}

// spec: r1 T5b
#[test]
fn spec_t5b_read_session_retry_policy_variants() {
    assert_eq!(
        ReadSessionRetryPolicy::default(),
        ReadSessionRetryPolicy::Budgeted
    );
    assert_ne!(
        ReadSessionRetryPolicy::Budgeted,
        ReadSessionRetryPolicy::Unbounded
    );
}

// ---------------------------------------------------------------------------
// PR 2 conformance tests: E1–E7, C6 error decompression, C8 redirects
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ErrorsFile {
    cases: Vec<ErrorCase>,
}

#[derive(Deserialize)]
struct ErrorCase {
    rule: String,
    name: String,
    call: String,
    status: u16,
    body: String,
    expect: serde_json::Value,
}

fn no_retry_config() -> RetryConfig {
    RetryConfig::new()
        .with_max_attempts(1)
        .expect("max_attempts = 1")
}

fn test_basin_and_stream() -> (BasinName, StreamName) {
    (
        "test-basin".parse().expect("valid basin"),
        "test-stream".parse().expect("valid stream"),
    )
}

fn sample_append_input() -> AppendInput {
    AppendInput::new(
        AppendRecordBatch::try_from_iter([AppendRecord::new("payload").expect("valid record")])
            .expect("valid batch"),
    )
}

// spec: r1 E1, E2, E2a, E2b, E4a, E4b, E4c, E4e, C8
#[tokio::test]
async fn spec_vectors_errors() {
    let file: ErrorsFile = read_json("sdk/vectors/errors.json");
    assert_eq!(file.cases.len(), 22);

    let (basin_name, stream_name) = test_basin_and_stream();

    for case in &file.cases {
        let label = format!("[{}] {}", case.rule, case.name);
        let expect = case.expect.get("if_representable").unwrap_or(&case.expect);
        let expected_type = expect["type"].as_str().unwrap();
        let expected_status = expect["status"].as_u64().unwrap() as u16;
        let expected_code = expect["code"].as_str();
        let expected_message = expect["message"].as_str().unwrap();
        let expected_retryable = expect["is_retryable"].as_bool().unwrap();
        let expected_no_side_effects = expect["has_no_side_effects"].as_bool().unwrap();

        let server =
            MockH2Server::from_responses([CannedResponse::new(case.status, case.body.clone())])
                .await;
        let s2 = server.client(no_retry_config());
        let stream = s2.basin(basin_name.clone()).stream(stream_name.clone());

        match case.call.as_str() {
            "append" => {
                let err = stream
                    .append(sample_append_input())
                    .await
                    .expect_err(&format!("{label}: expected append error"));

                assert_eq!(err.is_retryable(), expected_retryable, "{label}: retryable");
                assert_eq!(
                    err.has_no_side_effects(),
                    expected_no_side_effects,
                    "{label}: has_no_side_effects"
                );

                match expected_type {
                    "ServerError" => {
                        let AppendError::Server(se) = &err else {
                            panic!("{label}: expected AppendError::Server, got {err:?}");
                        };
                        assert_eq!(se.status.as_u16(), expected_status, "{label}");
                        assert_eq!(se.code.as_deref(), expected_code, "{label}");
                        assert_eq!(se.message, expected_message, "{label}");
                    }
                    "SeqNumMismatchError" => {
                        let AppendError::SeqNumMismatch(e) = &err else {
                            panic!("{label}: expected AppendError::SeqNumMismatch, got {err:?}");
                        };
                        let expected_seq: u64 = expect["assignable_seq_num"]
                            .as_str()
                            .unwrap()
                            .parse()
                            .unwrap();
                        assert_eq!(e.assignable_seq_num, expected_seq, "{label}");
                        assert_eq!(e.server.status.as_u16(), expected_status, "{label}");
                        assert_eq!(e.server.code.as_deref(), expected_code, "{label}");
                        assert_eq!(e.server.message, expected_message, "{label}");
                    }
                    "FencingTokenMismatchError" => {
                        let AppendError::FencingTokenMismatch(e) = &err else {
                            panic!(
                                "{label}: expected AppendError::FencingTokenMismatch, got {err:?}"
                            );
                        };
                        let expected_tok = expect["current_fencing_token"].as_str().unwrap();
                        assert_eq!(&*e.current_fencing_token, expected_tok, "{label}");
                        assert_eq!(e.server.status.as_u16(), expected_status, "{label}");
                        assert_eq!(e.server.code.as_deref(), expected_code, "{label}");
                        assert_eq!(e.server.message, expected_message, "{label}");
                    }
                    other => panic!("{label}: unexpected append error type {other:?}"),
                }

                // E1: converting into S2Error preserves classification and server_error().
                let base: S2Error = err.into();
                assert_eq!(base.is_retryable(), expected_retryable, "{label}: S2Error");
                assert_eq!(
                    base.has_no_side_effects(),
                    expected_no_side_effects,
                    "{label}: S2Error"
                );
                let se = base.server_error().expect("S2Error exposes ServerError");
                assert_eq!(se.status.as_u16(), expected_status, "{label}: S2Error");
                assert_eq!(se.code.as_deref(), expected_code, "{label}: S2Error");
            }
            "read" => {
                let err = stream
                    .read(ReadInput::new())
                    .await
                    .expect_err(&format!("{label}: expected read error"));

                assert_eq!(err.is_retryable(), expected_retryable, "{label}: retryable");
                assert_eq!(
                    err.has_no_side_effects(),
                    expected_no_side_effects,
                    "{label}: has_no_side_effects"
                );

                match expected_type {
                    "ReadUnwrittenError" => {
                        let ReadError::ReadUnwritten(e) = &err else {
                            panic!("{label}: expected ReadError::ReadUnwritten, got {err:?}");
                        };
                        let expected_seq: u64 =
                            expect["tail"]["seq_num"].as_str().unwrap().parse().unwrap();
                        let expected_ts: u64 = expect["tail"]["timestamp"]
                            .as_str()
                            .unwrap()
                            .parse()
                            .unwrap();
                        assert_eq!(e.tail.seq_num, expected_seq, "{label}");
                        assert_eq!(e.tail.timestamp, expected_ts, "{label}");
                        assert_eq!(e.server.status.as_u16(), expected_status, "{label}");
                        assert_eq!(e.server.code.as_deref(), expected_code, "{label}");
                        assert_eq!(e.server.message, expected_message, "{label}");
                    }
                    "ServerError" => {
                        let ReadError::Server(se) = &err else {
                            panic!("{label}: expected ReadError::Server, got {err:?}");
                        };
                        assert_eq!(se.status.as_u16(), expected_status, "{label}");
                        assert_eq!(se.code.as_deref(), expected_code, "{label}");
                        assert_eq!(se.message, expected_message, "{label}");
                    }
                    other => panic!("{label}: unexpected read error type {other:?}"),
                }

                let base: S2Error = err.into();
                assert_eq!(base.is_retryable(), expected_retryable, "{label}: S2Error");
                assert!(
                    base.has_no_side_effects(),
                    "{label}: read S2Error is definite"
                );
                let se = base.server_error().expect("S2Error exposes ServerError");
                assert_eq!(se.status.as_u16(), expected_status, "{label}: S2Error");
            }
            other => panic!("{label}: unexpected call {other:?}"),
        }
    }
}

// spec: r1 C8
#[tokio::test]
async fn spec_c8_redirects_are_never_followed() {
    let target = MockH2Server::from_responses([CannedResponse::new(200, "ok")]).await;
    let location = format!("{}/v1/streams/test-stream/records", target.endpoint_url());
    let (basin_name, stream_name) = test_basin_and_stream();

    for status in [301u16, 302, 307, 308] {
        let origin = MockH2Server::from_responses([
            CannedResponse::new(status, "").with_header("location", location.as_str()),
            CannedResponse::new(status, "").with_header("location", location.as_str()),
        ])
        .await;
        let s2 = origin.client(no_retry_config());
        let stream = s2.basin(basin_name.clone()).stream(stream_name.clone());

        let append_err = stream
            .append(sample_append_input())
            .await
            .expect_err("redirect must fail append");
        let AppendError::Server(se) = &append_err else {
            panic!("expected ServerError for {status}, got {append_err:?}");
        };
        assert_eq!(se.status.as_u16(), status);
        assert_eq!(se.code, None);
        assert_eq!(se.message, status.to_string());
        assert!(!append_err.is_retryable());
        assert!(!append_err.has_no_side_effects());

        let read_err = stream
            .read(ReadInput::new())
            .await
            .expect_err("redirect must fail read");
        let ReadError::Server(se) = &read_err else {
            panic!("expected ServerError for {status}, got {read_err:?}");
        };
        assert_eq!(se.status.as_u16(), status);
        assert!(!read_err.is_retryable());
        assert!(read_err.has_no_side_effects());
    }

    assert_eq!(
        target.request_count(),
        0,
        "redirect target server must never be contacted"
    );
}

// spec: r1 C6, E2
#[tokio::test]
async fn spec_c6_e2_compressed_and_corrupt_error_bodies() {
    let (basin_name, stream_name) = test_basin_and_stream();

    let gzip_body = gzip_bytes(br#"{"code":"server_draining","message":"draining"}"#).await;
    let zstd_body = zstd_bytes(br#"{"code":"unavailable","message":"busy"}"#).await;

    let server = MockH2Server::from_responses([
        CannedResponse::new(503, gzip_body).with_header("content-encoding", "gzip"),
        CannedResponse::new(503, zstd_body).with_header("content-encoding", "zstd"),
        CannedResponse::new(500, Bytes::from_static(b"not valid gzip bytes"))
            .with_header("content-encoding", "gzip"),
        CannedResponse::new(502, Bytes::from_static(b"brotli bytes"))
            .with_header("content-encoding", "br"),
    ])
    .await;
    let s2 = server.client(no_retry_config());
    let stream = s2.basin(basin_name).stream(stream_name);

    // 1. gzip error body decompressed
    let err = stream.append(sample_append_input()).await.unwrap_err();
    let AppendError::Server(se) = &err else {
        panic!("expected ServerError, got {err:?}");
    };
    assert_eq!(se.status.as_u16(), 503);
    assert_eq!(se.code.as_deref(), Some("server_draining"));
    assert_eq!(se.message, "draining");
    assert!(err.is_retryable());
    assert!(err.has_no_side_effects());

    // 2. zstd error body decompressed
    let err = stream.append(sample_append_input()).await.unwrap_err();
    let AppendError::Server(se) = &err else {
        panic!("expected ServerError, got {err:?}");
    };
    assert_eq!(se.status.as_u16(), 503);
    assert_eq!(se.code.as_deref(), Some("unavailable"));
    assert_eq!(se.message, "busy");
    assert!(err.is_retryable());
    assert!(!err.has_no_side_effects());

    // 3. corrupt gzip body on non-2xx still produces ServerError (not ProtocolError)
    let err = stream.append(sample_append_input()).await.unwrap_err();
    let AppendError::Server(se) = &err else {
        panic!("expected ServerError on corrupt gzip error body, got {err:?}");
    };
    assert_eq!(se.status.as_u16(), 500);
    assert_eq!(se.code, None);
    assert_eq!(se.message, "500");
    assert!(err.is_retryable());
    assert!(!err.has_no_side_effects());

    // 4. unsupported content-encoding on non-2xx still produces ServerError
    let err = stream.append(sample_append_input()).await.unwrap_err();
    let AppendError::Server(se) = &err else {
        panic!("expected ServerError on unsupported encoding error body, got {err:?}");
    };
    assert_eq!(se.status.as_u16(), 502);
    assert_eq!(se.code, None);
    assert_eq!(se.message, "502");
    assert!(err.is_retryable());
    assert!(!err.has_no_side_effects());

    // 5. C6: Unary requests compress with configured encoding & advertise only that encoding;
    //    session frames compress only when payload >= 1 KiB.
    let seen_unary = Arc::new(Mutex::new(Vec::<(Option<String>, Option<String>)>::new()));
    let seen_session_compressions = Arc::new(Mutex::new(Vec::<u8>::new()));
    let comp_server = MockH2Server::start({
        let seen_unary = seen_unary.clone();
        let seen_session_compressions = seen_session_compressions.clone();
        move |_conn_id, req, mut respond| {
            let seen_unary = seen_unary.clone();
            let seen_session_compressions = seen_session_compressions.clone();
            async move {
                let is_s2s = req
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    == Some("s2s/proto");
                if is_s2s {
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "s2s/proto")
                        .body(())
                        .unwrap();
                    let Ok(mut send) = respond.send_response(resp, false) else {
                        return;
                    };
                    let mut body = req.into_body();
                    let mut buf = BytesMut::new();
                    let mut next_seq = 0u64;
                    while let Some(msg @ SessionMessage::Regular(_)) =
                        read_one_s2s_frame(&mut body, &mut buf, true).await
                    {
                        let comp_bits = (msg.encode()[3] & 0b0110_0000) >> 5;
                        seen_session_compressions.lock().unwrap().push(comp_bits);
                        let _ = send.send_data(
                            encode_s2s_regular_frame(
                                &proto_append_ack(next_seq, next_seq + 1),
                                false,
                            ),
                            false,
                        );
                        next_seq += 1;
                    }
                    let _ = send.send_data(Bytes::new(), true);
                } else {
                    let ce = req
                        .headers()
                        .get("content-encoding")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned);
                    let ae = req
                        .headers()
                        .get("accept-encoding")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned);
                    seen_unary.lock().unwrap().push((ce, ae));
                    let mut body = req.into_body();
                    while let Some(Ok(_)) = body.data().await {}
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "application/protobuf")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(Bytes::from(proto_append_ack(0, 1)), true);
                    }
                }
            }
        }
    })
    .await;

    let ep = comp_server.endpoint_url();
    let make_compressed_stream = |compression: Compression| {
        let endpoints = S2Endpoints::new(
            AccountEndpoint::new(&ep).unwrap(),
            BasinEndpoint::new(&ep).unwrap(),
        )
        .unwrap();
        let (b, s) = test_basin_and_stream();
        S2::new(
            S2Config::new("test-token")
                .with_endpoints(endpoints)
                .with_compression(compression)
                .with_retry(no_retry_config()),
        )
        .unwrap()
        .basin(b)
        .stream(s)
    };
    let large_input = AppendInput::new(
        AppendRecordBatch::try_from_iter([AppendRecord::new(vec![b'x'; 2048]).unwrap()]).unwrap(),
    );

    make_compressed_stream(Compression::None)
        .append(sample_append_input())
        .await
        .unwrap();
    let gzip_stream = make_compressed_stream(Compression::Gzip);
    gzip_stream.append(sample_append_input()).await.unwrap();
    let zstd_stream = make_compressed_stream(Compression::Zstd);
    zstd_stream.append(sample_append_input()).await.unwrap();

    assert_eq!(
        *seen_unary.lock().unwrap(),
        vec![
            (None, None),
            (Some("gzip".to_owned()), Some("gzip".to_owned())),
            (Some("zstd".to_owned()), Some("zstd".to_owned())),
        ],
        "C6: unary requests compress and advertise only the configured algorithm"
    );

    // Session frames: < 1 KiB stays uncompressed; >= 1 KiB uses configured algorithm.
    let gzip_session = gzip_stream
        .append_session(AppendSessionConfig::new())
        .unwrap();
    gzip_session
        .submit(sample_append_input())
        .await
        .unwrap()
        .await
        .unwrap();
    gzip_session
        .submit(large_input.clone())
        .await
        .unwrap()
        .await
        .unwrap();
    gzip_session.close().await.unwrap();

    let zstd_session = zstd_stream
        .append_session(AppendSessionConfig::new())
        .unwrap();
    zstd_session
        .submit(sample_append_input())
        .await
        .unwrap()
        .await
        .unwrap();
    zstd_session
        .submit(large_input)
        .await
        .unwrap()
        .await
        .unwrap();
    zstd_session.close().await.unwrap();

    // S2S wire compression bits: 0 = None, 1 = Zstd, 2 = Gzip.
    assert_eq!(
        *seen_session_compressions.lock().unwrap(),
        vec![0, 2, 0, 1],
        "C6: session frames < 1 KiB stay uncompressed; >= 1 KiB use configured encoding"
    );
}

// spec: r1 E2, E2a, E2b, E4e, F1
#[tokio::test]
async fn spec_e2_typed_412_416_extra_fields_and_fallbacks() {
    let (basin_name, stream_name) = test_basin_and_stream();

    let server = MockH2Server::from_responses([
        CannedResponse::new(412, r#"{"seq_num_mismatch": 7, "future_field": true}"#),
        CannedResponse::new(412, r#"{"fencing_token_mismatch": "tok", "extra": 123}"#),
        CannedResponse::new(412, r#"{"seq_num_mismatch": 18446744073709551616}"#),
        CannedResponse::new(
            416,
            r#"{"tail": {"seq_num": 9, "timestamp": 1000, "extra": "ok"}, "other": 1}"#,
        ),
        CannedResponse::new(416, r#"{"tail": "not-an-object"}"#),
    ])
    .await;
    let s2 = server.client(no_retry_config());
    let stream = s2.basin(basin_name).stream(stream_name);

    // 1. 412 seq_num_mismatch with unknown field
    let err = stream.append(sample_append_input()).await.unwrap_err();
    let AppendError::SeqNumMismatch(e) = &err else {
        panic!("expected SeqNumMismatch, got {err:?}");
    };
    assert_eq!(e.assignable_seq_num, 7);
    assert_eq!(e.server.status.as_u16(), 412);
    assert!(!err.is_retryable());
    assert!(err.has_no_side_effects());

    // 2. 412 fencing_token_mismatch with unknown field
    let err = stream.append(sample_append_input()).await.unwrap_err();
    let AppendError::FencingTokenMismatch(e) = &err else {
        panic!("expected FencingTokenMismatch, got {err:?}");
    };
    assert_eq!(&*e.current_fencing_token, "tok");
    assert_eq!(e.server.status.as_u16(), 412);

    // 3. 412 out-of-range u64 falls back to plain ServerError, still definite & non-retryable (E4e)
    let err = stream.append(sample_append_input()).await.unwrap_err();
    let AppendError::Server(se) = &err else {
        panic!("expected plain ServerError on u64 overflow 412, got {err:?}");
    };
    assert_eq!(se.status.as_u16(), 412);
    assert!(!err.is_retryable());
    assert!(err.has_no_side_effects());

    // 4. 416 with extra fields still produces ReadUnwrittenError
    let err = stream.read(ReadInput::new()).await.unwrap_err();
    let ReadError::ReadUnwritten(e) = &err else {
        panic!("expected ReadUnwritten, got {err:?}");
    };
    assert_eq!(e.tail.seq_num, 9);
    assert_eq!(e.tail.timestamp, 1000);
    assert_eq!(e.server.status.as_u16(), 416);

    // 5. 416 malformed body falls back to plain ServerError, still definite on read
    let err = stream.read(ReadInput::new()).await.unwrap_err();
    let ReadError::Server(se) = &err else {
        panic!("expected plain ServerError on malformed 416, got {err:?}");
    };
    assert_eq!(se.status.as_u16(), 416);
    assert!(!err.is_retryable());
    assert!(err.has_no_side_effects());
}

// spec: r1 E1, E5, E5a, E5b, E7
#[tokio::test]
async fn spec_e5_e7_indefinite_append_wrapping_and_context() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let fast_retry_all = RetryConfig::new()
        .with_max_attempts(2)
        .unwrap()
        .with_min_base_delay(Duration::ZERO)
        .with_max_base_delay(Duration::ZERO)
        .with_append_retry_policy(AppendRetryPolicy::All);

    // Case 1: indefinite attempt 1 + definite attempt 2 -> wrapped in IndefiniteAppendError
    let server = MockH2Server::from_responses([
        CannedResponse::new(503, r#"{"code":"unavailable","message":"busy"}"#),
        CannedResponse::new(412, r#"{"seq_num_mismatch":5}"#),
    ])
    .await;
    let stream = server
        .client(fast_retry_all.clone())
        .basin(basin_name.clone())
        .stream(stream_name.clone());

    let err = stream.append(sample_append_input()).await.unwrap_err();
    assert!(!err.is_retryable());
    assert!(!err.has_no_side_effects());
    assert!(
        err.server_error().is_none(),
        "E5a: wrapper hides ServerError"
    );
    let display = err.to_string();
    assert!(display.contains("append"), "E7: {display}");
    assert!(display.contains("test-basin"), "E7: {display}");
    assert!(display.contains("test-stream"), "E7: {display}");
    assert!(display.contains("after 2 attempts"), "E7: {display}");

    let AppendError::IndefiniteAppend(wrapped) = &err else {
        panic!("expected IndefiniteAppend, got {err:?}");
    };
    assert!(matches!(
        wrapped.final_attempt_error(),
        AppendError::SeqNumMismatch(e) if e.assignable_seq_num == 5
    ));
    let source = wrapped
        .source()
        .expect("E5b: IndefiniteAppendError sets source");
    assert!(
        source.downcast_ref::<AppendError>().is_some(),
        "E5b: source must downcast directly to AppendError"
    );

    let base: S2Error = err.into();
    assert!(base.server_error().is_none(), "E1/E5a: S2Error wrapper");
    assert!(!base.has_no_side_effects());
    assert!(!base.is_retryable());

    // Case 2: indefinite attempt 1 + indefinite attempt 2 -> NOT wrapped
    let server = MockH2Server::from_responses([
        CannedResponse::new(503, r#"{"code":"unavailable","message":"busy 1"}"#),
        CannedResponse::new(503, r#"{"code":"unavailable","message":"busy 2"}"#),
    ])
    .await;
    let stream = server
        .client(fast_retry_all.clone())
        .basin(basin_name.clone())
        .stream(stream_name.clone());
    let err = stream.append(sample_append_input()).await.unwrap_err();
    assert!(
        matches!(err, AppendError::Server(ref se) if se.message == "busy 2"),
        "indefinite final error must not be wrapped: {err:?}"
    );
    assert!(err.to_string().contains("after 2 attempts"));

    // Case 3: definite attempt 1 + definite attempt 2 -> NOT wrapped
    let server = MockH2Server::from_responses([
        CannedResponse::new(503, r#"{"code":"server_draining","message":"draining"}"#),
        CannedResponse::new(404, r#"{"code":"stream_not_found","message":"missing"}"#),
    ])
    .await;
    let stream = server
        .client(fast_retry_all)
        .basin(basin_name.clone())
        .stream(stream_name.clone());
    let err = stream.append(sample_append_input()).await.unwrap_err();
    assert!(
        matches!(err, AppendError::Server(ref se) if se.code.as_deref() == Some("stream_not_found")),
        "definite earlier attempt must not trigger IndefiniteAppend: {err:?}"
    );
    assert!(err.has_no_side_effects());
    assert!(err.to_string().contains("after 2 attempts"));

    // Case 4: single attempt omits attempt count from Display (E7)
    let server = MockH2Server::from_responses([CannedResponse::new(
        404,
        r#"{"code":"stream_not_found","message":"missing"}"#,
    )])
    .await;
    let stream = server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name);
    let err = stream.append(sample_append_input()).await.unwrap_err();
    let display = err.to_string();
    assert!(display.contains("append"), "E7: {display}");
    assert!(display.contains("test-basin"), "E7: {display}");
    assert!(display.contains("test-stream"), "E7: {display}");
    assert!(!display.contains("attempts"), "E7: {display}");
}

fn encode_s2s_terminal_frame(status: u16, body: &[u8]) -> Bytes {
    let mut frame = Vec::with_capacity(6 + body.len());
    let length = 3 + body.len();
    frame.push(((length >> 16) & 0xff) as u8);
    frame.push(((length >> 8) & 0xff) as u8);
    frame.push((length & 0xff) as u8);
    frame.push(0x80); // terminal flag, uncompressed
    frame.extend_from_slice(&status.to_be_bytes());
    frame.extend_from_slice(body);
    Bytes::from(frame)
}

// spec: r1 E2, E2a, E2b, E5a, E5b, E6, T9
#[tokio::test]
async fn spec_e2_e6_s2s_terminal_frames_end_to_end() {
    let (basin_name, stream_name) = test_basin_and_stream();

    // 1. Append session receiving 412 seq_num_mismatch terminal frame.
    let append_terminal = encode_s2s_terminal_frame(412, br#"{"seq_num_mismatch":12}"#);
    let server = MockH2Server::start(move |_conn_id, req, mut respond| {
        let frame = append_terminal.clone();
        async move {
            let resp = Response::builder()
                .status(200)
                .header("content-type", "s2s/proto")
                .body(())
                .unwrap();
            let Ok(mut send) = respond.send_response(resp, false) else {
                return;
            };
            let mut body = req.into_body();
            let _ = body.data().await;
            let _ = send.send_data(frame, true);
        }
    })
    .await;

    let stream = server
        .client(no_retry_config())
        .basin(basin_name.clone())
        .stream(stream_name.clone());
    let session = stream.append_session(AppendSessionConfig::new()).unwrap();

    let ticket = session
        .submit(sample_append_input())
        .await
        .expect("initial submit accepted");
    let err = ticket.await.expect_err("terminal frame must fail ticket");
    let AppendSessionError::SeqNumMismatch(e) = &err else {
        panic!("expected AppendSessionError::SeqNumMismatch, got {err:?}");
    };
    assert_eq!(e.assignable_seq_num, 12);
    assert_eq!(e.server.status.as_u16(), 412);
    assert!(!err.is_retryable());
    assert!(err.has_no_side_effects());

    // E6: subsequent submit after terminal failure fails with SessionClosedError carrying failure.
    let closed_err = match session.submit(sample_append_input()).await {
        Err(e) => e,
        Ok(t) => t.await.expect_err("failed session must fail"),
    };
    let AppendSessionError::SessionClosed(closed) = &closed_err else {
        panic!("expected SessionClosedError on closed session, got {closed_err:?}");
    };
    assert!(closed_err.has_no_side_effects());
    assert!(!closed_err.is_retryable());
    assert!(
        closed_err.server_error().is_none(),
        "E5a: SessionClosedError must not match as inner ServerError"
    );
    assert!(matches!(
        closed.failure(),
        Some(AppendSessionError::SeqNumMismatch(inner)) if inner.assignable_seq_num == 12
    ));
    let source = closed
        .source()
        .expect("E5b: SessionClosedError sets source");
    assert!(
        source.downcast_ref::<AppendSessionError>().is_some(),
        "E5b: source must downcast directly to AppendSessionError"
    );
    assert!(
        closed.to_string().contains("12"),
        "E6: message includes failure message: {}",
        closed
    );

    // 2. Read session receiving 416 tail terminal frame.
    let read_terminal =
        encode_s2s_terminal_frame(416, br#"{"tail":{"seq_num":5,"timestamp":1234}}"#);
    let read_server = MockH2Server::start(move |_conn_id, _req, mut respond| {
        let frame = read_terminal.clone();
        async move {
            let resp = Response::builder()
                .status(200)
                .header("content-type", "s2s/proto")
                .body(())
                .unwrap();
            if let Ok(mut send) = respond.send_response(resp, false) {
                let _ = send.send_data(frame, true);
            }
        }
    })
    .await;

    let read_stream = read_server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name);
    let mut sess = read_stream
        .read_session(ReadInput::new(), ReadSessionConfig::default())
        .expect("open read session");
    let read_err = {
        use futures_util::StreamExt as _;
        sess.next()
            .await
            .expect("expected terminal error item")
            .expect_err("expected terminal error")
    };
    let ReadSessionError::ReadUnwritten(e) = &read_err else {
        panic!("expected ReadSessionError::ReadUnwritten, got {read_err:?}");
    };
    assert_eq!(e.tail.seq_num, 5);
    assert_eq!(e.tail.timestamp, 1234);
    assert_eq!(e.server.status.as_u16(), 416);
    assert!(!read_err.is_retryable());
    assert!(read_err.has_no_side_effects());
}

// ---------------------------------------------------------------------------
// PR 3 conformance tests: C12, T2d, T4, T6, T6c, T7a, REFUSED_STREAM
// ---------------------------------------------------------------------------

fn encode_s2s_regular_frame(payload: &[u8], reconnect_advised: bool) -> Bytes {
    let mut frame = Vec::with_capacity(4 + payload.len());
    let length = 1 + payload.len();
    frame.push(((length >> 16) & 0xff) as u8);
    frame.push(((length >> 8) & 0xff) as u8);
    frame.push((length & 0xff) as u8);
    frame.push(if reconnect_advised { 0x10 } else { 0x00 });
    frame.extend_from_slice(payload);
    Bytes::from(frame)
}

fn proto_append_ack(start: u64, end: u64) -> Vec<u8> {
    ProtoAppendAck {
        start: Some(ProtoStreamPosition {
            seq_num: start,
            timestamp: 1000,
        }),
        end: Some(ProtoStreamPosition {
            seq_num: end,
            timestamp: 1000,
        }),
        tail: Some(ProtoStreamPosition {
            seq_num: end,
            timestamp: 1000,
        }),
    }
    .encode_to_vec()
}

fn proto_read_batch(seq_num: u64, tail_seq: u64) -> Vec<u8> {
    ProtoReadBatch {
        records: vec![ProtoSequencedRecord {
            seq_num,
            timestamp: 1000,
            headers: vec![],
            body: Bytes::from_static(b"rec"),
        }],
        tail: Some(ProtoStreamPosition {
            seq_num: tail_seq,
            timestamp: 1000,
        }),
    }
    .encode_to_vec()
}

// spec: r1 C12
#[tokio::test]
async fn spec_c12_client_close_aborts_inflight_and_sessions_and_rejects_new_calls() {
    let (basin_name, stream_name) = test_basin_and_stream();

    // Server holds all requests open indefinitely (except GET /records s2s sends 200 headers
    // immediately so ReadSession enters its active streaming state).
    let server = MockH2Server::start(|_conn_id, req, mut respond| async move {
        let is_s2s_read = req.method() == http::Method::GET
            && req
                .headers()
                .get("content-type")
                .is_some_and(|v| v == "s2s/proto");
        let is_s2s_append = req.method() == http::Method::POST
            && req
                .headers()
                .get("content-type")
                .is_some_and(|v| v == "s2s/proto");
        if is_s2s_read || is_s2s_append {
            let resp = Response::builder()
                .status(200)
                .header("content-type", "s2s/proto")
                .body(())
                .unwrap();
            let Ok(_send) = respond.send_response(resp, false) else {
                return;
            };
            std::future::pending::<()>().await;
        } else {
            let _keep = respond;
            std::future::pending::<()>().await;
        }
    })
    .await;

    let s2 = server.client(no_retry_config());
    let basin = s2.basin(basin_name.clone());
    let stream = basin.stream(stream_name.clone());

    let append_session = stream
        .append_session(AppendSessionConfig::new())
        .expect("open append session");
    let producer = stream
        .producer(ProducerConfig::new().with_linger(Duration::from_secs(60)))
        .expect("open producer");
    let mut read_session = stream
        .read_session(ReadInput::new(), ReadSessionConfig::default())
        .expect("open read session");
    let caught_up = read_session.caught_up();

    let append_ticket = append_session
        .submit(sample_append_input())
        .await
        .expect("submit batch");
    let producer_ticket = producer
        .submit(AppendRecord::new("rec").unwrap())
        .await
        .expect("submit record");

    let unary_append = tokio::spawn({
        let stream = stream.clone();
        async move { stream.append(sample_append_input()).await }
    });
    let unary_read = tokio::spawn({
        let stream = stream.clone();
        async move { stream.read(ReadInput::new()).await }
    });
    let read_next = tokio::spawn(async move { read_session.next().await });

    // Give requests a brief moment to be in flight.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Close is synchronous, does not wait for the server, and is idempotent.
    s2.close();
    s2.close();

    // All in-flight calls and sessions fail immediately with AbortedError (well before 5s timeout).
    let append_err = tokio::time::timeout(Duration::from_secs(1), unary_append)
        .await
        .expect("unary append must abort promptly")
        .unwrap()
        .expect_err("unary append must fail");
    assert!(
        matches!(append_err, AppendError::Aborted(_)),
        "{append_err:?}"
    );
    assert!(!append_err.has_no_side_effects());
    assert!(!append_err.is_retryable());

    let read_err = tokio::time::timeout(Duration::from_secs(1), unary_read)
        .await
        .expect("unary read must abort promptly")
        .unwrap()
        .expect_err("unary read must fail");
    assert!(matches!(read_err, ReadError::Aborted(_)), "{read_err:?}");
    assert!(read_err.has_no_side_effects());

    let ticket_err = tokio::time::timeout(Duration::from_secs(1), append_ticket)
        .await
        .expect("append session ticket must abort promptly")
        .expect_err("append session ticket must fail");
    assert!(
        matches!(
            ticket_err,
            AppendSessionError::Aborted(_) | AppendSessionError::SessionClosed(_)
        ),
        "{ticket_err:?}"
    );

    let prod_err = tokio::time::timeout(Duration::from_secs(1), producer_ticket)
        .await
        .expect("producer ticket must abort promptly")
        .expect_err("producer ticket must fail");
    assert!(
        matches!(
            prod_err,
            AppendSessionError::Aborted(_) | AppendSessionError::SessionClosed(_)
        ),
        "{prod_err:?}"
    );

    let read_item = tokio::time::timeout(Duration::from_secs(1), read_next)
        .await
        .expect("read session must abort promptly")
        .unwrap()
        .expect("read session yields AbortedError");
    assert!(
        matches!(read_item, Err(ReadSessionError::Aborted(_))),
        "{read_item:?}"
    );
    let cu_err = tokio::time::timeout(Duration::from_secs(1), caught_up)
        .await
        .expect("caught_up must fail promptly")
        .expect_err("caught_up must fail");
    assert!(matches!(cu_err, ReadSessionError::Aborted(_)), "{cu_err:?}");

    // New calls on closed client or handles fail immediately with ClientClosedError.
    assert!(matches!(
        s2.list_basins(ListBasinsInput::new()).await,
        Err(RequestError::ClientClosed(_))
    ));
    assert!(matches!(
        stream.read(ReadInput::new()).await,
        Err(ReadError::ClientClosed(_))
    ));
    assert!(matches!(
        stream.append(sample_append_input()).await,
        Err(AppendError::ClientClosed(_))
    ));
    assert!(stream.append_session(AppendSessionConfig::new()).is_err());
    assert!(stream.producer(ProducerConfig::new()).is_err());
    assert!(
        stream
            .read_session(ReadInput::new(), ReadSessionConfig::default())
            .is_err()
    );
    assert!(
        stream
            .read_batch_session(ReadInput::new(), ReadSessionConfig::default())
            .is_err()
    );

    // Dropping S2 without calling close() keeps sessions alive.
    let ack_server = MockH2Server::start(|_conn_id, req, mut respond| async move {
        let resp = Response::builder()
            .status(200)
            .header("content-type", "s2s/proto")
            .body(())
            .unwrap();
        let Ok(mut send) = respond.send_response(resp, false) else {
            return;
        };
        let mut body = req.into_body();
        if let Some(Ok(_)) = body.data().await {
            let ack = encode_s2s_regular_frame(&proto_append_ack(0, 1), false);
            let _ = send.send_data(ack, true);
        }
    })
    .await;
    let s2_drop = ack_server.client(no_retry_config());
    let live_session = s2_drop
        .basin(basin_name.clone())
        .stream(stream_name.clone())
        .append_session(AppendSessionConfig::new())
        .expect("open session");
    drop(s2_drop);
    let ack = live_session
        .submit(sample_append_input())
        .await
        .expect("submit after dropping S2")
        .await
        .expect("ack after dropping S2");
    assert_eq!(ack.end.seq_num, 1);

    // C12: closing client aborts a connection still being established (TLS handshake stall).
    let stall_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stall_addr = stall_listener.local_addr().unwrap();
    let stall_task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = stall_listener.accept().await {
            held.push(sock);
        }
    });
    let ep = format!("https://{stall_addr}");
    let endpoints = S2Endpoints::new(
        AccountEndpoint::new(&ep).unwrap(),
        BasinEndpoint::new(&ep).unwrap(),
    )
    .unwrap();
    let stall_s2 = S2::new(
        S2Config::new("test-token")
            .with_endpoints(endpoints)
            .with_insecure_skip_cert_verification(true)
            .with_connection_timeout(Duration::from_secs(10))
            .unwrap()
            .with_request_timeout(Duration::from_secs(10))
            .unwrap()
            .with_retry(no_retry_config()),
    )
    .unwrap();
    let dial_task = tokio::spawn({
        let s2 = stall_s2.clone();
        async move { s2.list_basins(ListBasinsInput::new()).await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    stall_s2.close();
    let dial_err = tokio::time::timeout(Duration::from_secs(1), dial_task)
        .await
        .expect("in-progress connect must abort promptly on close()")
        .unwrap()
        .expect_err("must fail with Aborted");
    assert!(matches!(dial_err, RequestError::Aborted(_)), "{dial_err:?}");
    stall_task.abort();
}

// spec: r1 T7a
#[tokio::test]
async fn spec_t7a_connection_timeout_bounds_tls_handshake() {
    // Raw TCP listener accepts immediately and never sends a TLS ServerHello.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accept_task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });

    let ep = format!("https://{addr}");
    let endpoints = S2Endpoints::new(
        AccountEndpoint::new(&ep).unwrap(),
        BasinEndpoint::new(&ep).unwrap(),
    )
    .unwrap();
    let s2 = S2::new(
        S2Config::new("test-token")
            .with_endpoints(endpoints)
            .with_insecure_skip_cert_verification(true)
            .with_connection_timeout(Duration::from_millis(150))
            .unwrap()
            .with_request_timeout(Duration::from_secs(5))
            .unwrap()
            .with_retry(no_retry_config()),
    )
    .unwrap();

    let start = tokio::time::Instant::now();
    let err = s2
        .list_basins(ListBasinsInput::new())
        .await
        .expect_err("stalled TLS handshake must time out");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "TLS handshake must be bounded by connection_timeout (150ms), took {elapsed:?}"
    );
    assert!(
        matches!(err, RequestError::Connect(_)),
        "T7a: connection_timeout must fail with ConnectError, got {err:?}"
    );
    assert!(err.is_retryable());
    assert!(err.has_no_side_effects());
    accept_task.abort();
}

// spec: r1 T4, T5a, T6
#[tokio::test]
async fn spec_t4_s2_attempt_header_unary_and_sessions() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let fast_retry_3 = RetryConfig::new()
        .with_max_attempts(3)
        .unwrap()
        .with_min_base_delay(Duration::ZERO)
        .with_max_base_delay(Duration::ZERO);

    // 1. Unary s2-attempt header: 1, 2, 3
    let unary_attempts = Arc::new(Mutex::new(Vec::<String>::new()));
    let unary_server = MockH2Server::start({
        let attempts = unary_attempts.clone();
        move |_conn_id, req, mut respond| {
            let attempts = attempts.clone();
            async move {
                let hdr = req
                    .headers()
                    .get("s2-attempt")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_owned();
                let idx = {
                    let mut guard = attempts.lock().unwrap();
                    guard.push(hdr);
                    guard.len()
                };
                if idx < 3 {
                    let resp = Response::builder().status(503).body(()).unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            Bytes::from_static(br#"{"code":"unavailable","message":"busy"}"#),
                            true,
                        );
                    }
                } else {
                    let resp = Response::builder().status(200).body(()).unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            Bytes::from_static(br#"{"basins":[],"has_more":false}"#),
                            true,
                        );
                    }
                }
            }
        }
    })
    .await;

    unary_server
        .client(fast_retry_3.clone())
        .list_basins(ListBasinsInput::new())
        .await
        .expect("unary succeeds on attempt 3");
    assert_eq!(
        *unary_attempts.lock().unwrap(),
        vec!["1", "2", "3"],
        "T4: unary s2-attempt header"
    );

    // 2. AppendSession s2-attempt header across progress, retries, handover, and immediate drain
    let append_attempts = Arc::new(Mutex::new(Vec::<String>::new()));
    let append_server = MockH2Server::start({
        let attempts = append_attempts.clone();
        move |_conn_id, req, mut respond| {
            let attempts = attempts.clone();
            async move {
                let hdr = req
                    .headers()
                    .get("s2-attempt")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_owned();
                let idx = {
                    let mut guard = attempts.lock().unwrap();
                    guard.push(hdr);
                    guard.len()
                };
                match idx {
                    1 => {
                        // Ack batch 1, then drop connection when batch 2 arrives.
                        let resp = Response::builder()
                            .status(200)
                            .header("content-type", "s2s/proto")
                            .body(())
                            .unwrap();
                        let Ok(mut send) = respond.send_response(resp, false) else {
                            return;
                        };
                        let mut body = req.into_body();
                        let _ = body.data().await;
                        let _ = send.send_data(
                            encode_s2s_regular_frame(&proto_append_ack(0, 1), false),
                            false,
                        );
                        let _ = body.data().await;
                        // Close cleanly while batch 2 is unacked -> ConnectionLost -> retry 0.
                        let _ = send.send_data(Bytes::new(), true);
                    }
                    2 => {
                        // Retry 0: fail immediately with 503 unavailable -> retry 1.
                        let resp = Response::builder().status(503).body(()).unwrap();
                        if let Ok(mut send) = respond.send_response(resp, false) {
                            let _ = send.send_data(
                                Bytes::from_static(br#"{"code":"unavailable","message":"busy"}"#),
                                true,
                            );
                        }
                    }
                    3 => {
                        // Retry 1: ack batch 2 with reconnect-advised bit -> handover (attempt 1).
                        let resp = Response::builder()
                            .status(200)
                            .header("content-type", "s2s/proto")
                            .body(())
                            .unwrap();
                        let Ok(mut send) = respond.send_response(resp, false) else {
                            return;
                        };
                        let mut body = req.into_body();
                        let _ = body.data().await;
                        let _ = send.send_data(
                            encode_s2s_regular_frame(&proto_append_ack(1, 2), true),
                            true,
                        );
                    }
                    4 => {
                        // Handover request ends immediately with server_draining before any ack ->
                        // counts as retry 0 (T6) -> next request sends s2-attempt: 2.
                        let resp = Response::builder()
                            .status(200)
                            .header("content-type", "s2s/proto")
                            .body(())
                            .unwrap();
                        if let Ok(mut send) = respond.send_response(resp, false) {
                            let _ = send.send_data(
                                encode_s2s_terminal_frame(
                                    503,
                                    br#"{"code":"server_draining","message":"draining"}"#,
                                ),
                                true,
                            );
                        }
                    }
                    _ => {
                        // Attempt 2: ack batch 3 and close cleanly when client finishes.
                        let resp = Response::builder()
                            .status(200)
                            .header("content-type", "s2s/proto")
                            .body(())
                            .unwrap();
                        let Ok(mut send) = respond.send_response(resp, false) else {
                            return;
                        };
                        let mut body = req.into_body();
                        let _ = body.data().await;
                        let _ = send.send_data(
                            encode_s2s_regular_frame(&proto_append_ack(2, 3), false),
                            false,
                        );
                        while let Some(Ok(_)) = body.data().await {}
                        let _ = send.send_data(Bytes::new(), true);
                    }
                }
            }
        }
    })
    .await;

    let append_stream = append_server
        .client(
            fast_retry_3
                .clone()
                .with_append_retry_policy(AppendRetryPolicy::All),
        )
        .basin(basin_name.clone())
        .stream(stream_name.clone());
    let session = append_stream
        .append_session(AppendSessionConfig::new())
        .expect("open session");

    let ack1 = tokio::time::timeout(Duration::from_secs(3), async {
        session
            .submit(sample_append_input())
            .await
            .unwrap()
            .await
            .unwrap()
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "ack1 timed out; attempts={:?}",
            *append_attempts.lock().unwrap()
        )
    });
    assert_eq!(ack1.end.seq_num, 1);
    let ack2 = tokio::time::timeout(Duration::from_secs(3), async {
        session
            .submit(sample_append_input())
            .await
            .unwrap()
            .await
            .unwrap()
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "ack2 timed out; attempts={:?}",
            *append_attempts.lock().unwrap()
        )
    });
    assert_eq!(ack2.end.seq_num, 2);
    let ack3 = tokio::time::timeout(Duration::from_secs(3), async {
        session
            .submit(sample_append_input())
            .await
            .unwrap()
            .await
            .unwrap()
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "ack3 timed out; attempts={:?}",
            *append_attempts.lock().unwrap()
        )
    });
    assert_eq!(ack3.end.seq_num, 3);
    tokio::time::timeout(Duration::from_secs(3), session.close())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "close timed out; attempts={:?}",
                *append_attempts.lock().unwrap()
            )
        })
        .unwrap();

    assert_eq!(
        *append_attempts.lock().unwrap(),
        vec!["1", "2", "3", "1", "2"],
        "T4/T5a/T6: append session s2-attempt header sequence"
    );

    // 3. ReadSession s2-attempt header + T6 immediate server_draining exhaustion
    let read_attempts = Arc::new(Mutex::new(Vec::<String>::new()));
    let read_server = MockH2Server::start({
        let attempts = read_attempts.clone();
        move |_conn_id, req, mut respond| {
            let attempts = attempts.clone();
            async move {
                let hdr = req
                    .headers()
                    .get("s2-attempt")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_owned();
                let idx = {
                    let mut guard = attempts.lock().unwrap();
                    guard.push(hdr);
                    guard.len()
                };
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "s2s/proto")
                    .body(())
                    .unwrap();
                let Ok(mut send) = respond.send_response(resp, false) else {
                    return;
                };
                if idx == 1 {
                    // Progress (batch 0), then server_draining -> handover (attempt 1, no budget
                    // used).
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_read_batch(0, 1), false),
                        false,
                    );
                }
                let _ = send.send_data(
                    encode_s2s_terminal_frame(
                        503,
                        br#"{"code":"server_draining","message":"draining"}"#,
                    ),
                    true,
                );
            }
        }
    })
    .await;

    let mut read_session = read_server
        .client(fast_retry_3)
        .basin(basin_name)
        .stream(stream_name)
        .read_session(ReadInput::new(), ReadSessionConfig::default())
        .expect("open read session");
    let first = tokio::time::timeout(Duration::from_secs(3), read_session.next())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "read first timed out; attempts={:?}",
                *read_attempts.lock().unwrap()
            )
        })
        .unwrap()
        .unwrap();
    assert_eq!(first.seq_num, 0);
    let err = tokio::time::timeout(Duration::from_secs(3), read_session.next())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "read err timed out; attempts={:?}",
                *read_attempts.lock().unwrap()
            )
        })
        .expect("should terminate with server_draining")
        .expect_err("must exhaust budget on immediate server_draining");
    assert!(
        matches!(err, ReadSessionError::Server(ref se) if se.code.as_deref() == Some("server_draining")),
        "{err:?}"
    );
    assert_eq!(
        *read_attempts.lock().unwrap(),
        vec!["1", "1", "2", "3"],
        "T4/T6: read session handover then budgeted retries on immediate server_draining"
    );
}

// spec: r1 T2d
#[tokio::test]
async fn spec_t2d_definite_only_retries_for_token_and_network_policy() {
    let fast_retry_3 = RetryConfig::new()
        .with_max_attempts(3)
        .unwrap()
        .with_min_base_delay(Duration::ZERO)
        .with_max_base_delay(Duration::ZERO);

    let token_input = || {
        IssueAccessTokenInput::new(
            "tok-1".parse::<AccessTokenId>().unwrap(),
            AccessTokenScopeInput::from_op_group_perms(OperationGroupPermissions::read_write_all()),
        )
    };
    let policy_input = || {
        CreateNetworkPolicyInput::new(
            "pol-1".parse().unwrap(),
            NetworkPolicy::new().with_public_net(PublicNetPolicy::Cidrs(vec![
                "192.0.2.0/24".parse().unwrap(),
            ])),
        )
    };

    // 1. issue_access_token does NOT retry indefinite 503 unavailable
    let server = MockH2Server::from_responses([CannedResponse::new(
        503,
        r#"{"code":"unavailable","message":"busy"}"#,
    )])
    .await;
    let err = server
        .client(fast_retry_3.clone())
        .issue_access_token(token_input())
        .await
        .expect_err("must not retry indefinite error");
    assert!(matches!(err, RequestError::Server(_)));
    assert_eq!(server.request_count(), 1);

    // 2. issue_access_token DOES retry definite 503 server_draining
    let server = MockH2Server::from_responses([
        CannedResponse::new(503, r#"{"code":"server_draining","message":"draining"}"#),
        CannedResponse::new(201, r#"{"access_token":"secret-tok"}"#),
    ])
    .await;
    let tok = server
        .client(fast_retry_3.clone())
        .issue_access_token(token_input())
        .await
        .expect("must retry definite server_draining");
    assert_eq!(tok, "secret-tok");
    assert_eq!(server.request_count(), 2);

    // 3. create_network_policy does NOT retry indefinite 503 unavailable
    let server = MockH2Server::from_responses([CannedResponse::new(
        503,
        r#"{"code":"unavailable","message":"busy"}"#,
    )])
    .await;
    let err = server
        .client(fast_retry_3.clone())
        .create_network_policy(policy_input())
        .await
        .expect_err("must not retry indefinite error");
    assert!(matches!(err, RequestError::Server(_)));
    assert_eq!(server.request_count(), 1);

    // 4. create_network_policy DOES retry definite 429 rate_limited
    let server = MockH2Server::from_responses([
        CannedResponse::new(429, r#"{"code":"rate_limited","message":"slow down"}"#),
        CannedResponse::new(
            201,
            r#"{"id":"pol-1.abcd1234","slug":"pol-1","created_at":"2026-01-01T00:00:00Z","policy":{"public_net":{"cidrs":["192.0.2.0/24"]}}}"#,
        ),
    ])
    .await;
    let info = server
        .client(fast_retry_3)
        .create_network_policy(policy_input())
        .await
        .expect("must retry definite rate_limited");
    assert_eq!(info.id.slug().as_ref(), "pol-1");
    assert_eq!(server.request_count(), 2);
}

// spec: r1 T6, T6c
#[tokio::test]
async fn spec_t6_connection_retirement_on_server_draining_and_hot_server() {
    let fast_retry_2 = RetryConfig::new()
        .with_max_attempts(2)
        .unwrap()
        .with_min_base_delay(Duration::ZERO)
        .with_max_base_delay(Duration::ZERO);

    // Helper: serve first status+body, then 200 empty basins list, recording conn_id per request.
    async fn run_unary_retirement_case(
        retry: RetryConfig,
        first_status: u16,
        first_body: &'static [u8],
    ) -> Vec<usize> {
        let seen_conns = Arc::new(Mutex::new(Vec::<usize>::new()));
        let count = Arc::new(AtomicUsize::new(0));
        let server = MockH2Server::start({
            let seen_conns = seen_conns.clone();
            let count = count.clone();
            move |conn_id, _req, mut respond| {
                let seen_conns = seen_conns.clone();
                let count = count.clone();
                async move {
                    seen_conns.lock().unwrap().push(conn_id);
                    let n = count.fetch_add(1, Ordering::SeqCst);
                    if n == 0 {
                        let resp = Response::builder().status(first_status).body(()).unwrap();
                        if let Ok(mut send) = respond.send_response(resp, false) {
                            let _ = send.send_data(Bytes::from_static(first_body), true);
                        }
                    } else {
                        let resp = Response::builder().status(200).body(()).unwrap();
                        if let Ok(mut send) = respond.send_response(resp, false) {
                            let _ = send.send_data(
                                Bytes::from_static(br#"{"basins":[],"has_more":false}"#),
                                true,
                            );
                        }
                    }
                }
            }
        })
        .await;

        server
            .client(retry)
            .list_basins(ListBasinsInput::new())
            .await
            .expect("retry must succeed");
        seen_conns.lock().unwrap().clone()
    }

    // 1. Unary server_draining retires connection -> retry opens a new connection.
    let conns = run_unary_retirement_case(
        fast_retry_2.clone(),
        503,
        br#"{"code":"server_draining","message":"draining"}"#,
    )
    .await;
    assert_eq!(conns.len(), 2);
    assert_ne!(
        conns[0], conns[1],
        "T6/T6c: unary server_draining must retire connection"
    );

    // 2. Unary hot_server retires connection -> retry opens a new connection.
    let conns = run_unary_retirement_case(
        fast_retry_2.clone(),
        502,
        br#"{"code":"hot_server","message":"hot"}"#,
    )
    .await;
    assert_eq!(conns.len(), 2);
    assert_ne!(
        conns[0], conns[1],
        "T6/T6c: unary hot_server must retire connection"
    );

    // 3. Ordinary retryable 503 unavailable keeps using the same pooled connection.
    let conns = run_unary_retirement_case(
        fast_retry_2.clone(),
        503,
        br#"{"code":"unavailable","message":"busy"}"#,
    )
    .await;
    assert_eq!(conns.len(), 2);
    assert_eq!(
        conns[0], conns[1],
        "ordinary 503 unavailable should reuse pooled connection"
    );

    // 4. Session hot_server retires connection AND consumes retry budget even after progress (T6c).
    let (basin_name, stream_name) = test_basin_and_stream();
    let session_conns = Arc::new(Mutex::new(Vec::<usize>::new()));
    let session_server = MockH2Server::start({
        let session_conns = session_conns.clone();
        move |conn_id, _req, mut respond| {
            let session_conns = session_conns.clone();
            async move {
                let idx = {
                    let mut guard = session_conns.lock().unwrap();
                    guard.push(conn_id);
                    guard.len()
                };
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "s2s/proto")
                    .body(())
                    .unwrap();
                let Ok(mut send) = respond.send_response(resp, false) else {
                    return;
                };
                if idx == 1 {
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_read_batch(0, 1), false),
                        false,
                    );
                }
                let _ = send.send_data(
                    encode_s2s_terminal_frame(502, br#"{"code":"hot_server","message":"hot"}"#),
                    true,
                );
            }
        }
    })
    .await;

    let mut read_session = session_server
        .client(fast_retry_2)
        .basin(basin_name)
        .stream(stream_name)
        .read_session(ReadInput::new(), ReadSessionConfig::default())
        .expect("open read session");
    let _ = read_session.next().await.unwrap().unwrap();
    let err = read_session
        .next()
        .await
        .expect("must fail after hot_server consumes budget")
        .expect_err("hot_server must exhaust budget");
    assert!(
        matches!(err, ReadSessionError::Server(ref se) if se.code.as_deref() == Some("hot_server")),
        "{err:?}"
    );
    let conns = session_conns.lock().unwrap().clone();
    assert_eq!(conns.len(), 2, "T6c: hot_server consumes retry budget");
    assert_ne!(
        conns[0], conns[1],
        "T6c: session hot_server must retire connection"
    );
}

// spec: r1 E3, E4d, T1, T2c
#[tokio::test]
async fn spec_refused_stream_classified_as_definite_and_retried_under_no_side_effects() {
    let (basin_name, stream_name) = test_basin_and_stream();

    // 1. With max_attempts = 1: REFUSED_STREAM is ConnectionLostError with has_no_side_effects =
    //    true.
    let server = MockH2Server::start(|_conn_id, _req, mut respond| async move {
        respond.send_reset(h2::Reason::REFUSED_STREAM);
    })
    .await;
    let stream = server
        .client(no_retry_config().with_append_retry_policy(AppendRetryPolicy::NoSideEffects))
        .basin(basin_name.clone())
        .stream(stream_name.clone());
    let err = stream
        .append(sample_append_input())
        .await
        .expect_err("REFUSED_STREAM must fail with max_attempts = 1");
    assert!(
        matches!(err, AppendError::ConnectionLost(_)),
        "expected ConnectionLost, got {err:?}"
    );
    assert!(err.is_retryable());
    assert!(
        err.has_no_side_effects(),
        "REFUSED_STREAM must be definite (has_no_side_effects == true)"
    );

    // 2. With max_attempts = 2 + AppendRetryPolicy::NoSideEffects: REFUSED_STREAM is retried!
    let count = Arc::new(AtomicUsize::new(0));
    let server = MockH2Server::start({
        let count = count.clone();
        move |_conn_id, _req, mut respond| {
            let count = count.clone();
            async move {
                let n = count.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                } else {
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "application/protobuf")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(Bytes::from(proto_append_ack(0, 1)), true);
                    }
                }
            }
        }
    })
    .await;
    let retry = RetryConfig::new()
        .with_max_attempts(2)
        .unwrap()
        .with_min_base_delay(Duration::ZERO)
        .with_max_base_delay(Duration::ZERO)
        .with_append_retry_policy(AppendRetryPolicy::NoSideEffects);
    let ack = server
        .client(retry)
        .basin(basin_name)
        .stream(stream_name)
        .append(sample_append_input())
        .await
        .expect("NoSideEffects must retry definite REFUSED_STREAM");
    assert_eq!(ack.end.seq_num, 1);
    assert_eq!(count.load(Ordering::SeqCst), 2);

    // 3. T2c: With AppendRetryPolicy::NoSideEffects, an indefinite retryable error (500 internal)
    //    must NOT be retried even when max_attempts > 1!
    let indefinite_hits = Arc::new(AtomicUsize::new(0));
    let indefinite_server = MockH2Server::start({
        let indefinite_hits = indefinite_hits.clone();
        move |_conn_id, _req, mut respond| {
            let indefinite_hits = indefinite_hits.clone();
            async move {
                indefinite_hits.fetch_add(1, Ordering::SeqCst);
                let resp = Response::builder()
                    .status(500)
                    .header("content-type", "application/json")
                    .body(())
                    .unwrap();
                if let Ok(mut send) = respond.send_response(resp, false) {
                    let _ = send.send_data(
                        Bytes::from_static(br#"{"code":"internal","message":"boom"}"#),
                        true,
                    );
                }
            }
        }
    })
    .await;
    let (basin_name, stream_name) = test_basin_and_stream();
    let err = indefinite_server
        .client(
            RetryConfig::new()
                .with_max_attempts(3)
                .unwrap()
                .with_min_base_delay(Duration::ZERO)
                .with_max_base_delay(Duration::ZERO)
                .with_append_retry_policy(AppendRetryPolicy::NoSideEffects),
        )
        .basin(basin_name)
        .stream(stream_name)
        .append(sample_append_input())
        .await
        .expect_err("T2c: indefinite 500 must not be retried under NoSideEffects");
    assert!(matches!(err, AppendError::Server(_)), "{err:?}");
    assert!(!err.has_no_side_effects());
    assert_eq!(
        indefinite_hits.load(Ordering::SeqCst),
        1,
        "T2c: must not retry indefinite error under NoSideEffects"
    );
}

// ---------------------------------------------------------------------------
// PR 4 conformance tests: A1-A9, T6a, T6b, T7c, T8, T9, T10
// ---------------------------------------------------------------------------

async fn read_exact_h2_bytes(body: &mut h2::RecvStream, min_bytes: usize) -> usize {
    let mut total = 0;
    while total < min_bytes {
        match body.data().await {
            Some(Ok(chunk)) => total += chunk.len(),
            _ => break,
        }
    }
    total
}

async fn read_one_s2s_frame(
    body: &mut h2::RecvStream,
    buf: &mut BytesMut,
    release_flow_control: bool,
) -> Option<SessionMessage> {
    let mut decoder = FrameDecoder;
    loop {
        if let Ok(Some(msg)) = decoder.decode(buf) {
            return Some(msg);
        }
        match body.data().await {
            Some(Ok(chunk)) => {
                let len = chunk.len();
                buf.extend_from_slice(&chunk);
                if release_flow_control {
                    let _ = body.flow_control().release_capacity(len);
                }
            }
            _ => return None,
        }
    }
}

fn sized_append_input(body_len: usize) -> AppendInput {
    AppendInput::new(
        AppendRecordBatch::try_from_iter([AppendRecord::new(vec![b'x'; body_len]).unwrap()])
            .unwrap(),
    )
}

// spec: r1 A2, A2a, A2b, A2c, A2d, A5
#[tokio::test]
async fn spec_a2_validation_before_capacity_and_split_reserve_submit() {
    let (basin_name, stream_name) = test_basin_and_stream();

    // Server holds the first batch unacked until released so capacity is full.
    let release = Arc::new(tokio::sync::Notify::new());
    let server = MockH2Server::start({
        let release = release.clone();
        move |_conn_id, req, mut respond| {
            let release = release.clone();
            async move {
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "s2s/proto")
                    .body(())
                    .unwrap();
                let Ok(mut send) = respond.send_response(resp, false) else {
                    return;
                };
                let mut body = req.into_body();
                let mut buf = BytesMut::new();
                let mut seq = 0u64;
                while read_one_s2s_frame(&mut body, &mut buf, true)
                    .await
                    .is_some()
                {
                    release.notified().await;
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_append_ack(seq, seq + 1), false),
                        false,
                    );
                    seq += 1;
                }
                let _ = send.send_data(Bytes::new(), true);
            }
        }
    })
    .await;

    let stream = server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name);

    // 1. AppendSession: reserve() validates before waiting for capacity; permit.submit() rejects
    //    batches larger than reserved_bytes, releases reservation, and leaves session open.
    let session = stream
        .append_session(
            AppendSessionConfig::new()
                .with_max_unacked_batches(1)
                .unwrap(),
        )
        .unwrap();

    // Invalid reserve sizes fail immediately with ValidationError.
    let err = session.reserve(0).await.expect_err("0 bytes invalid");
    assert!(matches!(err, AppendSessionError::Validation(_)), "{err:?}");
    assert!(err.has_no_side_effects());
    let err = session.reserve(7).await.expect_err("7 bytes invalid");
    assert!(matches!(err, AppendSessionError::Validation(_)), "{err:?}");
    let err = session
        .reserve(1024 * 1024 + 1)
        .await
        .expect_err("> 1 MiB invalid");
    assert!(matches!(err, AppendSessionError::Validation(_)), "{err:?}");

    // Split reserve + submit with batch larger than reservation fails with ValidationError,
    // releases reservation, and leaves session open!
    let permit = session.reserve(10).await.unwrap();
    let too_big = sized_append_input(100); // 108 metered bytes > 10 reserved
    let err = permit
        .submit(too_big)
        .expect_err("batch > reservation must fail Validation");
    assert!(matches!(err, AppendSessionError::Validation(_)), "{err:?}");

    // Reservation was released (max_unacked_batches == 1): another submit succeeds immediately!
    let t1 = session.submit(sample_append_input()).await.unwrap();
    // Capacity is now full (1/1). Invalid reserve() STILL fails immediately without blocking!
    let err = tokio::time::timeout(Duration::from_millis(200), session.reserve(1024 * 1024 + 1))
        .await
        .expect("validation must not wait for capacity")
        .unwrap_err();
    assert!(matches!(err, AppendSessionError::Validation(_)), "{err:?}");

    release.notify_one();
    assert_eq!(t1.await.unwrap().end.seq_num, 1);
    session.close().await.unwrap();

    // 2. Producer: record > max_batch_bytes fails immediately before waiting, accepts nothing, and
    //    leaves producer open.
    let producer = stream
        .producer(
            ProducerConfig::new()
                .with_max_batch_bytes(64)
                .unwrap()
                .with_linger(Duration::from_secs(60)),
        )
        .unwrap();

    let oversized = AppendRecord::new(vec![b'a'; 100]).unwrap();
    let err = producer
        .submit(oversized)
        .await
        .expect_err("record > max_batch_bytes must fail");
    assert!(matches!(err, AppendSessionError::Validation(_)), "{err:?}");
    assert!(err.has_no_side_effects());

    // Split reserve + oversized submit releases reservation and leaves producer open.
    let r_permit = producer.reserve(16).await.unwrap();
    let err = r_permit
        .submit(AppendRecord::new(vec![b'b'; 20]).unwrap())
        .expect_err("record > reservation must fail");
    assert!(matches!(err, AppendSessionError::Validation(_)), "{err:?}");

    // Producer is still open and works normally.
    let t = producer
        .submit(AppendRecord::new("ok").unwrap())
        .await
        .unwrap();
    let close_fut = producer.close();
    release.notify_one();
    close_fut.await.unwrap();
    assert_eq!(t.await.unwrap().seq_num, 0);
}

// spec: r1 A3, A3a, A3b, T9
#[tokio::test]
async fn spec_a3_t9_lazy_open_and_idle_disconnect_uses_no_budget() {
    let (basin_name, stream_name) = test_basin_and_stream();

    let seen_attempts = Arc::new(Mutex::new(Vec::<String>::new()));
    let server = MockH2Server::start({
        let seen_attempts = seen_attempts.clone();
        move |_conn_id, req, mut respond| {
            let seen_attempts = seen_attempts.clone();
            async move {
                let hdr = req
                    .headers()
                    .get("s2-attempt")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_owned();
                let idx = {
                    let mut g = seen_attempts.lock().unwrap();
                    g.push(hdr);
                    g.len()
                };
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "s2s/proto")
                    .body(())
                    .unwrap();
                let Ok(mut send) = respond.send_response(resp, false) else {
                    return;
                };
                let mut body = req.into_body();
                let mut buf = BytesMut::new();
                match idx {
                    1 => {
                        // Ack batch 0, then immediately close cleanly while idle (T9).
                        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                        let _ = send.send_data(
                            encode_s2s_regular_frame(&proto_append_ack(0, 1), false),
                            true,
                        );
                    }
                    2 => {
                        // Ack batch 1, then abruptly reset stream while idle (T9).
                        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                        let _ = send.send_data(
                            encode_s2s_regular_frame(&proto_append_ack(1, 2), false),
                            false,
                        );
                        tokio::time::sleep(Duration::from_millis(30)).await;
                        send.send_reset(h2::Reason::INTERNAL_ERROR);
                    }
                    _ => {
                        // Ack batch 2 and wait for close.
                        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                        let _ = send.send_data(
                            encode_s2s_regular_frame(&proto_append_ack(2, 3), false),
                            false,
                        );
                        while let Some(Ok(_)) = body.data().await {}
                        let _ = send.send_data(Bytes::new(), true);
                    }
                }
            }
        }
    })
    .await;

    // max_attempts = 1: ANY budget consumption would immediately fail the session!
    let stream = server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name);

    // 1. Opening and closing idle AppendSession and Producer sends ZERO HTTP requests (A3).
    let idle_sess = stream.append_session(AppendSessionConfig::new()).unwrap();
    let idle_prod = stream.producer(ProducerConfig::new()).unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        server.request_count(),
        0,
        "A3: opening must send no request"
    );
    idle_sess.close().await.unwrap();
    idle_prod.close().await.unwrap();
    assert_eq!(
        server.request_count(),
        0,
        "A3: closing idle sessions must send no request"
    );

    // 2. Idle clean end and idle stream break cost zero budget and do not open a new request until
    //    the next batch arrives (A3, T9).
    let session = stream.append_session(AppendSessionConfig::new()).unwrap();
    assert_eq!(server.request_count(), 0);

    let ack0 = session
        .submit(sample_append_input())
        .await
        .unwrap()
        .await
        .unwrap();
    assert_eq!(ack0.end.seq_num, 1);
    // Give idle clean EOF time to be processed; must NOT open request #2 yet.
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(
        server.request_count(),
        1,
        "A3: idle clean end must not eagerly open a new request"
    );

    let ack1 = session
        .submit(sample_append_input())
        .await
        .unwrap()
        .await
        .unwrap();
    assert_eq!(ack1.end.seq_num, 2);
    // Wait for server to send RST_STREAM while idle; must NOT fail or eagerly reconnect.
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
        server.request_count(),
        2,
        "A3/T9: idle break must not eagerly open a new request"
    );

    let ack2 = session
        .submit(sample_append_input())
        .await
        .unwrap()
        .await
        .unwrap();
    assert_eq!(ack2.end.seq_num, 3);
    session.close().await.unwrap();

    assert_eq!(
        *seen_attempts.lock().unwrap(),
        vec!["1", "1", "1"],
        "T9/T4: idle ends consume zero retry budget"
    );
}

// spec: r1 A4, A4a, A4b, A4c, T8
#[tokio::test]
async fn spec_a4_fifo_capacity_cancel_and_closing_wakes_waiters() {
    let (basin_name, stream_name) = test_basin_and_stream();

    let ack_gate = Arc::new(tokio::sync::Notify::new());
    let server = MockH2Server::start({
        let ack_gate = ack_gate.clone();
        move |_conn_id, req, mut respond| {
            let ack_gate = ack_gate.clone();
            async move {
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "s2s/proto")
                    .body(())
                    .unwrap();
                let Ok(mut send) = respond.send_response(resp, false) else {
                    return;
                };
                let mut body = req.into_body();
                let mut buf = BytesMut::new();
                let mut seq = 0u64;
                while read_one_s2s_frame(&mut body, &mut buf, true)
                    .await
                    .is_some()
                {
                    ack_gate.notified().await;
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_append_ack(seq, seq + 1), false),
                        false,
                    );
                    seq += 1;
                }
                let _ = send.send_data(Bytes::new(), true);
            }
        }
    })
    .await;

    let stream = server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name);

    // 1. FIFO capacity: max_unacked_bytes = 1 MiB. Batch 1 takes 700 KiB -> 324 KiB remaining.
    //    Waiter A requests 500 KiB (must wait). Waiter B requests 200 KiB (fits in 324 KiB, but
    //    MUST queue behind Waiter A!).
    let session = Arc::new(
        stream
            .append_session(
                AppendSessionConfig::new()
                    .with_max_unacked_bytes(1024 * 1024)
                    .unwrap(),
            )
            .unwrap(),
    );

    let b1 = session
        .submit(sized_append_input(700 * 1024))
        .await
        .unwrap();

    let order = Arc::new(Mutex::new(Vec::<&'static str>::new()));
    let waiter_a = tokio::spawn({
        let session = session.clone();
        let order = order.clone();
        async move {
            let permit = session.reserve(500 * 1024).await.unwrap();
            order.lock().unwrap().push("A");
            permit
        }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let waiter_b = tokio::spawn({
        let session = session.clone();
        let order = order.clone();
        async move {
            let permit = session.reserve(200 * 1024).await.unwrap();
            order.lock().unwrap().push("B");
            permit
        }
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        order.lock().unwrap().is_empty(),
        "A4a: Waiter B must not overtake Waiter A even when 200 KiB fits"
    );

    // Cancel a third waiter before capacity frees (A4c, T8): accepts nothing, session unaffected.
    {
        let mut canceled = Box::pin(session.reserve(100 * 1024));
        assert!(futures_util::poll!(canceled.as_mut()).is_pending());
        drop(canceled);
    }

    // Ack Batch 1 -> Waiter A gets capacity first, then Waiter B!
    ack_gate.notify_one();
    assert_eq!(b1.await.unwrap().end.seq_num, 1);
    let permit_a = waiter_a.await.unwrap();
    let permit_b = waiter_b.await.unwrap();
    assert_eq!(*order.lock().unwrap(), vec!["A", "B"]);
    drop(permit_a);
    drop(permit_b);

    // 2. Waiting submit() fails immediately with SessionClosedError when close() begins (A4c), even
    //    while Batch 2 is still unacked!
    let b2 = session
        .submit(sized_append_input(700 * 1024))
        .await
        .unwrap();
    let blocked_submit = tokio::spawn({
        let session = session.clone();
        async move { session.submit(sized_append_input(500 * 1024)).await }
    });
    tokio::time::sleep(Duration::from_millis(30)).await;

    let close_task = tokio::spawn({
        let session = session.clone();
        async move { session.close().await }
    });

    let err = tokio::time::timeout(Duration::from_secs(1), blocked_submit)
        .await
        .expect("A4c: waiting submit must wake immediately when close() begins")
        .unwrap()
        .expect_err("must fail with SessionClosed");
    assert!(
        matches!(err, AppendSessionError::SessionClosed(ref c) if c.failure().is_none()),
        "{err:?}"
    );
    assert!(err.has_no_side_effects());

    // Now let Batch 2 finish so close() completes cleanly.
    ack_gate.notify_one();
    assert_eq!(b2.await.unwrap().end.seq_num, 2);
    close_task.await.unwrap().unwrap();
}

// spec: r1 A5, A5a, A5b
#[tokio::test]
async fn spec_a5_a5b_batcher_conformance_and_producer_match_seq_overflow() {
    let (basin_name, stream_name) = test_basin_and_stream();

    // 1. Batcher backpressure, fencing_token, match_seq_num, partial drop on error, clean end.
    let polled = Arc::new(AtomicUsize::new(0));
    let input_stream = futures_util::stream::poll_fn({
        let polled = polled.clone();
        move |_cx| {
            let i = polled.fetch_add(1, Ordering::SeqCst);
            if i < 5 {
                std::task::Poll::Ready(Some(AppendRecord::new(format!("rec-{i}")).unwrap()))
            } else {
                std::task::Poll::Ready(None)
            }
        }
    });
    let token: FencingToken = "f-tok".parse().unwrap();
    let mut batcher = Batcher::new(
        input_stream,
        BatcherConfig::new()
            .with_max_batch_records(2)
            .unwrap()
            .with_fencing_token(token.clone())
            .with_match_seq_num(50),
    );
    let b0 = batcher.next().await.unwrap().unwrap();
    assert_eq!(b0.records.len(), 2);
    assert_eq!(b0.match_seq_num, Some(50));
    assert_eq!(b0.fencing_token.as_ref(), Some(&token));
    assert_eq!(
        polled.load(Ordering::SeqCst),
        2,
        "A5b: must not poll next record while completed batch waits"
    );
    // Drop consumer early (A5b): stops and drops any remaining work.
    drop(batcher);
    assert_eq!(polled.load(Ordering::SeqCst), 2);

    // TryBatcher input error drops partial batch immediately.
    let err_stream = futures_util::stream::iter(vec![
        Ok(AppendRecord::new("partial").unwrap()),
        Err("input-failed"),
    ]);
    let items: Vec<_> = Batcher::try_new(err_stream, BatcherConfig::new())
        .collect()
        .await;
    assert_eq!(items.len(), 1);
    assert!(matches!(
        items[0],
        Err(TryBatchError::Input("input-failed"))
    ));

    // 2. Producer match_seq_num overflow rejects submit() with ValidationError without accepting
    //    and leaves the producer open to flush/close earlier accepted records (A5).
    let wire_match_seq = Arc::new(std::sync::Mutex::new(None::<u64>));
    let wire_match_seq_srv = wire_match_seq.clone();
    let server = MockH2Server::start(move |_conn_id, req, mut respond| {
        let wire_match_seq_srv = wire_match_seq_srv.clone();
        async move {
            let resp = Response::builder()
                .status(200)
                .header("content-type", "s2s/proto")
                .body(())
                .unwrap();
            let Ok(mut send) = respond.send_response(resp, false) else {
                return;
            };
            let mut body = req.into_body();
            let mut buf = BytesMut::new();
            if let Some(SessionMessage::Regular(regular)) =
                read_one_s2s_frame(&mut body, &mut buf, true).await
            {
                let payload = regular.decompressed().unwrap();
                let decoded = api::stream::proto::AppendInput::decode(payload).unwrap();
                *wire_match_seq_srv.lock().unwrap() = decoded.match_seq_num;
                let _ = send.send_data(
                    encode_s2s_regular_frame(&proto_append_ack(u64::MAX - 1, u64::MAX), false),
                    false,
                );
            }
            while let Some(Ok(_)) = body.data().await {}
            let _ = send.send_data(Bytes::new(), true);
        }
    })
    .await;

    let producer = server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name)
        .producer(
            ProducerConfig::new()
                .with_match_seq_num(u64::MAX)
                .with_linger(Duration::from_secs(60)),
        )
        .unwrap();

    // First record takes u64::MAX (valid).
    let t_max = producer
        .submit(AppendRecord::new("last").unwrap())
        .await
        .unwrap();
    // Second record would overflow u64::MAX -> ValidationError immediately, producer stays open!
    let err = producer
        .submit(AppendRecord::new("overflow").unwrap())
        .await
        .expect_err("overflowing match_seq_num must fail with ValidationError");
    assert!(matches!(err, AppendSessionError::Validation(_)), "{err:?}");
    assert!(err.has_no_side_effects());

    // Producer is still open and closes cleanly delivering the first record with exact wire seq!
    producer.close().await.unwrap();
    let ack = t_max.await.unwrap();
    assert_eq!(ack.seq_num, u64::MAX - 1);
    assert_eq!(*wire_match_seq.lock().unwrap(), Some(u64::MAX));
}

// spec: r1 A6, A6a, A6b, A6c, A6d, A8, A8b, A9, T10
#[tokio::test]
async fn spec_a6_a9_outcome_table_all_five_scenarios_and_producer_passthrough() {
    let (basin_name, stream_name) = test_basin_and_stream();

    // Helper: runs the exact 3-batch scenario (A=40 KiB, B=40 KiB, C=1 KiB) where A and B fill
    // the 65535-byte HTTP/2 initial stream flow-control window so A and B are guaranteed sent while
    // C is guaranteed accepted but NEVER sent!
    enum Scenario {
        Reject412,
        FailStorage,
        ConnectionLost,
        RetryThen412,
        ClientClose,
    }

    async fn run_scenario(
        basin_name: BasinName,
        stream_name: StreamName,
        scenario: Scenario,
    ) -> (
        AppendSessionError,
        AppendSessionError,
        AppendSessionError,
        AppendSessionError,
    ) {
        let ab_sent = Arc::new(tokio::sync::Notify::new());
        let attempt_num = Arc::new(AtomicUsize::new(0));
        let is_retry = matches!(scenario, Scenario::RetryThen412);
        let is_close = matches!(scenario, Scenario::ClientClose);
        let scenario_code = match scenario {
            Scenario::Reject412 => 1,
            Scenario::FailStorage => 2,
            Scenario::ConnectionLost => 3,
            Scenario::RetryThen412 => 4,
            Scenario::ClientClose => 5,
        };

        let server = MockH2Server::start({
            let ab_sent = ab_sent.clone();
            let attempt_num = attempt_num.clone();
            move |_conn_id, req, mut respond| {
                let ab_sent = ab_sent.clone();
                let attempt_num = attempt_num.clone();
                async move {
                    let n = attempt_num.fetch_add(1, Ordering::SeqCst);
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "s2s/proto")
                        .body(())
                        .unwrap();
                    let Ok(mut send) = respond.send_response(resp, false) else {
                        return;
                    };
                    let mut body = req.into_body();
                    // Read > 42 KiB WITHOUT releasing flow-control capacity so A (40 KiB) and at
                    // least the first chunk of B (40 KiB) are guaranteed sent while the 65535-byte
                    // H2 window blocks C from ever leaving the SDK!
                    let _ = read_exact_h2_bytes(&mut body, 50 * 1024).await;
                    match scenario_code {
                        1 => {
                            let _ = send.send_data(
                                encode_s2s_terminal_frame(412, br#"{"seq_num_mismatch":99}"#),
                                true,
                            );
                        }
                        2 => {
                            let _ = send.send_data(
                                encode_s2s_terminal_frame(
                                    500,
                                    br#"{"code":"storage","message":"disk err"}"#,
                                ),
                                true,
                            );
                        }
                        3 => {
                            let _ = send.send_data(Bytes::new(), true);
                        }
                        4 => {
                            if n == 0 {
                                // Attempt 1: connection lost (indefinite) -> sets prior_uncertainty
                                // on A and B (not C!).
                                let _ = send.send_data(Bytes::new(), true);
                            } else {
                                // Attempt 2: server rejects A with definite 412.
                                let _ = send.send_data(
                                    encode_s2s_terminal_frame(412, br#"{"seq_num_mismatch":99}"#),
                                    true,
                                );
                            }
                        }
                        5 => {
                            ab_sent.notify_one();
                            std::future::pending::<()>().await;
                        }
                        _ => unreachable!(),
                    }
                }
            }
        })
        .await;

        let retry = if is_retry {
            RetryConfig::new()
                .with_max_attempts(2)
                .unwrap()
                .with_min_base_delay(Duration::ZERO)
                .with_max_base_delay(Duration::ZERO)
                .with_append_retry_policy(AppendRetryPolicy::All)
        } else {
            no_retry_config()
        };
        let s2 = server.client(retry);
        let session = s2
            .basin(basin_name)
            .stream(stream_name)
            .append_session(AppendSessionConfig::new())
            .unwrap();

        let ta = session.submit(sized_append_input(40 * 1024)).await.unwrap();
        let tb = session.submit(sized_append_input(40 * 1024)).await.unwrap();
        let tc = session.submit(sized_append_input(1024)).await.unwrap();

        if is_close {
            ab_sent.notified().await;
            s2.close();
        }

        let ea = ta.await.unwrap_err();
        let eb = tb.await.unwrap_err();
        let ec = tc.await.unwrap_err();
        let eclose = session.close().await.unwrap_err();
        (ea, eb, ec, eclose)
    }

    // Row 1: Server rejects A with 412 -> A=412, B=SessionClosed(412), C=SessionClosed(412),
    // close=412
    let (ea, eb, ec, eclose) =
        run_scenario(basin_name.clone(), stream_name.clone(), Scenario::Reject412).await;
    assert!(
        matches!(ea, AppendSessionError::SeqNumMismatch(_)),
        "{ea:?}"
    );
    assert!(
        matches!(eb, AppendSessionError::SessionClosed(ref c) if matches!(c.failure(), Some(AppendSessionError::SeqNumMismatch(_)))),
        "Row 1 B: {eb:?}"
    );
    assert!(
        matches!(ec, AppendSessionError::SessionClosed(ref c) if matches!(c.failure(), Some(AppendSessionError::SeqNumMismatch(_)))),
        "Row 1 C: {ec:?}"
    );
    assert!(
        matches!(eclose, AppendSessionError::SeqNumMismatch(_)),
        "{eclose:?}"
    );

    // Row 2: Server fails A with storage (indefinite) -> A=storage, B=storage,
    // C=SessionClosed(storage), close=storage
    let (ea, eb, ec, eclose) = run_scenario(
        basin_name.clone(),
        stream_name.clone(),
        Scenario::FailStorage,
    )
    .await;
    assert!(
        matches!(ea, AppendSessionError::Server(ref s) if s.code.as_deref() == Some("storage")),
        "{ea:?}"
    );
    assert!(
        matches!(eb, AppendSessionError::Server(ref s) if s.code.as_deref() == Some("storage")),
        "{eb:?}"
    );
    assert!(
        matches!(ec, AppendSessionError::SessionClosed(ref c) if matches!(c.failure(), Some(AppendSessionError::Server(s)) if s.code.as_deref() == Some("storage"))),
        "Row 2 C: {ec:?}"
    );
    assert!(
        matches!(eclose, AppendSessionError::Server(ref s) if s.code.as_deref() == Some("storage")),
        "{eclose:?}"
    );

    // Row 3: Connection lost -> A=ConnectionLost, B=ConnectionLost,
    // C=SessionClosed(ConnectionLost), close=ConnectionLost
    let (ea, eb, ec, eclose) = run_scenario(
        basin_name.clone(),
        stream_name.clone(),
        Scenario::ConnectionLost,
    )
    .await;
    assert!(
        matches!(ea, AppendSessionError::ConnectionLost(_)),
        "{ea:?}"
    );
    assert!(
        matches!(eb, AppendSessionError::ConnectionLost(_)),
        "{eb:?}"
    );
    assert!(
        matches!(ec, AppendSessionError::SessionClosed(ref c) if matches!(c.failure(), Some(AppendSessionError::ConnectionLost(_)))),
        "Row 3 C: {ec:?}"
    );
    assert!(
        matches!(eclose, AppendSessionError::ConnectionLost(_)),
        "{eclose:?}"
    );

    // Row 4: Connection lost and retried; A and B resent; server rejects A with 412 ->
    //   A = Indefinite(412)
    //   B = Indefinite(SessionClosed(Indefinite(412)))
    //   C = SessionClosed(Indefinite(412))
    //   close() = Indefinite(412)
    let (ea, eb, ec, eclose) = run_scenario(
        basin_name.clone(),
        stream_name.clone(),
        Scenario::RetryThen412,
    )
    .await;
    assert!(
        matches!(ea, AppendSessionError::IndefiniteAppend(ref w) if matches!(w.final_attempt_error(), AppendSessionError::SeqNumMismatch(_))),
        "Row 4 A: {ea:?}"
    );
    assert!(
        matches!(
            eb,
            AppendSessionError::IndefiniteAppend(ref w)
                if matches!(
                    w.final_attempt_error(),
                    AppendSessionError::SessionClosed(c)
                        if matches!(
                            c.failure(),
                            Some(AppendSessionError::IndefiniteAppend(inner))
                                if matches!(inner.final_attempt_error(), AppendSessionError::SeqNumMismatch(_))
                        )
                )
        ),
        "Row 4 B: {eb:?}"
    );
    assert!(
        matches!(
            ec,
            AppendSessionError::SessionClosed(ref c)
                if matches!(
                    c.failure(),
                    Some(AppendSessionError::IndefiniteAppend(inner))
                        if matches!(inner.final_attempt_error(), AppendSessionError::SeqNumMismatch(_))
                )
        ),
        "Row 4 C: {ec:?}"
    );
    assert!(
        matches!(eclose, AppendSessionError::IndefiniteAppend(ref w) if matches!(w.final_attempt_error(), AppendSessionError::SeqNumMismatch(_))),
        "Row 4 close: {eclose:?}"
    );

    // Row 5: Client closed while A and B await acks -> A=Aborted, B=Aborted,
    // C=SessionClosed(Aborted), close=Aborted
    let (ea, eb, ec, eclose) = run_scenario(
        basin_name.clone(),
        stream_name.clone(),
        Scenario::ClientClose,
    )
    .await;
    assert!(matches!(ea, AppendSessionError::Aborted(_)), "{ea:?}");
    assert!(matches!(eb, AppendSessionError::Aborted(_)), "{eb:?}");
    assert!(
        matches!(ec, AppendSessionError::SessionClosed(ref c) if matches!(c.failure(), Some(AppendSessionError::Aborted(_)))),
        "Row 5 C: {ec:?}"
    );
    assert!(
        matches!(eclose, AppendSessionError::Aborted(_)),
        "{eclose:?}"
    );

    // T10 + A6d: Ack received before terminal error takes effect first, and Producer preserves
    // exact AppendSession outcomes without overriding them.
    let t10_server = MockH2Server::start(|_conn_id, req, mut respond| async move {
        let resp = Response::builder()
            .status(200)
            .header("content-type", "s2s/proto")
            .body(())
            .unwrap();
        let Ok(mut send) = respond.send_response(resp, false) else {
            return;
        };
        let mut body = req.into_body();
        let mut buf = BytesMut::new();
        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
        // Send ack for batch 0 AND 412 rejection for batch 1 in one coalesced write.
        let mut combined = BytesMut::new();
        combined.extend_from_slice(&encode_s2s_regular_frame(&proto_append_ack(0, 1), false));
        combined.extend_from_slice(&encode_s2s_terminal_frame(
            412,
            br#"{"seq_num_mismatch":1}"#,
        ));
        let _ = send.send_data(combined.freeze(), true);
    })
    .await;

    let producer = t10_server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name)
        .producer(
            ProducerConfig::new()
                .with_max_batch_records(1)
                .unwrap()
                .with_linger(Duration::from_secs(60)),
        )
        .unwrap();
    let r0 = producer
        .submit(AppendRecord::new("r0").unwrap())
        .await
        .unwrap();
    let r1 = producer
        .submit(AppendRecord::new("r1").unwrap())
        .await
        .unwrap();
    assert_eq!(r0.await.unwrap().seq_num, 0);
    assert!(matches!(
        r1.await.unwrap_err(),
        AppendSessionError::SeqNumMismatch(_)
    ));
    assert!(matches!(
        producer.close().await.unwrap_err(),
        AppendSessionError::SeqNumMismatch(_)
    ));
}

// spec: r1 A7, A4c
#[tokio::test]
async fn spec_a7_producer_flush_isolation_and_close_interaction() {
    let (basin_name, stream_name) = test_basin_and_stream();

    let server = MockH2Server::start(|_conn_id, req, mut respond| async move {
        let resp = Response::builder()
            .status(200)
            .header("content-type", "s2s/proto")
            .body(())
            .unwrap();
        let Ok(mut send) = respond.send_response(resp, false) else {
            return;
        };
        let mut body = req.into_body();
        let mut buf = BytesMut::new();
        // Batch 0 succeeds; Batch 1 fails with 412.
        if read_one_s2s_frame(&mut body, &mut buf, true)
            .await
            .is_some()
        {
            tokio::time::sleep(Duration::from_millis(40)).await;
            let _ = send.send_data(
                encode_s2s_regular_frame(&proto_append_ack(0, 1), false),
                false,
            );
        }
        if read_one_s2s_frame(&mut body, &mut buf, true)
            .await
            .is_some()
        {
            let _ = send.send_data(
                encode_s2s_terminal_frame(412, br#"{"seq_num_mismatch":1}"#),
                true,
            );
        }
    })
    .await;

    let stream = server
        .client(no_retry_config())
        .basin(basin_name.clone())
        .stream(stream_name.clone());

    // 1. Failure affecting only later records does NOT fail flush() covering earlier records, nor
    //    does closing the producer while flush() is waiting!
    let producer = Arc::new(
        stream
            .producer(
                ProducerConfig::new()
                    .with_max_batch_records(1)
                    .unwrap()
                    .with_linger(Duration::from_secs(60)),
            )
            .unwrap(),
    );

    let t0 = producer
        .submit(AppendRecord::new("ok").unwrap())
        .await
        .unwrap();
    let flush0 = tokio::spawn({
        let producer = producer.clone();
        async move { producer.flush().await }
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    // Submit a later record that will fail with 412, then immediately call close().
    let t1 = producer
        .submit(AppendRecord::new("fail").unwrap())
        .await
        .unwrap();
    let close_task = tokio::spawn({
        let producer = producer.clone();
        async move { producer.close().await }
    });

    // flush0 ONLY covered t0 (which succeeded) -> flush0 MUST return Ok(())!
    flush0
        .await
        .unwrap()
        .expect("A7: later failure and close() must not fail earlier flush()");
    assert_eq!(t0.await.unwrap().seq_num, 0);
    assert!(matches!(
        t1.await.unwrap_err(),
        AppendSessionError::SeqNumMismatch(_)
    ));
    assert!(matches!(
        close_task.await.unwrap().unwrap_err(),
        AppendSessionError::SeqNumMismatch(_)
    ));

    // A later flush() after t1 failed returns the session failure (NEVER SessionClosedError).
    let flush_after_err = producer.flush().await.unwrap_err();
    assert!(
        matches!(flush_after_err, AppendSessionError::SeqNumMismatch(_)),
        "A4c/A7: flush must never return SessionClosedError, got {flush_after_err:?}"
    );

    // 2. flush() after a clean close returns Ok(()) (NEVER SessionClosedError).
    let clean_prod = stream.producer(ProducerConfig::new()).unwrap();
    clean_prod.close().await.unwrap();
    clean_prod
        .flush()
        .await
        .expect("A4c/A7: flush after clean close must return Ok(())");
}

// spec: r1 A8a, A8c, T8
#[tokio::test]
async fn spec_a8_t8_close_idempotent_cancel_wait_and_drop_aborts() {
    let (basin_name, stream_name) = test_basin_and_stream();

    let ack_gate = Arc::new(tokio::sync::Notify::new());
    let server = MockH2Server::start({
        let ack_gate = ack_gate.clone();
        move |_conn_id, req, mut respond| {
            let ack_gate = ack_gate.clone();
            async move {
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "s2s/proto")
                    .body(())
                    .unwrap();
                let Ok(mut send) = respond.send_response(resp, false) else {
                    return;
                };
                let mut body = req.into_body();
                let mut buf = BytesMut::new();
                if read_one_s2s_frame(&mut body, &mut buf, true)
                    .await
                    .is_some()
                {
                    ack_gate.notified().await;
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_append_ack(0, 1), false),
                        false,
                    );
                }
                while let Some(Ok(_)) = body.data().await {}
                let _ = send.send_data(Bytes::new(), true);
            }
        }
    })
    .await;

    let stream = server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name);

    // 1. Dropping a close(&self) future cancels only the wait (T8); repeated/concurrent close()
    //    calls all return the exact same result (A8a).
    let session = Arc::new(stream.append_session(AppendSessionConfig::new()).unwrap());
    let ticket = session.submit(sample_append_input()).await.unwrap();

    // Start close() and cancel that wait by dropping the future.
    {
        let mut close_fut = Box::pin(session.close());
        assert!(futures_util::poll!(close_fut.as_mut()).is_pending());
        drop(close_fut);
    }

    // Session is now closing (new submit fails immediately with SessionClosed), NOT aborted!
    let closed_err = session.submit(sample_append_input()).await.err().unwrap();
    assert!(matches!(closed_err, AppendSessionError::SessionClosed(_)));

    // Two concurrent close() calls both wait and return Ok(()).
    let c1 = tokio::spawn({
        let session = session.clone();
        async move { session.close().await }
    });
    let c2 = tokio::spawn({
        let session = session.clone();
        async move { session.close().await }
    });
    ack_gate.notify_one();
    assert_eq!(ticket.await.unwrap().end.seq_num, 1);
    c1.await.unwrap().unwrap();
    c2.await.unwrap().unwrap();
    // Subsequent close() also returns the same Ok(()).
    session.close().await.unwrap();

    // 2. Dropping AppendSession without calling close() aborts unacked sent batches with
    //    AbortedError (A8c).
    let drop_sess = stream.append_session(AppendSessionConfig::new()).unwrap();
    let drop_ticket = drop_sess.submit(sample_append_input()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(40)).await;
    drop(drop_sess);
    let err = drop_ticket.await.unwrap_err();
    assert!(matches!(err, AppendSessionError::Aborted(_)), "{err:?}");
    assert!(!err.has_no_side_effects());
}

// spec: r1 T6a, T7c
#[tokio::test]
async fn spec_t6a_t7c_append_reconnect_advice_cooldown_and_oldest_batch_ack_timeout() {
    let (basin_name, stream_name) = test_basin_and_stream();

    // 1. T6a: Reconnect advice triggers handover to a new connection, then a second reconnect
    //    advice within 60 s is ignored (stays on the same connection!).
    let seen_conns = Arc::new(Mutex::new(Vec::<usize>::new()));
    let req_idx = Arc::new(AtomicUsize::new(0));
    let advice_server = MockH2Server::start({
        let seen_conns = seen_conns.clone();
        let req_idx = req_idx.clone();
        move |conn_id, req, mut respond| {
            let seen_conns = seen_conns.clone();
            let req_idx = req_idx.clone();
            async move {
                let n = req_idx.fetch_add(1, Ordering::SeqCst);
                seen_conns.lock().unwrap().push(conn_id);
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "s2s/proto")
                    .body(())
                    .unwrap();
                let Ok(mut send) = respond.send_response(resp, false) else {
                    return;
                };
                let mut body = req.into_body();
                let mut buf = BytesMut::new();
                if n == 0 {
                    // Ack batch 0 with reconnect-advised bit -> client drains and closes body.
                    let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_append_ack(0, 1), true),
                        false,
                    );
                    while let Some(Ok(_)) = body.data().await {}
                    let _ = send.send_data(Bytes::new(), true);
                } else {
                    // Request 2: ack batch 1 WITH reconnect-advised bit (must be ignored within
                    // 60 s cooldown!), then ack batch 2 on the SAME request!
                    let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_append_ack(1, 2), true),
                        false,
                    );
                    let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_append_ack(2, 3), false),
                        false,
                    );
                    while let Some(Ok(_)) = body.data().await {}
                    let _ = send.send_data(Bytes::new(), true);
                }
            }
        }
    })
    .await;

    let session = advice_server
        .client(no_retry_config())
        .basin(basin_name.clone())
        .stream(stream_name.clone())
        .append_session(AppendSessionConfig::new())
        .unwrap();
    assert_eq!(
        session
            .submit(sample_append_input())
            .await
            .unwrap()
            .await
            .unwrap()
            .end
            .seq_num,
        1
    );
    assert_eq!(
        session
            .submit(sample_append_input())
            .await
            .unwrap()
            .await
            .unwrap()
            .end
            .seq_num,
        2
    );
    assert_eq!(
        session
            .submit(sample_append_input())
            .await
            .unwrap()
            .await
            .unwrap()
            .end
            .seq_num,
        3
    );
    session.close().await.unwrap();
    let conns = seen_conns.lock().unwrap().clone();
    assert_eq!(
        conns.len(),
        2,
        "T6a: second reconnect advice within 60 s must be ignored"
    );
    assert_ne!(
        conns[0], conns[1],
        "T6a: first reconnect advice must move to a different connection"
    );

    // 2. T7c: Only the oldest unacked batch is timed! With request_timeout = 250ms:
    //    - Batch 0 and Batch 1 are pipelined together at t = 0.
    //    - Batch 0 is acked at t = 160ms (< 250ms).
    //    - Batch 1 is acked at t = 320ms (> 250ms since t = 0, but only 160ms since Batch 1 became
    //      oldest at t = 160ms!) -> BOTH MUST SUCCEED!
    //    - Batch 2 is never acked -> fails with TimeoutError!
    let timeout_server = MockH2Server::start(|_conn_id, req, mut respond| async move {
        let resp = Response::builder()
            .status(200)
            .header("content-type", "s2s/proto")
            .body(())
            .unwrap();
        let Ok(mut send) = respond.send_response(resp, false) else {
            return;
        };
        let mut body = req.into_body();
        let mut buf = BytesMut::new();
        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
        tokio::time::sleep(Duration::from_millis(160)).await;
        let _ = send.send_data(
            encode_s2s_regular_frame(&proto_append_ack(0, 1), false),
            false,
        );
        tokio::time::sleep(Duration::from_millis(160)).await;
        let _ = send.send_data(
            encode_s2s_regular_frame(&proto_append_ack(1, 2), false),
            false,
        );
        // Never ack Batch 2.
        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
        std::future::pending::<()>().await;
    })
    .await;

    let ep = timeout_server.endpoint_url();
    let endpoints = S2Endpoints::new(
        AccountEndpoint::new(&ep).unwrap(),
        BasinEndpoint::new(&ep).unwrap(),
    )
    .unwrap();
    let s2 = S2::new(
        S2Config::new("test-token")
            .with_endpoints(endpoints)
            .with_request_timeout(Duration::from_millis(250))
            .unwrap()
            .with_retry(no_retry_config()),
    )
    .unwrap();
    let session = s2
        .basin(basin_name)
        .stream(stream_name)
        .append_session(AppendSessionConfig::new())
        .unwrap();

    let t0 = session.submit(sample_append_input()).await.unwrap();
    let t1 = session.submit(sample_append_input()).await.unwrap();
    assert_eq!(t0.await.unwrap().end.seq_num, 1);
    assert_eq!(
        t1.await
            .expect("T7c: Batch 1 timer must start when it becomes oldest, not when pipelined")
            .end
            .seq_num,
        2
    );

    let t2 = session.submit(sample_append_input()).await.unwrap();
    let err = t2.await.unwrap_err();
    assert!(matches!(err, AppendSessionError::Timeout(_)), "{err:?}");
    assert!(err.is_retryable());
    assert!(!err.has_no_side_effects());
}

// ---------------------------------------------------------------------------
// PR 5 conformance tests: C5, C7, C10, C11, C13b, D1, E4, E8, T2, T2a, T2b,
// T5, T5b, T7, T7b, T7d, A1, R2-R11d, M1, M5-M8, F2-F4, L1-L3
// ---------------------------------------------------------------------------

fn proto_read_batch_records(seq_nums: &[u64], tail_seq: Option<u64>) -> Vec<u8> {
    ProtoReadBatch {
        records: seq_nums
            .iter()
            .map(|&seq_num| ProtoSequencedRecord {
                seq_num,
                timestamp: 1000 + seq_num,
                headers: vec![],
                body: Bytes::from(format!("rec-{seq_num}")),
            })
            .collect(),
        tail: tail_seq.map(|seq_num| ProtoStreamPosition {
            seq_num,
            timestamp: 1000 + seq_num,
        }),
    }
    .encode_to_vec()
}

fn proto_heartbeat(tail_seq: u64) -> Vec<u8> {
    proto_read_batch_records(&[], Some(tail_seq))
}

fn query_pairs(uri: &http::Uri) -> BTreeMap<String, String> {
    uri.query()
        .and_then(|q| serde_urlencoded::from_str::<Vec<(String, String)>>(q).ok())
        .map(|pairs| pairs.into_iter().collect())
        .unwrap_or_default()
}

// spec: r1 C5, C7, C10, C11, D1, A1
#[tokio::test]
async fn spec_c5_c7_c10_c11_d1_a1_transport_user_agent_inputs_concurrency_and_binary_records() {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_send<T: Send>() {}

    assert_send_sync::<S2>();
    assert_send_sync::<S2Basin>();
    assert_send_sync::<S2Stream>();
    assert_send_sync::<AppendSession>();
    assert_send_sync::<Producer>();
    assert_send_sync::<ReadSessionState>();
    assert_send::<ReadSession>();
    assert_send::<ReadBatchSession>();

    let (basin_name, stream_name) = test_basin_and_stream();
    let seen_user_agents = Arc::new(Mutex::new(Vec::<String>::new()));
    let stored = Arc::new(Mutex::new(Vec::<api::stream::proto::AppendRecord>::new()));

    let server = MockH2Server::start({
        let seen_user_agents = seen_user_agents.clone();
        let stored = stored.clone();
        move |_conn_id, req, mut respond| {
            let seen_user_agents = seen_user_agents.clone();
            let stored = stored.clone();
            async move {
                if let Some(ua) = req
                    .headers()
                    .get("user-agent")
                    .and_then(|v| v.to_str().ok())
                {
                    seen_user_agents.lock().unwrap().push(ua.to_owned());
                }
                let method = req.method().clone();
                let path = req.uri().path().to_owned();
                let mut body = req.into_body();
                let mut req_bytes = BytesMut::new();
                while let Some(Ok(chunk)) = body.data().await {
                    req_bytes.extend_from_slice(&chunk);
                    let _ = body.flow_control().release_capacity(chunk.len());
                }

                if method == http::Method::POST && path.ends_with("/records") {
                    let input =
                        api::stream::proto::AppendInput::decode(req_bytes.freeze()).unwrap();
                    let count = input.records.len() as u64;
                    *stored.lock().unwrap() = input.records;
                    let ack = proto_append_ack(0, count);
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "application/protobuf")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(Bytes::from(ack), true);
                    }
                } else if method == http::Method::GET && path.ends_with("/records") {
                    let records: Vec<ProtoSequencedRecord> = stored
                        .lock()
                        .unwrap()
                        .iter()
                        .enumerate()
                        .map(|(i, r)| ProtoSequencedRecord {
                            seq_num: i as u64,
                            timestamp: r.timestamp.unwrap_or(500),
                            headers: r.headers.clone(),
                            body: r.body.clone(),
                        })
                        .collect();
                    let batch = ProtoReadBatch {
                        tail: Some(ProtoStreamPosition {
                            seq_num: records.len() as u64,
                            timestamp: 500,
                        }),
                        records,
                    }
                    .encode_to_vec();
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "application/protobuf")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(Bytes::from(batch), true);
                    }
                } else {
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            Bytes::from_static(br#"{"tail":{"seq_num":1,"timestamp":500}}"#),
                            true,
                        );
                    }
                }
            }
        }
    })
    .await;

    let s2 = server.client(no_retry_config());
    let stream = s2.basin(basin_name).stream(stream_name);

    // D1 + A1 + C10: arbitrary non-UTF-8 binary body and ordered duplicate binary headers.
    let mut raw_body = vec![0x00, 0xff, 0xfe, 0x80, 0x42];
    let headers = vec![
        Header::new(
            Bytes::from_static(&[0x01, 0xff]),
            Bytes::from_static(b"first"),
        ),
        Header::new(
            Bytes::from_static(&[0x01, 0xff]),
            Bytes::from_static(&[0x00, 0xab]),
        ),
    ];
    let rec = AppendRecord::new(raw_body.clone())
        .unwrap()
        .with_headers(headers.clone())
        .unwrap()
        .with_timestamp(777);
    // Mutating caller's original Vec after constructing the record has no effect (C10).
    raw_body.fill(0x99);
    let batch = AppendRecordBatch::try_from_iter([rec]).unwrap();
    let ack = stream.append(AppendInput::new(batch)).await.unwrap();
    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1);
    assert_eq!(ack.tail.seq_num, 1);

    let read_batch = stream
        .read(ReadInput::new().with_start(ReadStart::new().with_from(ReadFrom::SeqNum(0))))
        .await
        .unwrap();
    assert_eq!(read_batch.records.len(), 1);
    let got = &read_batch.records[0];
    assert_eq!(got.body.as_ref(), &[0x00, 0xff, 0xfe, 0x80, 0x42]);
    assert_eq!(got.headers.len(), 2);
    assert_eq!(got.headers[0].name.as_ref(), &[0x01, 0xff]);
    assert_eq!(got.headers[0].value.as_ref(), b"first");
    assert_eq!(got.headers[1].name.as_ref(), &[0x01, 0xff]);
    assert_eq!(got.headers[1].value.as_ref(), &[0x00, 0xab]);
    assert_eq!(got.timestamp, 777);

    // C11: concurrent calls on cloned handles across tasks succeed cleanly.
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let s = stream.clone();
        tasks.push(tokio::spawn(async move { s.check_tail().await.unwrap() }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap().seq_num, 1);
    }

    // C7: user-agent matches s2-sdk-rust/<version>.
    let expected_ua = concat!("s2-sdk-rust/", env!("CARGO_PKG_VERSION"));
    let uas = seen_user_agents.lock().unwrap();
    assert!(!uas.is_empty());
    assert!(uas.iter().all(|ua| ua == expected_ua), "{uas:?}");
}

// spec: r1 C13, C13a, C13b
#[tokio::test]
async fn spec_c13b_http2_keepalive_ping_timeout_maps_to_connection_lost_and_spills_over() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let (basin_name, stream_name) = test_basin_and_stream();

    // 1. C13 + C13a: verify real pooled connection reuse & spillover when cap is reached.
    let release_first = Arc::new(tokio::sync::Notify::new());
    let first_arrived = Arc::new(tokio::sync::Notify::new());
    let req_conns = Arc::new(Mutex::new(Vec::<usize>::new()));
    let pool_server = MockH2Server::start({
        let release_first = release_first.clone();
        let first_arrived = first_arrived.clone();
        let req_conns = req_conns.clone();
        move |conn_id, _req, mut respond| {
            let release_first = release_first.clone();
            let first_arrived = first_arrived.clone();
            let req_conns = req_conns.clone();
            async move {
                let idx = {
                    let mut guard = req_conns.lock().unwrap();
                    guard.push(conn_id);
                    guard.len()
                };
                if idx == 1 {
                    first_arrived.notify_one();
                    release_first.notified().await;
                }
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(())
                    .unwrap();
                if let Ok(mut send) = respond.send_response(resp, false) {
                    let _ = send.send_data(
                        Bytes::from_static(br#"{"tail":{"seq_num":0,"timestamp":0}}"#),
                        true,
                    );
                }
            }
        }
    })
    .await;

    let ep = pool_server.endpoint_url();
    let endpoints = S2Endpoints::new(
        AccountEndpoint::new(&ep).unwrap(),
        BasinEndpoint::new(&ep).unwrap(),
    )
    .unwrap();
    let s2 = S2::new(
        S2Config::new("test-token")
            .with_endpoints(endpoints)
            .with_http2(Http2Config::new().with_max_concurrent_requests(1).unwrap())
            .with_retry(no_retry_config()),
    )
    .unwrap();
    let stream = s2.basin(basin_name.clone()).stream(stream_name.clone());

    let req1 = tokio::spawn({
        let stream = stream.clone();
        async move { stream.check_tail().await }
    });
    first_arrived.notified().await;
    // While req1 holds the sole slot on connection 0, req2 must spill over to connection 1.
    let tail2 = stream.check_tail().await.unwrap();
    assert_eq!(tail2.seq_num, 0);
    release_first.notify_one();
    assert_eq!(req1.await.unwrap().unwrap().seq_num, 0);
    let conns = req_conns.lock().unwrap().clone();
    assert_eq!(conns.len(), 2);
    assert_ne!(
        conns[0], conns[1],
        "C13a: spillover must open a 2nd connection"
    );

    // Sequential request reuses an existing pooled connection instead of opening a 3rd.
    assert_eq!(stream.check_tail().await.unwrap().seq_num, 0);
    assert_eq!(pool_server.connection_count(), 2);

    // 2. C13b: Raw HTTP/2 peer completes handshake and accepts request HEADERS, then ignores
    //    keep-alive PING frames. After 20s (PING sent) + 10s (PING timeout), hyper closes the
    //    connection and the SDK MUST classify it as ConnectionLostError (not TimeoutError).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let saw_headers = Arc::new(tokio::sync::Notify::new());
    let saw_ping = Arc::new(tokio::sync::Notify::new());
    let saw_ping_count = Arc::new(AtomicUsize::new(0));
    let raw_server = tokio::spawn({
        let saw_headers = saw_headers.clone();
        let saw_ping = saw_ping.clone();
        let saw_ping_count = saw_ping_count.clone();
        async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            // Read client HTTP/2 connection preface (24 bytes).
            let mut preface = [0u8; 24];
            if sock.read_exact(&mut preface).await.is_err() {
                return;
            }
            // Send empty server SETTINGS frame (9 bytes: len=0, type=0x04, flags=0, stream=0).
            let _ = sock
                .write_all(&[0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00])
                .await;
            let _ = sock.flush().await;

            // Read incoming frames: ACK client SETTINGS, signal HEADERS, ignore PING!
            let mut hdr = [0u8; 9];
            while sock.read_exact(&mut hdr).await.is_ok() {
                let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | (hdr[2] as usize);
                let frame_type = hdr[3];
                let flags = hdr[4];
                let mut payload = vec![0u8; len];
                if len > 0 && sock.read_exact(&mut payload).await.is_err() {
                    break;
                }
                if frame_type == 0x04 && (flags & 0x01) == 0 {
                    // Send SETTINGS ACK (len=0, type=0x04, flags=0x01, stream=0).
                    let _ = sock
                        .write_all(&[0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00])
                        .await;
                    let _ = sock.flush().await;
                } else if frame_type == 0x01 {
                    saw_headers.notify_waiters();
                } else if frame_type == 0x06 && (flags & 0x01) == 0 {
                    // Observed client HTTP/2 keep-alive PING; intentionally do NOT ACK!
                    saw_ping_count.fetch_add(1, Ordering::SeqCst);
                    saw_ping.notify_waiters();
                }
            }
        }
    });

    let raw_ep = format!("http://{addr}");
    let raw_endpoints = S2Endpoints::new(
        AccountEndpoint::new(&raw_ep).unwrap(),
        BasinEndpoint::new(&raw_ep).unwrap(),
    )
    .unwrap();
    let ping_client = S2::new(
        S2Config::new("test-token")
            .with_endpoints(raw_endpoints)
            .with_request_timeout(Duration::from_secs(120))
            .unwrap()
            .with_retry(no_retry_config()),
    )
    .unwrap();
    let ping_stream = ping_client.basin(basin_name).stream(stream_name);

    let call = tokio::spawn(async move { ping_stream.check_tail().await });
    // Wait until the real HTTP/2 handshake + request HEADERS actually arrive on the socket!
    tokio::time::timeout(Duration::from_secs(3), saw_headers.notified())
        .await
        .expect("client must complete HTTP/2 handshake and send HEADERS");

    // Advance Tokio's clock past hyper's 20s keep-alive PING interval (C13b), then resume so
    // real TCP I/O delivers the PING frame without auto-advance interference.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(21)).await;
    tokio::time::resume();

    if saw_ping_count.load(Ordering::SeqCst) == 0 {
        tokio::time::timeout(Duration::from_secs(3), saw_ping.notified())
            .await
            .expect("C13b: client must send HTTP/2 keep-alive PING within 20s");
    }
    assert!(
        saw_ping_count.load(Ordering::SeqCst) >= 1,
        "C13b: client must send HTTP/2 keep-alive PING within 20s"
    );

    // Advance Tokio's clock past the 10s keep-alive PING timeout (C13b).
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::time::resume();

    let err = tokio::time::timeout(Duration::from_secs(3), call)
        .await
        .expect("keep-alive PING timeout must fail active request promptly")
        .unwrap()
        .expect_err("keep-alive PING timeout must fail active request");
    assert!(
        matches!(err, ReadError::ConnectionLost(_)),
        "C13b: HTTP/2 keep-alive PING timeout must classify as ConnectionLostError, got {err:?}"
    );
    assert!(err.is_retryable());
    raw_server.abort();
}

// spec: r1 T2, T2a, T2b, T7, T7b, M1
#[tokio::test]
async fn spec_t2_t7_t7b_m1_retry_safety_request_tokens_and_timeouts() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let fast_retry_3 = RetryConfig::new()
        .with_max_attempts(3)
        .unwrap()
        .with_min_base_delay(Duration::ZERO)
        .with_max_base_delay(Duration::ZERO);

    // 1. T2b + M1: create_basin and create_stream reuse identical s2-request-token across retries;
    //    T2a: check_tail and delete_stream retry indefinite 503.
    let basin_tokens = Arc::new(Mutex::new(Vec::<String>::new()));
    let stream_tokens = Arc::new(Mutex::new(Vec::<String>::new()));
    let delete_attempts = Arc::new(AtomicUsize::new(0));
    let tail_attempts = Arc::new(AtomicUsize::new(0));

    let server = MockH2Server::start({
        let basin_tokens = basin_tokens.clone();
        let stream_tokens = stream_tokens.clone();
        let delete_attempts = delete_attempts.clone();
        let tail_attempts = tail_attempts.clone();
        move |_conn_id, req, mut respond| {
            let basin_tokens = basin_tokens.clone();
            let stream_tokens = stream_tokens.clone();
            let delete_attempts = delete_attempts.clone();
            let tail_attempts = tail_attempts.clone();
            async move {
                let method = req.method().clone();
                let path = req.uri().path().to_owned();
                let req_token = req
                    .headers()
                    .get("s2-request-token")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                let mut body = req.into_body();
                while let Some(Ok(chunk)) = body.data().await {
                    let _ = body.flow_control().release_capacity(chunk.len());
                }

                let (status, payload): (u16, &[u8]) = if method == http::Method::POST
                    && path == "/v1/basins"
                {
                    let mut guard = basin_tokens.lock().unwrap();
                    guard.push(req_token.unwrap_or_default());
                    if guard.len() == 1 {
                        (503, br#"{"code":"unavailable","message":"retry"}"#)
                    } else {
                        (
                            201,
                            br#"{"name":"test-basin","created_at":"2026-01-01T00:00:00Z"}"#,
                        )
                    }
                } else if method == http::Method::POST && path == "/v1/streams" {
                    let mut guard = stream_tokens.lock().unwrap();
                    guard.push(req_token.unwrap_or_default());
                    if guard.len() == 1 {
                        (503, br#"{"code":"unavailable","message":"retry"}"#)
                    } else {
                        (
                            201,
                            br#"{"name":"test-stream","created_at":"2026-01-01T00:00:00Z","deleted_at":null}"#,
                        )
                    }
                } else if method == http::Method::DELETE && path.starts_with("/v1/streams/") {
                    if delete_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        (503, br#"{"code":"unavailable","message":"retry"}"#)
                    } else {
                        (202, b"")
                    }
                } else if method == http::Method::GET && path.ends_with("/records/tail") {
                    if tail_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        (503, br#"{"code":"unavailable","message":"retry"}"#)
                    } else {
                        (200, br#"{"tail":{"seq_num":7,"timestamp":700}}"#)
                    }
                } else {
                    (404, br#"{"code":"not_found","message":"unexpected"}"#)
                };

                let resp = Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(())
                    .unwrap();
                if payload.is_empty() {
                    let _ = respond.send_response(resp, true);
                } else if let Ok(mut send) = respond.send_response(resp, false) {
                    let _ = send.send_data(Bytes::copy_from_slice(payload), true);
                }
            }
        }
    })
    .await;

    let s2 = server.client(fast_retry_3.clone());
    let created_basin = s2
        .create_basin(CreateBasinInput::new(basin_name.clone()))
        .await
        .unwrap();
    assert_eq!(created_basin.name, basin_name);
    let bt = basin_tokens.lock().unwrap().clone();
    assert_eq!(bt.len(), 2);
    assert!(!bt[0].is_empty());
    assert_eq!(
        bt[0], bt[1],
        "T2b: create_basin must reuse s2-request-token"
    );

    let basin = s2.basin(basin_name.clone());
    let created_stream = basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await
        .unwrap();
    assert_eq!(created_stream.name, stream_name);
    let st = stream_tokens.lock().unwrap().clone();
    assert_eq!(st.len(), 2);
    assert!(!st[0].is_empty());
    assert_eq!(
        st[0], st[1],
        "T2b: create_stream must reuse s2-request-token"
    );

    assert_eq!(
        basin
            .stream(stream_name.clone())
            .check_tail()
            .await
            .unwrap()
            .seq_num,
        7
    );
    assert_eq!(tail_attempts.load(Ordering::SeqCst), 2);
    basin.delete_stream(stream_name.clone()).await.unwrap();
    assert_eq!(delete_attempts.load(Ordering::SeqCst), 2);

    // 2. T7 + T7b: per-attempt request_timeout (unary succeeds on retry when attempt 1 times out,
    //    unary read with `wait` uses `request_timeout + wait`, session times out if headers stall).
    let attempt_counter = Arc::new(AtomicUsize::new(0));
    let timeout_server = MockH2Server::start({
        let attempt_counter = attempt_counter.clone();
        move |_conn_id, req, mut respond| {
            let attempt_counter = attempt_counter.clone();
            async move {
                let path = req.uri().path().to_owned();
                let is_s2s = req
                    .headers()
                    .get("content-type")
                    .is_some_and(|v| v == "s2s/proto");
                let params = query_pairs(req.uri());
                if is_s2s {
                    // Stall response headers so ReadSession hits T7b request_timeout.
                    let _keep = respond;
                    std::future::pending::<()>().await;
                } else if path.ends_with("/records/tail") {
                    if attempt_counter.fetch_add(1, Ordering::SeqCst) == 0 {
                        // Stall attempt 1 past request_timeout (150ms).
                        let _keep = respond;
                        std::future::pending::<()>().await;
                    } else {
                        let resp = Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(())
                            .unwrap();
                        if let Ok(mut send) = respond.send_response(resp, false) {
                            let _ = send.send_data(
                                Bytes::from_static(br#"{"tail":{"seq_num":9,"timestamp":900}}"#),
                                true,
                            );
                        }
                    }
                } else if params.get("wait").map(String::as_str) == Some("1") {
                    // Respond at 350ms: exceeds request_timeout (150ms) alone, but well within
                    // request_timeout + wait (1150ms)!
                    tokio::time::sleep(Duration::from_millis(350)).await;
                    let batch = proto_read_batch_records(&[0], Some(1));
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "application/protobuf")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(Bytes::from(batch), true);
                    }
                }
            }
        }
    })
    .await;

    let ep = timeout_server.endpoint_url();
    let endpoints = S2Endpoints::new(
        AccountEndpoint::new(&ep).unwrap(),
        BasinEndpoint::new(&ep).unwrap(),
    )
    .unwrap();
    let s2_t = S2::new(
        S2Config::new("test-token")
            .with_endpoints(endpoints.clone())
            .with_request_timeout(Duration::from_millis(150))
            .unwrap()
            .with_retry(fast_retry_3),
    )
    .unwrap();
    let stream_t = s2_t.basin(basin_name.clone()).stream(stream_name.clone());

    // Attempt 1 times out, attempt 2 succeeds -> proves timeout is per-attempt (T7).
    assert_eq!(stream_t.check_tail().await.unwrap().seq_num, 9);
    assert_eq!(attempt_counter.load(Ordering::SeqCst), 2);

    // Unary read with wait=1s succeeds when response arrives at 350ms > 150ms request_timeout.
    let batch = stream_t
        .read(
            ReadInput::new()
                .with_start(ReadStart::new().with_from(ReadFrom::SeqNum(0)))
                .with_stop(ReadStop::new().with_wait(Duration::from_secs(1)).unwrap()),
        )
        .await
        .expect("T7b: unary read timeout must be request_timeout + wait");
    assert_eq!(batch.records.len(), 1);

    // Session open headers stall past request_timeout -> fails with TimeoutError (T7b).
    let s2_no_retry = S2::new(
        S2Config::new("test-token")
            .with_endpoints(endpoints)
            .with_request_timeout(Duration::from_millis(150))
            .unwrap()
            .with_retry(no_retry_config()),
    )
    .unwrap();
    let mut sess = s2_no_retry
        .basin(basin_name)
        .stream(stream_name)
        .read_session(ReadInput::new(), ReadSessionConfig::default())
        .unwrap();
    let err = sess.next().await.unwrap().unwrap_err();
    assert!(matches!(err, ReadSessionError::Timeout(_)), "{err:?}");
    assert!(err.is_retryable());
}

// spec: r1 R2, R3, R4
#[tokio::test]
async fn spec_r2_r3_r4_unary_read_stop_options_empty_batch_416_and_check_tail() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let captured = Arc::new(Mutex::new(Vec::<(
        String,
        BTreeMap<String, String>,
        bool,
        bool,
    )>::new()));

    let server = MockH2Server::start({
        let captured = captured.clone();
        move |_conn_id, req, mut respond| {
            let captured = captured.clone();
            async move {
                let path = req.uri().path().to_owned();
                let params = query_pairs(req.uri());
                let has_enc = req.headers().contains_key("s2-encryption-key");
                let has_cfg = req.headers().contains_key("s2-stream-config");
                let idx = {
                    let mut guard = captured.lock().unwrap();
                    guard.push((path.clone(), params.clone(), has_enc, has_cfg));
                    guard.len()
                };
                if path.ends_with("/records/tail") {
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            Bytes::from_static(br#"{"tail":{"seq_num":42,"timestamp":4200}}"#),
                            true,
                        );
                    }
                } else if idx == 2 {
                    // Empty batch when stop condition met before any record (R3).
                    let empty = proto_read_batch_records(&[], Some(42));
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "application/protobuf")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(Bytes::from(empty), true);
                    }
                } else {
                    // wait=0 at tail returns 416 ReadUnwrittenError (R3).
                    let resp = Response::builder()
                        .status(416)
                        .header("content-type", "application/json")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            Bytes::from_static(br#"{"tail":{"seq_num":42,"timestamp":4200}}"#),
                            true,
                        );
                    }
                }
            }
        }
    })
    .await;

    let key = EncryptionKey::new([0x11u8; 32]).unwrap();
    let stream = server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name)
        .with_encryption_key(key);

    // R4 + C4: check_tail returns tail position and omits s2-encryption-key / s2-stream-config.
    let tail = stream.check_tail().await.unwrap();
    assert_eq!(tail.seq_num, 42);
    assert_eq!(tail.timestamp, 4200);

    // R2 + R3: unary read with omitted stop options sends none of count/bytes/until/wait and
    // returns empty server batch verbatim.
    let empty_batch = stream.read(ReadInput::new()).await.unwrap();
    assert!(empty_batch.records.is_empty());
    assert_eq!(empty_batch.tail.unwrap().seq_num, 42);

    // R2 + R3: explicit count/bytes/until/wait=0 serialized; 416 surfaces as ReadUnwrittenError.
    let err = stream
        .read(
            ReadInput::new().with_stop(
                ReadStop::new()
                    .with_limits(ReadLimits::new().with_count(10).with_bytes(1024))
                    .with_until(..9999)
                    .with_wait(Duration::ZERO)
                    .unwrap(),
            ),
        )
        .await
        .unwrap_err();
    let ReadError::ReadUnwritten(unwritten) = err else {
        panic!("expected ReadError::ReadUnwritten, got {err:?}");
    };
    assert_eq!(unwritten.tail.seq_num, 42);

    let log = captured.lock().unwrap();
    // Call 1: check_tail -> no encryption key header
    assert!(
        !log[0].2,
        "R4/C4: check_tail must not send s2-encryption-key"
    );
    assert!(
        !log[0].3,
        "R4/C4: check_tail must not send s2-stream-config"
    );
    // Call 2: ReadInput::new() -> omitted stop params left unset
    assert!(
        log[1].1.is_empty(),
        "R2: omitted options must be unset: {:?}",
        log[1].1
    );
    assert!(log[1].2, "C4: read must send s2-encryption-key");
    // Call 3: explicit stop params
    assert_eq!(log[2].1.get("count").map(String::as_str), Some("10"));
    assert_eq!(log[2].1.get("bytes").map(String::as_str), Some("1024"));
    assert_eq!(log[2].1.get("until").map(String::as_str), Some("9999"));
    assert_eq!(log[2].1.get("wait").map(String::as_str), Some("0"));
}

// spec: r1 R5, R6, R6a, R6b, R6c, R7, R7a, R7b, R7c, R8, R8a, R8b, R8c, R8d
#[tokio::test]
async fn spec_r5_r6_r7_r8_read_session_records_batches_readahead_state_and_caught_up() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let fast_retry = RetryConfig::new()
        .with_max_attempts(3)
        .unwrap()
        .with_min_base_delay(Duration::ZERO)
        .with_max_base_delay(Duration::ZERO);

    // 1. R5 + R6 + R6c + R7 + R7a + R7b + R7c + R8 + R8a-R8d: Walk the exact spec Example table
    //    over loopback HTTP/2 with a concurrent observer task!
    let opened_notify = Arc::new(tokio::sync::Notify::new());
    let send_step4_hb = Arc::new(tokio::sync::Notify::new());
    let send_step5_rec5 = Arc::new(tokio::sync::Notify::new());
    let break_conn = Arc::new(tokio::sync::Notify::new());
    let allow_reconnect_hb = Arc::new(tokio::sync::Notify::new());
    let attempt_num = Arc::new(AtomicUsize::new(0));

    let server = MockH2Server::start({
        let opened_notify = opened_notify.clone();
        let send_step4_hb = send_step4_hb.clone();
        let send_step5_rec5 = send_step5_rec5.clone();
        let break_conn = break_conn.clone();
        let allow_reconnect_hb = allow_reconnect_hb.clone();
        let attempt_num = attempt_num.clone();
        move |_conn_id, _req, mut respond| {
            let opened_notify = opened_notify.clone();
            let send_step4_hb = send_step4_hb.clone();
            let send_step5_rec5 = send_step5_rec5.clone();
            let break_conn = break_conn.clone();
            let allow_reconnect_hb = allow_reconnect_hb.clone();
            let attempt_num = attempt_num.clone();
            async move {
                let idx = attempt_num.fetch_add(1, Ordering::SeqCst) + 1;
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "s2s/proto")
                    .body(())
                    .unwrap();
                let Ok(mut send) = respond.send_response(resp, false) else {
                    return;
                };
                if idx == 1 {
                    opened_notify.notify_one();
                    // Records 0-4 with tail 5
                    let _ = send.send_data(
                        encode_s2s_regular_frame(
                            &proto_read_batch_records(&[0, 1, 2, 3, 4], Some(5)),
                            false,
                        ),
                        false,
                    );
                    send_step4_hb.notified().await;
                    let _ =
                        send.send_data(encode_s2s_regular_frame(&proto_heartbeat(5), false), false);
                    send_step5_rec5.notified().await;
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_read_batch_records(&[5], Some(6)), false),
                        false,
                    );
                    break_conn.notified().await;
                    // Break active request with RST_STREAM
                    send.send_reset(h2::Reason::INTERNAL_ERROR);
                } else {
                    allow_reconnect_hb.notified().await;
                    let _ =
                        send.send_data(encode_s2s_regular_frame(&proto_heartbeat(6), false), false);
                    std::future::pending::<()>().await;
                }
            }
        }
    })
    .await;

    let stream = server
        .client(fast_retry.clone())
        .basin(basin_name.clone())
        .stream(stream_name.clone());

    let mut session = stream
        .read_session(
            ReadInput::new().with_start(ReadStart::new().with_from(ReadFrom::SeqNum(0))),
            ReadSessionConfig::default(),
        )
        .expect("R5: sync open succeeds");
    // R5: request initiates immediately WITHOUT polling session.next()!
    tokio::time::timeout(Duration::from_secs(2), opened_notify.notified())
        .await
        .expect("R5: read_session must initiate first request immediately on open");

    // R6c: concurrent ReadSessionState handle observed from another task while iterating.
    let state = session.state();
    assert_eq!(state.next_seq_num(), Some(0));
    assert!(!state.is_caught_up());
    let cu1 = state.caught_up();

    // Deliver record 0 -> next_seq_num=1, last_observed_tail=5, is_caught_up=false
    let r0 = session.next().await.unwrap().unwrap();
    assert_eq!(r0.seq_num, 0);
    assert_eq!(state.next_seq_num(), Some(1));
    assert_eq!(state.last_observed_tail().unwrap().seq_num, 5);
    assert!(!state.is_caught_up());

    // Deliver records 1..=4 -> next_seq_num=5, last_observed_tail=5, is_caught_up=true
    for expected in 1..=4 {
        let rec = session.next().await.unwrap().unwrap();
        assert_eq!(rec.seq_num, expected);
    }
    let concurrent_check = tokio::spawn({
        let state = state.clone();
        async move {
            (
                state.next_seq_num(),
                state.last_observed_tail(),
                state.is_caught_up(),
            )
        }
    })
    .await
    .unwrap();
    assert_eq!(concurrent_check.0, Some(5));
    assert_eq!(concurrent_check.1.unwrap().seq_num, 5);
    assert!(concurrent_check.2);
    assert_eq!(cu1.await.unwrap().seq_num, 5);
    let pinned_cu = state.caught_up();
    assert_eq!(pinned_cu.clone().await.unwrap().seq_num, 5);

    // Heartbeat tail=5 -> still caught up
    send_step4_hb.notify_one();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(state.is_caught_up());

    // Record 5 fetched with tail=6 BEFORE delivery -> next_seq_num=5, last_observed_tail=6,
    // is_caught_up=false!
    send_step5_rec5.notify_one();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if state.last_observed_tail().is_some_and(|t| t.seq_num == 6) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("driver should fetch record 5 and update last_observed_tail");
    assert_eq!(state.next_seq_num(), Some(5));
    assert!(!state.is_caught_up());
    // R8a: already-resolved caught_up future never changes!
    assert_eq!(pinned_cu.await.unwrap().seq_num, 5);

    // Record 5 delivered -> next_seq_num=6, is_caught_up=true
    let r5 = session.next().await.unwrap().unwrap();
    assert_eq!(r5.seq_num, 5);
    assert_eq!(state.next_seq_num(), Some(6));
    assert!(state.is_caught_up());

    // Active request breaks -> is_caught_up=false; caught_up() stays pending across retry (R8c)
    break_conn.notify_one();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if !state.is_caught_up() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("is_caught_up must clear on disconnect");
    assert_eq!(state.next_seq_num(), Some(6));
    assert_eq!(state.last_observed_tail().unwrap().seq_num, 6);
    let cu_across_retry = state.caught_up();

    // Reconnected; heartbeat with tail=6 -> is_caught_up=true and cu_across_retry resolves!
    allow_reconnect_hb.notify_one();
    let tail = tokio::time::timeout(Duration::from_secs(2), cu_across_retry)
        .await
        .expect("R8c: caught_up must resolve after reconnect")
        .unwrap();
    assert_eq!(tail.seq_num, 6);
    assert!(state.is_caught_up());

    // Dropping session rejects new caught_up with SessionClosedError (R8d)
    drop(session);
    assert!(!state.is_caught_up());
    assert!(matches!(
        state.caught_up().await,
        Err(ReadSessionError::SessionClosed(e)) if e.failure().is_none()
    ));

    // 2. R6a: ReadBatchSession delivers whole non-empty batches and skips empty heartbeats.
    let batch_server = MockH2Server::start(|_conn_id, _req, mut respond| async move {
        let resp = Response::builder()
            .status(200)
            .header("content-type", "s2s/proto")
            .body(())
            .unwrap();
        let Ok(mut send) = respond.send_response(resp, false) else {
            return;
        };
        let _ = send.send_data(encode_s2s_regular_frame(&proto_heartbeat(0), false), false);
        let _ = send.send_data(
            encode_s2s_regular_frame(&proto_read_batch_records(&[0, 1], Some(2)), false),
            false,
        );
        let _ = send.send_data(encode_s2s_regular_frame(&proto_heartbeat(2), false), true);
    })
    .await;

    let mut batch_session = batch_server
        .client(no_retry_config())
        .basin(basin_name.clone())
        .stream(stream_name.clone())
        .read_batch_session(
            ReadInput::new()
                .with_start(ReadStart::new().with_from(ReadFrom::SeqNum(0)))
                .with_stop(ReadStop::new().with_limits(ReadLimits::new().with_count(2))),
            ReadSessionConfig::default(),
        )
        .unwrap();
    let b = batch_session.next().await.unwrap().unwrap();
    assert_eq!(b.records.len(), 2);
    assert_eq!(batch_session.next_seq_num(), Some(2));
    assert!(batch_session.is_caught_up());
    assert!(batch_session.next().await.is_none());
    assert!(!batch_session.is_caught_up());

    // 3. R6b: At most 1 batch decoded ahead of the batch currently being delivered!
    let readahead_server = MockH2Server::start(|_conn_id, _req, mut respond| async move {
        let resp = Response::builder()
            .status(200)
            .header("content-type", "s2s/proto")
            .body(())
            .unwrap();
        let Ok(mut send) = respond.send_response(resp, false) else {
            return;
        };
        for b_idx in 0u64..4 {
            let s0 = b_idx * 2;
            let s1 = s0 + 1;
            let _ = send.send_data(
                encode_s2s_regular_frame(&proto_read_batch_records(&[s0, s1], Some(s1 + 1)), false),
                false,
            );
        }
        std::future::pending::<()>().await;
    })
    .await;

    let mut ra_session = readahead_server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name)
        .read_session(
            ReadInput::new().with_start(ReadStart::new().with_from(ReadFrom::SeqNum(0))),
            ReadSessionConfig::default(),
        )
        .unwrap();

    // Before consuming anything, at most B0 (tail=2) is decoded into the 1-slot buffer.
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
        ra_session.last_observed_tail().map(|t| t.seq_num),
        Some(2),
        "R6b: before consumer pulls B0, driver must decode at most 1 batch (B0)"
    );

    // Pull record 0 of B0 -> now B0 is being delivered, so driver may decode at most B1 (tail=4),
    // NEVER B2 (tail=6) or B3 (tail=8)!
    assert_eq!(ra_session.next().await.unwrap().unwrap().seq_num, 0);
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
        ra_session.last_observed_tail().map(|t| t.seq_num),
        Some(4),
        "R6b: while delivering B0, driver must decode at most 1 batch ahead (B1)"
    );

    // Finish B0 (record 1) and pull record 2 of B1 -> driver decodes B2 (tail=6), NOT B3 (tail=8)!
    assert_eq!(ra_session.next().await.unwrap().unwrap().seq_num, 1);
    assert_eq!(ra_session.next().await.unwrap().unwrap().seq_num, 2);
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
        ra_session.last_observed_tail().map(|t| t.seq_num),
        Some(6),
        "R6b: while delivering B1, driver must decode at most 1 batch ahead (B2)"
    );
}

// spec: r1 R9, R9a, R9b, R9c, R9d, R10
#[tokio::test]
async fn spec_r9_r10_read_session_closing_buffered_delivery_and_abort() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let fast_retry_2 = RetryConfig::new()
        .with_max_attempts(2)
        .unwrap()
        .with_min_base_delay(Duration::ZERO)
        .with_max_base_delay(Duration::ZERO);

    // 1. R9a + T9: Clean EOF WITHOUT any stop option is ConnectionLostError (retried!), whereas
    //    clean EOF WITH a stop option finishes cleanly.
    let eof_attempts = Arc::new(AtomicUsize::new(0));
    let eof_server = MockH2Server::start({
        let eof_attempts = eof_attempts.clone();
        move |_conn_id, _req, mut respond| {
            let eof_attempts = eof_attempts.clone();
            async move {
                eof_attempts.fetch_add(1, Ordering::SeqCst);
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "s2s/proto")
                    .body(())
                    .unwrap();
                let _ = respond.send_response(resp, true);
            }
        }
    })
    .await;

    let stream = eof_server
        .client(fast_retry_2)
        .basin(basin_name.clone())
        .stream(stream_name.clone());

    // Without stop option -> retried (2 attempts) then fails with ConnectionLostError.
    let mut no_stop = stream
        .read_session(ReadInput::new(), ReadSessionConfig::default())
        .unwrap();
    let err = no_stop.next().await.unwrap().unwrap_err();
    assert!(
        matches!(err, ReadSessionError::ConnectionLost(_)),
        "T9: clean EOF without stop option must fail with ConnectionLostError, got {err:?}"
    );
    assert!(err.has_no_side_effects());
    assert!(err.is_retryable());
    assert_eq!(eof_attempts.load(Ordering::SeqCst), 2);
    assert!(no_stop.next().await.is_none());

    // With stop option -> ends cleanly (None).
    let mut with_stop = stream
        .read_session(
            ReadInput::new()
                .with_stop(ReadStop::new().with_limits(ReadLimits::new().with_count(5))),
            ReadSessionConfig::default(),
        )
        .unwrap();
    assert!(with_stop.next().await.is_none());

    // 2. R9c + R10: Terminal failure delivers all already-fetched records FIRST, then yields the
    //    unwrapped failure once, then None!
    let fail_server = MockH2Server::start(|_conn_id, _req, mut respond| async move {
        let resp = Response::builder()
            .status(200)
            .header("content-type", "s2s/proto")
            .body(())
            .unwrap();
        let Ok(mut send) = respond.send_response(resp, false) else {
            return;
        };
        let _ = send.send_data(
            encode_s2s_regular_frame(&proto_read_batch_records(&[0, 1], None), false),
            false,
        );
        let _ = send.send_data(
            encode_s2s_terminal_frame(404, br#"{"code":"stream_not_found","message":"deleted"}"#),
            true,
        );
    })
    .await;

    let mut fail_sess = fail_server
        .client(no_retry_config())
        .basin(basin_name.clone())
        .stream(stream_name.clone())
        .read_session(
            ReadInput::new().with_start(ReadStart::new().with_from(ReadFrom::SeqNum(0))),
            ReadSessionConfig::default(),
        )
        .unwrap();
    assert_eq!(fail_sess.next().await.unwrap().unwrap().seq_num, 0);
    assert_eq!(fail_sess.next().await.unwrap().unwrap().seq_num, 1);
    let err = fail_sess.next().await.unwrap().unwrap_err();
    assert!(
        matches!(err, ReadSessionError::Server(ref s) if s.code.as_deref() == Some("stream_not_found")),
        "R9c/R10: expected unwrapped ServerError after buffered records, got {err:?}"
    );
    assert!(err.has_no_side_effects());
    assert!(fail_sess.next().await.is_none());

    // 3. R9b: Dropping a pending next() future cancels only the wait without losing records;
    //    dropping the session rejects pending caught_up with SessionClosedError(None).
    let delayed_release = Arc::new(tokio::sync::Notify::new());
    let delayed_server = MockH2Server::start({
        let delayed_release = delayed_release.clone();
        move |_conn_id, _req, mut respond| {
            let delayed_release = delayed_release.clone();
            async move {
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "s2s/proto")
                    .body(())
                    .unwrap();
                let Ok(mut send) = respond.send_response(resp, false) else {
                    return;
                };
                delayed_release.notified().await;
                let _ = send.send_data(
                    encode_s2s_regular_frame(&proto_read_batch_records(&[0, 1], Some(2)), false),
                    false,
                );
                std::future::pending::<()>().await;
            }
        }
    })
    .await;

    let s2_abort = delayed_server.client(no_retry_config());
    let mut sess = s2_abort
        .basin(basin_name)
        .stream(stream_name)
        .read_session(
            ReadInput::new().with_start(ReadStart::new().with_from(ReadFrom::SeqNum(0))),
            ReadSessionConfig::default(),
        )
        .unwrap();

    // Cancel a pending next() future -> session stays alive and delivers record 0 next!
    assert!(
        tokio::time::timeout(Duration::from_millis(30), sess.next())
            .await
            .is_err()
    );
    delayed_release.notify_one();
    assert_eq!(sess.next().await.unwrap().unwrap().seq_num, 0);

    // 4. R9d: Record 1 is STILL buffered in current_batch when s2.close() aborts the session;
    //    record 1 MUST be dropped and iteration MUST yield AbortedError immediately, then None!
    s2_abort.close();
    let abort_err = sess.next().await.unwrap().unwrap_err();
    assert!(
        matches!(abort_err, ReadSessionError::Aborted(_)),
        "R9d: client close must drop buffered records and yield AbortedError, got {abort_err:?}"
    );
    assert!(sess.next().await.is_none());
}

// spec: r1 T7d
#[tokio::test]
async fn spec_t7d_read_session_heartbeat_timeout_and_backpressure_pause() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let fast_retry_2 = RetryConfig::new()
        .with_max_attempts(2)
        .unwrap()
        .with_min_base_delay(Duration::ZERO)
        .with_max_base_delay(Duration::ZERO);

    let attempts = Arc::new(AtomicUsize::new(0));
    let server = MockH2Server::start({
        let attempts = attempts.clone();
        move |_conn_id, _req, mut respond| {
            let attempts = attempts.clone();
            async move {
                let idx = attempts.fetch_add(1, Ordering::SeqCst) + 1;
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "s2s/proto")
                    .body(())
                    .unwrap();
                let Ok(mut send) = respond.send_response(resp, false) else {
                    return;
                };
                if idx == 1 {
                    // Send two batches immediately so B0 is delivered and B1 fills the 1-slot
                    // read-ahead channel; then go silent!
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_read_batch_records(&[0, 1], None), false),
                        false,
                    );
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_read_batch_records(&[2], None), false),
                        false,
                    );
                    std::future::pending::<()>().await;
                } else {
                    // On retry after heartbeat timeout, deliver record 3 and end cleanly.
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_read_batch_records(&[3], Some(4)), false),
                        false,
                    );
                    std::future::pending::<()>().await;
                }
            }
        }
    })
    .await;

    let mut session = server
        .client(fast_retry_2)
        .basin(basin_name)
        .stream(stream_name)
        .read_session(
            ReadInput::new().with_start(ReadStart::new().with_from(ReadFrom::SeqNum(0))),
            ReadSessionConfig::default(),
        )
        .unwrap();

    // Pull record 0 (record 1 stays in current_batch, record 2 fills the 1-slot channel).
    assert_eq!(session.next().await.unwrap().unwrap().seq_num, 0);
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Advance 60s (> 20s heartbeat timeout!) while caller has NOT consumed buffered records.
    // T7d: backpressure time MUST NOT count toward the 20s heartbeat timeout!
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(60)).await;
    tokio::time::resume();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "T7d: heartbeat timer must not fire while caller has not consumed buffered records"
    );

    // Drain remaining buffered records 1 and 2 on the SAME attempt!
    assert_eq!(session.next().await.unwrap().unwrap().seq_num, 1);
    assert_eq!(session.next().await.unwrap().unwrap().seq_num, 2);
    assert_eq!(attempts.load(Ordering::SeqCst), 1);

    // Now actively waiting for next server message -> after 20s silent, heartbeat timeout fires
    // and retries onto attempt 2, which delivers record 3!
    let next_rec = tokio::spawn(async move { session.next().await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(21)).await;
    tokio::time::resume();
    let rec3 = tokio::time::timeout(Duration::from_secs(3), next_rec)
        .await
        .expect("heartbeat timeout must trigger retry")
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(rec3.seq_num, 3);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

// spec: r1 R11, R11a, R11b, R11c, R11d, T5, T5b
#[tokio::test]
async fn spec_r11_t5_t5b_read_session_resume_clamp_wait_416_and_unbounded() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let fast_retry_2 = RetryConfig::new()
        .with_max_attempts(2)
        .unwrap()
        .with_min_base_delay(Duration::ZERO)
        .with_max_base_delay(Duration::ZERO);

    // 1. R11 + R11a + R11b + R11c + R11d: Start with TailOffset(2), clamp=true, count=5, wait=10s:
    //    - Attempt 1: sends heartbeat tail=10 -> resolves start to 10 & starts wait clock (t=0). At
    //      t=3s: sends 2nd heartbeat tail=10 (MUST NOT restart wait clock!). At t=5.1s: breaks
    //      connection!
    //    - Attempt 2: MUST send seq_num=10, NO tail_offset, NO clamp, count=5, wait=5 (ceil(4.9))!
    //      Sends records [10, 11] (restarts wait clock at t=5.1s, decrements count to 3!). At
    //      t=16.5s (11.4s elapsed since records): breaks connection!
    //    - Attempt 3: MUST send seq_num=12, count=3, wait=0 (R11c reached 0; SDK does not close
    //      locally)! Server replies 416 (tail=12) -> R11d closes cleanly (None), NOT an error!
    let seen_queries = Arc::new(Mutex::new(Vec::<BTreeMap<String, String>>::new()));
    let attempt_ctr = Arc::new(AtomicUsize::new(0));
    let send_hb2 = Arc::new(tokio::sync::Notify::new());
    let break_a1 = Arc::new(tokio::sync::Notify::new());
    let break_a2 = Arc::new(tokio::sync::Notify::new());
    let a1_hb1_sent = Arc::new(tokio::sync::Notify::new());

    let server = MockH2Server::start({
        let seen_queries = seen_queries.clone();
        let attempt_ctr = attempt_ctr.clone();
        let send_hb2 = send_hb2.clone();
        let break_a1 = break_a1.clone();
        let break_a2 = break_a2.clone();
        let a1_hb1_sent = a1_hb1_sent.clone();
        move |_conn_id, req, mut respond| {
            let seen_queries = seen_queries.clone();
            let attempt_ctr = attempt_ctr.clone();
            let send_hb2 = send_hb2.clone();
            let break_a1 = break_a1.clone();
            let break_a2 = break_a2.clone();
            let a1_hb1_sent = a1_hb1_sent.clone();
            async move {
                let idx = attempt_ctr.fetch_add(1, Ordering::SeqCst) + 1;
                seen_queries.lock().unwrap().push(query_pairs(req.uri()));
                if idx == 3 {
                    let resp = Response::builder()
                        .status(416)
                        .header("content-type", "application/json")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            Bytes::from_static(br#"{"tail":{"seq_num":12,"timestamp":1200}}"#),
                            true,
                        );
                    }
                    return;
                }
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "s2s/proto")
                    .body(())
                    .unwrap();
                let Ok(mut send) = respond.send_response(resp, false) else {
                    return;
                };
                if idx == 1 {
                    let _ = send
                        .send_data(encode_s2s_regular_frame(&proto_heartbeat(10), false), false);
                    a1_hb1_sent.notify_one();
                    send_hb2.notified().await;
                    let _ = send
                        .send_data(encode_s2s_regular_frame(&proto_heartbeat(10), false), false);
                    break_a1.notified().await;
                    send.send_reset(h2::Reason::INTERNAL_ERROR);
                } else {
                    let _ = send.send_data(
                        encode_s2s_regular_frame(
                            &proto_read_batch_records(&[10, 11], Some(12)),
                            false,
                        ),
                        false,
                    );
                    break_a2.notified().await;
                    send.send_reset(h2::Reason::INTERNAL_ERROR);
                }
            }
        }
    })
    .await;

    let mut session = server
        .client(fast_retry_2.clone())
        .basin(basin_name.clone())
        .stream(stream_name.clone())
        .read_session(
            ReadInput::new()
                .with_start(
                    ReadStart::new()
                        .with_from(ReadFrom::TailOffset(2))
                        .with_clamp_to_tail(true),
                )
                .with_stop(
                    ReadStop::new()
                        .with_limits(ReadLimits::new().with_count(5))
                        .with_wait(Duration::from_secs(10))
                        .unwrap(),
                ),
            ReadSessionConfig::default(),
        )
        .unwrap();

    tokio::time::timeout(Duration::from_secs(3), a1_hb1_sent.notified())
        .await
        .expect("hb1 sent");
    // Wait until the client driver has actually decoded hb1 and resolved next_seq_num to 10!
    tokio::time::timeout(Duration::from_secs(3), async {
        while session.next_seq_num() != Some(10) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("client must resolve start from hb1");
    // Wait 3s, send 2nd heartbeat (must NOT reset clock), wait 2.1s more (5.1s total elapsed).
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::time::resume();
    send_hb2.notify_one();
    tokio::time::sleep(Duration::from_millis(30)).await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_millis(2_100)).await;
    tokio::time::resume();
    break_a1.notify_one();

    // Attempt 2 delivers records 10 and 11 (restarting wait clock!).
    assert_eq!(session.next().await.unwrap().unwrap().seq_num, 10);
    assert_eq!(session.next().await.unwrap().unwrap().seq_num, 11);

    // Wait 11.4s (> 10s wait) -> break attempt 2 -> Attempt 3 sends wait=0, gets 416 -> clean end!
    tokio::time::pause();
    tokio::time::advance(Duration::from_millis(11_400)).await;
    tokio::time::resume();
    break_a2.notify_one();
    assert!(
        tokio::time::timeout(Duration::from_secs(3), session.next())
            .await
            .expect("R11d must terminate promptly")
            .is_none(),
        "R11d: 416 on resumed request with 0 remaining wait must end cleanly"
    );

    let qs = seen_queries.lock().unwrap().clone();
    assert_eq!(qs.len(), 3, "{qs:?}");
    // Attempt 1: original relative start + clamp=true + count=5 + wait=10
    assert_eq!(qs[0].get("tail_offset").map(String::as_str), Some("2"));
    assert_eq!(qs[0].get("clamp").map(String::as_str), Some("true"));
    assert_eq!(qs[0].get("count").map(String::as_str), Some("5"));
    assert_eq!(qs[0].get("wait").map(String::as_str), Some("10"));
    // Attempt 2: R11b resolved seq_num=10, clamp OMITTED, R11c wait=ceil(4.9)=5
    assert_eq!(qs[1].get("seq_num").map(String::as_str), Some("10"));
    assert!(!qs[1].contains_key("tail_offset"), "R11b: {:?}", qs[1]);
    assert!(
        !qs[1].contains_key("clamp"),
        "R11b: clamp must be cleared: {:?}",
        qs[1]
    );
    assert_eq!(qs[1].get("count").map(String::as_str), Some("5"));
    assert_eq!(qs[1].get("wait").map(String::as_str), Some("5"));
    // Attempt 3: R11a seq_num=12, R11c count=3, wait=0
    assert_eq!(qs[2].get("seq_num").map(String::as_str), Some("12"));
    assert_eq!(qs[2].get("count").map(String::as_str), Some("3"));
    assert_eq!(qs[2].get("wait").map(String::as_str), Some("0"));

    // 2. R11d negative check: 416 on resumed request while wait > 0 STILL fails with ReadUnwritten!
    let r11d_neg_attempts = Arc::new(AtomicUsize::new(0));
    let r11d_break = Arc::new(tokio::sync::Notify::new());
    let r11d_neg_server = MockH2Server::start({
        let r11d_neg_attempts = r11d_neg_attempts.clone();
        let r11d_break = r11d_break.clone();
        move |_conn_id, _req, mut respond| {
            let r11d_neg_attempts = r11d_neg_attempts.clone();
            let r11d_break = r11d_break.clone();
            async move {
                let idx = r11d_neg_attempts.fetch_add(1, Ordering::SeqCst) + 1;
                if idx == 1 {
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "s2s/proto")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            encode_s2s_regular_frame(
                                &proto_read_batch_records(&[0], Some(1)),
                                false,
                            ),
                            false,
                        );
                        r11d_break.notified().await;
                        send.send_reset(h2::Reason::INTERNAL_ERROR);
                    }
                } else {
                    let resp = Response::builder()
                        .status(416)
                        .header("content-type", "application/json")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            Bytes::from_static(br#"{"tail":{"seq_num":0,"timestamp":0}}"#),
                            true,
                        );
                    }
                }
            }
        }
    })
    .await;

    let mut neg_sess = r11d_neg_server
        .client(fast_retry_2.clone())
        .basin(basin_name.clone())
        .stream(stream_name.clone())
        .read_session(
            ReadInput::new()
                .with_start(ReadStart::new().with_from(ReadFrom::SeqNum(0)))
                .with_stop(ReadStop::new().with_wait(Duration::from_secs(30)).unwrap()),
            ReadSessionConfig::default(),
        )
        .unwrap();
    assert_eq!(neg_sess.next().await.unwrap().unwrap().seq_num, 0);
    r11d_break.notify_one();
    let err = neg_sess.next().await.unwrap().unwrap_err();
    assert!(
        matches!(err, ReadSessionError::ReadUnwritten(_)),
        "R11d: 416 while wait > 0 must still fail with ReadUnwrittenError, got {err:?}"
    );

    // 3. T5 + T5b: ReadSessionRetryPolicy::Unbounded retries past max_attempts (2) and succeeds!
    let unbounded_attempts = Arc::new(AtomicUsize::new(0));
    let unbounded_server = MockH2Server::start({
        let unbounded_attempts = unbounded_attempts.clone();
        move |_conn_id, _req, mut respond| {
            let unbounded_attempts = unbounded_attempts.clone();
            async move {
                let idx = unbounded_attempts.fetch_add(1, Ordering::SeqCst) + 1;
                if idx <= 5 {
                    let resp = Response::builder()
                        .status(503)
                        .header("content-type", "application/json")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            Bytes::from_static(br#"{"code":"unavailable","message":"retry"}"#),
                            true,
                        );
                    }
                } else {
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "s2s/proto")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            encode_s2s_regular_frame(
                                &proto_read_batch_records(&[0], Some(1)),
                                false,
                            ),
                            true,
                        );
                    }
                }
            }
        }
    })
    .await;

    let mut unbounded_sess = unbounded_server
        .client(fast_retry_2)
        .basin(basin_name)
        .stream(stream_name)
        .read_session(
            ReadInput::new()
                .with_start(ReadStart::new().with_from(ReadFrom::SeqNum(0)))
                .with_stop(ReadStop::new().with_limits(ReadLimits::new().with_count(1))),
            ReadSessionConfig::new().with_retry_policy(ReadSessionRetryPolicy::Unbounded),
        )
        .unwrap();
    assert_eq!(unbounded_sess.next().await.unwrap().unwrap().seq_num, 0);
    assert!(unbounded_sess.next().await.is_none());
    assert_eq!(unbounded_attempts.load(Ordering::SeqCst), 6);
}

// spec: r1 M5, M6, M7, M8
#[tokio::test]
async fn spec_m5_m6_m7_m8_issue_token_and_list_pagination() {
    let seen_start_after = Arc::new(Mutex::new(Vec::<Option<String>>::new()));
    let server = MockH2Server::start({
        let seen_start_after = seen_start_after.clone();
        move |_conn_id, req, mut respond| {
            let seen_start_after = seen_start_after.clone();
            async move {
                let method = req.method().clone();
                let path = req.uri().path().to_owned();
                let params = query_pairs(req.uri());
                let mut body = req.into_body();
                while let Some(Ok(chunk)) = body.data().await {
                    let _ = body.flow_control().release_capacity(chunk.len());
                }

                let payload: &[u8] = if method == http::Method::POST && path == "/v1/access-tokens" {
                    br#"{"access_token":"s2_issued_secret_val"}"#
                } else if method == http::Method::GET && path == "/v1/basins" {
                    let sa = params.get("start_after").cloned().filter(|s| !s.is_empty());
                    seen_start_after.lock().unwrap().push(sa.clone());
                    match sa.as_deref() {
                        None => br#"{
                            "basins": [
                                {"name":"basin-0001","created_at":"2026-01-01T00:00:00Z","deleted_at":"2026-01-02T00:00:00Z"},
                                {"name":"basin-0002","created_at":"2026-01-01T00:00:00Z","deleted_at":"2026-01-02T00:00:00Z"}
                            ],
                            "has_more": true
                        }"#,
                        Some("basin-0002") => br#"{
                            "basins": [
                                {"name":"basin-0003","created_at":"2026-01-01T00:00:00Z"}
                            ],
                            "has_more": true
                        }"#,
                        // Empty page with has_more=true MUST terminate iteration (M7)!
                        Some("basin-0003") => br#"{"basins":[],"has_more":true}"#,
                        _ => br#"{"basins":[],"has_more":false}"#,
                    }
                } else {
                    br#"{"streams":[],"has_more":false}"#
                };

                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(())
                    .unwrap();
                if let Ok(mut send) = respond.send_response(resp, false) {
                    let _ = send.send_data(Bytes::copy_from_slice(payload), true);
                }
            }
        }
    })
    .await;

    let s2 = server.client(no_retry_config());

    // M5: issue_access_token returns secret.
    let token_id: AccessTokenId = "m5-test-token".parse().unwrap();
    let scope = AccessTokenScopeInput::from_ops([Operation::ListBasins]);
    let secret = s2
        .issue_access_token(IssueAccessTokenInput::new(token_id, scope))
        .await
        .unwrap();
    assert_eq!(secret, "s2_issued_secret_val");

    // M6 + M8: list_basins returns exact server page including deleting basins.
    let page = s2.list_basins(ListBasinsInput::new()).await.unwrap();
    assert_eq!(page.values.len(), 2);
    assert!(page.has_more);
    assert!(page.values.iter().all(|b| b.deleted_at.is_some()));

    // M7 + M8: list_all_basins excludes deleting by default, advances start_after from the
    // unfiltered last item (`basin-0002`), and stops on empty page with `has_more = true`.
    seen_start_after.lock().unwrap().clear();
    let active: Vec<String> = s2
        .list_all_basins(ListAllBasinsInput::new())
        .map(|r| r.unwrap().name.to_string())
        .collect()
        .await;
    assert_eq!(active, vec!["basin-0003"]);
    assert_eq!(
        *seen_start_after.lock().unwrap(),
        vec![
            None,
            Some("basin-0002".to_owned()),
            Some("basin-0003".to_owned())
        ]
    );

    // M8: with include_deleted = true, yields deleting basins too.
    let all: Vec<String> = s2
        .list_all_basins(ListAllBasinsInput::new().with_include_deleted(true))
        .map(|r| r.unwrap().name.to_string())
        .collect()
        .await;
    assert_eq!(all, vec!["basin-0001", "basin-0002", "basin-0003"]);

    // Verify list_streams / list_all_streams work as well.
    let basin = s2.basin("test-basin-1".parse().unwrap());
    let spage = basin.list_streams(ListStreamsInput::new()).await.unwrap();
    assert!(spage.values.is_empty());
    let sall: Vec<_> = basin
        .list_all_streams(ListAllStreamsInput::new())
        .collect()
        .await;
    assert!(sall.is_empty());
}

// spec: r1 F2, F3, F4
#[test]
fn spec_f2_f3_f4_open_enums_tagged_unions_closed_request_enums_and_unknown_error_codes() {
    // F2: Every server-returned enum and externally tagged `oneOf` union preserves unknown wire
    // name / tag in `Unknown(String)`.
    let metric: Metric = serde_json::from_str::<api::MaybeKnown<api::metrics::Metric>>(
        r#"{"histogram":{"name":"latency","buckets":[1,2]}}"#,
    )
    .unwrap()
    .into();
    assert!(matches!(metric, Metric::Unknown(ref tag) if tag == "histogram"));

    let unit: MetricUnit =
        serde_json::from_str::<api::MaybeKnown<api::metrics::MetricUnit>>(r#""microseconds""#)
            .unwrap()
            .into();
    assert_eq!(unit, MetricUnit::Unknown("microseconds".to_owned()));

    let interval: TimeseriesInterval =
        serde_json::from_str::<api::MaybeKnown<api::metrics::TimeseriesInterval>>(r#""week""#)
            .unwrap()
            .into();
    assert_eq!(interval, TimeseriesInterval::Unknown("week".to_owned()));

    let retention: RetentionPolicy = serde_json::from_str::<
        api::MaybeKnown<api::config::RetentionPolicy>,
    >(r#"{"max_bytes":1048576}"#)
    .unwrap()
    .into();
    assert_eq!(retention, RetentionPolicy::Unknown("max_bytes".to_owned()));

    let ts_mode: TimestampingMode =
        serde_json::from_str::<api::MaybeKnown<api::config::TimestampingMode>>(r#""hybrid""#)
            .unwrap()
            .into();
    assert_eq!(ts_mode, TimestampingMode::Unknown("hybrid".to_owned()));

    let cipher: EncryptionAlgorithm = serde_json::from_str::<
        api::MaybeKnown<api::config::EncryptionAlgorithm>,
    >(r#""chacha20-poly1305""#)
    .unwrap()
    .into();
    assert_eq!(
        cipher,
        EncryptionAlgorithm::Unknown("chacha20-poly1305".to_owned())
    );

    let priv_net: PrivateNet = serde_json::from_str::<api::MaybeKnown<api::location::PrivateNet>>(
        r#"{"gcp":{"service_attachment":"projects/p/regions/r/serviceAttachments/s"}}"#,
    )
    .unwrap()
    .into();
    assert_eq!(priv_net, PrivateNet::Unknown("gcp".to_owned()));

    let pub_pol: PublicNetPolicy = serde_json::from_str::<
        api::MaybeKnown<api::network_policy::PublicNetPolicy>,
    >(r#"{"asn":[64512]}"#)
    .unwrap()
    .into();
    assert_eq!(pub_pol, PublicNetPolicy::Unknown("asn".to_owned()));

    let priv_pol: PrivateNetPolicy = serde_json::from_str::<
        api::MaybeKnown<api::network_policy::PrivateNetPolicy>,
    >(r#"{"gcp":{"psc_ids":["1"]}}"#)
    .unwrap()
    .into();
    assert_eq!(priv_pol, PrivateNetPolicy::Unknown("gcp".to_owned()));

    let op: Operation =
        serde_json::from_str::<api::MaybeKnown<api::access::Operation>>(r#""future-op""#)
            .unwrap()
            .into();
    assert_eq!(op, Operation::Unknown("future-op".to_owned()));

    let token_info: api::access::AccessTokenInfo = serde_json::from_str(
        r#"{
            "id": "tok-1",
            "auto_prefix_streams": false,
            "scope": {
                "basins": {"glob": "prod-*"},
                "streams": {"regex": "events-.*"},
                "access_tokens": {"tag": "ci"}
            }
        }"#,
    )
    .unwrap();
    let sdk_token: s2_sdk::types::AccessTokenInfo = token_info.into();
    assert!(matches!(
        sdk_token.scope.basins,
        Some(BasinMatcher::Unknown(ref t)) if t == "glob"
    ));
    assert!(matches!(
        sdk_token.scope.streams,
        Some(StreamMatcher::Unknown(ref t)) if t == "regex"
    ));
    assert!(matches!(
        sdk_token.scope.access_tokens,
        Some(AccessTokenMatcher::Unknown(ref t)) if t == "tag"
    ));

    // F3: Client-sent-only enums are closed (verified by exhaustive match with no wildcard and no
    // Unknown variant).
    fn check_closed_request_enums(
        c: Compression,
        f: ReadFrom,
        am: AccountMetricSet,
        bm: BasinMetricSet,
        sm: StreamMetricSet,
    ) {
        match c {
            Compression::None | Compression::Gzip | Compression::Zstd => {}
        }
        match f {
            ReadFrom::SeqNum(_) | ReadFrom::Timestamp(_) | ReadFrom::TailOffset(_) => {}
        }
        match am {
            AccountMetricSet::ActiveBasins(_)
            | AccountMetricSet::AccountOps(_)
            | AccountMetricSet::EstimatedBillableUsage(_)
            | AccountMetricSet::TokenActivity(_) => {}
        }
        match bm {
            BasinMetricSet::Storage(_)
            | BasinMetricSet::AppendOps(_)
            | BasinMetricSet::ReadOps(_)
            | BasinMetricSet::ReadThroughput(_)
            | BasinMetricSet::AppendThroughput(_)
            | BasinMetricSet::BasinOps(_) => {}
        }
        match sm {
            StreamMetricSet::Storage(_) => {}
        }
    }
    let range = TimeRange::new(
        Timestamp::from_second(0).unwrap(),
        Timestamp::from_second(60).unwrap(),
    )
    .unwrap();
    check_closed_request_enums(
        Compression::None,
        ReadFrom::SeqNum(0),
        AccountMetricSet::ActiveBasins(range),
        BasinMetricSet::Storage(range),
        StreamMetricSet::Storage(range),
    );

    // F4: Unrecognized server error codes classify by HTTP status (E4c).
    let parsed: Result<ErrorCode, _> = "future_unknown_code".parse();
    assert!(parsed.is_err());
}

// spec: r1 E4, E8, L1, L2, L3
#[tokio::test]
async fn spec_e4_e8_l1_l2_l3_logging_levels_secret_redaction_and_unobserved_errors() {
    use std::sync::atomic::AtomicU64;

    use tracing::{
        Event, Id, Level, Metadata, Subscriber,
        field::{Field, Visit},
        span::{Attributes, Record},
    };

    #[derive(Clone, Default)]
    struct CaptureSubscriber {
        next_id: Arc<AtomicU64>,
        events: Arc<Mutex<Vec<(String, Level, String)>>>,
    }

    struct StringVisitor(String);
    impl Visit for StringVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write as _;
            let _ = write!(self.0, "{}={:?} ", field.name(), value);
        }
    }

    impl Subscriber for CaptureSubscriber {
        fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _span: &Attributes<'_>) -> Id {
            Id::from_u64(self.next_id.fetch_add(1, Ordering::Relaxed) + 1)
        }
        fn record(&self, _span: &Id, _values: &Record<'_>) {}
        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
        fn event(&self, event: &Event<'_>) {
            let meta = event.metadata();
            let mut visitor = StringVisitor(String::new());
            event.record(&mut visitor);
            self.events
                .lock()
                .unwrap()
                .push((meta.target().to_owned(), *meta.level(), visitor.0));
        }
        fn enter(&self, _span: &Id) {}
        fn exit(&self, _span: &Id) {}
    }

    let capture = CaptureSubscriber::default();
    let _guard = tracing::subscriber::set_default(capture.clone());

    const CLIENT_TOKEN: &str = "tok_SUPER_SECRET_CLIENT_TOKEN_98765";
    const RAW_ENC_KEY: &[u8; 32] = b"KEY_SUPER_SECRET_ENC_KEY_67890!!";
    const RAW_ENC_KEY_STR: &str = "KEY_SUPER_SECRET_ENC_KEY_67890!!";
    const ISSUED_TOKEN: &str = "tok_SUPER_SECRET_ISSUED_TOKEN_43210";
    const SECRET_BODY: &str = "BODY_SUPER_SECRET_RECORD_PAYLOAD_55555";

    let enc_key = EncryptionKey::new(RAW_ENC_KEY).unwrap();
    let enc_key_b64 = enc_key.to_header_value().to_str().unwrap().to_owned();

    let (basin_name, stream_name) = test_basin_and_stream();
    let server = MockH2Server::start(|_conn_id, req, mut respond| async move {
        let method = req.method().clone();
        let path = req.uri().path().to_owned();
        let is_s2s = req
            .headers()
            .get("content-type")
            .is_some_and(|v| v == "s2s/proto");
        let mut body = req.into_body();
        if !is_s2s {
            while let Some(Ok(chunk)) = body.data().await {
                let _ = body.flow_control().release_capacity(chunk.len());
            }
        }
        if method == http::Method::POST && path == "/v1/access-tokens" {
            let resp = Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(())
                .unwrap();
            if let Ok(mut send) = respond.send_response(resp, false) {
                let _ = send.send_data(
                    Bytes::from(format!(r#"{{"access_token":"{ISSUED_TOKEN}"}}"#)),
                    true,
                );
            }
            return;
        }
        // Fail everything else with 503 so retries + terminal errors exercise SDK debug logging.
        let resp = Response::builder()
            .status(503)
            .header("content-type", "application/json")
            .body(())
            .unwrap();
        if let Ok(mut send) = respond.send_response(resp, false) {
            let _ = send.send_data(
                Bytes::from_static(br#"{"code":"unavailable","message":"transient"}"#),
                true,
            );
        }
    })
    .await;

    let ep = server.endpoint_url();
    let endpoints = S2Endpoints::new(
        AccountEndpoint::new(&ep).unwrap(),
        BasinEndpoint::new(&ep).unwrap(),
    )
    .unwrap();
    let config = S2Config::new(CLIENT_TOKEN)
        .with_endpoints(endpoints)
        .with_retry(
            RetryConfig::new()
                .with_max_attempts(2)
                .unwrap()
                .with_min_base_delay(Duration::ZERO)
                .with_max_base_delay(Duration::ZERO),
        );
    let s2 = S2::new(config.clone()).unwrap();
    let basin = s2.basin(basin_name);
    let stream = basin
        .stream(stream_name)
        .with_encryption_key(enc_key.clone());

    // L3: formatted/debug representations of settings, client, handles, and key redact secrets.
    let formatted_objects = vec![
        format!("{config:?}"),
        format!("{s2:?}"),
        format!("{basin:?}"),
        format!("{stream:?}"),
        format!("{enc_key:?}"),
    ];
    for text in &formatted_objects {
        assert!(
            !text.contains(CLIENT_TOKEN),
            "L3: token leaked in Debug: {text}"
        );
        assert!(
            !text.contains(RAW_ENC_KEY_STR),
            "L3: raw key leaked in Debug: {text}"
        );
        assert!(
            !text.contains(&enc_key_b64),
            "L3: base64 key leaked in Debug: {text}"
        );
    }

    // M5 + L3: issue_access_token returns secret without logging it.
    let issued = s2
        .issue_access_token(IssueAccessTokenInput::new(
            "l3-tok".parse().unwrap(),
            AccessTokenScopeInput::from_ops([Operation::ListBasins]),
        ))
        .await
        .unwrap();
    assert_eq!(issued, ISSUED_TOKEN);

    // Unary append failure + E4 predicates + L3 error message check.
    let secret_record = AppendRecord::new(SECRET_BODY).unwrap();
    let append_err = stream
        .append(AppendInput::new(
            AppendRecordBatch::try_from_iter([secret_record.clone()]).unwrap(),
        ))
        .await
        .unwrap_err();
    assert!(append_err.is_retryable());
    assert!(!append_err.has_no_side_effects());
    let s2_err: S2Error = append_err.clone().into();
    assert!(s2_err.is_retryable());
    assert!(!s2_err.has_no_side_effects());

    // E8: AppendSession ticket dropped unawaited, plus ReadSession caught_up dropped unawaited.
    let append_sess = stream.append_session(AppendSessionConfig::new()).unwrap();
    let unawaited_ticket = append_sess
        .submit(AppendInput::new(
            AppendRecordBatch::try_from_iter([secret_record]).unwrap(),
        ))
        .await
        .unwrap();
    drop(unawaited_ticket);
    let close_err = append_sess.close().await.unwrap_err();
    assert!(close_err.is_retryable());

    let mut read_sess = stream
        .read_session(ReadInput::new(), ReadSessionConfig::default())
        .unwrap();
    let unawaited_cu = read_sess.caught_up();
    drop(unawaited_cu);
    let read_err = read_sess.next().await.unwrap().unwrap_err();
    assert!(read_err.is_retryable());
    assert!(read_err.has_no_side_effects());

    // L3: check error messages contain no secrets.
    let error_texts = [
        format!("{append_err}"),
        format!("{append_err:?}"),
        format!("{close_err}"),
        format!("{close_err:?}"),
        format!("{read_err}"),
        format!("{read_err:?}"),
    ];
    for text in &error_texts {
        for secret in [
            CLIENT_TOKEN,
            RAW_ENC_KEY_STR,
            &enc_key_b64,
            ISSUED_TOKEN,
            SECRET_BODY,
        ] {
            assert!(
                !text.contains(secret),
                "L3: secret `{secret}` leaked in error: {text}"
            );
        }
    }

    // L1 + L2 + L3: All s2_sdk tracing events are DEBUG or TRACE (never INFO/WARN/ERROR),
    // and no event contains any secret!
    let events = capture.events.lock().unwrap();
    let sdk_events: Vec<_> = events
        .iter()
        .filter(|(target, _, _)| target.starts_with("s2_sdk"))
        .collect();
    assert!(
        !sdk_events.is_empty(),
        "expected SDK debug events during retries"
    );
    for (target, level, msg) in &sdk_events {
        assert!(
            *level == Level::DEBUG || *level == Level::TRACE,
            "L1/L2: SDK emitted log above debug level: {level} {target}: {msg}"
        );
        for secret in [
            CLIENT_TOKEN,
            RAW_ENC_KEY_STR,
            &enc_key_b64,
            ISSUED_TOKEN,
            SECRET_BODY,
        ] {
            assert!(
                !msg.contains(secret),
                "L3: secret `{secret}` leaked in log ({target}): {msg}"
            );
        }
    }
}

// spec: r1 T6b
#[tokio::test]
async fn spec_t6b_read_session_reconnect_advice_cooldown() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let seen_conns = Arc::new(Mutex::new(Vec::<usize>::new()));
    let req_idx = Arc::new(AtomicUsize::new(0));
    let server = MockH2Server::start({
        let seen_conns = seen_conns.clone();
        let req_idx = req_idx.clone();
        move |conn_id, _req, mut respond| {
            let seen_conns = seen_conns.clone();
            let req_idx = req_idx.clone();
            async move {
                let n = req_idx.fetch_add(1, Ordering::SeqCst);
                seen_conns.lock().unwrap().push(conn_id);
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "s2s/proto")
                    .body(())
                    .unwrap();
                let Ok(mut send) = respond.send_response(resp, false) else {
                    return;
                };
                if n == 0 {
                    // Record 0 with reconnect-advised bit -> client reconnects on a new connection.
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_read_batch(0, 1), true),
                        false,
                    );
                    std::future::pending::<()>().await;
                } else {
                    // Request 2: Record 1 WITH reconnect-advised bit (ignored within 60 s
                    // cooldown!), then Record 2 on the SAME request before clean EOF.
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_read_batch(1, 2), true),
                        false,
                    );
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_read_batch(2, 3), false),
                        true,
                    );
                }
            }
        }
    })
    .await;

    let mut session = server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name)
        .read_session(
            ReadInput::new()
                .with_start(ReadStart::new().with_from(ReadFrom::SeqNum(0)))
                .with_stop(ReadStop::new().with_limits(ReadLimits::new().with_count(3))),
            ReadSessionConfig::default(),
        )
        .unwrap();

    let mut seqs = Vec::new();
    while let Some(res) = session.next().await {
        seqs.push(res.unwrap().seq_num);
    }
    assert_eq!(seqs, vec![0, 1, 2]);
    let conns = seen_conns.lock().unwrap().clone();
    assert_eq!(
        conns.len(),
        2,
        "T6b: second reconnect advice within 60 s must be ignored"
    );
    assert_ne!(
        conns[0], conns[1],
        "T6b: first reconnect advice must move to a different connection"
    );
}

// spec: r1 T3
#[tokio::test]
async fn spec_t3_retry_backoff_delivers_bounded_exponential_delay() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let attempt_times = Arc::new(Mutex::new(Vec::<std::time::Instant>::new()));
    let server = MockH2Server::start({
        let attempt_times = attempt_times.clone();
        move |_conn_id, _req, mut respond| {
            let attempt_times = attempt_times.clone();
            async move {
                let n = {
                    let mut times = attempt_times.lock().unwrap();
                    times.push(std::time::Instant::now());
                    times.len()
                };
                if n < 3 {
                    let resp = Response::builder()
                        .status(503)
                        .header("content-type", "application/json")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            Bytes::from_static(br#"{"code":"unavailable","message":"busy"}"#),
                            true,
                        );
                    }
                } else {
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            Bytes::from_static(br#"{"tail":{"seq_num":0,"timestamp":0}}"#),
                            true,
                        );
                    }
                }
            }
        }
    })
    .await;

    let retry = RetryConfig::new()
        .with_max_attempts(3)
        .unwrap()
        .with_min_base_delay(Duration::from_millis(40))
        .with_max_base_delay(Duration::from_millis(200));
    server
        .client(retry)
        .basin(basin_name)
        .stream(stream_name)
        .check_tail()
        .await
        .unwrap();

    let times = attempt_times.lock().unwrap().clone();
    assert_eq!(times.len(), 3);
    let d1 = times[1].duration_since(times[0]);
    let d2 = times[2].duration_since(times[1]);
    // Full-base + [0, base] jitter: delay 1 in [40ms, 80ms], delay 2 in [80ms, 160ms] (with CI
    // scheduling slack on upper bound).
    assert!(d1 >= Duration::from_millis(35), "delay 1 too short: {d1:?}");
    assert!(d2 >= Duration::from_millis(70), "delay 2 too short: {d2:?}");
}

// Regression: hyper dropping request body when server sends Ok(ack 0) + terminal 412 must drain
// ack 0 and deliver SeqNumMismatch (not ConnectionLost) to batch 1 (T10, A6a).
#[tokio::test]
async fn regression_append_session_drains_buffered_ack_and_terminal_412_after_body_drop() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let server = MockH2Server::start(|_conn_id, req, mut respond| async move {
        let resp = Response::builder()
            .status(200)
            .header("content-type", "s2s/proto")
            .body(())
            .unwrap();
        let Ok(mut send) = respond.send_response(resp, false) else {
            return;
        };
        let mut body = req.into_body();
        let mut buf = BytesMut::new();
        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
        // Drop request body stream right before sending ack 0 + terminal 412 so the client's
        // input_tx.reserve() fails while responses are still in flight.
        drop(body);
        let _ = send.send_data(
            encode_s2s_regular_frame(&proto_append_ack(0, 1), false),
            false,
        );
        let _ = send.send_data(
            encode_s2s_terminal_frame(412, br#"{"seq_num_mismatch":1}"#),
            true,
        );
    })
    .await;

    let session = server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name)
        .append_session(AppendSessionConfig::new())
        .unwrap();

    let t0 = session.submit(sample_append_input()).await.unwrap();
    let t1 = session.submit(sample_append_input()).await.unwrap();
    // Submit a 3rd batch so `input_tx.reserve()` is actively raced against the server body drop.
    let t2 = session.submit(sample_append_input()).await.unwrap();

    assert_eq!(t0.await.expect("batch 0 must succeed").end.seq_num, 1);
    let err1 = t1.await.expect_err("batch 1 must receive SeqNumMismatch");
    assert!(
        matches!(err1, AppendSessionError::SeqNumMismatch(ref e) if e.assignable_seq_num == 1),
        "expected SeqNumMismatch(1), got {err1:?}"
    );
    let err2 = t2.await.expect_err("batch 2 must receive SessionClosed");
    assert!(
        matches!(
            err2,
            AppendSessionError::SessionClosed(ref c)
                if matches!(c.failure(), Some(AppendSessionError::SeqNumMismatch(_)))
        ),
        "expected SessionClosed(SeqNumMismatch), got {err2:?}"
    );
    let close_err = session.close().await.unwrap_err();
    assert!(
        matches!(close_err, AppendSessionError::SeqNumMismatch(_)),
        "{close_err:?}"
    );
}

// Regression: invalid ack record count delivers ProtocolError to the batch ticket (not Aborted).
#[tokio::test]
async fn regression_append_session_invalid_ack_delivers_protocol_error_to_ticket() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let server = MockH2Server::start(|_conn_id, req, mut respond| async move {
        let resp = Response::builder()
            .status(200)
            .header("content-type", "s2s/proto")
            .body(())
            .unwrap();
        let Ok(mut send) = respond.send_response(resp, false) else {
            return;
        };
        let mut body = req.into_body();
        let mut buf = BytesMut::new();
        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
        // Batch had 1 record, but server erroneously acks 2 records [0, 2).
        let _ = send.send_data(
            encode_s2s_regular_frame(&proto_append_ack(0, 2), false),
            true,
        );
    })
    .await;

    let session = server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name)
        .append_session(AppendSessionConfig::new())
        .unwrap();

    let ticket = session.submit(sample_append_input()).await.unwrap();
    let err = ticket.await.expect_err("bad ack must yield ProtocolError");
    assert!(
        matches!(err, AppendSessionError::Protocol(_)),
        "expected ProtocolError, got {err:?}"
    );
    let close_err = session.close().await.unwrap_err();
    assert!(
        matches!(close_err, AppendSessionError::Protocol(_)),
        "{close_err:?}"
    );
}

// Regression: Producer partial-batch backpressure flush breaks long linger (including
// Duration::MAX) so reserve() never deadlocks waiting for its own partial batch to linger.
#[tokio::test]
async fn regression_producer_backpressure_flushes_partial_batch_with_long_linger() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let server = MockH2Server::start(|_conn_id, req, mut respond| async move {
        let resp = Response::builder()
            .status(200)
            .header("content-type", "s2s/proto")
            .body(())
            .unwrap();
        let Ok(mut send) = respond.send_response(resp, false) else {
            return;
        };
        let mut body = req.into_body();
        let mut buf = BytesMut::new();
        let mut next_seq = 0u64;
        while let Some(SessionMessage::Regular(regular)) =
            read_one_s2s_frame(&mut body, &mut buf, true).await
        {
            let payload = regular.decompressed().unwrap();
            let decoded = api::stream::proto::AppendInput::decode(payload).unwrap();
            let count = decoded.records.len() as u64;
            let _ = send.send_data(
                encode_s2s_regular_frame(&proto_append_ack(next_seq, next_seq + count), false),
                false,
            );
            next_seq += count;
        }
        let _ = send.send_data(Bytes::new(), true);
    })
    .await;

    // max_unacked_bytes = 1 MiB, max_batch_bytes = 1 MiB, linger = Duration::MAX.
    // Record 1 is ~700 KiB (leaves batch partial!), Record 2 is ~700 KiB (exceeds remaining 300 KiB
    // unacked capacity). Without backpressure-triggered partial flush, Record 2 would deadlock!
    let producer = server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name)
        .producer(
            ProducerConfig::new()
                .with_max_unacked_bytes(1024 * 1024)
                .unwrap()
                .with_linger(Duration::MAX),
        )
        .unwrap();

    let big_record = || AppendRecord::new(vec![b'a'; 700 * 1024]).unwrap();
    let t1 = producer.submit(big_record()).await.unwrap();
    let t2 = tokio::time::timeout(Duration::from_secs(3), producer.submit(big_record()))
        .await
        .expect("backpressure must flush partial batch immediately even with Duration::MAX linger")
        .unwrap();

    producer.close().await.unwrap();
    assert_eq!(t1.await.unwrap().seq_num, 0);
    assert_eq!(t2.await.unwrap().seq_num, 1);
}

// Regression: ReadSession R11c reduced-wait after fetching a new record must reconnect with
// refreshed remaining wait instead of prematurely terminating on the server's shorter timer,
// AND R11d zero-wait 416 must resolve caught_up() across a trimmed gap, AND count=0 disconnect
// must stop cleanly instead of sending count=0.
#[tokio::test]
async fn regression_read_session_r11c_reduced_wait_r11d_caught_up_and_count_exhausted() {
    let (basin_name, stream_name) = test_basin_and_stream();

    // 1. R11c: baseline wait = 4s.
    //    - Attempt 1 sends heartbeat (starts idle clock), waits 1.2s, resets connection.
    //    - Attempt 2 arrives with reduced wait (< 4s), delivers a new record (restarts idle clock
    //      to full 4s!), then server closes cleanly -> client MUST reconnect (Attempt 3) with
    //      refreshed wait!
    let observed_waits = Arc::new(Mutex::new(Vec::<Option<u32>>::new()));
    let attempt_idx = Arc::new(AtomicUsize::new(0));
    let r11c_server = MockH2Server::start({
        let observed_waits = observed_waits.clone();
        let attempt_idx = attempt_idx.clone();
        move |_conn_id, req, mut respond| {
            let observed_waits = observed_waits.clone();
            let attempt_idx = attempt_idx.clone();
            async move {
                let wait_param = req.uri().query().and_then(|q| {
                    q.split('&')
                        .find_map(|kv| kv.strip_prefix("wait=")?.parse::<u32>().ok())
                });
                observed_waits.lock().unwrap().push(wait_param);
                let n = attempt_idx.fetch_add(1, Ordering::SeqCst);
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "s2s/proto")
                    .body(())
                    .unwrap();
                let Ok(mut send) = respond.send_response(resp, false) else {
                    return;
                };
                match n {
                    0 => {
                        let hb = ProtoReadBatch {
                            records: vec![],
                            tail: Some(ProtoStreamPosition {
                                seq_num: 0,
                                timestamp: 1000,
                            }),
                        }
                        .encode_to_vec();
                        let _ = send.send_data(encode_s2s_regular_frame(&hb, false), false);
                        tokio::time::sleep(Duration::from_millis(1200)).await;
                        send.send_reset(h2::Reason::INTERNAL_ERROR);
                    }
                    1 => {
                        // Deliver record 0 on the reduced-wait attempt, then clean EOF immediately.
                        let _ = send.send_data(
                            encode_s2s_regular_frame(&proto_read_batch(0, 1), false),
                            true,
                        );
                    }
                    _ => {
                        // Attempt 3: deliver record 1 and end cleanly.
                        let _ = send.send_data(
                            encode_s2s_regular_frame(&proto_read_batch(1, 2), false),
                            true,
                        );
                    }
                }
            }
        }
    })
    .await;

    let retry = RetryConfig::new()
        .with_max_attempts(3)
        .unwrap()
        .with_min_base_delay(Duration::ZERO)
        .with_max_base_delay(Duration::ZERO);
    let mut sess = r11c_server
        .client(retry)
        .basin(basin_name.clone())
        .stream(stream_name.clone())
        .read_session(
            ReadInput::new()
                .with_start(ReadStart::new().with_from(ReadFrom::SeqNum(0)))
                .with_stop(
                    ReadStop::new()
                        .with_wait(Duration::from_secs(4))
                        .unwrap()
                        .with_limits(ReadLimits::new().with_count(2)),
                ),
            ReadSessionConfig::default(),
        )
        .unwrap();

    let mut seqs = Vec::new();
    while let Some(res) = sess.next().await {
        seqs.push(res.unwrap().seq_num);
    }
    assert_eq!(seqs, vec![0, 1]);
    let waits = observed_waits.lock().unwrap().clone();
    assert_eq!(waits.len(), 3, "must reconnect after reduced-wait attempt");
    assert_eq!(waits[0], Some(4));
    assert!(
        waits[1].unwrap() < 4,
        "attempt 2 should have reduced wait: {waits:?}"
    );
    assert_eq!(
        waits[2],
        Some(4),
        "attempt 3 should refresh wait after new record: {waits:?}"
    );

    // 2. R11d: resumed zero-wait 416 resolves caught_up() and advances next_seq_num across trimmed
    //    gap (record 0 has tail=3 so session is not yet caught up, then attempt 2 gets 416
    //    {tail:5}).
    let r11d_attempt = Arc::new(AtomicUsize::new(0));
    let r11d_reset_gate = Arc::new(tokio::sync::Notify::new());
    let r11d_server = MockH2Server::start({
        let r11d_attempt = r11d_attempt.clone();
        let r11d_reset_gate = r11d_reset_gate.clone();
        move |_conn_id, _req, mut respond| {
            let r11d_attempt = r11d_attempt.clone();
            let r11d_reset_gate = r11d_reset_gate.clone();
            async move {
                let n = r11d_attempt.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "s2s/proto")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        // Record 0 with tail=3 so session is still behind tail after delivering 0.
                        let _ = send.send_data(
                            encode_s2s_regular_frame(&proto_read_batch(0, 3), false),
                            false,
                        );
                        // Wait until client receives record 0 before resetting so h2 does not
                        // drop the buffered DATA frame on RST_STREAM.
                        r11d_reset_gate.notified().await;
                        send.send_reset(h2::Reason::INTERNAL_ERROR);
                    }
                } else {
                    // Resumed with wait=0 -> 416 with tail jumped to seq 5 (trimmed gap).
                    let resp = Response::builder()
                        .status(416)
                        .header("content-type", "application/json")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            Bytes::from_static(br#"{"tail":{"seq_num":5,"timestamp":5000}}"#),
                            true,
                        );
                    }
                }
            }
        }
    })
    .await;

    let mut r11d_sess = r11d_server
        .client(
            RetryConfig::new()
                .with_max_attempts(2)
                .unwrap()
                .with_min_base_delay(Duration::ZERO)
                .with_max_base_delay(Duration::ZERO),
        )
        .basin(basin_name.clone())
        .stream(stream_name.clone())
        .read_session(
            ReadInput::new()
                .with_start(ReadStart::new().with_from(ReadFrom::SeqNum(0)))
                .with_stop(ReadStop::new().with_wait(Duration::ZERO).unwrap()),
            ReadSessionConfig::default(),
        )
        .unwrap();

    let cu = r11d_sess.caught_up();
    assert_eq!(r11d_sess.next().await.unwrap().unwrap().seq_num, 0);
    assert!(!r11d_sess.is_caught_up());
    r11d_reset_gate.notify_one();
    assert!(r11d_sess.next().await.is_none());
    assert_eq!(r11d_sess.next_seq_num(), Some(5));
    assert_eq!(r11d_sess.last_observed_tail().unwrap().seq_num, 5);
    assert_eq!(cu.await.unwrap().seq_num, 5);

    // 3. Count exhausted + transport reset ends cleanly without retrying with count=0.
    let count_reqs = Arc::new(AtomicUsize::new(0));
    let count_reset_gate = Arc::new(tokio::sync::Notify::new());
    let count_server = MockH2Server::start({
        let count_reqs = count_reqs.clone();
        let count_reset_gate = count_reset_gate.clone();
        move |_conn_id, _req, mut respond| {
            let count_reqs = count_reqs.clone();
            let count_reset_gate = count_reset_gate.clone();
            async move {
                count_reqs.fetch_add(1, Ordering::SeqCst);
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "s2s/proto")
                    .body(())
                    .unwrap();
                if let Ok(mut send) = respond.send_response(resp, false) {
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_read_batch(0, 1), false),
                        false,
                    );
                    count_reset_gate.notified().await;
                    send.send_reset(h2::Reason::INTERNAL_ERROR);
                }
            }
        }
    })
    .await;

    let mut count_sess = count_server
        .client(
            RetryConfig::new()
                .with_max_attempts(3)
                .unwrap()
                .with_min_base_delay(Duration::ZERO)
                .with_max_base_delay(Duration::ZERO),
        )
        .basin(basin_name)
        .stream(stream_name)
        .read_session(
            ReadInput::new()
                .with_start(ReadStart::new().with_from(ReadFrom::SeqNum(0)))
                .with_stop(ReadStop::new().with_limits(ReadLimits::new().with_count(1))),
            ReadSessionConfig::default(),
        )
        .unwrap();

    assert_eq!(count_sess.next().await.unwrap().unwrap().seq_num, 0);
    count_reset_gate.notify_one();
    assert!(count_sess.next().await.is_none());
    assert_eq!(
        count_reqs.load(Ordering::SeqCst),
        1,
        "must not reconnect with count=0 after limit exhausted"
    );
}

// r1 A1
#[tokio::test]
async fn spec_a1_unary_append_rejects_malformed_ack_range() {
    let (basin_name, stream_name) = test_basin_and_stream();

    let server = MockH2Server::from_responses([
        // 1. end.seq_num < start.seq_num
        CannedResponse::new(200, proto_append_ack(5, 3))
            .with_header("content-type", "application/protobuf"),
        // 2. end.seq_num - start.seq_num != batch record count (submitted 2, acked 1)
        CannedResponse::new(200, proto_append_ack(10, 11))
            .with_header("content-type", "application/protobuf"),
        // 3. matching count (submitted 2, acked 2) succeeds
        CannedResponse::new(200, proto_append_ack(10, 12))
            .with_header("content-type", "application/protobuf"),
    ])
    .await;

    let stream = server
        .client(RetryConfig::new().with_max_attempts(1).unwrap())
        .basin(basin_name)
        .stream(stream_name);

    let two_records = || {
        AppendInput::new(
            AppendRecordBatch::try_from_iter([
                AppendRecord::new("a").unwrap(),
                AppendRecord::new("b").unwrap(),
            ])
            .unwrap(),
        )
    };

    let err_reversed = stream.append(two_records()).await.unwrap_err();
    assert!(
        matches!(err_reversed, AppendError::Protocol(_)),
        "expected ProtocolError when end.seq_num < start.seq_num, got {err_reversed:?}"
    );
    assert!(!err_reversed.is_retryable());
    assert!(!err_reversed.has_no_side_effects());

    let err_mismatch = stream.append(two_records()).await.unwrap_err();
    assert!(
        matches!(err_mismatch, AppendError::Protocol(_)),
        "expected ProtocolError when ack count mismatches batch size, got {err_mismatch:?}"
    );

    let ok_ack = stream.append(two_records()).await.unwrap();
    assert_eq!(ok_ack.start.seq_num, 10);
    assert_eq!(ok_ack.end.seq_num, 12);
}
