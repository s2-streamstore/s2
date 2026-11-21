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
    S2,
    append_session::AppendSessionConfig,
    batching::{Batcher, BatcherConfig, TryBatchError},
    error::{AppendError, AppendSessionError, ReadError, ReadSessionError, RequestError, S2Error},
    producer::ProducerConfig,
    types::{
        AccessTokenId, AccessTokenScopeInput, AccountEndpoint, AppendInput, AppendRecord,
        AppendRecordBatch, AppendRetryPolicy, BasinEndpoint, BasinName, BasinReconfiguration,
        CommandRecord, CreateNetworkPolicyInput, DeleteOnEmptyConfig, DeleteOnEmptyReconfiguration,
        EncryptionKey, EnsureOutput, FencingToken, Header, IssueAccessTokenInput, ListBasinsInput,
        Maybe, MeteredBytes, NetworkPolicy, OperationGroupPermissions, PublicNetPolicy, ReadFrom,
        ReadInput, ReadLimits, ReadSessionConfig, ReadSessionRetryPolicy, ReadStart, ReadStop,
        RetentionPolicy, RetryConfig, S2Config, S2Endpoints, SequencedRecord, StreamName,
        StreamReconfiguration, TimeRange, TimeRangeAndInterval, Timestamp, TimestampingMode,
        TimestampingReconfiguration,
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
#[test]
fn spec_m2_ensure_output_variants() {
    assert!(matches!(
        EnsureOutput::from(ProvisionResult::Created(1)),
        EnsureOutput::Created(1)
    ));
    assert!(matches!(
        EnsureOutput::from(ProvisionResult::Updated(2)),
        EnsureOutput::Updated(2)
    ));
    assert!(matches!(
        EnsureOutput::from(ProvisionResult::Noop(3)),
        EnsureOutput::Noop(3)
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
    let read_res = read_stream
        .read_session(ReadInput::new(), ReadSessionConfig::default())
        .await;
    let read_err = match read_res {
        Err(e) => e,
        Ok(mut sess) => {
            use futures_util::StreamExt as _;
            sess.next()
                .await
                .expect("expected terminal error item")
                .expect_err("expected terminal error")
        }
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
        .await
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
    assert!(matches!(
        stream
            .read_session(ReadInput::new(), ReadSessionConfig::default())
            .await,
        Err(ReadSessionError::ClientClosed(_))
    ));

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

    let mut read_session = tokio::time::timeout(
        Duration::from_secs(3),
        read_server
            .client(fast_retry_3)
            .basin(basin_name)
            .stream(stream_name)
            .read_session(ReadInput::new(), ReadSessionConfig::default()),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "read open timed out; attempts={:?}",
            *read_attempts.lock().unwrap()
        )
    })
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
    assert_eq!(first.records.len(), 1);
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
        .await
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

// spec: r1 A6, A6a, A6b, A6d, A8b, A9, T10
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

// spec: r1 T6a, T6b, T7c
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
