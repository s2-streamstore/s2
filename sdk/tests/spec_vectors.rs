//! Spec conformance vector runner and rule-tagged tests for Revision 1 (Draft).
//!
//! Runs the shared JSON test vectors from `api/specs/sdk/vectors/` and
//! `api/specs/s2/v1/error-codes.json` against `s2-sdk` and `s2-api`.

use std::{
    collections::{BTreeMap, BTreeSet},
    env::VarError,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use s2_api::v1::{
    self as api,
    error::ErrorCode,
    stream::s2s::{FrameDecoder, SessionMessage},
};
use s2_common::resources::ProvisionResult;
use s2_sdk::{
    S2,
    append_session::AppendSessionConfig,
    batching::{BatchLimits, BatchingConfig},
    error::RequestError,
    producer::ProducerConfig,
    types::{
        AccountEndpoint, AppendInput, AppendRecord, AppendRecordBatch, BasinEndpoint, BasinName,
        BasinReconfiguration, CommandRecord, DeleteOnEmptyConfig, DeleteOnEmptyReconfiguration,
        EncryptionKey, EnsureOutput, FencingToken, Header, Maybe, MeteredBytes, ReadFrom,
        ReadLimits, ReadSessionRetryPolicy, ReadStart, ReadStop, RetentionPolicy, RetryConfig,
        S2Config, S2Endpoints, SequencedRecord, StreamReconfiguration, TimeRange,
        TimeRangeAndInterval, Timestamp, TimestampingMode, TimestampingReconfiguration,
    },
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
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
                        let res = BatchLimits::new().with_max_batch_records(v);
                        assert_eq!(res.is_ok(), expect_valid, "{label}");
                    }
                    Err(_) => assert!(!expect_valid, "{label}"),
                },
                "batching.max_batch_bytes" => match raw.parse::<usize>() {
                    Ok(v) => {
                        let res = BatchLimits::new().with_max_batch_bytes(v);
                        assert_eq!(res.is_ok(), expect_valid, "{label}");
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
                            let _ = BatchingConfig::new().with_linger(dur);
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
