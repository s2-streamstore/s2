use std::{
    collections::{BTreeMap, BTreeSet},
    env::VarError,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use s2_api::v1::{
    error::ErrorCode,
    stream::s2s::{FrameDecoder, SessionMessage},
};
use s2_sdk::{
    S2,
    append_session::AppendSessionConfig,
    batching::BatcherConfig,
    error::{AppendError, ReadError, ReadSessionError, S2Error, ValidationError},
    producer::ProducerConfig,
    read_session::ReadSessionConfig,
    types::{
        AccessTokenMatcher, AccessTokenScope, AccountEndpoint, AccountMetricSet, AppendInput,
        AppendRecord, AppendRecordBatch, BasinEndpoint, BasinMatcher, BasinMetricSet, BasinName,
        CommandRecord, Compression, DeleteOnEmptyConfig, DeleteOnEmptyReconfiguration,
        EncryptionAlgorithm, EncryptionKey, FencingToken, Header, IssueAccessTokenInput,
        ListAccessTokensInput, Metric, MetricUnit, NetworkPolicySlug, Operation,
        OperationGroupPermissions, PrivateNet, PrivateNetPolicy, PublicNetPolicy, ReadInput,
        ReadStart, RetentionPolicy, RetryConfig, S2Config, S2Endpoints, SequencedRecord,
        StreamMatcher, StreamMetricSet, TimeRange, TimeRangeAndInterval, TimeseriesInterval,
        Timestamp, TimestampingMode,
    },
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio_util::codec::Decoder;

use crate::support::*;

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
#[test]
fn spec_vectors_endpoints() {
    let file: EndpointsFile = read_json("sdk/vectors/endpoints.json");
    assert!(!file.cases.is_empty());

    for case in &file.cases {
        let label = format!("[{}] {}", case.rule, case.name);
        let basin: BasinName = case.basin.parse().expect("valid basin in vector");

        if let Some(env) = &case.env {
            let result =
                S2Config::from_env_with(|key| env.get(key).cloned().ok_or(VarError::NotPresent))
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
            let result: Result<S2Endpoints, ValidationError> =
                match (&endpoints.account, &endpoints.basin) {
                    (Some(account), Some(basin_ep)) => AccountEndpoint::new(account)
                        .and_then(|a| BasinEndpoint::new(basin_ep).map(|b| (a, b)))
                        .and_then(|(a, b)| S2Endpoints::new(a, b)),
                    (Some(account), None) => S2Endpoints::from_env_with(|key| match key {
                        "S2_ACCOUNT_ENDPOINT" => Ok(account.clone()),
                        _ => Err(VarError::NotPresent),
                    }),
                    (None, Some(basin_ep)) => S2Endpoints::from_env_with(|key| match key {
                        "S2_BASIN_ENDPOINT" => Ok(basin_ep.clone()),
                        _ => Err(VarError::NotPresent),
                    }),
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
    result: Result<S2Endpoints, ValidationError>,
    expect: &EndpointExpect,
) {
    match expect {
        EndpointExpect::Error { error } => {
            assert_eq!(error, "ValidationError", "{label}");
            let _ = result.expect_err(&format!("{label}: expected ValidationError"));
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
#[tokio::test]
async fn spec_vectors_keys() {
    let file: KeysFile = read_json("sdk/vectors/keys.json");
    assert!(!file.cases.is_empty());

    let seen_header = Arc::new(Mutex::new(None::<String>));
    let server = MockH2Server::start({
        let seen_header = seen_header.clone();
        move |_conn_id, req, respond| {
            let seen_header = seen_header.clone();
            async move {
                *seen_header.lock().unwrap() =
                    header_str(&req, "s2-encryption-key").map(str::to_owned);
                send_proto(respond, proto_read_batch_records(&[], Some(0)));
            }
        }
    })
    .await;
    let (basin_name, stream_name) = test_basin_and_stream();
    let client = server.client(no_retry_config());
    let basin = client.basin(basin_name);

    for case in &file.cases {
        let label = format!("[{}] {}", case.rule, case.name);
        let result = match (&case.text, &case.bytes_hex) {
            (Some(text), None) => text.parse::<EncryptionKey>(),
            (None, Some(hex)) => EncryptionKey::from_bytes(&decode_hex(hex)),
            _ => panic!("{label}: case must set exactly one of text or bytes_hex"),
        };

        match &case.expect {
            KeyExpect::Header { header } => {
                let key = result.unwrap_or_else(|e| panic!("{label}: unexpected error {e}"));
                *seen_header.lock().unwrap() = None;
                let stream = basin.stream(stream_name.clone()).with_encryption_key(key);
                let _ = stream.read(ReadInput::new()).await.expect("mock read ok");
                assert_eq!(
                    seen_header.lock().unwrap().as_deref(),
                    Some(header.as_str()),
                    "{label}"
                );
            }
            KeyExpect::Error { error } => {
                assert_eq!(error, "ValidationError", "{label}");
                assert!(result.is_err(), "{label}: expected ValidationError");
            }
        }
    }
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
#[test]
fn spec_vectors_numbers() {
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
            let check_u64 = |verify: &dyn Fn(u64)| match raw.parse::<u64>() {
                Ok(v) => {
                    assert!(expect_valid, "{label}");
                    verify(v);
                }
                Err(_) => assert!(!expect_valid, "{label}: expected valid u64"),
            };
            match case.field.as_str() {
                "record.timestamp" => check_u64(&|v| {
                    assert_eq!(
                        AppendRecord::new("").unwrap().with_timestamp(v).timestamp(),
                        Some(v),
                        "{label}"
                    );
                }),
                "append.match_seq_num" => check_u64(&|v| {
                    let input = AppendInput::new(dummy_batch.clone()).with_match_seq_num(v);
                    assert_eq!(input.match_seq_num(), Some(v), "{label}");
                }),
                "read.start.seq_num" => check_u64(&|v| {
                    let input = ReadInput::new().with_start(ReadStart::SeqNum(v));
                    assert_eq!(input.start(), Some(ReadStart::SeqNum(v)), "{label}");
                }),
                "read.start.timestamp" => check_u64(&|v| {
                    let input = ReadInput::new().with_start(ReadStart::Timestamp(v));
                    assert_eq!(input.start(), Some(ReadStart::Timestamp(v)), "{label}");
                }),
                "read.start.tail_offset" => check_u64(&|v| {
                    let input = ReadInput::new().with_start(ReadStart::TailOffset(v));
                    assert_eq!(input.start(), Some(ReadStart::TailOffset(v)), "{label}");
                }),
                "read.stop.count" => check_u64(&|v| {
                    assert_eq!(ReadInput::new().with_count(v).count(), Some(v), "{label}");
                }),
                "read.stop.bytes" => check_u64(&|v| {
                    assert_eq!(ReadInput::new().with_bytes(v).bytes(), Some(v), "{label}");
                }),
                "read.stop.until" => check_u64(&|v| {
                    assert_eq!(ReadInput::new().with_until(v).until(), Some(v), "{label}");
                }),
                "trim.seq_num" => check_u64(&|v| {
                    let rec: AppendRecord = CommandRecord::trim(v).into();
                    assert_eq!(rec.body().as_ref(), &v.to_be_bytes(), "{label}");
                }),
                "client.max_attempts" => match raw.parse::<u32>() {
                    Ok(v) => {
                        let res = RetryConfig::new().with_max_attempts(v);
                        assert_eq!(res.is_ok(), expect_valid, "{label}");
                    }
                    Err(_) => assert!(!expect_valid, "{label}"),
                },
                "session.max_unacked_bytes" => match raw.parse::<usize>() {
                    Ok(v) => {
                        let sess = AppendSessionConfig::new().with_max_unacked_bytes(v);
                        let prod = ProducerConfig::new().with_max_unacked_bytes(v);
                        assert_eq!(sess.is_ok(), expect_valid, "{label}");
                        assert_eq!(prod.is_ok(), expect_valid, "{label}");
                    }
                    Err(_) => assert!(!expect_valid, "{label}"),
                },
                "session.max_unacked_batches" => match raw.parse::<usize>() {
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
            let parse_whole_secs_u64 = || {
                raw_ms
                    .parse::<u128>()
                    .ok()
                    .filter(|ms| ms % 1000 == 0)
                    .and_then(|ms| u64::try_from(ms / 1000).ok())
            };
            match case.field.as_str() {
                "read.stop.wait" => {
                    match parse_whole_secs_u64().and_then(|s| u32::try_from(s).ok()) {
                        Some(secs) => {
                            assert!(expect_valid, "{label}");
                            assert_eq!(
                                ReadInput::new().with_wait_secs(secs).wait_secs(),
                                Some(secs),
                                "{label}"
                            );
                        }
                        None => assert!(
                            !expect_valid,
                            "{label}: unrepresentable in Rust u32 whole seconds"
                        ),
                    }
                }
                "stream_config.retention_age" => match parse_whole_secs_u64() {
                    Some(secs) => {
                        assert!(expect_valid, "{label}");
                        assert_eq!(
                            s2_sdk::types::StreamConfig::new()
                                .with_retention_policy(RetentionPolicy::Age(secs))
                                .retention_policy(),
                            Some(&RetentionPolicy::Age(secs)),
                            "{label}"
                        );
                    }
                    None => assert!(
                        !expect_valid,
                        "{label}: unrepresentable in Rust u64 whole seconds"
                    ),
                },
                "stream_config.delete_on_empty.min_age" => match parse_whole_secs_u64() {
                    Some(secs) => {
                        assert!(expect_valid, "{label}");
                        assert_eq!(
                            DeleteOnEmptyConfig::new()
                                .with_min_age_secs(secs)
                                .min_age_secs(),
                            secs,
                            "{label}"
                        );
                        assert_eq!(
                            DeleteOnEmptyReconfiguration::new()
                                .with_min_age_secs(secs)
                                .min_age_secs(),
                            s2_sdk::types::Reconfigure::Set(secs),
                            "{label}"
                        );
                    }
                    None => assert!(
                        !expect_valid,
                        "{label}: unrepresentable in Rust u64 whole seconds"
                    ),
                },
                other => match raw_ms.parse::<u64>() {
                    Ok(ms) => {
                        let dur = Duration::from_millis(ms);
                        match other {
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
                },
            }
        } else {
            panic!("{label}: case must have value or millis");
        }
    }

    // Cross-field constraint (C2): min_base_delay <= max_base_delay checked at S2::new().
    let bad_retry = RetryConfig::new()
        .with_min_base_delay(Duration::from_secs(2))
        .with_max_base_delay(Duration::from_secs(1));
    let _err: ValidationError = S2::new(S2Config::new("token").with_retry(bad_retry))
        .expect_err("min_base_delay > max_base_delay must fail S2::new");

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
                let seq_rec = SequencedRecord::new(0, body, headers, 0);
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
            let rec = SequencedRecord::new(0, Bytes::new(), headers, 0);
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
    message: Option<String>,
}

// spec: r1 C6, E2, F1, T9
#[tokio::test]
async fn spec_vectors_s2s_frames() {
    let file: S2sFramesFile = read_json("sdk/vectors/s2s-frames.json");
    assert!(!file.cases.is_empty());

    let pending_wire = Arc::new(Mutex::new(Bytes::new()));
    let server = MockH2Server::start({
        let pending_wire = pending_wire.clone();
        move |_conn_id, _req, respond| {
            let pending_wire = pending_wire.clone();
            async move {
                let wire = pending_wire.lock().unwrap().clone();
                if let Some(mut s2s) = S2sResponder::open(respond) {
                    s2s.send_raw(wire, true);
                }
            }
        }
    })
    .await;
    let stream = server.stream(no_retry_config());

    for case in &file.cases {
        let label = format!("[{}] {}", case.rule, case.name);
        let mut wire = Vec::new();
        for piece in &case.bytes {
            match piece {
                BytePiece::Hex { hex } => wire.extend_from_slice(&decode_hex(hex)),
                BytePiece::Zeros { zeros } => wire.resize(wire.len() + *zeros, 0),
            }
        }

        // 1. Decode regular payloads via FrameDecoder and track the offset where the terminal or
        //    trailing failure starts so we can also replay it through a real ReadSession!
        let mut decoder = FrameDecoder;
        let mut buf = BytesMut::from(wire.as_slice());
        let mut messages = Vec::new();
        let mut end_slice_offset = wire.len();
        loop {
            let remaining_before = buf.len();
            match decoder.decode(&mut buf) {
                Ok(Some(SessionMessage::Regular(data))) => {
                    let reconnect_advised = data.reconnect_advised();
                    match data.decompressed() {
                        Ok(payload) => messages.push((payload, reconnect_advised)),
                        Err(_) => {
                            end_slice_offset = wire.len() - remaining_before;
                            break;
                        }
                    }
                }
                Ok(Some(SessionMessage::Terminal(_))) | Err(_) => {
                    end_slice_offset = wire.len() - remaining_before;
                    break;
                }
                Ok(None) => {
                    if !buf.is_empty() {
                        end_slice_offset = wire.len() - remaining_before;
                    }
                    break;
                }
            }
        }

        assert_eq!(
            messages.len(),
            case.expect.messages.len(),
            "{label}: message count mismatch"
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

        // 2. Replay the ending bytes through a real ReadSession so terminal/error parsing goes
        //    through the SDK's real ReadSessionError::from_terminal_message & stream decoder!
        *pending_wire.lock().unwrap() = Bytes::copy_from_slice(&wire[end_slice_offset..]);
        let mut sess = stream
            .read_session(ReadInput::new().with_count(1), ReadSessionConfig::default())
            .unwrap();
        let outcome = sess.next().await;
        match case.expect.end.kind.as_str() {
            "clean" => assert!(
                outcome.is_none(),
                "{label}: expected clean EOF, got {outcome:?}"
            ),
            "ServerError" => match outcome {
                Some(Err(ReadSessionError::Server(s))) => {
                    assert_eq!(Some(s.status.as_u16()), case.expect.end.status, "{label}");
                    assert_eq!(s.code, case.expect.end.code, "{label}");
                    if let Some(expected_msg) = &case.expect.end.message {
                        assert_eq!(&s.message, expected_msg, "{label}");
                    }
                }
                other => panic!("{label}: expected ServerError, got {other:?}"),
            },
            "ProtocolError" => assert!(
                matches!(outcome, Some(Err(ReadSessionError::Protocol(_)))),
                "{label}: expected ProtocolError, got {outcome:?}"
            ),
            "ConnectionLostError" => assert!(
                matches!(outcome, Some(Err(ReadSessionError::ConnectionLost(_)))),
                "{label}: expected ConnectionLostError, got {outcome:?}"
            ),
            other => panic!("{label}: unexpected end type {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// D4: dates.json — wall-clock and metrics timestamps
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct DatesFile {
    cases: Vec<DateCase>,
}

#[derive(Deserialize)]
struct DateCase {
    rule: String,
    name: String,
    field: String,
    epoch_secs: String,
    #[serde(default)]
    subsec_millis: i32,
    expect: serde_json::Value,
}

// spec: r1 D4
#[test]
fn spec_d4_wall_clock_and_metrics_timestamps() {
    let file: DatesFile = read_json("sdk/vectors/dates.json");
    assert!(!file.cases.is_empty());

    let scope = AccessTokenScope::from_op_group_perms(OperationGroupPermissions::read_write_all());

    for case in &file.cases {
        let label = format!("[{}] {}", case.rule, case.name);
        let secs: i64 = case.epoch_secs.parse().expect("valid i64 epoch_secs");
        let nanos: i32 = case.subsec_millis * 1_000_000;
        let ts = Timestamp::new(secs, nanos);

        match case.field.as_str() {
            "access_token.expires_at" => {
                let expect_valid = match case.expect.as_str() {
                    Some("valid") => true,
                    Some("ValidationError") => false,
                    other => panic!("{label}: unexpected expect {other:?}"),
                };
                match ts {
                    Ok(ts) => {
                        let res =
                            IssueAccessTokenInput::new("tok-d4".parse().unwrap(), scope.clone())
                                .with_expires_at(ts);
                        assert_eq!(res.is_ok(), expect_valid, "{label}: ts={ts}");
                    }
                    Err(_) => {
                        // jiff::Timestamp::MAX is 9999-12-30T22:00:00.999999999Z (253402207200),
                        // documented on IssueAccessTokenInput::with_expires_at and in D4.
                        assert!(
                            !expect_valid || secs > Timestamp::MAX.as_second(),
                            "{label}: unexpectedly unrepresentable in jiff::Timestamp"
                        );
                    }
                }
            }
            "metrics.timestamp" => {
                let ts = ts.unwrap_or_else(|e| panic!("{label}: unexpected Timestamp err {e}"));
                if case.expect.as_str() == Some("ValidationError") {
                    assert!(
                        TimeRange::new(ts, Timestamp::UNIX_EPOCH).is_err(),
                        "{label}: start"
                    );
                    assert!(
                        TimeRange::new(Timestamp::UNIX_EPOCH, ts).is_err(),
                        "{label}: end"
                    );
                    assert!(
                        TimeRangeAndInterval::new(ts, Timestamp::UNIX_EPOCH).is_err(),
                        "{label}: start"
                    );
                    assert!(
                        TimeRangeAndInterval::new(Timestamp::UNIX_EPOCH, ts).is_err(),
                        "{label}: end"
                    );
                } else {
                    let expected_secs: i64 = case.expect["unix_secs"]
                        .as_str()
                        .expect("unix_secs string")
                        .parse()
                        .expect("valid i64 unix_secs");
                    let range = TimeRange::new(ts, ts)
                        .unwrap_or_else(|e| panic!("{label}: unexpected error {e}"));
                    assert_eq!(range.start().as_second(), expected_secs, "{label}");
                    assert_eq!(range.end().as_second(), expected_secs, "{label}");
                    assert_eq!(range.start().subsec_nanosecond(), 0, "{label}");
                    let tri = TimeRangeAndInterval::new(ts, ts)
                        .unwrap_or_else(|e| panic!("{label}: unexpected error {e}"));
                    assert_eq!(tri.start().as_second(), expected_secs, "{label}");
                    assert_eq!(tri.end().as_second(), expected_secs, "{label}");
                    assert_eq!(tri.start().subsec_nanosecond(), 0, "{label}");
                }
            }
            other => panic!("{label}: unexpected field {other:?}"),
        }
    }
}

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

// spec: r1 E1, E2, E2a, E2b, E4a, E4b, E4c, E4e, F4, C8
#[tokio::test]
async fn spec_vectors_errors() {
    let file: ErrorsFile = read_json("sdk/vectors/errors.json");
    assert!(!file.cases.is_empty());

    let mut responses: Vec<CannedResponse> = file
        .cases
        .iter()
        .map(|c| CannedResponse::new(c.status, c.body.clone()))
        .collect();
    // Extra E4c check: known code paired with mismatched HTTP status falls back to HTTP status.
    responses.push(CannedResponse::new(
        400,
        r#"{"code":"unavailable","message":"mismatch"}"#,
    ));
    let server = MockH2Server::from_responses(responses).await;
    let stream = server.stream(no_retry_config());

    for case in &file.cases {
        let label = format!("[{}] {}", case.rule, case.name);
        let expect = case.expect.get("if_representable").unwrap_or(&case.expect);
        let expected_type = expect["type"].as_str().unwrap();
        let expected_status = expect["status"].as_u64().unwrap() as u16;
        let expected_code = expect["code"].as_str();
        let expected_message = expect["message"].as_str().unwrap();
        let expected_retryable = expect["is_retryable"].as_bool().unwrap();
        let expected_no_side_effects = expect["has_no_side_effects"].as_bool().unwrap();

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
                        assert_eq!(e.server_error().status.as_u16(), expected_status, "{label}");
                        assert_eq!(e.server_error().code.as_deref(), expected_code, "{label}");
                        assert_eq!(e.server_error().message, expected_message, "{label}");
                    }
                    "FencingTokenMismatchError" => {
                        let AppendError::FencingTokenMismatch(e) = &err else {
                            panic!(
                                "{label}: expected AppendError::FencingTokenMismatch, got {err:?}"
                            );
                        };
                        let expected_tok = expect["current_fencing_token"].as_str().unwrap();
                        assert_eq!(&*e.current_fencing_token, expected_tok, "{label}");
                        assert_eq!(e.server_error().status.as_u16(), expected_status, "{label}");
                        assert_eq!(e.server_error().code.as_deref(), expected_code, "{label}");
                        assert_eq!(e.server_error().message, expected_message, "{label}");
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
                        assert_eq!(e.server_error().status.as_u16(), expected_status, "{label}");
                        assert_eq!(e.server_error().code.as_deref(), expected_code, "{label}");
                        assert_eq!(e.server_error().message, expected_message, "{label}");
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

    // E4c: status/code mismatch falls back to HTTP status classification.
    let mismatch = stream
        .append(sample_append_input())
        .await
        .expect_err("400 mismatch must fail");
    assert!(!mismatch.is_retryable());
    assert!(!mismatch.has_no_side_effects());
    let AppendError::Server(se) = mismatch else {
        panic!("expected ServerError, got {mismatch:?}");
    };
    assert_eq!(se.status.as_u16(), 400);
    assert_eq!(se.code.as_deref(), Some("unavailable"));
}

// spec: r1 F2, F3
#[tokio::test]
async fn spec_f2_f3_open_enums_tagged_unions_and_closed_request_enums() {
    // F2: Every server-returned enum and externally tagged `oneOf` union preserves unknown wire
    // name / tag in `Unknown(String)` end-to-end across HTTP responses.
    let server = MockH2Server::from_responses([
        CannedResponse::new(
            200,
            r#"{
                "values": [
                    {"histogram":{"name":"latency","buckets":[1,2]}},
                    {"scalar":{"name":"x","unit":"microseconds","value":1.0}},
                    {"accumulation":{"name":"y","unit":"bytes","interval":"week","values":[]}}
                ]
            }"#,
        ),
        CannedResponse::new(
            200,
            r#"{
                "stream_cipher": "chacha20-poly1305",
                "default_stream_config": {
                    "retention_policy": {"max_bytes": 1048576},
                    "timestamping": {"mode": "hybrid"}
                }
            }"#,
        ),
        CannedResponse::new(
            200,
            r#"[{"name":"aws:us-east-1","is_private":false,"private_net":{"gcp":{"service_attachment":"projects/p/regions/r/serviceAttachments/s"}}}]"#,
        ),
        CannedResponse::new(
            200,
            r#"{
                "id": "pol.a1b2c3d4",
                "slug": "pol",
                "created_at": "2026-01-01T00:00:00Z",
                "policy": {
                    "public_net": {"asn": [64512]},
                    "private_net": {"gcp": {"psc_ids": ["1"]}}
                }
            }"#,
        ),
        CannedResponse::new(
            200,
            r#"{
                "access_tokens": [{
                    "id": "tok-1",
                    "auto_prefix_streams": false,
                    "scope": {
                        "ops": ["future-op"],
                        "basins": {"glob": "prod-*"},
                        "streams": {"regex": "events-.*"},
                        "access_tokens": {"tag": "ci"}
                    }
                }],
                "has_more": false
            }"#,
        ),
    ])
    .await;
    let s2 = server.client(no_retry_config());
    let (basin_name, _) = test_basin_and_stream();

    let metrics = s2
        .get_account_metrics(AccountMetricSet::ActiveBasins(
            TimeRange::new(
                Timestamp::UNIX_EPOCH,
                Timestamp::UNIX_EPOCH + Duration::from_secs(60),
            )
            .unwrap(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        &metrics[0],
        Metric::Unknown(tag) if tag == "histogram"
    ));
    assert!(matches!(
        &metrics[1],
        Metric::Scalar(s) if s.unit == MetricUnit::Unknown("microseconds".to_owned())
    ));
    assert!(matches!(
        &metrics[2],
        Metric::Accumulation(a) if a.interval == TimeseriesInterval::Unknown("week".to_owned())
    ));

    let basin_cfg = s2.get_basin_config(basin_name).await.unwrap();
    assert_eq!(
        basin_cfg.stream_cipher(),
        Some(&EncryptionAlgorithm::Unknown(
            "chacha20-poly1305".to_owned()
        ))
    );
    let stream_cfg = basin_cfg.default_stream_config().unwrap();
    assert_eq!(
        stream_cfg.retention_policy(),
        Some(&RetentionPolicy::Unknown("max_bytes".to_owned()))
    );
    assert_eq!(
        stream_cfg.timestamping().unwrap().mode(),
        Some(&TimestampingMode::Unknown("hybrid".to_owned()))
    );

    let locations = s2.list_locations().await.unwrap();
    assert_eq!(
        locations[0].private_net,
        Some(PrivateNet::Unknown("gcp".to_owned()))
    );

    let pol = s2
        .get_network_policy("pol".parse::<NetworkPolicySlug>().unwrap())
        .await
        .unwrap();
    assert_eq!(
        pol.policy.public_net(),
        Some(&PublicNetPolicy::Unknown("asn".to_owned()))
    );
    assert_eq!(
        pol.policy.private_net(),
        Some(&PrivateNetPolicy::Unknown("gcp".to_owned()))
    );

    let tokens = s2
        .list_access_tokens(ListAccessTokensInput::new())
        .await
        .unwrap();
    let scope = &tokens.values[0].scope;
    assert!(
        scope
            .ops()
            .contains(&Operation::Unknown("future-op".to_owned()))
    );
    assert_eq!(
        scope.basins(),
        Some(&BasinMatcher::Unknown("glob".to_owned()))
    );
    assert_eq!(
        scope.streams(),
        Some(&StreamMatcher::Unknown("regex".to_owned()))
    );
    assert_eq!(
        scope.access_tokens(),
        Some(&AccessTokenMatcher::Unknown("tag".to_owned()))
    );

    // F3: Client-sent-only enums are closed (verified by exhaustive match with no wildcard and no
    // Unknown variant).
    fn check_closed_request_enums(
        c: Compression,
        f: ReadStart,
        am: AccountMetricSet,
        bm: BasinMetricSet,
        sm: StreamMetricSet,
    ) {
        match c {
            Compression::None | Compression::Gzip | Compression::Zstd => {}
        }
        match f {
            ReadStart::SeqNum(_) | ReadStart::Timestamp(_) | ReadStart::TailOffset(_) => {}
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
        ReadStart::SeqNum(0),
        AccountMetricSet::ActiveBasins(range),
        BasinMetricSet::Storage(range),
        StreamMetricSet::Storage(range),
    );
}
