use std::time::Duration;

use http::uri::{Authority, Scheme};
#[cfg(feature = "_hidden")]
use http::{HeaderMap, HeaderValue};
use proptest::prelude::*;
use rstest::rstest;
use s2_api::v1::{self as api, MaybeKnown};
use s2_common::record::MAX_FENCING_TOKEN_LENGTH;

use super::*;

type HeaderParts = (Vec<u8>, Vec<u8>);
type AppendRecordParts = (Vec<u8>, Vec<HeaderParts>);

#[test]
fn network_policy_kinds_from_newer_service_are_kept_by_name() {
    let info: api::network_policy::NetworkPolicyInfo = serde_json::from_value(serde_json::json!({
        "id": "office.a1b2c3d4",
        "slug": "office",
        "created_at": "2026-01-01T00:00:00Z",
        "policy": {
            "public_net": { "cidr-and-asn": { "cidrs": ["10.0.0.0/8"], "asns": [64512] } },
            "private_net": { "gcp": { "psc_ids": ["1"] } },
            "geo": { "countries": ["DE"] },
        },
    }))
    .expect("decodes");

    // A kind added later is kept by name, and never read as part of a known kind.
    let policy = NetworkPolicyInfo::from(info).policy;
    assert_eq!(
        policy.public_net,
        Some(PublicNetPolicy::Unknown("cidr-and-asn".to_owned()))
    );
    assert_eq!(
        policy.private_net,
        Some(PrivateNetPolicy::Unknown("gcp".to_owned()))
    );

    // A service must not accept either back.
    for policy in [
        NetworkPolicy {
            private_net: None,
            ..policy.clone()
        },
        NetworkPolicy {
            public_net: None,
            ..policy
        },
    ] {
        let request = api::network_policy::NetworkPolicy::from(policy);
        assert!(s2_common::network_policy::NetworkPolicy::try_from(request).is_err());
    }
}

fn byte_vec_strategy(max_len: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=max_len)
}

fn header_parts_strategy() -> impl Strategy<Value = HeaderParts> {
    (byte_vec_strategy(32), byte_vec_strategy(64))
}

fn string_strategy(max_chars: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(any::<char>(), 0..=max_chars)
        .prop_map(|chars| chars.into_iter().collect())
}

fn read_start_strategy() -> impl Strategy<Value = ReadStart> {
    prop_oneof![
        any::<u64>().prop_map(ReadStart::SeqNum),
        any::<u64>().prop_map(ReadStart::Timestamp),
        any::<u64>().prop_map(ReadStart::TailOffset),
    ]
}

fn append_record_parts_strategy() -> impl Strategy<Value = AppendRecordParts> {
    (
        byte_vec_strategy(256),
        prop::collection::vec(header_parts_strategy(), 0..=16),
    )
}

fn proto_stream_position_strategy() -> impl Strategy<Value = api::stream::proto::StreamPosition> {
    (any::<u64>(), any::<u64>())
        .prop_map(|(seq_num, timestamp)| api::stream::proto::StreamPosition { seq_num, timestamp })
}

fn headers_from_parts(headers: &[HeaderParts]) -> Vec<Header> {
    headers
        .iter()
        .map(|(name, value)| Header::new(Bytes::from(name.clone()), Bytes::from(value.clone())))
        .collect()
}

fn expected_metered_bytes(body: &[u8], headers: &[HeaderParts]) -> usize {
    8 + (2 * headers.len())
        + headers
            .iter()
            .map(|(name, value)| name.len() + value.len())
            .sum::<usize>()
        + body.len()
}

// -- Timestamp & TimeRange --

#[test]
fn rfc3339_timestamp_bounds() {
    assert_eq!(RFC3339_MIN.to_string(), "0000-01-01T00:00:00Z");
    // `jiff::Timestamp::MAX` reserves timezone-offset headroom within year 9999.
    assert_eq!(Timestamp::MAX.to_string(), "9999-12-30T22:00:00.999999999Z");

    assert!(validate_rfc3339_timestamp(RFC3339_MIN).is_ok());
    assert!(validate_rfc3339_timestamp(Timestamp::MAX).is_ok());
    // Negative years are outside RFC 3339 (0000..=9999).
    assert!(
        validate_rfc3339_timestamp(Timestamp::new(-62_167_219_201, 999_999_999).unwrap()).is_err()
    );
    assert!(validate_rfc3339_timestamp(Timestamp::MIN).is_err());
}

#[test]
fn time_range_floors_subseconds_checks_bounds_and_wraps_interval() {
    let start = Timestamp::new(100, 999_999_999).unwrap();
    let end = Timestamp::new(200, 500_000_000).unwrap();
    let range = TimeRange::new(start, end).unwrap();
    assert_eq!(range.start().as_second(), 100);
    assert_eq!(range.start().subsec_nanosecond(), 0);
    assert_eq!(range.end().as_second(), 200);
    assert_eq!(range.end().subsec_nanosecond(), 0);

    let with_interval = range.with_interval(TimeseriesInterval::Minute);
    assert_eq!(with_interval.range(), range);
    assert_eq!(with_interval.interval(), Some(&TimeseriesInterval::Minute));
    assert_eq!(TimeRangeAndInterval::from(range).interval(), None);

    let before_epoch = Timestamp::new(-1, 500_000_000).unwrap();
    assert!(TimeRange::new(before_epoch, end).is_err());

    let max_valid = Timestamp::from_second(i64::from(u32::MAX)).unwrap();
    assert!(TimeRange::new(Timestamp::UNIX_EPOCH, max_valid).is_ok());

    let over_max = Timestamp::from_second(i64::from(u32::MAX) + 1).unwrap();
    assert!(TimeRange::new(Timestamp::UNIX_EPOCH, over_max).is_err());
}

// -- EncryptionKey --

#[test]
fn encryption_key_debug_is_redacted_and_parse_validates() {
    let key: EncryptionKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        .parse()
        .unwrap();
    assert_eq!(format!("{key:?}"), "EncryptionKey(<redacted>)");
    assert!(key.to_header_value().is_sensitive());

    // Empty input, invalid base64, and unpadded base64 are rejected; non-empty bytes succeed.
    assert!("".parse::<EncryptionKey>().is_err());
    assert!("   ".parse::<EncryptionKey>().is_err());
    assert!("not-base64!!!".parse::<EncryptionKey>().is_err());
    assert!("AA".parse::<EncryptionKey>().is_err());
    assert!(EncryptionKey::new([]).is_err());
    assert!(EncryptionKey::new([0u8; 32]).is_ok());
}

// -- Endpoints & S2Config --

#[rstest]
#[case::https_with_scheme("https://a.s2.dev", Scheme::HTTPS)]
#[case::http_with_scheme("http://localhost:8080", Scheme::HTTP)]
#[case::default_https("a.s2.dev", Scheme::HTTPS)]
#[case::ipv4("http://127.0.0.1:8080", Scheme::HTTP)]
#[case::ipv6("http://[::1]:8080", Scheme::HTTP)]
#[case::ipv6_default_https("[2001:db8::1]", Scheme::HTTPS)]
#[case::underscore_dns("http://s2_lite:8080", Scheme::HTTP)]
fn account_endpoint_parse(#[case] input: &str, #[case] expected_scheme: Scheme) {
    let ep: AccountEndpoint = input.parse().unwrap();
    assert_eq!(ep.scheme, expected_scheme);
}

#[rstest]
#[case::loopback("http://::1:8080")]
#[case::no_port("2001:db8::1")]
fn endpoint_unbracketed_ipv6_suggests_brackets(#[case] input: &str) {
    let error = input.parse::<AccountEndpoint>().unwrap_err();
    assert!(error.0.contains("must be enclosed in brackets"));
    let error = input.parse::<BasinEndpoint>().unwrap_err();
    assert!(error.0.contains("must be enclosed in brackets"));
}

#[rstest]
#[case::not_ipv6("http://bad host")]
#[case::bracketed_ipv6("http://{basin}.[::1]:8080")]
fn endpoint_invalid_authority_has_no_bracket_hint(#[case] input: &str) {
    let error = input.parse::<AccountEndpoint>().unwrap_err();
    assert!(!error.0.contains("brackets"));
}

#[rstest]
#[case::https_parent_zone("https://{basin}.b.s2.dev", Scheme::HTTPS, true)]
#[case::http_direct("http://localhost:8080", Scheme::HTTP, false)]
#[case::default_https_parent_zone("{basin}.b.s2.dev", Scheme::HTTPS, true)]
#[case::ipv4_direct("http://127.0.0.1:8080", Scheme::HTTP, false)]
#[case::ipv6_direct("http://[::1]:8080", Scheme::HTTP, false)]
#[case::ipv6_default_https_direct("[2001:db8::1]:8443", Scheme::HTTPS, false)]
fn basin_endpoint_parse(
    #[case] input: &str,
    #[case] expected_scheme: Scheme,
    #[case] expected_parent_zone: bool,
) {
    let ep: BasinEndpoint = input.parse().unwrap();
    assert_eq!(ep.scheme, expected_scheme);
    assert_eq!(
        matches!(ep.authority, BasinAuthority::ParentZone(_)),
        expected_parent_zone
    );
}

#[rstest]
#[case::ipv4("http://{basin}.127.0.0.1:8080", "127.0.0.1")]
#[case::ipv6("http://{basin}.[::1]:8080", "[::1]")]
#[case::ipv6_default_https("{basin}.[2001:db8::1]", "[2001:db8::1]")]
fn basin_endpoint_parent_zone_rejects_ip_literals(#[case] input: &str, #[case] host: &str) {
    let error = input.parse::<BasinEndpoint>().unwrap_err();
    assert!(error.0.contains(&format!(
        "placeholder requires a DNS name, but {host} is an IP address"
    )));
}

#[test]
fn s2_endpoints_scheme_and_for_endpoint() {
    let https_account: AccountEndpoint = "https://a.s2.dev".parse().unwrap();
    let http_basin: BasinEndpoint = "http://localhost:8080".parse().unwrap();
    assert!(S2Endpoints::new(https_account.clone(), http_basin).is_err());

    let https_basin: BasinEndpoint = "https://{basin}.b.s2.dev".parse().unwrap();
    assert_eq!(
        S2Endpoints::new(https_account, https_basin).unwrap().scheme,
        Scheme::HTTPS
    );

    let ep = S2Endpoints::for_endpoint("localhost:8080").unwrap();
    let authority: Authority = "localhost:8080".parse().unwrap();
    assert_eq!(ep.scheme, Scheme::HTTPS);
    assert_eq!(ep.account_authority, authority);
    assert_eq!(ep.basin_authority, BasinAuthority::Direct(authority));
    assert_eq!(
        S2Endpoints::for_endpoint("http://localhost:8080")
            .unwrap()
            .scheme,
        Scheme::HTTP
    );
    assert!(S2Endpoints::for_endpoint("not a valid endpoint").is_err());
}

#[test]
fn s2_config_from_env_with_validation() {
    let env = |pairs: &[(&str, &str)]| {
        let map: std::collections::HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k: &str| map.get(k).cloned().ok_or(std::env::VarError::NotPresent)
    };

    // Missing token fails.
    assert!(S2Config::from_env_with(env(&[])).is_err());
    // Empty token fails.
    assert!(S2Config::from_env_with(env(&[("S2_ACCESS_TOKEN", "")])).is_err());

    // Default endpoints when only token is set.
    let cfg = S2Config::from_env_with(env(&[("S2_ACCESS_TOKEN", "tok")])).unwrap();
    assert_eq!(cfg.endpoints(), &S2Endpoints::default());

    // Partial custom endpoints fail closed.
    assert!(
        S2Config::from_env_with(env(&[
            ("S2_ACCESS_TOKEN", "tok"),
            ("S2_ACCOUNT_ENDPOINT", "http://localhost:8080"),
        ]))
        .is_err()
    );
    assert!(
        S2Config::from_env_with(env(&[
            ("S2_ACCESS_TOKEN", "tok"),
            ("S2_BASIN_ENDPOINT", "http://localhost:8080"),
        ]))
        .is_err()
    );

    // Mismatched schemes fail.
    assert!(
        S2Config::from_env_with(env(&[
            ("S2_ACCESS_TOKEN", "tok"),
            ("S2_ACCOUNT_ENDPOINT", "https://a.s2.dev"),
            ("S2_BASIN_ENDPOINT", "http://localhost:8080"),
        ]))
        .is_err()
    );

    // Both endpoints set with matching scheme succeed.
    let cfg = S2Config::from_env_with(env(&[
        ("S2_ACCESS_TOKEN", "tok"),
        ("S2_ACCOUNT_ENDPOINT", "http://localhost:8080"),
        ("S2_BASIN_ENDPOINT", "http://localhost:8080"),
    ]))
    .unwrap();
    assert_eq!(cfg.endpoints().scheme, Scheme::HTTP);
}

#[test]
fn s2_config_rejects_min_base_delay_exceeding_max_base_delay() {
    let retry = RetryConfig::new()
        .with_min_base_delay(Duration::from_secs(2))
        .with_max_base_delay(Duration::from_secs(1));
    let config = S2Config::new("test-token").with_retry(retry);
    let err = crate::S2::new(config).unwrap_err();
    assert!(err.0.contains("min_base_delay"));
}

#[cfg(feature = "_hidden")]
#[rstest]
#[case::matching_compression("content-encoding", "gzip", Compression::Gzip)]
#[case::mixed_case("Content-Encoding", "identity", Compression::None)]
#[case::empty_value("content-encoding", "", Compression::None)]
fn default_headers_reject_content_encoding(
    #[case] name: &str,
    #[case] value: &str,
    #[case] compression: Compression,
) {
    let headers = HeaderMap::from_iter([(
        name.parse::<http::header::HeaderName>().unwrap(),
        HeaderValue::from_str(value).unwrap(),
    )]);
    let error = S2Config::new("token")
        .with_compression(compression)
        .with_default_headers(headers)
        .unwrap_err();
    assert!(error.0.contains("Content-Encoding"));
    assert!(error.0.contains("with_compression"));
}

#[cfg(feature = "_hidden")]
#[rstest]
#[case::content_type_s2s("content-type", "s2s/proto")]
#[case::content_type_protobuf("content-type", "application/protobuf")]
#[case::content_type_json("content-type", "application/json")]
#[case::content_type_mixed_case("Content-Type", "s2s/proto")]
#[case::content_type_empty("content-type", "")]
#[case::content_length("content-length", "123")]
#[case::content_length_mixed_case("Content-Length", "0")]
#[case::content_length_empty("content-length", "")]
#[case::transfer_encoding("transfer-encoding", "chunked")]
#[case::transfer_encoding_mixed_case("Transfer-Encoding", "chunked")]
#[case::transfer_encoding_empty("transfer-encoding", "")]
fn default_headers_reject_framing_headers(#[case] name: &str, #[case] value: &str) {
    let headers = HeaderMap::from_iter([(
        name.parse::<http::header::HeaderName>().unwrap(),
        HeaderValue::from_str(value).unwrap(),
    )]);
    let error = S2Config::new("token")
        .with_default_headers(headers)
        .unwrap_err();
    assert!(error.0.contains(&name.to_ascii_lowercase()));
    assert!(error.0.contains("framing"));
}

// -- Whole-second duration invariants & enums --

#[test]
fn sub_second_durations_are_rejected() {
    let subsec = Duration::from_millis(1500);
    assert!(DeleteOnEmptyConfig::new().with_min_age(subsec).is_err());
    assert!(
        DeleteOnEmptyReconfiguration::new()
            .with_min_age(subsec)
            .is_err()
    );
    assert!(ReadInput::new().with_wait(subsec).is_err());
    assert!(RetentionPolicy::age(subsec).is_err());
    // RetentionPolicy::age(Duration::ZERO) is allowed client-side per D5 spec vector.
    assert_eq!(
        RetentionPolicy::age(Duration::ZERO).unwrap(),
        RetentionPolicy::Age(0)
    );
}

#[rstest]
#[case::age(RetentionPolicy::Age(3600))]
#[case::infinite(RetentionPolicy::Infinite)]
fn retention_policy_roundtrip(#[case] sdk: RetentionPolicy) {
    let api: MaybeKnown<api::config::RetentionPolicy> = sdk.clone().into();
    let back: RetentionPolicy = api.into();
    assert_eq!(back, sdk);
}

#[rstest]
#[case::client_prefer(
    TimestampingMode::ClientPrefer,
    api::config::TimestampingMode::ClientPrefer
)]
#[case::client_require(
    TimestampingMode::ClientRequire,
    api::config::TimestampingMode::ClientRequire
)]
#[case::arrival(TimestampingMode::Arrival, api::config::TimestampingMode::Arrival)]
fn timestamping_mode_roundtrip(
    #[case] sdk: TimestampingMode,
    #[case] expected_api: api::config::TimestampingMode,
) {
    let converted: MaybeKnown<api::config::TimestampingMode> = sdk.clone().into();
    assert_eq!(converted, MaybeKnown::Known(expected_api));
    let back: TimestampingMode = converted.into();
    assert_eq!(back, sdk);
}

// -- Validated identifiers & Ordering --

#[test]
fn validated_identifiers_support_ord_and_conversions() {
    let b1: BasinName = "alpha-basin".parse().unwrap();
    let b2: BasinName = "beta-basin".parse().unwrap();
    assert!(b1 < b2);

    let s1: StreamName = "a/stream".parse().unwrap();
    let s2: StreamName = "b/stream".parse().unwrap();
    assert!(s1 < s2);

    let t1: AccessTokenId = "tok-1".parse().unwrap();
    let t2: AccessTokenId = "tok-2".parse().unwrap();
    assert!(t1 < t2);

    let f1 = FencingToken::try_from("aaa").unwrap();
    let f2 = FencingToken::try_from("bbb".to_owned()).unwrap();
    assert!(f1 < f2);
    assert_eq!(f1.as_ref(), "aaa");
    assert_eq!(String::from(f2), "bbb");

    let vpce = VpcEndpointId::try_from("vpce-0123456789abcdef0").unwrap();
    assert_eq!(vpce.as_ref(), "vpce-0123456789abcdef0");
    assert_eq!(
        VpcEndpointId::try_from("vpce-0123456789abcdef0".to_owned()).unwrap(),
        vpce
    );
    assert_eq!(String::from(vpce), "vpce-0123456789abcdef0");
    assert!(VpcEndpointId::try_from("not-a-vpce").is_err());
}

// -- FencingToken --

proptest! {
    #[test]
    fn fencing_token_parse_accepts_only_within_byte_limit(
        token in string_strategy(MAX_FENCING_TOKEN_LENGTH + 8),
    ) {
        let parsed = token.parse::<FencingToken>();

        if token.len() <= MAX_FENCING_TOKEN_LENGTH {
            prop_assert_eq!(parsed.unwrap().to_string(), token);
        } else {
            prop_assert!(parsed.is_err());
        }
    }
}

// -- StreamPosition --

#[test]
fn stream_position_display() {
    let pos = StreamPosition {
        seq_num: 42,
        timestamp: 1700000000,
    };
    assert_eq!(pos.to_string(), "seq_num=42, timestamp=1700000000");
}

proptest! {
    #[test]
    fn stream_position_conversions_preserve_values(seq_num in any::<u64>(), timestamp in any::<u64>()) {
        let proto: StreamPosition = api::stream::proto::StreamPosition {
            seq_num,
            timestamp,
        }
        .into();
        prop_assert_eq!(proto.seq_num, seq_num);
        prop_assert_eq!(proto.timestamp, timestamp);

        let api: StreamPosition = api::stream::StreamPosition {
            seq_num,
            timestamp,
        }
        .into();
        prop_assert_eq!(api.seq_num, seq_num);
        prop_assert_eq!(api.timestamp, timestamp);
    }
}

// -- Header --

proptest! {
    #[test]
    fn header_proto_roundtrip_preserves_binary_parts(
        name in byte_vec_strategy(64),
        value in byte_vec_strategy(128),
    ) {
        let header = Header::new(Bytes::from(name.clone()), Bytes::from(value.clone()));
        let proto: api::stream::proto::Header = header.into();
        let back: Header = proto.into();

        prop_assert_eq!(back.name.as_ref(), name.as_slice());
        prop_assert_eq!(back.value.as_ref(), value.as_slice());
    }
}

// -- AppendRecord & MeteredBytes --

#[test]
fn append_record_too_large() {
    let big_body = vec![0u8; RECORD_BATCH_MAX.bytes + 1];
    assert!(AppendRecord::new(big_body).is_err());
}

proptest! {
    #[test]
    fn append_record_preserves_fields_and_metered_byte_formula(
        (body, headers) in append_record_parts_strategy(),
        timestamp in proptest::option::of(any::<u64>()),
    ) {
        let mut record = AppendRecord::new(body.clone())
            .unwrap()
            .with_headers(headers_from_parts(&headers))
            .unwrap();
        if let Some(timestamp) = timestamp {
            record = record.with_timestamp(timestamp);
        }

        prop_assert_eq!(record.body().as_ref(), body.as_slice());
        prop_assert_eq!(record.headers().len(), headers.len());
        prop_assert_eq!(record.timestamp(), timestamp);
        prop_assert_eq!(record.metered_bytes(), expected_metered_bytes(&body, &headers));

        for (actual, (expected_name, expected_value)) in record.headers().iter().zip(headers.iter()) {
            prop_assert_eq!(actual.name.as_ref(), expected_name.as_slice());
            prop_assert_eq!(actual.value.as_ref(), expected_value.as_slice());
        }
    }
}

// -- AppendRecordBatch --

#[test]
fn append_record_batch_bounds_and_conversions() {
    assert!(AppendRecordBatch::try_from_iter(Vec::<AppendRecord>::new()).is_err());
    let too_many: Vec<_> = (0..1001).map(|_| AppendRecord::new("x").unwrap()).collect();
    assert!(AppendRecordBatch::try_from_iter(too_many).is_err());

    let rec = AppendRecord::new("hello").unwrap();
    let batch = AppendRecordBatch::from(rec.clone());
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0], rec);

    let input = AppendInput::from(rec);
    assert_eq!(input.records, batch);

    let cmd = CommandRecord::trim(7);
    let cmd_batch = AppendRecordBatch::try_from_iter([cmd.clone()]).unwrap();
    assert_eq!(cmd_batch, AppendRecordBatch::from(cmd.clone()));
    assert_eq!(AppendInput::from(cmd).records, cmd_batch);
}

proptest! {
    #[test]
    fn append_record_batch_metered_bytes_is_sum_of_records(
        records in prop::collection::vec(append_record_parts_strategy(), 1..=32),
    ) {
        let expected = records
            .iter()
            .map(|(body, headers)| expected_metered_bytes(body, headers))
            .sum::<usize>();
        let records = records
            .into_iter()
            .map(|(body, headers)| {
                AppendRecord::new(body)
                    .unwrap()
                    .with_headers(headers_from_parts(&headers))
                    .unwrap()
            })
            .collect::<Vec<_>>();

        let batch = AppendRecordBatch::try_from_iter(records).unwrap();
        prop_assert_eq!(batch.metered_bytes(), expected);
        prop_assert_eq!(batch.iter().map(MeteredBytes::metered_bytes).sum::<usize>(), expected);
    }
}

// -- CommandRecord & SequencedRecord --

#[test]
fn command_records_encode_headers_and_body() {
    let token: FencingToken = "tok".parse().unwrap();
    let fence: AppendRecord = CommandRecord::fence(token).into();
    assert_eq!(fence.headers().len(), 1);
    assert_eq!(fence.headers()[0].name.as_ref(), b"");
    assert_eq!(fence.headers()[0].value.as_ref(), b"fence");
    assert_eq!(fence.body().as_ref(), b"tok");

    let trim: AppendRecord = CommandRecord::trim(42).into();
    assert_eq!(trim.headers().len(), 1);
    assert_eq!(trim.headers()[0].value.as_ref(), b"trim");
    assert_eq!(trim.body().as_ref(), &42u64.to_be_bytes());
}

#[rstest]
#[case::command(vec![Header::new("", "fence")], true)]
#[case::regular(vec![Header::new("key", "value")], false)]
#[case::no_headers(vec![], false)]
fn sequenced_record_command_detection(#[case] headers: Vec<Header>, #[case] expected: bool) {
    let record = SequencedRecord::new(0, Bytes::from("data"), headers, 0);
    assert_eq!(record.is_command_record(), expected);
}

// -- ReadInput --

proptest! {
    #[test]
    fn read_input_to_api_sets_only_selected_position_field(
        from in read_start_strategy(),
        clamp in any::<bool>(),
    ) {
        let (seq_num, timestamp, tail_offset) = match from {
            ReadStart::SeqNum(value) => (Some(value), None, None),
            ReadStart::Timestamp(value) => (None, Some(value), None),
            ReadStart::TailOffset(value) => (None, None, Some(value)),
        };
        let input = ReadInput::new().with_start(from).with_clamp(clamp);
        prop_assert_eq!(input.start(), Some(from));
        prop_assert_eq!(ReadInput::from(from).start(), Some(from));
        let (api, _, _) = input.into_api_parts();

        prop_assert_eq!(api.seq_num, seq_num);
        prop_assert_eq!(api.timestamp, timestamp);
        prop_assert_eq!(api.tail_offset, tail_offset);
        prop_assert_eq!(api.clamp, clamp.then_some(true));
    }
}

// spec: r1 R1
#[test]
fn read_input_default_and_stop_params_to_api() {
    let (api_start, api_end, cfg) = ReadInput::new().into_api_parts();
    assert_eq!(api_start.seq_num, None);
    assert_eq!(api_start.timestamp, None);
    assert_eq!(api_start.tail_offset, None);
    assert_eq!(api_start.clamp, None);
    assert_eq!(api_end.count, None);
    assert_eq!(api_end.bytes, None);
    assert_eq!(api_end.until, None);
    assert_eq!(api_end.wait, None);
    assert!(cfg.is_none());

    let input = ReadInput::new()
        .with_count(50)
        .with_bytes(1024)
        .with_until(1000)
        .with_wait(Duration::from_secs(30))
        .unwrap();
    assert_eq!(input.count(), Some(50));
    assert_eq!(input.bytes(), Some(1024));
    assert_eq!(input.until(), Some(1000));
    assert_eq!(input.wait(), Some(Duration::from_secs(30)));
    let (_, api_end, _) = input.into_api_parts();
    assert_eq!(api_end.count, Some(50));
    assert_eq!(api_end.bytes, Some(1024));
    assert_eq!(api_end.until, Some(1000));
    assert_eq!(api_end.wait, Some(30));
}

// -- Operation roundtrip --

#[test]
fn operation_roundtrip_all_variants() {
    let variants = [
        Operation::ListBasins,
        Operation::CreateBasin,
        Operation::GetBasinConfig,
        Operation::DeleteBasin,
        Operation::ReconfigureBasin,
        Operation::ListAccessTokens,
        Operation::IssueAccessToken,
        Operation::RevokeAccessToken,
        Operation::GetAccountMetrics,
        Operation::GetBasinMetrics,
        Operation::GetStreamMetrics,
        Operation::ListStreams,
        Operation::CreateStream,
        Operation::GetStreamConfig,
        Operation::DeleteStream,
        Operation::ReconfigureStream,
        Operation::CheckTail,
        Operation::Append,
        Operation::Read,
        Operation::Trim,
        Operation::Fence,
        Operation::ListLocations,
        Operation::GetDefaultLocation,
        Operation::SetDefaultLocation,
        Operation::ListNetworkPolicies,
        Operation::CreateNetworkPolicy,
        Operation::GetNetworkPolicy,
        Operation::DeleteNetworkPolicy,
    ];
    for op in variants {
        let api_op: MaybeKnown<api::access::Operation> = op.clone().into();
        let back: Operation = api_op.into();
        assert_eq!(back, op);
    }
}

// -- AppendAck --

proptest! {
    #[test]
    fn append_ack_from_proto_requires_all_positions(
        start in proptest::option::of(proto_stream_position_strategy()),
        end in proptest::option::of(proto_stream_position_strategy()),
        tail in proptest::option::of(proto_stream_position_strategy()),
    ) {
        let expected = match (start, end) {
            (Some(s), Some(e)) if e.seq_num >= s.seq_num => e.seq_num - s.seq_num,
            _ => 1,
        };
        let res = AppendAck::try_from_proto(
            api::stream::proto::AppendAck { start, end, tail },
            expected,
            crate::error::ErrorContext::default(),
        );
        match (start, end, tail) {
            (Some(s), Some(e), Some(t)) if e.seq_num >= s.seq_num => {
                let ack = res.expect("all positions present with end >= start");
                prop_assert_eq!(ack.start.seq_num, s.seq_num);
                prop_assert_eq!(ack.start.timestamp, s.timestamp);
                prop_assert_eq!(ack.end.seq_num, e.seq_num);
                prop_assert_eq!(ack.end.timestamp, e.timestamp);
                prop_assert_eq!(ack.tail.seq_num, t.seq_num);
                prop_assert_eq!(ack.tail.timestamp, t.timestamp);
                let wrong_count = AppendAck::try_from_proto(
                    api::stream::proto::AppendAck { start, end, tail },
                    expected.wrapping_add(1),
                    crate::error::ErrorContext::default(),
                );
                prop_assert!(wrong_count.is_err());
            }
            _ => {
                prop_assert!(res.is_err());
            }
        }
    }
}

// -- Http2Config & Endpoints validation --

#[test]
fn http2_config_bounds() {
    let config = Http2Config::new()
        .with_max_concurrent_requests(Http2Config::MAX_CONCURRENT_REQUESTS)
        .unwrap()
        .with_stream_receive_window(Http2Config::MAX_RECEIVE_WINDOW)
        .unwrap()
        .with_connection_receive_window(Http2Config::MIN_CONNECTION_RECEIVE_WINDOW)
        .unwrap();
    assert_eq!(
        config.max_concurrent_requests(),
        Some(Http2Config::MAX_CONCURRENT_REQUESTS)
    );
    assert_eq!(
        config.stream_receive_window(),
        Some(Http2Config::MAX_RECEIVE_WINDOW)
    );
    assert_eq!(
        config.connection_receive_window(),
        Some(Http2Config::MIN_CONNECTION_RECEIVE_WINDOW)
    );

    let partial = Http2Config::new().with_stream_receive_window(1).unwrap();
    assert_eq!(partial.max_concurrent_requests(), None);
    assert_eq!(partial.connection_receive_window(), None);

    assert!(Http2Config::new().with_max_concurrent_requests(0).is_err());
    assert!(
        Http2Config::new()
            .with_max_concurrent_requests(Http2Config::MAX_CONCURRENT_REQUESTS + 1)
            .is_err()
    );
    assert!(Http2Config::new().with_stream_receive_window(0).is_err());
    assert!(
        Http2Config::new()
            .with_stream_receive_window(Http2Config::MAX_RECEIVE_WINDOW + 1)
            .is_err()
    );
    assert!(
        Http2Config::new()
            .with_connection_receive_window(Http2Config::MIN_CONNECTION_RECEIVE_WINDOW - 1)
            .is_err()
    );
    assert!(
        Http2Config::new()
            .with_connection_receive_window(u32::MAX)
            .is_err()
    );
}

#[test]
fn endpoint_validation_rejects_malformed_hosts_ports_and_bracketed_basin_zone() {
    for bad in [
        "https://[::1::1]",
        "https://[1234]",
        "https://[fe80::1%25eth0]",
        "https://example%20.com",
        "https://a!b",
        "https://..",
        "https://.example.com",
        "https://-example.com",
        "https://example-.com",
        "https://example.com:0",
        "https://example.com:99999",
        "https://example.com:abc",
        "https://[::1]:0",
        "https://[::1]:99999",
    ] {
        assert!(
            AccountEndpoint::new(bad).is_err(),
            "expected AccountEndpoint::new({bad:?}) to fail"
        );
        assert!(
            BasinEndpoint::new(bad).is_err(),
            "expected BasinEndpoint::new({bad:?}) to fail"
        );
    }
    assert!(BasinEndpoint::new("https://{basin}.[::1::1]").is_err());
    assert!(BasinEndpoint::new("https://{basin}.[::1]").is_err());
    assert!(BasinEndpoint::new("https://{basin}.127.0.0.1").is_err());
    assert!(BasinEndpoint::new("https://{basin}..example.com").is_err());
    assert!(AccountEndpoint::new("https://[::1]:8080").is_ok());
    assert!(AccountEndpoint::new("https://localhost:8080").is_ok());
    assert!(AccountEndpoint::new("http://s2_lite:8080").is_ok());
    assert!(BasinEndpoint::new("http://s2_lite:8080").is_ok());
    assert!(AccountEndpoint::new("https://example.com:65535").is_ok());
    assert!(BasinEndpoint::new("https://{basin}.b.example.com.").is_ok());
}

#[test]
fn issue_access_token_rejects_negative_year_timestamp() {
    let scope =
        AccessTokenScopeInput::from_op_group_perms(OperationGroupPermissions::read_write_all());
    let id: AccessTokenId = "tok-1".parse().unwrap();
    let err = IssueAccessTokenInput::new(id, scope)
        .with_expires_at(Timestamp::MIN)
        .unwrap_err();
    assert!(err.to_string().contains("0000"));
}

#[test]
fn fencing_token_generate_validates_before_allocating() {
    assert!(FencingToken::generate(usize::MAX).is_err());
    assert!(FencingToken::generate(MAX_FENCING_TOKEN_LENGTH + 1).is_err());
    assert_eq!(
        FencingToken::generate(MAX_FENCING_TOKEN_LENGTH)
            .unwrap()
            .len(),
        MAX_FENCING_TOKEN_LENGTH
    );
}

#[test]
fn basin_reconfiguration_reset_booleans() {
    let reconfig = BasinReconfiguration::new()
        .reset_create_stream_on_append()
        .reset_create_stream_on_read();
    assert_eq!(reconfig.create_stream_on_append(), Reconfigure::Reset);
    assert_eq!(reconfig.create_stream_on_read(), Reconfigure::Reset);
    assert_eq!(reconfig.stream_cipher(), Reconfigure::Unchanged);
    let api_reconfig: api::config::BasinReconfiguration = reconfig.into();
    let json = serde_json::to_string(&api_reconfig).unwrap();
    assert_eq!(
        json,
        r#"{"create_stream_on_append":null,"create_stream_on_read":null}"#
    );
}

#[test]
fn account_metrics_query_repeats_token_id() {
    let request = api::metrics::AccountMetricSetRequest {
        set: api::metrics::AccountMetricSet::TokenActivity,
        start: None,
        end: None,
        interval: None,
        token_ids: vec!["a,b".parse().unwrap(), "c&d".parse().unwrap()],
    };

    let query = serde_urlencoded::to_string(&request).unwrap();
    assert_eq!(query, "set=token-activity&token_id=a%2Cb&token_id=c%26d");

    let parsed: api::metrics::AccountMetricSetRequest = serde_urlencoded::from_str(&query).unwrap();
    assert_eq!(parsed.token_ids, request.token_ids);
    assert!(
        serde_urlencoded::from_str::<api::metrics::AccountMetricSetRequest>(
            "set=token-activity&set=account-ops"
        )
        .is_err()
    );
}

#[test]
fn config_debug_does_not_dump_rustls_crypto_provider_details() {
    let config = S2Config::new("super-secret-token");
    let debug = format!("{config:?}");
    assert!(!debug.contains("super-secret-token"));
    assert!(!debug.contains("cipher_suites"));
}
