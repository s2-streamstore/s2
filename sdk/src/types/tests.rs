use std::time::Duration;

use http::uri::{Authority, Scheme};
#[cfg(feature = "_hidden")]
use http::{HeaderMap, HeaderValue};
use s2_api::v1 as api;
use s2_common::record::MAX_FENCING_TOKEN_LENGTH;

use super::*;

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
    let policy = NetworkPolicyInfo::from_api(info).policy;
    assert_eq!(
        policy.public_net(),
        Some(&PublicNetPolicy::Unknown("cidr-and-asn".to_owned()))
    );
    assert_eq!(
        policy.private_net(),
        Some(&PrivateNetPolicy::Unknown("gcp".to_owned()))
    );

    // A service must not accept either back.
    for policy in [
        NetworkPolicy::new().with_public_net(policy.public_net().unwrap().clone()),
        NetworkPolicy::new().with_private_net(policy.private_net().unwrap().clone()),
    ] {
        let request = policy.into_api();
        assert!(s2_common::network_policy::NetworkPolicy::try_from(request).is_err());
    }
}

// spec: r1 F2
#[test]
fn open_enums_from_newer_service_preserve_unknown_wire_names() {
    let basin_cfg: api::config::BasinConfig = serde_json::from_value(serde_json::json!({
        "stream_cipher": "chacha20-poly1305",
        "default_stream_config": {
            "retention_policy": { "future_policy": 1 },
            "timestamping": { "mode": "hybrid" }
        }
    }))
    .unwrap();
    let cfg = BasinConfig::from_api(basin_cfg);
    assert_eq!(
        cfg.stream_cipher(),
        Some(&EncryptionAlgorithm::Unknown(
            "chacha20-poly1305".to_owned()
        ))
    );
    assert_eq!(cfg.stream_cipher().unwrap().as_str(), "chacha20-poly1305");
    let stream_cfg = cfg.default_stream_config().unwrap();
    assert_eq!(
        stream_cfg.retention_policy(),
        Some(&RetentionPolicy::Unknown("future_policy".to_owned()))
    );
    assert_eq!(
        stream_cfg.timestamping().unwrap().mode(),
        Some(&TimestampingMode::Unknown("hybrid".to_owned()))
    );
    assert_eq!(
        stream_cfg.timestamping().unwrap().mode().unwrap().as_str(),
        "hybrid"
    );

    let token_info: api::access::AccessTokenInfo = serde_json::from_value(serde_json::json!({
        "id": "tok-1",
        "auto_prefix_streams": false,
        "scope": {
            "ops": ["read", "future-op"]
        }
    }))
    .unwrap();
    let token = AccessTokenInfo::from_api(token_info);
    assert!(token.scope.ops().contains(&Operation::Read));
    assert!(
        token
            .scope
            .ops()
            .contains(&Operation::Unknown("future-op".to_owned()))
    );

    // Wire empty exact resource matchers decode to `None` ("match no resources").
    let empty_matchers: api::access::AccessTokenScope = serde_json::from_value(serde_json::json!({
        "basins": { "exact": "" },
        "streams": { "exact": "" },
        "access_tokens": { "exact": "" },
    }))
    .unwrap();
    let scope = AccessTokenScope::from_api(empty_matchers);
    assert_eq!(scope.basins(), &BasinMatcher::None);
    assert_eq!(scope.streams(), &StreamMatcher::None);
    assert_eq!(scope.access_tokens(), &AccessTokenMatcher::None);
}

#[test]
fn endpoint_validation_edge_cases() {
    // Unbracketed IPv6 hints brackets; unrelated invalid authorities do not.
    for unbracketed in ["http://::1:8080", "2001:db8::1"] {
        assert!(
            unbracketed
                .parse::<AccountEndpoint>()
                .unwrap_err()
                .0
                .contains("must be enclosed in brackets")
        );
        assert!(
            unbracketed
                .parse::<BasinEndpoint>()
                .unwrap_err()
                .0
                .contains("must be enclosed in brackets")
        );
    }
    for other in ["http://bad host", "http://{basin}.[::1]:8080"] {
        assert!(
            !other
                .parse::<AccountEndpoint>()
                .unwrap_err()
                .0
                .contains("brackets")
        );
    }

    // Rust parser edge cases beyond endpoints.json vectors.
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
        assert!(AccountEndpoint::new(bad).is_err(), "{bad:?}");
        assert!(BasinEndpoint::new(bad).is_err(), "{bad:?}");
    }
    assert!(BasinEndpoint::new("https://{basin}.[::1::1]").is_err());
    assert!(BasinEndpoint::new("https://{basin}..example.com").is_err());

    // Valid Rust-specific cases (omitted scheme, portless IPv6, underscore DNS, trailing dot, max
    // port).
    let ipv6_default: AccountEndpoint = "[2001:db8::1]".parse().unwrap();
    assert_eq!(ipv6_default.scheme, Scheme::HTTPS);
    let parent_default: BasinEndpoint = "{basin}.b.s2.dev".parse().unwrap();
    assert_eq!(parent_default.scheme, Scheme::HTTPS);
    assert!(matches!(
        parent_default.authority,
        BasinAuthority::ParentZone(_)
    ));
    assert!(AccountEndpoint::new("http://s2_lite:8080").is_ok());
    assert!(BasinEndpoint::new("http://s2_lite:8080").is_ok());
    assert!(AccountEndpoint::new("https://example.com:65535").is_ok());
    assert!(BasinEndpoint::new("https://{basin}.b.example.com.").is_ok());

    // S2Endpoints::for_endpoint convenience constructor.
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

#[cfg(feature = "_hidden")]
#[test]
fn default_headers_reject_forbidden_headers() {
    let err = S2Config::new("token")
        .with_compression(Compression::Gzip)
        .with_default_headers(HeaderMap::from_iter([(
            http::header::CONTENT_ENCODING,
            HeaderValue::from_static("gzip"),
        )]))
        .unwrap_err();
    assert!(err.0.contains("Content-Encoding") && err.0.contains("with_compression"));

    for name in [
        http::header::CONTENT_TYPE,
        http::header::CONTENT_LENGTH,
        http::header::TRANSFER_ENCODING,
    ] {
        let err = S2Config::new("token")
            .with_default_headers(HeaderMap::from_iter([(
                name.clone(),
                HeaderValue::from_static("val"),
            )]))
            .unwrap_err();
        assert!(err.0.contains(name.as_str()) && err.0.contains("framing"));
    }
}

#[test]
fn read_input_to_api_sets_only_selected_position_field() {
    for (start, expected) in [
        (ReadStart::SeqNum(7), (Some(7), None, None)),
        (ReadStart::Timestamp(42), (None, Some(42), None)),
        (ReadStart::TailOffset(3), (None, None, Some(3))),
    ] {
        for clamp in [false, true] {
            let input = ReadInput::new().with_start(start).with_clamp(clamp);
            assert_eq!(input.start(), Some(start));
            let (api, _, _) = input.into_api_parts();
            assert_eq!((api.seq_num, api.timestamp, api.tail_offset), expected);
            assert_eq!(api.clamp, clamp.then_some(true));
        }
    }
}

#[test]
fn append_ack_from_proto_requires_all_positions() {
    let pos = |seq_num| {
        Some(api::stream::proto::StreamPosition {
            seq_num,
            timestamp: 100,
        })
    };
    let ack = AppendAck::try_from_proto(
        api::stream::proto::AppendAck {
            start: pos(5),
            end: pos(8),
            tail: pos(10),
        },
        3,
    )
    .unwrap();
    assert_eq!(
        (ack.start.seq_num, ack.end.seq_num, ack.tail.seq_num),
        (5, 8, 10)
    );

    for (raw, count) in [
        (
            api::stream::proto::AppendAck {
                start: None,
                end: pos(1),
                tail: pos(1),
            },
            1,
        ),
        (
            api::stream::proto::AppendAck {
                start: pos(0),
                end: None,
                tail: pos(1),
            },
            1,
        ),
        (
            api::stream::proto::AppendAck {
                start: pos(0),
                end: pos(1),
                tail: None,
            },
            1,
        ),
        (
            api::stream::proto::AppendAck {
                start: pos(5),
                end: pos(4),
                tail: pos(5),
            },
            1,
        ),
        (
            api::stream::proto::AppendAck {
                start: pos(5),
                end: pos(8),
                tail: pos(10),
            },
            2,
        ),
    ] {
        assert!(AppendAck::try_from_proto(raw, count).is_err());
    }
}

#[test]
fn http2_config_bounds() {
    let http_endpoints = S2Endpoints::for_endpoint("http://localhost:8080").unwrap();
    let new_client = |http2| {
        crate::S2::new(
            S2Config::new("token")
                .with_endpoints(http_endpoints.clone())
                .with_http2(http2),
        )
    };

    let max_window_cfg = Http2Config::new()
        .with_max_concurrent_requests(1)
        .with_stream_receive_window(Http2Config::MAX_RECEIVE_WINDOW)
        .with_connection_receive_window(Http2Config::MAX_RECEIVE_WINDOW);
    assert_eq!(max_window_cfg.max_concurrent_requests(), Some(1));
    assert_eq!(
        max_window_cfg.stream_receive_window(),
        Some(Http2Config::MAX_RECEIVE_WINDOW)
    );
    assert_eq!(
        max_window_cfg.connection_receive_window(),
        Some(Http2Config::MAX_RECEIVE_WINDOW)
    );
    assert!(new_client(max_window_cfg).is_ok());

    let max_concurrent_cfg = Http2Config::new()
        .with_max_concurrent_requests(Http2Config::MAX_CONCURRENT_REQUESTS)
        .with_stream_receive_window(
            Http2Config::MAX_RECEIVE_WINDOW / Http2Config::MAX_CONCURRENT_REQUESTS as u32,
        )
        .with_connection_receive_window(Http2Config::MAX_RECEIVE_WINDOW);
    assert_eq!(
        max_concurrent_cfg.max_concurrent_requests(),
        Some(Http2Config::MAX_CONCURRENT_REQUESTS)
    );
    assert!(new_client(max_concurrent_cfg).is_ok());

    let min_cfg = Http2Config::new()
        .with_max_concurrent_requests(1)
        .with_stream_receive_window(1)
        .with_connection_receive_window(Http2Config::MIN_CONNECTION_RECEIVE_WINDOW);
    assert_eq!(
        min_cfg.connection_receive_window(),
        Some(Http2Config::MIN_CONNECTION_RECEIVE_WINDOW)
    );
    assert!(new_client(min_cfg).is_ok());
    assert_eq!(Http2Config::new().max_concurrent_requests(), None);

    assert!(new_client(Http2Config::new().with_max_concurrent_requests(0)).is_err());
    assert!(
        new_client(
            Http2Config::new()
                .with_max_concurrent_requests(Http2Config::MAX_CONCURRENT_REQUESTS + 1)
        )
        .is_err()
    );
    assert!(new_client(Http2Config::new().with_stream_receive_window(0)).is_err());
    assert!(
        new_client(
            Http2Config::new().with_stream_receive_window(Http2Config::MAX_RECEIVE_WINDOW + 1)
        )
        .is_err()
    );
    assert!(
        new_client(
            Http2Config::new()
                .with_connection_receive_window(Http2Config::MIN_CONNECTION_RECEIVE_WINDOW - 1)
        )
        .is_err()
    );
    assert!(new_client(Http2Config::new().with_connection_receive_window(u32::MAX)).is_err());

    // Cross-field C13d validation rejects explicit connection_receive_window smaller than
    // max_concurrent_requests * stream_receive_window.
    let smaller_conn = Http2Config::new()
        .with_connection_receive_window(Http2Config::MIN_CONNECTION_RECEIVE_WINDOW);
    assert!(new_client(smaller_conn).is_err());
    let undersized_for_default_concurrency = Http2Config::new()
        .with_stream_receive_window(Http2Config::MIN_CONNECTION_RECEIVE_WINDOW)
        .with_connection_receive_window(Http2Config::MIN_CONNECTION_RECEIVE_WINDOW);
    assert!(new_client(undersized_for_default_concurrency).is_err());
    let undersized_for_two_streams = Http2Config::new()
        .with_max_concurrent_requests(2)
        .with_stream_receive_window(4 * 1024 * 1024)
        .with_connection_receive_window(4 * 1024 * 1024);
    assert!(new_client(undersized_for_two_streams).is_err());

    let isolated_single = Http2Config::new()
        .with_max_concurrent_requests(1)
        .with_stream_receive_window(Http2Config::MIN_CONNECTION_RECEIVE_WINDOW)
        .with_connection_receive_window(Http2Config::MIN_CONNECTION_RECEIVE_WINDOW);
    assert!(new_client(isolated_single).is_ok());

    let isolated_small_streams = Http2Config::new()
        .with_stream_receive_window(64 * 1024)
        .with_connection_receive_window(4 * 1024 * 1024);
    assert!(new_client(isolated_small_streams).is_ok());
}

// spec: r1 C2
#[test]
fn s2_config_validates_timeouts_and_retry_at_client_construction() {
    let http_endpoints = S2Endpoints::for_endpoint("http://localhost:8080").unwrap();
    let base = || S2Config::new("token").with_endpoints(http_endpoints.clone());

    assert!(crate::S2::new(base().with_connection_timeout(Duration::ZERO)).is_err());
    assert!(crate::S2::new(base().with_request_timeout(Duration::ZERO)).is_err());
    assert!(crate::S2::new(base().with_retry(RetryConfig::new().with_max_attempts(0))).is_err());
    assert!(
        crate::S2::new(
            base()
                .with_connection_timeout(Duration::from_millis(1))
                .with_request_timeout(Duration::from_millis(1))
                .with_retry(RetryConfig::new().with_max_attempts(1)),
        )
        .is_ok()
    );
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
fn config_and_encryption_key_debug_redact_secrets() {
    let config = S2Config::new("super-secret-token");
    let debug = format!("{config:?}");
    assert!(!debug.contains("super-secret-token"));
    assert!(!debug.contains("cipher_suites"));

    let key: EncryptionKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        .parse()
        .unwrap();
    assert_eq!(format!("{key:?}"), "EncryptionKey(<redacted>)");
    assert!(key.to_header_value().is_sensitive());

    let raw = [0x42u8; 32];
    let from_bytes = EncryptionKey::from_bytes(&raw).unwrap();
    let from_b64 =
        EncryptionKey::from_base64("QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=").unwrap();
    assert_eq!(from_bytes.to_header_value(), from_b64.to_header_value());
    assert!(EncryptionKey::from_bytes(&[]).is_err());
    assert!(EncryptionKey::from_base64("").is_err());
    assert!(EncryptionKey::from_base64("not!base64").is_err());
}

#[test]
fn sequenced_record_command_roundtrip_and_metered_bytes() {
    let fence_cmd = CommandRecord::fence("token-1".parse().unwrap()).with_timestamp(99);
    let rec = AppendRecord::from(fence_cmd.clone());
    assert_eq!(fence_cmd.metered_bytes(), rec.metered_bytes());

    let batch = AppendRecordBatch::try_from_iter([rec.clone()]).unwrap();
    assert_eq!(batch.metered_bytes(), rec.metered_bytes());
    let input = AppendInput::new(batch);
    assert_eq!(input.metered_bytes(), rec.metered_bytes());

    let seq = SequencedRecord::new(7, rec.body().clone(), rec.headers().to_vec(), 99);
    assert_eq!(seq.metered_bytes(), rec.metered_bytes());
    assert_eq!(
        seq.command(),
        Some(Command::Fence {
            fencing_token: "token-1".parse().unwrap(),
        })
    );

    let trim_rec = AppendRecord::from(CommandRecord::trim(42));
    let trim_seq =
        SequencedRecord::new(8, trim_rec.body().clone(), trim_rec.headers().to_vec(), 100);
    assert_eq!(trim_seq.command(), Some(Command::Trim { trim_point: 42 }));

    let normal_seq = SequencedRecord::new(9, bytes::Bytes::from_static(b"hello"), vec![], 101);
    assert_eq!(normal_seq.command(), None);

    let read_batch = ReadBatch::new(vec![seq.clone(), normal_seq.clone()], None);
    assert_eq!(
        read_batch.metered_bytes(),
        seq.metered_bytes() + normal_seq.metered_bytes()
    );
    assert_eq!(
        <ReadBatch as MeteredBytes>::metered_bytes(&read_batch),
        read_batch.metered_bytes()
    );
}

#[test]
fn error_helpers_debug_and_conversions() {
    use http::StatusCode;

    use crate::error::{
        AppendError, AppendSessionError, ErrorCode, ErrorContext, IndefiniteAppendError,
        ProtocolError, RequestError, S2Error, ServerError, SessionClosedError,
    };

    let server =
        ServerError::new(StatusCode::NOT_FOUND, "missing").with_code(ErrorCode::StreamNotFound);
    assert_eq!(server.known_code(), Some(ErrorCode::StreamNotFound));
    assert!(server.has_error_code(ErrorCode::StreamNotFound));
    assert!(!server.has_error_code(ErrorCode::BasinNotFound));
    let req_err = RequestError::Server(server);
    assert!(req_err.has_error_code(ErrorCode::StreamNotFound));
    let s2_err: S2Error = req_err.into();
    assert_eq!(s2_err.known_code(), Some(ErrorCode::StreamNotFound));
    assert!(s2_err.has_error_code(ErrorCode::StreamNotFound));

    // Clean Debug does not dump internal ErrorContext or no_side_effects internals.
    let proto = ProtocolError::new_definite(
        "encode failed",
        ErrorContext::stream("append_session", "b", "s", false),
    );
    assert!(proto.has_no_side_effects());
    let proto_dbg = format!("{proto:?}");
    assert!(!proto_dbg.contains("ErrorContext"));
    assert!(proto_dbg.contains("has_no_side_effects: true"));

    // Wrapper From conversions and into_* owned accessors.
    let indef = IndefiniteAppendError::new(AppendError::Server(ServerError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "boom",
    )));
    let s2_from_indef: S2Error = indef.clone().into();
    assert!(matches!(s2_from_indef, S2Error::IndefiniteAppend(_)));
    let session_from_indef: AppendSessionError = indef.clone().into();
    assert!(matches!(
        session_from_indef,
        AppendSessionError::IndefiniteAppend(_)
    ));
    assert!(matches!(
        indef.into_final_attempt_error(),
        AppendError::Server(_)
    ));

    let closed =
        SessionClosedError::<AppendSessionError>::new(Some(AppendSessionError::Protocol(proto)));
    let s2_from_closed: S2Error = closed.clone().into();
    assert!(matches!(s2_from_closed, S2Error::SessionClosed(_)));
    assert!(matches!(
        closed.into_failure(),
        Some(AppendSessionError::Protocol(_))
    ));
}

#[test]
fn page_next_start_after_cursors_and_deleted_items() {
    let ts = Timestamp::from_second(1_700_000_000).unwrap();

    // Page<BasinInfo>: advances past deleting last item when has_more = true.
    let basin_a: BasinName = "basin-aaaa".parse().unwrap();
    let basin_b: BasinName = "basin-bbbb".parse().unwrap();
    let basin_page = Page::new(
        vec![
            BasinInfo::new(basin_a.clone(), ts),
            BasinInfo::new(basin_b.clone(), ts).with_deleted_at(ts),
        ],
        true,
    );
    assert_eq!(
        basin_page.next_start_after(),
        Some(BasinNameStartAfter::from(basin_b.clone()))
    );
    assert_eq!(
        Page::new(vec![BasinInfo::new(basin_a, ts)], false).next_start_after(),
        None
    );
    assert_eq!(
        Page::<BasinInfo>::new(vec![], true).next_start_after(),
        None
    );

    // Page<StreamInfo>: advances past deleting last item when has_more = true.
    let stream_a: StreamName = "stream-a".parse().unwrap();
    let stream_b: StreamName = "stream-b".parse().unwrap();
    let stream_page = Page::new(
        vec![
            StreamInfo::new(stream_a.clone(), ts),
            StreamInfo::new(stream_b.clone(), ts).with_deleted_at(ts),
        ],
        true,
    );
    assert_eq!(
        stream_page.next_start_after(),
        Some(StreamNameStartAfter::from(stream_b))
    );
    assert_eq!(
        Page::new(vec![StreamInfo::new(stream_a, ts)], false).next_start_after(),
        None
    );
    assert_eq!(
        Page::<StreamInfo>::new(vec![], true).next_start_after(),
        None
    );

    // Page<AccessTokenInfo>
    let tok_a: AccessTokenId = "tok-a".parse().unwrap();
    let tok_b: AccessTokenId = "tok-b".parse().unwrap();
    let tok_page = Page::new(
        vec![
            AccessTokenInfo::new(tok_a.clone(), AccessTokenScope::default()),
            AccessTokenInfo::new(tok_b.clone(), AccessTokenScope::default()),
        ],
        true,
    );
    assert_eq!(
        tok_page.next_start_after(),
        Some(AccessTokenIdStartAfter::from(tok_b))
    );
    assert_eq!(
        Page::new(
            vec![AccessTokenInfo::new(tok_a, AccessTokenScope::default())],
            false
        )
        .next_start_after(),
        None
    );
    assert_eq!(
        Page::<AccessTokenInfo>::new(vec![], true).next_start_after(),
        None
    );

    // Page<NetworkPolicyInfo>: uses the policy slug (not full `<slug>.<nonce>` ref).
    let ref_a: NetworkPolicyRef = "policy-a.aaaaaaaa".parse().unwrap();
    let ref_b: NetworkPolicyRef = "policy-b.bbbbbbbb".parse().unwrap();
    let np_page = Page::new(
        vec![
            NetworkPolicyInfo::new(ref_a.clone(), ts, NetworkPolicy::new()),
            NetworkPolicyInfo::new(ref_b.clone(), ts, NetworkPolicy::new()),
        ],
        true,
    );
    assert_eq!(
        np_page.next_start_after(),
        Some(NetworkPolicySlugStartAfter::from(ref_b.slug().clone()))
    );
    assert_eq!(
        Page::new(
            vec![NetworkPolicyInfo::new(ref_a, ts, NetworkPolicy::new())],
            false
        )
        .next_start_after(),
        None
    );
    assert_eq!(
        Page::<NetworkPolicyInfo>::new(vec![], true).next_start_after(),
        None
    );
}

#[test]
fn endpoint_host_rejects_invalid_ipv4_and_trailing_dot_ipv4_placeholder() {
    assert!(AccountEndpoint::new("127.0.0.999").is_err());
    assert!(BasinEndpoint::new("127.0.0.999").is_err());
    assert!(BasinEndpoint::new("https://{basin}.127.0.0.1.").is_err());
    assert!(AccountEndpoint::new("127.0.0.1.").is_err());
    // Valid DNS names with trailing dot or numeric non-TLD labels remain accepted.
    assert!(AccountEndpoint::new("a.s2.dev.").is_ok());
    assert!(BasinEndpoint::new("https://{basin}.123.example.com").is_ok());
}

#[test]
fn list_inputs_omit_empty_prefix_and_start_after_on_wire() {
    let b = ListBasinsInput::new().into_api();
    assert!(b.prefix.is_none() && b.start_after.is_none());

    let s = ListStreamsInput::new().into_api();
    assert!(s.prefix.is_none() && s.start_after.is_none());

    let t = ListAccessTokensInput::new().into_api();
    assert!(t.prefix.is_none() && t.start_after.is_none());

    let n = ListNetworkPoliciesInput::new().into_api();
    assert!(n.prefix.is_none() && n.start_after.is_none());
}

#[test]
fn server_oversized_fencing_token_rejected_when_reused_for_writes() {
    let oversized = FencingToken::from_server("x".repeat(40));
    assert!(oversized.validate().is_err());

    // Batcher options reject oversized server tokens.
    let rec = AppendRecord::new("payload").unwrap();
    let cfg = crate::batching::BatcherConfig::new().with_fencing_token(oversized.clone());
    assert!(crate::batching::batch_iter([rec], cfg).is_err());

    // CommandRecord::fence carrying an oversized server token is rejected on write validation.
    let fence_cmd = AppendRecord::from(CommandRecord::fence(oversized));
    assert!(fence_cmd.validate_for_write().is_err());
    assert!(
        AppendInput::new(fence_cmd.clone())
            .validate_for_write()
            .is_err()
    );
    assert!(
        crate::batching::batch_iter([fence_cmd], crate::batching::BatcherConfig::new()).is_err()
    );
}
