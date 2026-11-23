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
    let ctx = crate::error::ErrorContext::default();

    let ack = AppendAck::try_from_proto(
        api::stream::proto::AppendAck {
            start: pos(5),
            end: pos(8),
            tail: pos(10),
        },
        3,
        ctx.clone(),
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
        assert!(AppendAck::try_from_proto(raw, count, ctx.clone()).is_err());
    }
}

#[test]
fn http2_config_bounds() {
    let cfg = Http2Config::new()
        .with_max_concurrent_requests(Http2Config::MAX_CONCURRENT_REQUESTS)
        .unwrap()
        .with_stream_receive_window(Http2Config::MAX_RECEIVE_WINDOW)
        .unwrap()
        .with_connection_receive_window(Http2Config::MIN_CONNECTION_RECEIVE_WINDOW)
        .unwrap();
    assert_eq!(
        cfg.max_concurrent_requests(),
        Some(Http2Config::MAX_CONCURRENT_REQUESTS)
    );
    assert_eq!(
        cfg.stream_receive_window(),
        Some(Http2Config::MAX_RECEIVE_WINDOW)
    );
    assert_eq!(
        cfg.connection_receive_window(),
        Some(Http2Config::MIN_CONNECTION_RECEIVE_WINDOW)
    );
    assert_eq!(Http2Config::new().max_concurrent_requests(), None);

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
}
