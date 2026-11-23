use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use futures_util::StreamExt as _;
use s2_api::v1 as api;
use s2_sdk::{
    error::{AppendError, RequestError},
    types::{
        AccessTokenId, AccessTokenScopeInput, AppendRetryPolicy, BasinReconfiguration,
        DeleteOnEmptyReconfiguration, EnsureBasinInput, EnsureOutput, EnsureStreamInput,
        IssueAccessTokenInput, ListAllBasinsInput, ListAllStreamsInput, ListBasinsInput,
        ListStreamsInput, NetworkPolicy, Operation, OperationGroupPermissions, PublicNetPolicy,
        Reconfigure, RetentionPolicy, StreamReconfiguration, TimestampingMode,
        TimestampingReconfiguration,
    },
};

use crate::support::*;

// spec: r1 M2
#[tokio::test]
async fn spec_m2_ensure_output_variants() {
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
        .reset_stream_cipher()
        .reset_create_stream_on_append()
        .reset_create_stream_on_read();
    assert_eq!(basin_reset.default_stream_config(), Reconfigure::Reset);
    assert_eq!(basin_reset.stream_cipher(), Reconfigure::Reset);
    assert_eq!(basin_reset.create_stream_on_append(), Reconfigure::Reset);
    assert_eq!(basin_reset.create_stream_on_read(), Reconfigure::Reset);
    let basin_api: api::config::BasinReconfiguration = basin_reset.into();
    assert_eq!(
        serde_json::to_value(&basin_api).unwrap(),
        serde_json::json!({
            "default_stream_config": null,
            "stream_cipher": null,
            "create_stream_on_append": null,
            "create_stream_on_read": null,
        })
    );
}

// spec: r1 T2d
#[tokio::test]
async fn spec_t2d_definite_only_retries_for_token_and_network_policy() {
    let fast_retry_3 = fast_retry_config(3);

    let token_input = || {
        IssueAccessTokenInput::new(
            "tok-1".parse::<AccessTokenId>().unwrap(),
            AccessTokenScopeInput::from_op_group_perms(OperationGroupPermissions::read_write_all()),
        )
    };
    let policy_slug = || "pol-1".parse().unwrap();
    let policy = || {
        NetworkPolicy::new().with_public_net(PublicNetPolicy::Cidrs(vec![
            "192.0.2.0/24".parse().unwrap(),
        ]))
    };

    // 1. issue_access_token does NOT retry indefinite 503 unavailable
    let server = MockH2Server::from_responses([CannedResponse::new(
        503,
        r#"{"code":"unavailable","message":"busy"}"#,
    )])
    .await;
    let err = server
        .client(fast_retry_3)
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
        .client(fast_retry_3)
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
        .client(fast_retry_3)
        .create_network_policy(policy_slug(), policy())
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
        .create_network_policy(policy_slug(), policy())
        .await
        .expect("must retry definite rate_limited");
    assert_eq!(info.id.slug().as_ref(), "pol-1");
    assert_eq!(server.request_count(), 2);

    // 5. AppendRetryPolicy::NoSideEffects must NOT retry indefinite 503 unavailable even if the
    //    server replies immediately before consuming request body frames (T2c/T2d).
    let early_503 = MockH2Server::start(|_conn_id, _req, respond| async move {
        send_json(respond, 503, r#"{"code":"unavailable","message":"busy"}"#);
    })
    .await;
    let err = early_503
        .stream(fast_retry_3.with_append_retry_policy(AppendRetryPolicy::NoSideEffects))
        .append(sample_append_input())
        .await
        .expect_err("NoSideEffects must not retry indefinite 503");
    assert!(matches!(err, AppendError::Server(_)), "{err:?}");
    assert_eq!(early_503.request_count(), 1);
}

// spec: r1 M5, M6, M7, M8
#[tokio::test]
async fn spec_m5_m6_m7_m8_issue_token_and_list_pagination() {
    let seen_start_after = Arc::new(Mutex::new(Vec::<Option<String>>::new()));
    let server = MockH2Server::start({
        let seen_start_after = seen_start_after.clone();
        move |_conn_id, req, respond| {
            let seen_start_after = seen_start_after.clone();
            async move {
                let method = req.method().clone();
                let path = req.uri().path().to_owned();
                let params = query_pairs(req.uri());
                let _ = drain_body(&mut req.into_body()).await;

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

                send_json(respond, 200, payload);
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

// spec: r1 M4
#[tokio::test]
async fn spec_m4_delete_idempotency_and_error_discrimination() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let token_id: AccessTokenId = "m4-token".parse().unwrap();
    let policy_sel = s2_sdk::types::NetworkPolicySelector::Slug("m4-policy".parse().unwrap());

    // 1. Each delete succeeds on its own resource's not-found code.
    let ok_server = MockH2Server::from_responses([
        CannedResponse::new(404, r#"{"code":"basin_not_found","message":"gone"}"#),
        CannedResponse::new(404, r#"{"code":"stream_not_found","message":"gone"}"#),
        CannedResponse::new(404, r#"{"code":"access_token_not_found","message":"gone"}"#),
        CannedResponse::new(
            404,
            r#"{"code":"network_policy_not_found","message":"gone"}"#,
        ),
    ])
    .await;
    let s2 = ok_server.client(no_retry_config());
    s2.delete_basin(basin_name.clone()).await.unwrap();
    s2.basin(basin_name.clone())
        .delete_stream(stream_name.clone())
        .await
        .unwrap();
    s2.revoke_access_token(token_id.clone()).await.unwrap();
    s2.delete_network_policy(policy_sel.clone()).await.unwrap();

    // 2. Other 404 codes, plain 404 without code, and 409 network_policy_in_use MUST fail.
    let err_server = MockH2Server::from_responses([
        CannedResponse::new(404, r#"{"code":"stream_not_found","message":"wrong code"}"#),
        CannedResponse::new(404, r#"{"code":"basin_not_found","message":"wrong code"}"#),
        CannedResponse::new(404, "plain not found"),
        CannedResponse::new(409, r#"{"code":"network_policy_in_use","message":"bound"}"#),
    ])
    .await;
    let s2 = err_server.client(no_retry_config());
    assert!(matches!(
        s2.delete_basin(basin_name.clone()).await,
        Err(RequestError::Server(ref e)) if e.code.as_deref() == Some("stream_not_found")
    ));
    assert!(matches!(
        s2.basin(basin_name).delete_stream(stream_name).await,
        Err(RequestError::Server(ref e)) if e.code.as_deref() == Some("basin_not_found")
    ));
    assert!(matches!(
        s2.revoke_access_token(token_id).await,
        Err(RequestError::Server(ref e)) if e.status == http::StatusCode::NOT_FOUND && e.code.is_none()
    ));
    assert!(matches!(
        s2.delete_network_policy(policy_sel).await,
        Err(RequestError::Server(ref e)) if e.code.as_deref() == Some("network_policy_in_use")
    ));
}
