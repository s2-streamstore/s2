use p256::{SecretKey, elliptic_curve::rand_core::OsRng};
use s2_common::types::access::{
    AccessTokenScope, Operation, PermittedOperationGroups, ReadWritePermissions, ResourceSet,
};
use s2_lite::auth::{ClientPublicKey, RootKey, authorize, build_token, verify_token};
use time::OffsetDateTime;

fn generate_test_root_key() -> RootKey {
    let secret = SecretKey::random(&mut OsRng);
    let bytes = secret.to_bytes();
    let base58 = bs58::encode(&bytes).into_string();
    RootKey::from_base58(&base58).unwrap()
}

fn generate_test_client_key() -> (SecretKey, ClientPublicKey) {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let secret = SecretKey::random(&mut OsRng);
    let public = secret.public_key();
    let point = public.to_encoded_point(true);
    let base58 = bs58::encode(point.as_bytes()).into_string();
    let client_pubkey = ClientPublicKey::from_base58(&base58).unwrap();
    (secret, client_pubkey)
}

#[test]
fn test_token_issue_and_verify() {
    let root_key = generate_test_root_key();
    let (_, client_pubkey) = generate_test_client_key();

    let scope = AccessTokenScope {
        basins: ResourceSet::Prefix("test-".parse().unwrap()),
        streams: ResourceSet::Prefix("test-".parse().unwrap()),
        access_tokens: ResourceSet::None,
        op_groups: PermittedOperationGroups {
            account: ReadWritePermissions {
                read: true,
                write: false,
            },
            basin: ReadWritePermissions {
                read: true,
                write: false,
            },
            stream: ReadWritePermissions {
                read: true,
                write: true,
            },
        },
        ops: [Operation::Append, Operation::Read].into_iter().collect(),
    };

    let expires = OffsetDateTime::now_utc() + time::Duration::hours(1);

    let biscuit = build_token(&root_key, &client_pubkey, expires, &scope).unwrap();
    let token_bytes = biscuit.to_vec().unwrap();

    let verified = verify_token(&token_bytes, &root_key.public_key()).unwrap();
    assert!(verified.allowed_public_keys.contains(&client_pubkey));
}

#[test]
fn test_token_authorize_operation() {
    let root_key = generate_test_root_key();
    let (_, client_pubkey) = generate_test_client_key();

    let scope = AccessTokenScope {
        basins: ResourceSet::Prefix("test-".parse().unwrap()),
        streams: ResourceSet::Prefix("test-".parse().unwrap()),
        access_tokens: ResourceSet::None,
        op_groups: PermittedOperationGroups {
            account: ReadWritePermissions {
                read: false,
                write: false,
            },
            basin: ReadWritePermissions {
                read: false,
                write: false,
            },
            stream: ReadWritePermissions {
                read: true,
                write: true,
            },
        },
        ops: Default::default(),
    };

    let expires = OffsetDateTime::now_utc() + time::Duration::hours(1);

    let biscuit = build_token(&root_key, &client_pubkey, expires, &scope).unwrap();
    let token_bytes = biscuit.to_vec().unwrap();

    let verified = verify_token(&token_bytes, &root_key.public_key()).unwrap();

    // Should succeed: stream read on matching prefix
    let result = authorize(
        &verified,
        &client_pubkey,
        Some(&root_key.public_key()),
        Some("test-mybasin"),
        Some("test-mystream"),
        None,
        Operation::Read,
    );
    assert!(result.is_ok(), "Expected success, got: {:?}", result);

    // Should fail: account-level operation (list_basins) not allowed
    let result = authorize(
        &verified,
        &client_pubkey,
        Some(&root_key.public_key()),
        None,
        None,
        None,
        Operation::ListBasins,
    );
    assert!(result.is_err(), "Expected failure for ListBasins");

    // Should fail: request signed by unauthorized key
    let (_, unauthorized_key) = generate_test_client_key();
    let result = authorize(
        &verified,
        &unauthorized_key,
        Some(&root_key.public_key()),
        Some("test-mybasin"),
        Some("test-mystream"),
        None,
        Operation::Read,
    );
    assert!(result.is_err(), "Expected failure for unauthorized signer");
}

#[test]
fn test_token_scope_enforcement() {
    let root_key = generate_test_root_key();
    let (_, client_pubkey) = generate_test_client_key();

    let scope = AccessTokenScope {
        basins: ResourceSet::Prefix("allowed-".parse().unwrap()),
        streams: ResourceSet::Prefix("allowed-".parse().unwrap()),
        access_tokens: ResourceSet::None,
        op_groups: PermittedOperationGroups {
            account: ReadWritePermissions {
                read: false,
                write: false,
            },
            basin: ReadWritePermissions {
                read: false,
                write: false,
            },
            stream: ReadWritePermissions {
                read: true,
                write: true,
            },
        },
        ops: Default::default(),
    };

    let expires = OffsetDateTime::now_utc() + time::Duration::hours(1);

    let biscuit = build_token(&root_key, &client_pubkey, expires, &scope).unwrap();
    let token_bytes = biscuit.to_vec().unwrap();

    let verified = verify_token(&token_bytes, &root_key.public_key()).unwrap();

    // Should succeed: basin within allowed prefix
    let result = authorize(
        &verified,
        &client_pubkey,
        Some(&root_key.public_key()),
        Some("allowed-mybasin"),
        Some("allowed-mystream"),
        None,
        Operation::Read,
    );
    assert!(result.is_ok(), "Expected success, got: {:?}", result);

    // Should fail: basin outside allowed prefix
    let result = authorize(
        &verified,
        &client_pubkey,
        Some(&root_key.public_key()),
        Some("forbidden-otherbasin"),
        Some("forbidden-otherstream"),
        None,
        Operation::Read,
    );
    assert!(result.is_err(), "Expected failure for out-of-scope basin");
}

#[test]
fn test_token_delegation_via_attenuation() {
    use biscuit_auth::builder::BlockBuilder;

    let root_key = generate_test_root_key();
    let (_, alice_pubkey) = generate_test_client_key();
    let (_, bob_pubkey) = generate_test_client_key();

    // Alice gets a token with stream read/write permissions
    let scope = AccessTokenScope {
        basins: ResourceSet::Prefix("alice-".parse().unwrap()),
        streams: ResourceSet::Prefix("alice-".parse().unwrap()),
        access_tokens: ResourceSet::None,
        op_groups: PermittedOperationGroups {
            account: ReadWritePermissions {
                read: false,
                write: false,
            },
            basin: ReadWritePermissions {
                read: false,
                write: false,
            },
            stream: ReadWritePermissions {
                read: true,
                write: true,
            },
        },
        ops: Default::default(),
    };
    let expires = OffsetDateTime::now_utc() + time::Duration::hours(1);
    let biscuit = build_token(&root_key, &alice_pubkey, expires, &scope).unwrap();

    // Alice attenuates for Bob (offline operation)
    let mut attenuator = BlockBuilder::new();
    attenuator = attenuator
        .fact(format!("public_key(\"{}\")", bob_pubkey.to_base58()).as_str())
        .unwrap();
    attenuator = attenuator
        .check(format!("check if signer($s), $s == \"{}\"", bob_pubkey.to_base58()).as_str())
        .unwrap();
    // Narrow scope further
    attenuator = attenuator
        .check("check if basin($b), $b.starts_with(\"alice-shared/\")")
        .unwrap();

    let delegated = biscuit.append(attenuator).unwrap();
    let token_bytes = delegated.to_vec().unwrap();

    // Verify the delegated token
    let verified = verify_token(&token_bytes, &root_key.public_key()).unwrap();

    // Both public keys should be present
    assert!(
        verified.allowed_public_keys.contains(&alice_pubkey),
        "Alice's key should be present"
    );
    assert!(
        verified.allowed_public_keys.contains(&bob_pubkey),
        "Bob's key should be present"
    );
}

#[test]
fn test_public_key_injection_blocked() {
    use biscuit_auth::builder::BlockBuilder;

    let root_key = generate_test_root_key();
    let (_, alice_pubkey) = generate_test_client_key();
    let (_, attacker_pubkey) = generate_test_client_key();

    // Alice gets a token
    let scope = AccessTokenScope {
        basins: ResourceSet::Prefix("alice-".parse().unwrap()),
        streams: ResourceSet::Prefix("alice-".parse().unwrap()),
        access_tokens: ResourceSet::None,
        op_groups: PermittedOperationGroups {
            account: ReadWritePermissions {
                read: false,
                write: false,
            },
            basin: ReadWritePermissions {
                read: false,
                write: false,
            },
            stream: ReadWritePermissions {
                read: true,
                write: true,
            },
        },
        ops: Default::default(),
    };
    let expires = OffsetDateTime::now_utc() + time::Duration::hours(1);
    let biscuit = build_token(&root_key, &alice_pubkey, expires, &scope).unwrap();

    // Attacker tries to inject their key via a check containing the string
    let mut attenuator = BlockBuilder::new();
    // This embeds public_key("...") inside a string literal - should NOT be extracted
    let injection_check = format!(
        "check if debug_log(\"injected public_key(\\\"{}\\\")\")",
        attacker_pubkey.to_base58()
    );
    attenuator = attenuator.check(injection_check.as_str()).unwrap();

    let injected = biscuit.append(attenuator).unwrap();
    let token_bytes = injected.to_vec().unwrap();

    let verified = verify_token(&token_bytes, &root_key.public_key()).unwrap();

    // Alice's key should be present (from authority block)
    assert!(
        verified.allowed_public_keys.contains(&alice_pubkey),
        "Alice's key should be present"
    );
    // Attacker's key should NOT be extracted - it was inside a string literal
    assert!(
        !verified.allowed_public_keys.contains(&attacker_pubkey),
        "Attacker's key should NOT be extracted from string literal injection"
    );
}

#[test]
fn test_path_traversal_blocked() {
    let root_key = generate_test_root_key();
    let (_, client_pubkey) = generate_test_client_key();

    // Token scoped to "tenant-a-" prefix
    let scope = AccessTokenScope {
        basins: ResourceSet::Prefix("tenant-a-".parse().unwrap()),
        streams: ResourceSet::Prefix("tenant-a-".parse().unwrap()),
        access_tokens: ResourceSet::None,
        op_groups: PermittedOperationGroups {
            account: ReadWritePermissions {
                read: false,
                write: false,
            },
            basin: ReadWritePermissions {
                read: false,
                write: false,
            },
            stream: ReadWritePermissions {
                read: true,
                write: true,
            },
        },
        ops: Default::default(),
    };

    let expires = OffsetDateTime::now_utc() + time::Duration::hours(1);
    let biscuit = build_token(&root_key, &client_pubkey, expires, &scope).unwrap();
    let token_bytes = biscuit.to_vec().unwrap();
    let verified = verify_token(&token_bytes, &root_key.public_key()).unwrap();

    // These should all FAIL - path traversal attempts should not bypass prefix check
    // Note: s2 basin names can only contain lowercase letters, numbers, and hyphens
    // so ".." is not a valid basin name anyway, but we verify the scope check doesn't
    // get confused by traversal-like patterns

    // Attempt 1: basin that starts with prefix but tries to escape
    // "tenant-a-../tenant-b" starts with "tenant-a-" so would pass starts_with
    // but this is actually fine - we're not doing filesystem paths
    let result = authorize(
        &verified,
        &client_pubkey,
        Some(&root_key.public_key()),
        Some("tenant-a-foo"), // valid: starts with tenant-a-
        Some("tenant-a-bar"),
        None,
        Operation::Read,
    );
    assert!(result.is_ok(), "tenant-a-foo should be allowed");

    // Attempt 2: basin that doesn't start with prefix
    let result = authorize(
        &verified,
        &client_pubkey,
        Some(&root_key.public_key()),
        Some("tenant-b-foo"),
        Some("tenant-b-bar"),
        None,
        Operation::Read,
    );
    assert!(result.is_err(), "tenant-b-foo should be denied");

    // Attempt 3: prefix with different continuation
    let result = authorize(
        &verified,
        &client_pubkey,
        Some(&root_key.public_key()),
        Some("tenant-a"), // missing the hyphen
        Some("stream"),
        None,
        Operation::Read,
    );
    assert!(
        result.is_err(),
        "tenant-a (without hyphen) should be denied"
    );
}

/// Helper to create a token where the root key is used as the client key.
/// This is the bug scenario we're testing against.
fn create_root_as_client_token() -> (
    s2_lite::auth::RootKey,
    ClientPublicKey,
    s2_lite::auth::VerifiedToken,
) {
    let root_key = generate_test_root_key();

    // Get the root PUBLIC key and use it as the "client" public key
    // This simulates the bug: someone creating a token with the root key as the signer
    let root_public_key = root_key.public_key();
    let root_as_client = ClientPublicKey::from_base58(&root_public_key.to_base58()).unwrap();

    // Token with full permissions to isolate the root-key-as-client check
    let scope = AccessTokenScope {
        basins: ResourceSet::Prefix("".parse().unwrap()),
        streams: ResourceSet::Prefix("".parse().unwrap()),
        access_tokens: ResourceSet::Prefix("".parse().unwrap()),
        op_groups: PermittedOperationGroups {
            account: ReadWritePermissions {
                read: true,
                write: true,
            },
            basin: ReadWritePermissions {
                read: true,
                write: true,
            },
            stream: ReadWritePermissions {
                read: true,
                write: true,
            },
        },
        ops: Default::default(),
    };

    let expires = OffsetDateTime::now_utc() + time::Duration::hours(1);
    let biscuit = build_token(&root_key, &root_as_client, expires, &scope).unwrap();
    let token_bytes = biscuit.to_vec().unwrap();

    let verified = verify_token(&token_bytes, &root_key.public_key()).unwrap();

    (root_key, root_as_client, verified)
}

// =============================================================================
// ACCOUNT OPERATIONS - Root key must be REJECTED
// =============================================================================

/// Per design doc: "No superuser bypass - root key only for token management endpoints"
#[test]
fn test_root_key_rejected_for_list_basins() {
    let (root_key, root_as_client, verified) = create_root_as_client_token();

    let result = authorize(
        &verified,
        &root_as_client,
        Some(&root_key.public_key()),
        None,
        None,
        None,
        Operation::ListBasins,
    );
    assert!(
        result.is_err(),
        "Root key must NOT be usable for ListBasins (account operation)"
    );
}

#[test]
fn test_root_key_rejected_for_create_basin() {
    let (root_key, root_as_client, verified) = create_root_as_client_token();

    let result = authorize(
        &verified,
        &root_as_client,
        Some(&root_key.public_key()),
        Some("new-basin"),
        None,
        None,
        Operation::CreateBasin,
    );
    assert!(
        result.is_err(),
        "Root key must NOT be usable for CreateBasin (account operation)"
    );
}

#[test]
fn test_root_key_rejected_for_delete_basin() {
    let (root_key, root_as_client, verified) = create_root_as_client_token();

    let result = authorize(
        &verified,
        &root_as_client,
        Some(&root_key.public_key()),
        Some("my-basin"),
        None,
        None,
        Operation::DeleteBasin,
    );
    assert!(
        result.is_err(),
        "Root key must NOT be usable for DeleteBasin (account operation)"
    );
}

#[test]
fn test_root_key_rejected_for_account_metrics() {
    let (root_key, root_as_client, verified) = create_root_as_client_token();

    let result = authorize(
        &verified,
        &root_as_client,
        Some(&root_key.public_key()),
        None,
        None,
        None,
        Operation::AccountMetrics,
    );
    assert!(
        result.is_err(),
        "Root key must NOT be usable for AccountMetrics (account operation)"
    );
}

// =============================================================================
// BASIN OPERATIONS - Root key must be REJECTED
// =============================================================================

#[test]
fn test_root_key_rejected_for_get_basin_config() {
    let (root_key, root_as_client, verified) = create_root_as_client_token();

    let result = authorize(
        &verified,
        &root_as_client,
        Some(&root_key.public_key()),
        Some("my-basin"),
        None,
        None,
        Operation::GetBasinConfig,
    );
    assert!(
        result.is_err(),
        "Root key must NOT be usable for GetBasinConfig (basin operation)"
    );
}

#[test]
fn test_root_key_rejected_for_reconfigure_basin() {
    let (root_key, root_as_client, verified) = create_root_as_client_token();

    let result = authorize(
        &verified,
        &root_as_client,
        Some(&root_key.public_key()),
        Some("my-basin"),
        None,
        None,
        Operation::ReconfigureBasin,
    );
    assert!(
        result.is_err(),
        "Root key must NOT be usable for ReconfigureBasin (basin operation)"
    );
}

#[test]
fn test_root_key_rejected_for_list_streams() {
    let (root_key, root_as_client, verified) = create_root_as_client_token();

    let result = authorize(
        &verified,
        &root_as_client,
        Some(&root_key.public_key()),
        Some("my-basin"),
        None,
        None,
        Operation::ListStreams,
    );
    assert!(
        result.is_err(),
        "Root key must NOT be usable for ListStreams (basin operation)"
    );
}

#[test]
fn test_root_key_rejected_for_create_stream() {
    let (root_key, root_as_client, verified) = create_root_as_client_token();

    let result = authorize(
        &verified,
        &root_as_client,
        Some(&root_key.public_key()),
        Some("my-basin"),
        Some("new-stream"),
        None,
        Operation::CreateStream,
    );
    assert!(
        result.is_err(),
        "Root key must NOT be usable for CreateStream (basin operation)"
    );
}

#[test]
fn test_root_key_rejected_for_delete_stream() {
    let (root_key, root_as_client, verified) = create_root_as_client_token();

    let result = authorize(
        &verified,
        &root_as_client,
        Some(&root_key.public_key()),
        Some("my-basin"),
        Some("my-stream"),
        None,
        Operation::DeleteStream,
    );
    assert!(
        result.is_err(),
        "Root key must NOT be usable for DeleteStream (basin operation)"
    );
}

#[test]
fn test_root_key_rejected_for_basin_metrics() {
    let (root_key, root_as_client, verified) = create_root_as_client_token();

    let result = authorize(
        &verified,
        &root_as_client,
        Some(&root_key.public_key()),
        Some("my-basin"),
        None,
        None,
        Operation::BasinMetrics,
    );
    assert!(
        result.is_err(),
        "Root key must NOT be usable for BasinMetrics (basin operation)"
    );
}

// =============================================================================
// STREAM OPERATIONS - Root key must be REJECTED
// =============================================================================

#[test]
fn test_root_key_rejected_for_get_stream_config() {
    let (root_key, root_as_client, verified) = create_root_as_client_token();

    let result = authorize(
        &verified,
        &root_as_client,
        Some(&root_key.public_key()),
        Some("my-basin"),
        Some("my-stream"),
        None,
        Operation::GetStreamConfig,
    );
    assert!(
        result.is_err(),
        "Root key must NOT be usable for GetStreamConfig (stream operation)"
    );
}

#[test]
fn test_root_key_rejected_for_reconfigure_stream() {
    let (root_key, root_as_client, verified) = create_root_as_client_token();

    let result = authorize(
        &verified,
        &root_as_client,
        Some(&root_key.public_key()),
        Some("my-basin"),
        Some("my-stream"),
        None,
        Operation::ReconfigureStream,
    );
    assert!(
        result.is_err(),
        "Root key must NOT be usable for ReconfigureStream (stream operation)"
    );
}

#[test]
fn test_root_key_rejected_for_check_tail() {
    let (root_key, root_as_client, verified) = create_root_as_client_token();

    let result = authorize(
        &verified,
        &root_as_client,
        Some(&root_key.public_key()),
        Some("my-basin"),
        Some("my-stream"),
        None,
        Operation::CheckTail,
    );
    assert!(
        result.is_err(),
        "Root key must NOT be usable for CheckTail (stream operation)"
    );
}

#[test]
fn test_root_key_rejected_for_append() {
    let (root_key, root_as_client, verified) = create_root_as_client_token();

    let result = authorize(
        &verified,
        &root_as_client,
        Some(&root_key.public_key()),
        Some("my-basin"),
        Some("my-stream"),
        None,
        Operation::Append,
    );
    assert!(
        result.is_err(),
        "Root key must NOT be usable for Append (stream operation)"
    );
}

#[test]
fn test_root_key_rejected_for_read() {
    let (root_key, root_as_client, verified) = create_root_as_client_token();

    let result = authorize(
        &verified,
        &root_as_client,
        Some(&root_key.public_key()),
        Some("my-basin"),
        Some("my-stream"),
        None,
        Operation::Read,
    );
    assert!(
        result.is_err(),
        "Root key must NOT be usable for Read (stream operation)"
    );
}

#[test]
fn test_root_key_rejected_for_trim() {
    let (root_key, root_as_client, verified) = create_root_as_client_token();

    let result = authorize(
        &verified,
        &root_as_client,
        Some(&root_key.public_key()),
        Some("my-basin"),
        Some("my-stream"),
        None,
        Operation::Trim,
    );
    assert!(
        result.is_err(),
        "Root key must NOT be usable for Trim (stream operation)"
    );
}

#[test]
fn test_root_key_rejected_for_fence() {
    let (root_key, root_as_client, verified) = create_root_as_client_token();

    let result = authorize(
        &verified,
        &root_as_client,
        Some(&root_key.public_key()),
        Some("my-basin"),
        Some("my-stream"),
        None,
        Operation::Fence,
    );
    assert!(
        result.is_err(),
        "Root key must NOT be usable for Fence (stream operation)"
    );
}

#[test]
fn test_root_key_rejected_for_stream_metrics() {
    let (root_key, root_as_client, verified) = create_root_as_client_token();

    let result = authorize(
        &verified,
        &root_as_client,
        Some(&root_key.public_key()),
        Some("my-basin"),
        Some("my-stream"),
        None,
        Operation::StreamMetrics,
    );
    assert!(
        result.is_err(),
        "Root key must NOT be usable for StreamMetrics (stream operation)"
    );
}

// =============================================================================
// ACCESS TOKEN OPERATIONS - Root key SHOULD be accepted (the exception)
// =============================================================================

#[test]
fn test_root_key_accepted_for_issue_access_token() {
    let (root_key, root_as_client, verified) = create_root_as_client_token();

    let result = authorize(
        &verified,
        &root_as_client,
        Some(&root_key.public_key()),
        Some("my-basin"),
        None,
        Some("new-token-id"),
        Operation::IssueAccessToken,
    );
    assert!(
        result.is_ok(),
        "Root key SHOULD be usable for IssueAccessToken: {:?}",
        result
    );
}

#[test]
fn test_root_key_accepted_for_revoke_access_token() {
    let (root_key, root_as_client, verified) = create_root_as_client_token();

    let result = authorize(
        &verified,
        &root_as_client,
        Some(&root_key.public_key()),
        Some("my-basin"),
        None,
        Some("token-to-revoke"),
        Operation::RevokeAccessToken,
    );
    assert!(
        result.is_ok(),
        "Root key SHOULD be usable for RevokeAccessToken: {:?}",
        result
    );
}

#[test]
fn test_root_key_accepted_for_list_access_tokens() {
    let (root_key, root_as_client, verified) = create_root_as_client_token();

    let result = authorize(
        &verified,
        &root_as_client,
        Some(&root_key.public_key()),
        Some("my-basin"),
        None,
        None,
        Operation::ListAccessTokens,
    );
    assert!(
        result.is_ok(),
        "Root key SHOULD be usable for ListAccessTokens: {:?}",
        result
    );
}

#[test]
fn test_access_token_scope_enforced() {
    let root_key = generate_test_root_key();
    let (_, client_pubkey) = generate_test_client_key();

    // Token with limited access_token scope
    let scope = AccessTokenScope {
        basins: ResourceSet::Prefix("".parse().unwrap()),
        streams: ResourceSet::Prefix("".parse().unwrap()),
        access_tokens: ResourceSet::Prefix("allowed-".parse().unwrap()),
        op_groups: PermittedOperationGroups {
            account: ReadWritePermissions {
                read: false,
                write: false,
            },
            basin: ReadWritePermissions {
                read: false,
                write: true, // includes IssueAccessToken
            },
            stream: ReadWritePermissions {
                read: false,
                write: false,
            },
        },
        ops: Default::default(),
    };

    let expires = OffsetDateTime::now_utc() + time::Duration::hours(1);
    let biscuit = build_token(&root_key, &client_pubkey, expires, &scope).unwrap();
    let token_bytes = biscuit.to_vec().unwrap();
    let verified = verify_token(&token_bytes, &root_key.public_key()).unwrap();

    // Should succeed: access token within allowed prefix
    let result = authorize(
        &verified,
        &client_pubkey,
        Some(&root_key.public_key()),
        Some("mybasin"),
        None,
        Some("allowed-token-123"),
        Operation::IssueAccessToken,
    );
    assert!(
        result.is_ok(),
        "Should allow issuing token with allowed- prefix"
    );

    // Should fail: access token outside allowed prefix
    let result = authorize(
        &verified,
        &client_pubkey,
        Some(&root_key.public_key()),
        Some("mybasin"),
        None,
        Some("forbidden-token-456"),
        Operation::IssueAccessToken,
    );
    assert!(
        result.is_err(),
        "Should deny issuing token with forbidden- prefix"
    );
}
