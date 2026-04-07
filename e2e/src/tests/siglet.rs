//  Copyright (c) 2026 Metaform Systems, Inc
//
//  This program and the accompanying materials are made available under the
//  terms of the Apache License, Version 2.0 which is available at
//  https://www.apache.org/licenses/LICENSE-2.0
//
//  SPDX-License-Identifier: Apache-2.0
//
//  Contributors:
//       Metaform Systems, Inc. - initial API and implementation
//

//! E2E tests for Siglet DataFlow handler
//!
//! These tests deploy Siglet in a Kind cluster and verify its DataFlow
//! handling capabilities, including signaling API interactions and health endpoints.
//!
//! Note: These tests share a single Siglet deployment and can run in parallel.

use crate::fixtures::consumer_did::ensure_consumer_did;
use crate::fixtures::siglet::ensure_siglet_deployed;
use crate::utils::*;
use anyhow::{Context, Result};
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::jwt::jwtutils::StaticSigningKeyResolver;
use dsdk_facet_core::jwt::{JwtGenerator, KeyFormat, LocalJwtGenerator, SigningAlgorithm, TokenClaims};
use reqwest::Client;
use std::sync::Arc;

/// Test that Siglet deploys successfully and responds to health checks
#[tokio::test]
#[ignore]
async fn test_siglet_deployment_and_health() -> Result<()> {
    let deployment = ensure_siglet_deployed().await?;
    let pod_name = &deployment.pod_name;

    // Test health endpoint using kubectl exec
    let health_response = kubectl_exec(
        E2E_NAMESPACE,
        pod_name,
        "siglet",
        &["wget", "-q", "-O-", "http://localhost:8080/health"],
    )?;

    assert!(
        health_response.contains("healthy"),
        "Health endpoint should return healthy status"
    );

    // Test root endpoint
    let root_response = kubectl_exec(
        E2E_NAMESPACE,
        pod_name,
        "siglet",
        &["wget", "-q", "-O-", "http://localhost:8080/"],
    )?;

    assert!(
        root_response.contains("Siglet"),
        "Root endpoint should return Siglet metadata"
    );
    assert!(root_response.contains("version"), "Root endpoint should return version");
    assert!(
        root_response.contains("running"),
        "Root endpoint should indicate running status"
    );

    let logs = get_pod_logs(E2E_NAMESPACE, pod_name, "siglet")?;

    assert!(logs.contains("Siglet API"), "Logs should indicate Siglet API started");
    assert!(
        logs.contains("Signaling API"),
        "Logs should indicate Signaling API started"
    );
    assert!(logs.contains("Refresh API"), "Logs should indicate Refresh API started");
    assert!(logs.contains("Ready"), "Logs should indicate Siglet is ready");

    Ok(())
}

/// Test consumer-provider pull interaction
///
/// This test verifies the complete pull transfer flow:
/// - Consumer calls prepare endpoint (no data address returned)
/// - Provider calls start endpoint and returns data address with tokens
/// - Consumer calls started endpoint with provider's data address
/// - Consumer refreshes the access token
/// - Provider terminates the transfer
#[tokio::test]
#[ignore]
async fn test_pull_operations() -> Result<()> {
    let deployment = ensure_siglet_deployed().await?;
    let key_material = ensure_consumer_did().await?;
    let private_key_der = key_material.private_key_der.to_vec();

    // Pre-flight: verify the DID document served by the consumer-did pod contains the
    // expected public key before making any API calls. If this fails the signing key the
    // test uses won't match what Siglet fetches from the DID server, causing an opaque
    // "Invalid token signature" at the refresh step.
    {
        let did_doc_raw = kubectl_exec(
            E2E_NAMESPACE,
            &deployment.pod_name,
            "siglet",
            &["sh", "-c", "wget -q -O- http://consumer/.well-known/did.json"],
        )
        .context("Failed to fetch consumer DID document from inside siglet pod")?;

        let did_doc: serde_json::Value =
            serde_json::from_str(&did_doc_raw).context("Failed to parse consumer DID document")?;

        let served_multibase = did_doc
            .get("verificationMethod")
            .and_then(|vms| vms.as_array())
            .and_then(|arr| arr.first())
            .and_then(|vm| vm.get("publicKeyMultibase"))
            .and_then(|v| v.as_str())
            .context("No publicKeyMultibase in served DID document")?;

        let expected_multibase = String::from_utf8(
            read_secret_bytes(E2E_NAMESPACE, "consumer-did-private-key", "publicKeyMultibase")
                .context("Failed to read expected public key from consumer-did-private-key secret")?,
        )
        .context("Non-UTF8 public key multibase in secret")?;

        assert_eq!(
            served_multibase, expected_multibase,
            "DID document public key mismatch: the consumer-did pod is not serving the key from setup.sh.\n\
             Served:   {}\n\
             Expected: {}\n\
             Re-run 'cd e2e && ./scripts/setup.sh' to reprovision the consumer DID server.",
            served_multibase, expected_multibase
        );
        println!("DID document key verified: {}", &served_multibase[..20]);
    }

    let signaling_url = format!("http://localhost:{}", deployment.signaling_port);
    let client = Client::new();

    // Use unique IDs per run so retries don't collide with flows left in Siglet state
    // from a prior attempt.
    let run_id = uuid::Uuid::new_v4().to_string();
    let dataset_id = format!("dataset-{}", run_id);
    let agreement_id = format!("agreement-{}", run_id);
    let consumer_flow_id = format!("consumer-flow-{}", run_id);
    let provider_flow_id = format!("provider-flow-{}", run_id);

    // Step 1: Consumer calls prepare endpoint
    let prepare_message = serde_json::json!({
        "datasetId": dataset_id,
        "participantId": "did:web:consumer",
        "processId": consumer_flow_id,
        "agreementId": agreement_id,
        "transferType": "http-pull",
        "dataspaceContext": "test-dataspace",
        "callbackAddress": "https://consumer.example.com/callback",
        "messageId": format!("msg-prepare-{}", run_id),
        "counterPartyId": "did:web:provider",
        "labels": [],
        "metadata": {},
    });

    let prepare_response = client
        .post(format!("{}/api/v1/dataflows/prepare", signaling_url))
        .header("Content-Type", "application/json")
        .header("X-Participant-Id", "test-participant-context")
        .json(&prepare_message)
        .send()
        .await
        .context("Failed to send prepare request")?;

    assert!(
        prepare_response.status().is_success(),
        "Prepare request should succeed, got status: {}",
        prepare_response.status()
    );

    let prepare_result: serde_json::Value = prepare_response
        .json()
        .await
        .context("Failed to parse prepare response")?;

    // Verify prepare response does NOT contain a meaningful dataAddress (it's a pull)
    if let Some(data_address) = prepare_result.get("dataAddress") {
        assert!(
            data_address.is_null(),
            "Prepare response should not contain a dataAddress for pull transfers, got: {}",
            data_address
        );
    }

    // Step 2: Provider calls start endpoint
    let start_message = serde_json::json!({
        "datasetId": dataset_id,
        "participantId": "did:web:provider",
        "processId": provider_flow_id,
        "agreementId": agreement_id,
        "transferType": "http-pull",
        "dataspaceContext": "test-dataspace",
        "callbackAddress": "https://provider.example.com/callback",
        "messageId": format!("msg-start-{}", run_id),
        "counterPartyId": "did:web:consumer",
        "labels": [],
        "metadata": {
            "claim1": "claimvalue1",
            "claim2": "claimvalue2"
        }
    });

    let start_response = client
        .post(format!("{}/api/v1/dataflows/start", signaling_url))
        .header("Content-Type", "application/json")
        .header("X-Participant-Id", "test-participant-context")
        .json(&start_message)
        .send()
        .await
        .context("Failed to send start request")?;

    assert!(
        start_response.status().is_success(),
        "Start request should succeed, got status: {}",
        start_response.status()
    );

    let start_result: serde_json::Value = start_response.json().await.context("Failed to parse start response")?;

    assert!(
        start_result.get("state").is_some(),
        "Response should contain 'state' field"
    );
    assert!(
        start_result.get("dataplaneId").is_some(),
        "Response should contain 'dataplaneId' field"
    );

    let state = start_result["state"].as_str().unwrap();
    assert_eq!(state, "STARTED", "DataFlow should be in STARTED state");

    let data_address = start_result.get("dataAddress").unwrap();
    let properties = data_address.get("endpointProperties").unwrap();
    let properties_array = properties.as_array().unwrap();

    let has_auth = properties_array
        .iter()
        .any(|p| p.get("name").and_then(|n| n.as_str()) == Some("authorization"));
    assert!(has_auth, "Authorization property not found in data address");

    let auth_prop = properties_array
        .iter()
        .find(|p| p.get("name").and_then(|n| n.as_str()) == Some("authorization"))
        .unwrap();

    let token = auth_prop.get("value").and_then(|v| v.as_str()).unwrap();
    assert!(!token.is_empty());

    // Decode and parse the JWT
    let token_parts: Vec<&str> = token.split('.').collect();
    assert_eq!(
        token_parts.len(),
        3,
        "JWT should have 3 parts (header.payload.signature)"
    );

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(token_parts[1])
        .context("Failed to decode JWT payload")?;
    let payload_str = String::from_utf8(payload_bytes).context("Failed to convert payload to string")?;
    let jwt_payload: serde_json::Value =
        serde_json::from_str(&payload_str).context("Failed to parse JWT payload as JSON")?;

    assert_eq!(
        jwt_payload.get("claim1").and_then(|v| v.as_str()),
        Some("claimvalue1"),
        "claim1 should be present in JWT with correct value"
    );
    assert_eq!(
        jwt_payload.get("claim2").and_then(|v| v.as_str()),
        Some("claimvalue2"),
        "claim2 should be present in JWT with correct value"
    );

    let has_refresh = properties_array
        .iter()
        .any(|p| p.get("name").and_then(|n| n.as_str()) == Some("refreshToken"));
    assert!(has_refresh, "Refresh token not found in data address");

    let has_endpoint = properties_array
        .iter()
        .any(|p| p.get("name").and_then(|n| n.as_str()) == Some("refreshEndpoint"));
    assert!(has_endpoint, "Refresh Endpoint not found in data address");

    // Step 3: Consumer calls started endpoint with provider's data address
    let started_message = serde_json::json!({
        "participantId": "did:web:consumer",
        "counterPartyId": "did:web:provider",
        "dataAddress": data_address,
        "messageId": format!("msg-started-{}", run_id)
    });

    let started_response = client
        .post(format!(
            "{}/api/v1/dataflows/{}/started",
            signaling_url, consumer_flow_id
        ))
        .header("Content-Type", "application/json")
        .json(&started_message)
        .send()
        .await
        .context("Failed to send started request")?;

    let status = started_response.status();
    if !status.is_success() {
        let error_body = started_response
            .text()
            .await
            .unwrap_or_else(|_| "Unable to read error body".to_string());
        panic!(
            "Started request should succeed, got status: {}, body: {}",
            status, error_body
        );
    }

    // Step 4: Verify the access token.
    let verify_url = format!("http://localhost:{}/tokens/verify", deployment.siglet_api_port);
    let verify_response = client
        .post(&verify_url)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "token": token, "audience": "did:web:provider" }))
        .send()
        .await
        .context("Token verification request failed")?;

    if !verify_response.status().is_success() {
        let status = verify_response.status();
        let body = verify_response.text().await.unwrap_or_default();
        anyhow::bail!("Token verification returned HTTP {}: {}", status, body);
    }

    let verify_result: serde_json::Value = verify_response
        .json()
        .await
        .context("Failed to parse token verification response")?;

    assert!(
        verify_result.get("sub").is_some(),
        "Verified token claims should contain 'sub' field, got: {}",
        verify_result
    );

    // Step 5: Consumer refreshes the access token via the dedicated Refresh API port.
    // Port-forwarding for port 8082 is set up in the fixture, so we can call it
    // directly from the test using the reqwest client.
    let refresh_token_prop = properties_array
        .iter()
        .find(|p| p.get("name").and_then(|n| n.as_str()) == Some("refreshToken"))
        .unwrap();
    let refresh_token_value = refresh_token_prop.get("value").and_then(|v| v.as_str()).unwrap();

    // Build a JWT to authenticate the refresh request (consumer signs as itself, audience = provider).
    let resolver = Arc::new(
        StaticSigningKeyResolver::builder()
            .key(private_key_der)
            .key_format(KeyFormat::DER)
            .iss("did:web:consumer")
            .kid("did:web:consumer#key-1")
            .build(),
    );
    let jwt_gen = Arc::new(
        LocalJwtGenerator::builder()
            .signing_key_resolver(resolver)
            .signing_algorithm(SigningAlgorithm::EdDSA)
            .build(),
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut token_claim = serde_json::Map::new();
    token_claim.insert("token".to_string(), serde_json::Value::String(token.to_string()));
    let claims = TokenClaims::builder()
        .iss("did:web:consumer")
        .sub("did:web:consumer")
        .aud("did:web:provider")
        .exp(now + 300)
        .custom(token_claim)
        .build();
    let consumer_ctx = ParticipantContext::builder()
        .id("test-participant-context")
        .identifier("did:web:consumer")
        .audience("did:web:consumer")
        .build();
    let bearer_jwt = jwt_gen
        .generate_token(&consumer_ctx, claims)
        .await
        .context("Failed to generate JWT for refresh")?;

    let refresh_url = format!("http://localhost:{}/token/refresh", deployment.refresh_api_port);
    let refresh_response = client
        .post(&refresh_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Authorization", format!("Bearer {}", bearer_jwt))
        .body(format!(
            "grant_type=refresh_token&refresh_token={}",
            refresh_token_value
        ))
        .send()
        .await
        .context("Token refresh request failed")?;

    if !refresh_response.status().is_success() {
        let status = refresh_response.status();
        let body = refresh_response.text().await.unwrap_or_default();
        anyhow::bail!("Token refresh returned HTTP {}: {}", status, body);
    }

    let refresh_result: serde_json::Value = refresh_response
        .json()
        .await
        .context("Failed to parse token refresh response")?;

    assert!(
        refresh_result
            .get("access_token")
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty()),
        "Refreshed access token should not be empty, got: {}",
        refresh_result
    );
    assert!(
        refresh_result
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty()),
        "New refresh token should not be empty, got: {}",
        refresh_result
    );

    let new_access_token = refresh_result["access_token"].as_str().unwrap();

    // Step 6: Old token should now be rejected (it was rotated out by the refresh).
    let stale_verify_response = client
        .post(&verify_url)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "token": token, "audience": "did:web:provider" }))
        .send()
        .await
        .context("Stale token verification request failed")?;
    assert_eq!(
        stale_verify_response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Old access token should be rejected after refresh"
    );

    // Step 7: New access token obtained from refresh should be valid.
    let new_verify_response = client
        .post(&verify_url)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "token": new_access_token, "audience": "did:web:provider" }))
        .send()
        .await
        .context("New token verification request failed")?;
    if !new_verify_response.status().is_success() {
        let status = new_verify_response.status();
        let body = new_verify_response.text().await.unwrap_or_default();
        anyhow::bail!("New access token verification returned HTTP {}: {}", status, body);
    }

    // Step 8: Provider terminates the transfer
    let terminate_message = serde_json::json!({ "reason": "Test termination" });

    let terminate_response = client
        .post(format!(
            "{}/api/v1/dataflows/{}/terminate",
            signaling_url, provider_flow_id
        ))
        .header("Content-Type", "application/json")
        .json(&terminate_message)
        .send()
        .await
        .context("Failed to send terminate request")?;

    assert!(
        terminate_response.status().is_success(),
        "Terminate should return 200 OK for successful termination, got: {}",
        terminate_response.status()
    );

    Ok(())
}
