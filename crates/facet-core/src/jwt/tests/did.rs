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

use crate::jwt::{DidWebVerificationKeyResolver, JwtVerificationError, VerificationKeyResolver};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[test]
fn test_did_web_to_url_basic_domain() {
    let resolver = DidWebVerificationKeyResolver::builder().build();

    let result = resolver.did_web_to_url("did:web:example.com").unwrap();
    assert_eq!(result, "https://example.com/.well-known/did.json");
}

#[test]
fn test_did_web_to_url_with_path() {
    let resolver = DidWebVerificationKeyResolver::builder().build();

    let result = resolver.did_web_to_url("did:web:example.com:user:alice").unwrap();
    assert_eq!(result, "https://example.com/user/alice/did.json");
}

#[test]
fn test_did_web_to_url_with_port() {
    let resolver = DidWebVerificationKeyResolver::builder().build();

    let result = resolver.did_web_to_url("did:web:example.com%3A3000").unwrap();
    assert_eq!(result, "https://example.com:3000/.well-known/did.json");
}

#[test]
fn test_did_web_to_url_with_port_lowercase() {
    let resolver = DidWebVerificationKeyResolver::builder().build();

    let result = resolver.did_web_to_url("did:web:example.com%3a8080").unwrap();
    assert_eq!(result, "https://example.com:8080/.well-known/did.json");
}

#[test]
fn test_did_web_to_url_with_port_and_path() {
    let resolver = DidWebVerificationKeyResolver::builder().build();

    let result = resolver.did_web_to_url("did:web:example.com%3A3000:user:bob").unwrap();
    assert_eq!(result, "https://example.com:3000/user/bob/did.json");
}

#[test]
fn test_did_web_to_url_http_protocol() {
    let resolver = DidWebVerificationKeyResolver::builder().use_https(false).build();

    // Port must be percent-encoded in did:web format
    let result = resolver.did_web_to_url("did:web:localhost%3A3000").unwrap();
    assert_eq!(result, "http://localhost:3000/.well-known/did.json");
}

#[test]
fn test_did_web_to_url_invalid_format_no_prefix() {
    let resolver = DidWebVerificationKeyResolver::builder().build();

    let result = resolver.did_web_to_url("example.com");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        JwtVerificationError::VerificationFailed(_)
    ));
}

#[test]
fn test_did_web_to_url_with_empty_path_segment() {
    let resolver = DidWebVerificationKeyResolver::builder().build();

    // Multiple colons create empty path segments
    let result = resolver.did_web_to_url("did:web:example.com::user").unwrap();
    assert_eq!(result, "https://example.com//user/did.json");
}

#[tokio::test]
async fn test_fetch_did_document_success() {
    let mock_server = MockServer::start().await;
    let did_doc = create_did_document(
        "did:web:example.com",
        "did:web:example.com#key-1",
        &valid_ed25519_multibase(),
    );

    Mock::given(method("GET"))
        .and(path("/.well-known/did.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&did_doc))
        .mount(&mock_server)
        .await;

    let resolver = DidWebVerificationKeyResolver::builder().build();
    let url = format!("{}/.well-known/did.json", mock_server.uri());
    let result = resolver.fetch_did_document(&url).await;

    assert!(result.is_ok());
    let doc = result.unwrap();
    assert!(doc.verification_method.is_some());
}

#[tokio::test]
async fn test_fetch_did_document_not_found() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/did.json"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let resolver = DidWebVerificationKeyResolver::builder().build();
    let url = format!("{}/.well-known/did.json", mock_server.uri());
    let result = resolver.fetch_did_document(&url).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        JwtVerificationError::VerificationFailed(msg) => {
            assert!(msg.contains("404"));
        }
        _ => panic!("Expected VerificationFailed error"),
    }
}

#[tokio::test]
async fn test_fetch_did_document_invalid_json() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/did.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not valid json"))
        .mount(&mock_server)
        .await;

    let resolver = DidWebVerificationKeyResolver::builder().build();
    let url = format!("{}/.well-known/did.json", mock_server.uri());
    let result = resolver.fetch_did_document(&url).await;

    assert!(result.is_err());
}

#[test]
fn test_find_verification_method_by_fragment_suffix() {
    let did_doc = serde_json::from_value::<crate::jwt::DidDocument>(create_did_document(
        "did:web:example.com",
        "did:web:example.com#key-1",
        &valid_ed25519_multibase(),
    ))
    .unwrap();

    let result = DidWebVerificationKeyResolver::find_verification_method(&did_doc, "key-1");
    assert!(result.is_ok());
}

#[test]
fn test_find_verification_method_by_exact_match() {
    let did_doc = serde_json::from_value::<crate::jwt::DidDocument>(json!({
        "@context": "https://www.w3.org/ns/did/v1",
        "id": "did:web:example.com",
        "verificationMethod": [{
            "id": "key-1",
            "type": "Ed25519VerificationKey2020",
            "controller": "did:web:example.com",
            "publicKeyMultibase": valid_ed25519_multibase()
        }]
    }))
    .unwrap();

    let result = DidWebVerificationKeyResolver::find_verification_method(&did_doc, "key-1");
    assert!(result.is_ok());
}

#[test]
fn test_find_verification_method_not_found() {
    let did_doc = serde_json::from_value::<crate::jwt::DidDocument>(create_did_document(
        "did:web:example.com",
        "did:web:example.com#key-1",
        &valid_ed25519_multibase(),
    ))
    .unwrap();

    let result = DidWebVerificationKeyResolver::find_verification_method(&did_doc, "key-2");
    assert!(result.is_err());
    match result.unwrap_err() {
        JwtVerificationError::VerificationFailed(msg) => {
            assert!(msg.contains("not found"));
        }
        _ => panic!("Expected VerificationFailed error"),
    }
}

#[test]
fn test_find_verification_method_no_methods() {
    let did_doc = serde_json::from_value::<crate::jwt::DidDocument>(json!({
        "@context": "https://www.w3.org/ns/did/v1",
        "id": "did:web:example.com"
    }))
    .unwrap();

    let result = DidWebVerificationKeyResolver::find_verification_method(&did_doc, "key-1");
    assert!(result.is_err());
    match result.unwrap_err() {
        JwtVerificationError::VerificationFailed(msg) => {
            assert!(msg.contains("no verification methods"));
        }
        _ => panic!("Expected VerificationFailed error"),
    }
}

#[test]
fn test_verification_method_to_key_material_multibase() {
    let vm = serde_json::from_value::<crate::jwt::VerificationMethod>(json!({
        "id": "did:web:example.com#key-1",
        "type": "Ed25519VerificationKey2020",
        "controller": "did:web:example.com",
        "publicKeyMultibase": valid_ed25519_multibase()
    }))
    .unwrap();

    let result =
        DidWebVerificationKeyResolver::verification_method_to_key_material(&vm, "did:web:example.com", "key-1");

    assert!(result.is_ok());
    let key_material = result.unwrap();
    assert_eq!(key_material.iss, "did:web:example.com");
    assert_eq!(key_material.kid, "key-1");
    // DER format should be 44 bytes (12 byte prefix + 32 byte key)
    assert_eq!(key_material.key.len(), 44);
}

#[test]
fn test_verification_method_to_key_material_invalid_multibase() {
    let vm = serde_json::from_value::<crate::jwt::VerificationMethod>(json!({
        "id": "did:web:example.com#key-1",
        "type": "Ed25519VerificationKey2020",
        "controller": "did:web:example.com",
        "publicKeyMultibase": "invalid-multibase-key"
    }))
    .unwrap();

    let result =
        DidWebVerificationKeyResolver::verification_method_to_key_material(&vm, "did:web:example.com", "key-1");

    assert!(result.is_err());
}

#[test]
fn test_verification_method_to_key_material_jwk_unsupported() {
    let vm = serde_json::from_value::<crate::jwt::VerificationMethod>(json!({
        "id": "did:web:example.com#key-1",
        "type": "JsonWebKey2020",
        "controller": "did:web:example.com",
        "publicKeyJwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        }
    }))
    .unwrap();

    let result =
        DidWebVerificationKeyResolver::verification_method_to_key_material(&vm, "did:web:example.com", "key-1");

    assert!(result.is_err());
    match result.unwrap_err() {
        JwtVerificationError::VerificationFailed(msg) => {
            assert!(msg.contains("not yet supported"));
        }
        _ => panic!("Expected VerificationFailed error"),
    }
}

#[test]
fn test_verification_method_to_key_material_no_key() {
    let vm = serde_json::from_value::<crate::jwt::VerificationMethod>(json!({
        "id": "did:web:example.com#key-1",
        "type": "Ed25519VerificationKey2020",
        "controller": "did:web:example.com"
    }))
    .unwrap();

    let result =
        DidWebVerificationKeyResolver::verification_method_to_key_material(&vm, "did:web:example.com", "key-1");

    assert!(result.is_err());
    match result.unwrap_err() {
        JwtVerificationError::VerificationFailed(msg) => {
            assert!(msg.contains("No supported public key format"));
        }
        _ => panic!("Expected VerificationFailed error"),
    }
}

#[tokio::test]
async fn test_resolve_key_full_did_url() {
    let mock_server = MockServer::start().await;
    let did = format!("did:web:{}", mock_server.address().to_string().replace(":", "%3A"));
    let key_id = format!("{}#key-1", did);

    let did_doc = create_did_document(&did, &key_id, &valid_ed25519_multibase());

    Mock::given(method("GET"))
        .and(path("/.well-known/did.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&did_doc))
        .mount(&mock_server)
        .await;

    let resolver = DidWebVerificationKeyResolver::builder().use_https(false).build();

    // Use spawn_blocking to avoid nested runtime issue
    let did_clone = did.clone();
    let key_id_clone = key_id.clone();
    let result = tokio::task::spawn_blocking(move || resolver.resolve_key(&did_clone, &key_id_clone))
        .await
        .unwrap();

    assert!(result.is_ok());
    let key_material = result.unwrap();
    assert_eq!(key_material.iss, did);
}

#[tokio::test]
async fn test_resolve_key_fragment_only_kid() {
    let mock_server = MockServer::start().await;
    let did = format!("did:web:{}", mock_server.address().to_string().replace(":", "%3A"));
    let key_id = format!("{}#key-1", did);

    let did_doc = create_did_document(&did, &key_id, &valid_ed25519_multibase());

    Mock::given(method("GET"))
        .and(path("/.well-known/did.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&did_doc))
        .mount(&mock_server)
        .await;

    let resolver = DidWebVerificationKeyResolver::builder().use_https(false).build();

    // Pass just fragment as kid
    let did_clone = did.clone();
    let result = tokio::task::spawn_blocking(move || resolver.resolve_key(&did_clone, "#key-1"))
        .await
        .unwrap();

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_resolve_key_bare_fragment_kid() {
    let mock_server = MockServer::start().await;
    let did = format!("did:web:{}", mock_server.address().to_string().replace(":", "%3A"));
    let key_id = format!("{}#key-1", did);

    let did_doc = create_did_document(&did, &key_id, &valid_ed25519_multibase());

    Mock::given(method("GET"))
        .and(path("/.well-known/did.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&did_doc))
        .mount(&mock_server)
        .await;

    let resolver = DidWebVerificationKeyResolver::builder().use_https(false).build();

    // Pass bare fragment as kid (no # prefix)
    let did_clone = did.clone();
    let result = tokio::task::spawn_blocking(move || resolver.resolve_key(&did_clone, "key-1"))
        .await
        .unwrap();

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_resolve_key_with_path() {
    let mock_server = MockServer::start().await;
    let host = mock_server.address().to_string().replace(":", "%3A");
    let did = format!("did:web:{}:users:alice", host);
    let key_id = format!("{}#signing-key", did);

    let did_doc = create_did_document(&did, &key_id, &valid_ed25519_multibase());

    Mock::given(method("GET"))
        .and(path("/users/alice/did.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&did_doc))
        .mount(&mock_server)
        .await;

    let resolver = DidWebVerificationKeyResolver::builder().use_https(false).build();

    let did_clone = did.clone();
    let result = tokio::task::spawn_blocking(move || resolver.resolve_key(&did_clone, "signing-key"))
        .await
        .unwrap();

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_resolve_key_missing_fragment() {
    let mock_server = MockServer::start().await;
    let did = format!("did:web:{}", mock_server.address().to_string().replace(":", "%3A"));

    let resolver = DidWebVerificationKeyResolver::builder().use_https(false).build();

    // Pass kid without fragment (full DID URL without #)
    let did_clone = did.clone();
    let did_clone2 = did.clone();
    let result = tokio::task::spawn_blocking(move || resolver.resolve_key(&did_clone, &did_clone2))
        .await
        .unwrap();

    assert!(result.is_err());
    match result.unwrap_err() {
        JwtVerificationError::VerificationFailed(msg) => {
            assert!(msg.contains("must include fragment"));
        }
        _ => panic!("Expected VerificationFailed error"),
    }
}

#[tokio::test]
async fn test_resolve_key_http_vs_https() {
    let mock_server = MockServer::start().await;
    let did = format!("did:web:{}", mock_server.address().to_string().replace(":", "%3A"));
    let key_id = format!("{}#key-1", did);

    let did_doc = create_did_document(&did, &key_id, &valid_ed25519_multibase());

    Mock::given(method("GET"))
        .and(path("/.well-known/did.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&did_doc))
        .mount(&mock_server)
        .await;

    // Test with HTTP (should work with mock server)
    let resolver_http = DidWebVerificationKeyResolver::builder().use_https(false).build();

    let did_clone = did.clone();
    let result = tokio::task::spawn_blocking(move || resolver_http.resolve_key(&did_clone, "key-1"))
        .await
        .unwrap();
    assert!(result.is_ok());

    // Test with HTTPS (will fail because mock server uses HTTP)
    let resolver_https = DidWebVerificationKeyResolver::builder().use_https(true).build();

    let did_clone2 = did.clone();
    let result = tokio::task::spawn_blocking(move || resolver_https.resolve_key(&did_clone2, "key-1"))
        .await
        .unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn test_resolve_key_network_error() {
    // Use a server that doesn't exist
    let resolver = DidWebVerificationKeyResolver::builder().build();

    let result =
        tokio::task::spawn_blocking(move || resolver.resolve_key("did:web:nonexistent.invalid.domain.test", "key-1"))
            .await
            .unwrap();

    assert!(result.is_err());
}

// Test helper to create a valid Ed25519 public key in multibase format
fn valid_ed25519_multibase() -> String {
    // z prefix indicates base58btc encoding of Ed25519 public key
    // This is a valid 32-byte Ed25519 public key
    "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string()
}

// Test helper to create a mock DID document
fn create_did_document(did: &str, key_id: &str, multibase_key: &str) -> serde_json::Value {
    json!({
        "@context": "https://www.w3.org/ns/did/v1",
        "id": did,
        "verificationMethod": [{
            "id": key_id,
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyMultibase": multibase_key
        }]
    })
}
