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

use crate::util::crypto::{convert_to_multibase, validate_multibase_ed25519};
use crate::vault::VaultError;

// Tests for multibase encoding
#[test]
fn test_convert_to_multibase_valid_key() {
    // Ed25519 public key example (32 bytes) encoded in base64
    // This is a valid Ed25519 public key
    let public_key_base64 = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

    let result = convert_to_multibase(public_key_base64);
    assert!(result.is_ok(), "Should successfully convert valid key");

    let multibase_key = result.unwrap();
    // Should start with 'z' for base58btc encoding
    assert!(multibase_key.starts_with('z'), "Multibase key should start with 'z'");

    // Should have reasonable length (32 bytes key + 2 bytes multicodec prefix = 34 bytes)
    // Base58btc encoding should result in ~46-48 characters plus 'z' prefix
    assert!(
        multibase_key.len() > 40 && multibase_key.len() < 60,
        "Multibase key length {} seems incorrect",
        multibase_key.len()
    );
}

#[test]
fn test_convert_to_multibase_deterministic() {
    let public_key_base64 = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

    // Convert the same key twice
    let result1 = convert_to_multibase(public_key_base64).unwrap();
    let result2 = convert_to_multibase(public_key_base64).unwrap();

    // Should produce identical results
    assert_eq!(result1, result2, "Same key should produce same multibase encoding");
}

#[test]
fn test_convert_to_multibase_different_keys() {
    let key1_base64 = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
    // Another valid Ed25519 public key (32 bytes)
    let key2_base64 = "mcDE6jR9BjH3kojBtfm0wJrrm43rE9f+rVMKIaqIJQk=";

    let result1 = convert_to_multibase(key1_base64).unwrap();
    let result2 = convert_to_multibase(key2_base64).unwrap();

    // Different keys should produce different multibase encodings
    assert_ne!(
        result1, result2,
        "Different keys should produce different multibase encodings"
    );
}

#[test]
fn test_convert_to_multibase_invalid_base64() {
    // Invalid base64 string
    let invalid_base64 = "not-valid-base64!@#$%";

    let result = convert_to_multibase(invalid_base64);
    assert!(result.is_err(), "Should fail with invalid base64");

    match result {
        Err(VaultError::InvalidData(msg)) => {
            assert!(msg.contains("Invalid key format"), "Error message should be generic");
        }
        _ => panic!("Expected InvalidData error"),
    }
}

#[test]
fn test_convert_to_multibase_has_correct_multicodec_prefix() {
    let public_key_base64 = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
    let multibase_key = convert_to_multibase(public_key_base64).unwrap();

    // Decode the multibase key to verify the multicodec prefix
    // Remove 'z' prefix
    let encoded = &multibase_key[1..];
    let decoded = bs58::decode(encoded).into_vec().unwrap();

    // First two bytes should be 0xed, 0x01 (Ed25519 public key multicodec)
    assert_eq!(decoded[0], 0xed, "First byte should be 0xed");
    assert_eq!(decoded[1], 0x01, "Second byte should be 0x01");

    // Remaining bytes should be the public key (32 bytes for Ed25519)
    assert_eq!(
        decoded.len(),
        34,
        "Decoded length should be 34 bytes (2 multicodec + 32 key)"
    );
}

// Tests for multibase validation
#[test]
fn test_validate_multibase_ed25519_valid_key() {
    // Generate a valid multibase key
    let public_key_base64 = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
    let multibase_key = convert_to_multibase(public_key_base64).unwrap();

    // Validate it
    let result = validate_multibase_ed25519(&multibase_key);
    assert!(result.is_ok(), "Should validate correct multibase key");

    let key_bytes = result.unwrap();
    assert_eq!(key_bytes.len(), 32, "Should extract 32-byte Ed25519 key");
}

#[test]
fn test_validate_multibase_ed25519_invalid_prefix() {
    // Key with wrong prefix (not 'z')
    let invalid_key = "f6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    let result = validate_multibase_ed25519(invalid_key);
    assert!(result.is_err(), "Should reject key without 'z' prefix");

    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("expected 'z' prefix"),
        "Error should mention missing 'z' prefix"
    );
}

#[test]
fn test_validate_multibase_ed25519_wrong_multicodec() {
    // Create a key with wrong multicodec prefix (e.g., 0xec01 instead of 0xed01)
    let mut wrong_prefix = vec![0xec, 0x01]; // Wrong prefix
    wrong_prefix.extend_from_slice(&[0u8; 32]); // Add 32 bytes

    let encoded = format!("z{}", bs58::encode(&wrong_prefix).into_string());

    let result = validate_multibase_ed25519(&encoded);
    assert!(result.is_err(), "Should reject key with wrong multicodec prefix");

    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("Invalid multicodec prefix"),
        "Error should mention invalid prefix"
    );
}

#[test]
fn test_validate_multibase_ed25519_wrong_key_size() {
    // Create a key with correct prefix but wrong size (16 bytes instead of 32)
    let mut wrong_size = vec![0xed, 0x01];
    wrong_size.extend_from_slice(&[0u8; 16]); // Only 16 bytes

    let encoded = format!("z{}", bs58::encode(&wrong_size).into_string());

    let result = validate_multibase_ed25519(&encoded);
    assert!(result.is_err(), "Should reject key with wrong size");

    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("Invalid Ed25519 key size"),
        "Error should mention wrong key size"
    );
}

#[test]
fn test_validate_multibase_ed25519_invalid_base58() {
    // Invalid base58 characters
    let invalid_key = "z0OIl"; // Contains invalid base58 characters (0, O, I, l)

    let result = validate_multibase_ed25519(invalid_key);
    assert!(result.is_err(), "Should reject invalid base58 encoding");
}
