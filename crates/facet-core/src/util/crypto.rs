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

use crate::vault::VaultError;
use base64::Engine;

/// Converts an Ed25519 public key to multibase format (base58btc with 'z' prefix).
pub fn convert_to_multibase(public_key_base64: &str) -> Result<String, VaultError> {
    // Decode the base64 public key
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(public_key_base64)
        .map_err(|_| VaultError::InvalidData("Invalid key format".to_string()))?;

    // Validate Ed25519 key size (32 bytes)
    if key_bytes.len() != 32 {
        return Err(VaultError::InvalidData(format!(
            "Invalid Ed25519 key size: expected 32 bytes, got {}",
            key_bytes.len()
        )));
    }

    // Add multicodec prefix for Ed25519 public key (0xed01)
    let mut prefixed_key = vec![0xed, 0x01];
    prefixed_key.extend_from_slice(&key_bytes);

    // Encode with base58btc and prepend 'z' prefix
    let encoded = bs58::encode(&prefixed_key).into_string();
    Ok(format!("z{}", encoded))
}

/// Validates and decodes a multibase-encoded Ed25519 public key.
/// Returns the raw 32-byte Ed25519 public key if valid.
pub fn validate_multibase_ed25519(multibase_key: &str) -> Result<Vec<u8>, VaultError> {
    // Check for 'z' prefix (base58btc)
    if !multibase_key.starts_with('z') {
        return Err(VaultError::InvalidData(
            "Invalid multibase format: expected 'z' prefix for base58btc".to_string(),
        ));
    }

    // Decode base58btc (skip 'z' prefix)
    let decoded = bs58::decode(&multibase_key[1..])
        .into_vec()
        .map_err(|e| VaultError::InvalidData(format!("Failed to decode base58: {}", e)))?;

    // Validate minimum length (multicodec prefix + key)
    if decoded.len() < 3 {
        return Err(VaultError::InvalidData(
            "Invalid key: too short to contain multicodec prefix".to_string(),
        ));
    }

    // Validate Ed25519 multicodec prefix (0xed01)
    if decoded[0] != 0xed || decoded[1] != 0x01 {
        return Err(VaultError::InvalidData(format!(
            "Invalid multicodec prefix: expected [0xed, 0x01] for Ed25519, got [{:#x}, {:#x}]",
            decoded[0], decoded[1]
        )));
    }

    // Extract and validate key bytes
    let key_bytes = &decoded[2..];
    if key_bytes.len() != 32 {
        return Err(VaultError::InvalidData(format!(
            "Invalid Ed25519 key size: expected 32 bytes, got {}",
            key_bytes.len()
        )));
    }

    Ok(key_bytes.to_vec())
}
