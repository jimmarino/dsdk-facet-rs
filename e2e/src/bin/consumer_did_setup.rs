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

//! Generates an Ed25519 keypair for the consumer DID server.
//!
//! Outputs a single line to stdout: `<base64-private-key-der> <public-key-multibase>`
//!
//! Used by `scripts/setup-consumer-did.sh` to avoid a Python dependency.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use dsdk_facet_core::jwt::jwtutils::generate_ed25519_keypair_der;
use dsdk_facet_core::util::crypto::convert_to_multibase;

fn main() {
    let keypair = generate_ed25519_keypair_der().expect("Ed25519 keypair generation failed");

    let private_key_b64 = STANDARD.encode(&keypair.private_key);

    // convert_to_multibase expects a base64-encoded raw 32-byte public key
    let public_key_b64 = STANDARD.encode(&keypair.public_key);
    let public_key_multibase = convert_to_multibase(&public_key_b64).expect("multibase encoding failed");

    println!("{} {}", private_key_b64, public_key_multibase);
}
