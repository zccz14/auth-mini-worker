//! Rewrites legacy `webauthn_credentials.passkey_json` rows into the neutral document the Worker
//! stores, so passkeys survive the cutover instead of every user re-registering.
//!
//! The row is read by `webauthn-rs` 0.5.5 — the crate and version the legacy server runs — and
//! nothing here tries to parse its serde layout by hand. What the export has to reconstruct is the
//! COSE public key in its wire form (a CBOR map with integer keys), because the Worker hands the
//! bytes to `@simplewebauthn/server`, which decodes exactly that.
//!
//! Input, one JSON object per line:
//!   {"credential_id":"…","user_id":"…","rp_id":"…","passkey_json":"…"}
//! Output, one JSON object per line:
//!   {"credential_id":"…","user_id":"…","neutral_json":"…"}
//! With `--sql` the output is instead the `UPDATE` statements that apply those rows in D1.

use std::io::{self, BufRead, Write};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use webauthn_rs::prelude::{
    COSEAlgorithm, COSEEC2Key, COSEKey, COSEKeyType, COSEOKPKey, COSERSAKey, Credential, Passkey,
};

const USER_HANDLE_PREFIX: &[u8] = b"auth-mini-webauthn-user-handle\0";

#[derive(Deserialize)]
struct Input {
    credential_id: String,
    user_id: String,
    rp_id: String,
    passkey_json: String,
}

#[derive(Serialize)]
struct Output {
    credential_id: String,
    user_id: String,
    neutral_json: String,
}

/// Port of the legacy `user_webauthn_id`: this is what a discoverable sign-in hands back, so it has
/// to be the same 16 bytes the browser was given at registration.
fn user_handle(user_id: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(USER_HANDLE_PREFIX);
    hasher.update(user_id.as_bytes());
    let digest = hasher.finalize();
    let mut handle = digest[..16].to_vec();
    handle[6] = (handle[6] & 0x0f) | 0x50;
    handle[8] = (handle[8] & 0x3f) | 0x80;
    handle
}

fn cbor_head(major: u8, length: u64, out: &mut Vec<u8>) {
    match length {
        0..=23 => out.push((major << 5) | length as u8),
        24..=255 => {
            out.push((major << 5) | 24);
            out.push(length as u8);
        }
        256..=65535 => {
            out.push((major << 5) | 25);
            out.extend_from_slice(&(length as u16).to_be_bytes());
        }
        _ => {
            out.push((major << 5) | 26);
            out.extend_from_slice(&(length as u32).to_be_bytes());
        }
    }
}

fn cbor_int(value: i64, out: &mut Vec<u8>) {
    if value >= 0 {
        cbor_head(0, value as u64, out);
    } else {
        cbor_head(1, (-1 - value) as u64, out);
    }
}

fn cbor_bytes(value: &[u8], out: &mut Vec<u8>) {
    cbor_head(2, value.len() as u64, out);
    out.extend_from_slice(value);
}

fn cbor_map_header(entries: u64, out: &mut Vec<u8>) {
    cbor_head(5, entries, out);
}

/// Re-builds the COSE key exactly as it arrives in authenticator data: `{1: kty, 3: alg, …}` with
/// integer keys. The values come from the parsed credential, never from its JSON encoding.
fn cose_key_cbor(key: &COSEKey) -> Vec<u8> {
    let alg = key.type_ as i64;
    let mut out = Vec::new();
    match &key.key {
        COSEKeyType::EC_OKP(COSEOKPKey { curve, x }) => {
            cbor_map_header(4, &mut out);
            cbor_int(1, &mut out);
            cbor_int(1, &mut out); // kty: OKP
            cbor_int(3, &mut out);
            cbor_int(alg, &mut out);
            cbor_int(-1, &mut out);
            cbor_int(curve.clone() as i64, &mut out);
            cbor_int(-2, &mut out);
            cbor_bytes(x.as_ref(), &mut out);
        }
        COSEKeyType::EC_EC2(COSEEC2Key { curve, x, y }) => {
            cbor_map_header(5, &mut out);
            cbor_int(1, &mut out);
            cbor_int(2, &mut out); // kty: EC2
            cbor_int(3, &mut out);
            cbor_int(alg, &mut out);
            cbor_int(-1, &mut out);
            cbor_int(curve.clone() as i64, &mut out);
            cbor_int(-2, &mut out);
            cbor_bytes(x.as_ref(), &mut out);
            cbor_int(-3, &mut out);
            cbor_bytes(y.as_ref(), &mut out);
        }
        COSEKeyType::RSA(COSERSAKey { n, e }) => {
            cbor_map_header(4, &mut out);
            cbor_int(1, &mut out);
            cbor_int(3, &mut out); // kty: RSA
            cbor_int(3, &mut out);
            cbor_int(alg, &mut out);
            cbor_int(-1, &mut out);
            cbor_bytes(n.as_ref(), &mut out);
            cbor_int(-2, &mut out);
            cbor_bytes(e, &mut out);
        }
    }
    out
}

/// The transport enum serialises as the lowercase strings the browser used, so it is read back
/// through serde rather than by formatting the variant name. `Unknown` — what the deserialiser
/// produces for a value this version does not know — is dropped instead of being written back.
fn transports_of(credential: &Credential) -> Vec<String> {
    credential
        .transports
        .as_ref()
        .map(|list| {
            list.iter()
                .filter_map(|transport| match serde_json::to_value(transport) {
                    Ok(serde_json::Value::String(name))
                        if matches!(name.as_str(), "usb" | "nfc" | "ble" | "internal" | "hybrid") =>
                    {
                        Some(name)
                    }
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn neutral_json(input: &Input) -> Result<String, String> {
    let passkey: Passkey = serde_json::from_str(&input.passkey_json)
        .map_err(|error| format!("passkey_json does not deserialize: {error}"))?;
    let credential: Credential = passkey.into();

    let credential_id = URL_SAFE_NO_PAD.encode(credential.cred_id.as_ref());
    if credential_id != input.credential_id {
        return Err(format!(
            "credential id mismatch: column has {}, passkey_json has {credential_id}",
            input.credential_id
        ));
    }
    if credential.cred.type_ != COSEAlgorithm::ES256 && credential.cred.type_ != COSEAlgorithm::RS256 {
        return Err(format!("unsupported algorithm {:?}", credential.cred.type_));
    }

    let public_key = URL_SAFE_NO_PAD.encode(cose_key_cbor(&credential.cred));
    let user_handle = URL_SAFE_NO_PAD.encode(user_handle(&input.user_id));
    let transports = transports_of(&credential);

    Ok(serde_json::json!({
        "format": "auth-mini-passkey",
        "version": 1,
        "id": credential_id,
        "public_key": public_key,
        "counter": credential.counter,
        "transports": transports,
        "user_handle": user_handle,
        "rp_id": input.rp_id,
    })
    .to_string())
}

fn main() {
    let sql = std::env::args().any(|argument| argument == "--sql");
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let mut failures = 0usize;
    let mut count = 0usize;

    for (index, line) in stdin.lock().lines().enumerate() {
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                eprintln!("line {}: {error}", index + 1);
                failures += 1;
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let input: Input = match serde_json::from_str(&line) {
            Ok(input) => input,
            Err(error) => {
                eprintln!("line {}: {error}", index + 1);
                failures += 1;
                continue;
            }
        };
        match neutral_json(&input) {
            Ok(neutral) => {
                count += 1;
                if sql {
                    // The literal is single-quoted; a neutral document never contains one, because
                    // every field is base64url, a number, or a fixed identifier.
                    let escaped = neutral.replace('\'', "''");
                    let _ = writeln!(
                        out,
                        "UPDATE webauthn_credentials SET passkey_json = '{escaped}' WHERE credential_id = '{}';",
                        input.credential_id.replace('\'', "''")
                    );
                } else {
                    let record = Output {
                        credential_id: input.credential_id,
                        user_id: input.user_id,
                        neutral_json: neutral,
                    };
                    let _ = writeln!(out, "{}", serde_json::to_string(&record).unwrap());
                }
            }
            Err(error) => {
                eprintln!("line {} ({}): {error}", index + 1, input.credential_id);
                failures += 1;
            }
        }
    }

    let _ = out.flush();
    eprintln!("{count} row(s) exported, {failures} failure(s)");
    if failures > 0 {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../tests/fixtures/passkey-row.jsonl");

    fn fixture_input() -> Input {
        serde_json::from_str(FIXTURE.trim()).expect("fixture parses")
    }

    #[test]
    fn derives_the_same_user_handle_as_the_worker() {
        // Pinned in tests/webauthn.test.ts on the TypeScript side: both implementations, and the
        // legacy server they were ported from, produce these 16 bytes for this user id.
        assert_eq!(
            URL_SAFE_NO_PAD.encode(user_handle("031a393d-8a0a-4ca0-8cb1-313e0d71dfa9")),
            "eQsKK9E1VHGhkAUzKbPgXg"
        );
    }

    #[test]
    fn rewrites_a_legacy_row_into_the_neutral_document() {
        let neutral = neutral_json(&fixture_input()).expect("row exports");
        assert_eq!(
            neutral,
            "{\"counter\":0,\"format\":\"auth-mini-passkey\",\"id\":\"AAAAAAAAAAAAAAAAAAAAAA\",\
             \"public_key\":\"pQECAyYgASFYIPXzwf8yRjoeo4eNkJcsM_Lr68t7vn1b2Wd2ZahAMTj6IlggdEH-aP7pjryw5zsBluFn0di0EtX0L26pVCD4RL1URuE\",\
             \"rp_id\":\"auth.ntnl.io\",\"transports\":[],\"user_handle\":\"ZoDgpuziVdW6wQqrE5Y3UQ\",\"version\":1}"
        );
    }

    #[test]
    fn refuses_a_row_whose_column_and_payload_disagree() {
        let mut input = fixture_input();
        input.credential_id = "something-else".to_string();
        let error = neutral_json(&input).expect_err("mismatched id is refused");
        assert!(error.contains("credential id mismatch"), "{error}");
    }

    #[test]
    fn refuses_a_payload_it_cannot_read() {
        let mut input = fixture_input();
        input.passkey_json = "{\"cred\":{}}".to_string();
        assert!(neutral_json(&input).is_err());
    }
}
