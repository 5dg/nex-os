//! Exact compatibility with the existing Go evidence v1 journal bytes.
//! This is separate from manifest serialization: RawValue preserves the JSON
//! number tokens the signer receives without changing global Value behavior.
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const MAX_EVENT_BYTES: usize = 128 * 1024;
const MAX_DETAIL_DEPTH: usize = 128;

// Declaration order is the existing Go Event struct's JSON field order.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Event {
    resource_id: String,
    delegation_id: String,
    timestamp_us: i64,
    #[serde(default)]
    producer: String,
    event_id: String,
    tenant_id: String,
    actor_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    job_id: String,
    action: String,
    detail: Box<RawValue>,
}

#[derive(Serialize)]
struct Envelope<'a> {
    event: &'a Event,
    previous: &'a str,
}

pub(crate) fn head(body: &[u8], producer: &str, previous: &str) -> Result<String, ()> {
    Ok(format!(
        "{:x}",
        Sha256::digest(canonical(body, producer, previous)?)
    ))
}

/// Canonical Go v1 event bytes with the authenticated kernel producer.
/// Derive these from the same envelope used for journal heads so the outbox
/// cannot silently use a different event serialization.
pub(crate) fn canonical_kernel_event(body: &[u8]) -> Result<Vec<u8>, ()> {
    let envelope = canonical(body, "kernel", "")?;
    let event = envelope
        .strip_prefix(br#"{"event":"#)
        .and_then(|bytes| bytes.strip_suffix(br#","previous":""}"#))
        .ok_or(())?;
    Ok(event.to_vec())
}

fn canonical(body: &[u8], producer: &str, previous: &str) -> Result<Vec<u8>, ()> {
    if body.len() > MAX_EVENT_BYTES || !matches!(producer, "control" | "kernel") {
        return Err(());
    }
    let mut event: Event = serde_json::from_slice(body).map_err(|_| ())?;
    // The authenticated Go endpoint assigns its producer, not the request.
    event.producer = producer.to_owned();
    let mut detail = Vec::new();
    normalize(&event.detail, 0, &mut detail)?;
    event.detail =
        RawValue::from_string(String::from_utf8(detail).map_err(|_| ())?).map_err(|_| ())?;
    let encoded = serde_json::to_string(&Envelope {
        event: &event,
        previous,
    })
    .map_err(|_| ())?;
    // Go encoding/json's default HTML and JavaScript line-separator escaping.
    // Escaping actual characters after serialization leaves literal backslash
    // escape text distinct and also covers object keys and the outer fields.
    let mut go = Vec::with_capacity(encoded.len());
    for character in encoded.chars() {
        match character {
            '<' => go.extend_from_slice(br"\u003c"),
            '>' => go.extend_from_slice(br"\u003e"),
            '&' => go.extend_from_slice(br"\u0026"),
            '\u{2028}' => go.extend_from_slice(br"\u2028"),
            '\u{2029}' => go.extend_from_slice(br"\u2029"),
            other => {
                let mut bytes = [0u8; 4];
                go.extend_from_slice(other.encode_utf8(&mut bytes).as_bytes());
            }
        }
    }
    Ok(go)
}

fn normalize(raw: &RawValue, depth: usize, out: &mut Vec<u8>) -> Result<(), ()> {
    if depth > MAX_DETAIL_DEPTH {
        return Err(());
    }
    let text = raw.get();
    match text.as_bytes().first().ok_or(())? {
        b'{' => {
            let fields: BTreeMap<String, Box<RawValue>> =
                serde_json::from_str(text).map_err(|_| ())?;
            out.push(b'{');
            for (index, (key, value)) in fields.iter().enumerate() {
                if index != 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, key).map_err(|_| ())?;
                out.push(b':');
                normalize(value, depth + 1, out)?;
            }
            out.push(b'}');
        }
        b'[' => {
            let values: Vec<Box<RawValue>> = serde_json::from_str(text).map_err(|_| ())?;
            out.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    out.push(b',');
                }
                normalize(value, depth + 1, out)?;
            }
            out.push(b']');
        }
        b'"' => {
            let value: String = serde_json::from_str(text).map_err(|_| ())?;
            serde_json::to_writer(out, &value).map_err(|_| ())?;
        }
        b'-' | b'0'..=b'9' | b't' | b'f' | b'n' => {
            // RawValue has already validated this single JSON token. In
            // particular, do not parse numbers as f64 or reformat their text:
            // Go's UseNumber preserves exponent and integer spelling here.
            out.extend_from_slice(text.as_bytes());
        }
        _ => return Err(()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    #[test]
    fn exact_bytes_heads_and_signatures_match_independent_go_v1_vectors() {
        let vectors: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../packages/evidence/event-v1-vectors.json"
        ))
        .unwrap();
        assert_eq!(vectors.len(), 6);
        for vector in vectors {
            let name = vector["name"].as_str().unwrap();
            let body = vector["event_json"].as_str().unwrap().as_bytes();
            let previous = vector["previous"].as_str().unwrap();
            let expected = vector["head"].as_str().unwrap();
            let vector_envelope = vector["canonical_json"].as_str().unwrap();
            let previous_suffix = format!(",\"previous\":\"{previous}\"}}");
            let expected_event = vector_envelope
                .strip_prefix("{\"event\":")
                .and_then(|envelope| envelope.strip_suffix(previous_suffix.as_str()))
                .unwrap();
            assert_eq!(
                canonical_kernel_event(body).unwrap(),
                expected_event.as_bytes(),
                "{name} canonical event bytes"
            );
            assert_eq!(
                canonical(body, "kernel", previous).unwrap(),
                vector["canonical_json"].as_str().unwrap().as_bytes(),
                "{name} canonical bytes"
            );
            assert_eq!(head(body, "kernel", previous).unwrap(), expected, "{name}");
            let proof = &vector["proof"];
            let public = URL_SAFE_NO_PAD
                .decode(vector["public_key"].as_str().unwrap())
                .unwrap();
            let public = VerifyingKey::from_bytes(public.as_slice().try_into().unwrap()).unwrap();
            let message = format!(
                "nex-evidence-v1:{}:{}:{}:{}",
                proof["sequence"].as_u64().unwrap(),
                expected,
                proof["event_id"].as_str().unwrap(),
                proof["producer"].as_str().unwrap()
            );
            let signature = URL_SAFE_NO_PAD
                .decode(proof["signature"].as_str().unwrap())
                .unwrap();
            public
                .verify(
                    message.as_bytes(),
                    &Signature::from_slice(&signature).unwrap(),
                )
                .unwrap();
            assert_ne!(
                head(body, "kernel", "changed-link").unwrap(),
                expected,
                "{name} linkage"
            );
        }
    }

    #[test]
    fn malformed_oversized_or_unsupported_event_input_is_rejected() {
        assert!(canonical_kernel_event(b"not JSON").is_err());
        assert!(canonical_kernel_event(&vec![b' '; MAX_EVENT_BYTES + 1]).is_err());
        assert!(head(b"not JSON", "kernel", "").is_err());
        assert!(head(&vec![b' '; MAX_EVENT_BYTES + 1], "kernel", "").is_err());
        assert!(head(b"{}", "untrusted", "").is_err());
        assert!(head(b"{}", "kernel", "").is_err());
    }
}
