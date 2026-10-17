//! The official headers pack against the official key, as the scanner loads it. Signed build: the embedded signature
//! verifies, and any change to the pack bytes (one byte changed, appended or removed) or to the signature is rejected.
//! Unsigned development build: the registry refuses the pack whenever unsigned packs are not allowed.

#![allow(clippy::unwrap_used)]

use opencomply_core::rules::{OFFICIAL_HEADERS_PACK, OFFICIAL_HEADERS_SIG};
use opencomply_core::signing::{verify_pack, PackTrust, SignatureError, TrustedKey};
use opencomply_core::RuleRegistry;

fn tampered_packs() -> Vec<(&'static str, Vec<u8>)> {
    let pack = OFFICIAL_HEADERS_PACK.as_bytes();
    let mut one_byte = pack.to_vec();
    let at = OFFICIAL_HEADERS_PACK.find("weight = 15").unwrap() + "weight = 1".len();
    one_byte[at] = b'6';
    let mut appended = pack.to_vec();
    appended.push(b'\n');
    vec![
        ("one byte changed", one_byte),
        ("one byte appended", appended),
        ("last byte removed", pack[..pack.len() - 1].to_vec()),
    ]
}

#[test]
fn official_signature_verifies_and_rejects_any_change() {
    let keys = TrustedKey::official();
    let Some(sig) = OFFICIAL_HEADERS_SIG else {
        // Development build: an official pack without a signature must never load.
        let err = RuleRegistry::new()
            .add_file(
                "opencomply-headers.toml",
                OFFICIAL_HEADERS_PACK.as_bytes(),
                None,
                &keys,
                false,
            )
            .unwrap_err();
        assert!(err.to_string().contains("must be signed"), "{err}");
        return;
    };
    assert_eq!(
        verify_pack(OFFICIAL_HEADERS_PACK.as_bytes(), Some(sig), &keys),
        Ok(PackTrust::Verified {
            key_id: "opencomply-2026".into()
        })
    );
    for (what, bytes) in tampered_packs() {
        assert_eq!(
            verify_pack(&bytes, Some(sig), &keys),
            Err(SignatureError::BadSignature {
                key_id: "opencomply-2026".into()
            }),
            "{what}"
        );
        let mut reg = RuleRegistry::new();
        assert!(
            reg.add_file("opencomply-headers.toml", &bytes, Some(sig), &keys, false)
                .is_err(),
            "{what}: registry loaded a modified official pack"
        );
    }
    // A changed signature is rejected as well (last hex digit flipped).
    let mut bad = sig.trim_end().to_string();
    let last = bad.pop().unwrap();
    bad.push(if last == '0' { '1' } else { '0' });
    assert!(verify_pack(OFFICIAL_HEADERS_PACK.as_bytes(), Some(&bad), &keys).is_err());
}
