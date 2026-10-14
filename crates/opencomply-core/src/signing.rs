//! Rule pack integrity: SHA-256 checksum of the exact pack bytes plus an optional detached Ed25519 signature.
//! Signature file format (`<pack>.sig`, text, ≤ 1 KiB):
//!   key-id: <id>
//!   signature: <128 hex chars = 64-byte raw Ed25519 signature over the pack file bytes>
//! Compatible with `openssl pkeyutl -sign -rawin` output (hex-encoded). Policy (enforced by the registry):
//! packs whose id starts with `opencomply-` must carry a valid signature from an official key.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;

/// Pack ids reserved for official packs; these must verify against `OFFICIAL_KEYS`.
pub const OFFICIAL_PREFIX: &str = "opencomply-";
pub const MAX_SIGNATURE_FILE_BYTES: usize = 1024;

/// Official verification keys `(key id, 64 hex chars)`. The matching private key is kept offline by the
/// maintainer; rotate by adding the new key here first, then removing the old one in a later release.
pub const OFFICIAL_KEYS: &[(&str, &str)] = &[(
    "opencomply-2026",
    "be0b0521956c92fdb993ecab30605945d509e2cb848d725ec9b0b674d77928d6",
)];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    Malformed(String),
    UnknownKey(String),
    BadSignature { key_id: String },
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureError::Malformed(why) => write!(f, "malformed signature: {why}"),
            SignatureError::UnknownKey(id) => write!(f, "signature uses untrusted key \"{id}\""),
            SignatureError::BadSignature { key_id } => {
                write!(
                    f,
                    "signature by \"{key_id}\" does not match the pack (modified or corrupted)"
                )
            }
        }
    }
}

impl std::error::Error for SignatureError {}

#[derive(Debug, Clone)]
pub struct TrustedKey {
    pub id: String,
    key: VerifyingKey,
}

impl TrustedKey {
    pub fn from_hex(id: &str, public_key_hex: &str) -> Result<Self, SignatureError> {
        let bytes: [u8; 32] = decode_hex(public_key_hex)?
            .try_into()
            .map_err(|_| SignatureError::Malformed("public key must be 32 bytes".into()))?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| SignatureError::Malformed("invalid Ed25519 public key".into()))?;
        Ok(Self {
            id: id.to_string(),
            key,
        })
    }

    /// The built-in official keys (empty until the first signed release).
    pub fn official() -> Vec<TrustedKey> {
        OFFICIAL_KEYS
            .iter()
            .filter_map(|(id, hex)| TrustedKey::from_hex(id, hex).ok())
            .collect()
    }
}

/// How a loaded pack was authenticated; recorded in the report for traceability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackTrust {
    Verified { key_id: String },
    Unsigned,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            s.push(char::from(HEX[usize::from(b >> 4)]));
            s.push(char::from(HEX[usize::from(b & 0x0f)]));
            s
        })
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn decode_hex(s: &str) -> Result<Vec<u8>, SignatureError> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(SignatureError::Malformed("expected hex".into()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| SignatureError::Malformed("expected hex".into()))
        })
        .collect()
}

fn parse_signature_file(text: &str) -> Result<(String, Signature), SignatureError> {
    if text.len() > MAX_SIGNATURE_FILE_BYTES {
        return Err(SignatureError::Malformed("signature file too large".into()));
    }
    let mut key_id = None;
    let mut sig_hex = None;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        match line.split_once(':') {
            Some(("key-id", v)) => key_id = Some(v.trim().to_string()),
            Some(("signature", v)) => sig_hex = Some(v.trim().to_string()),
            _ => {
                return Err(SignatureError::Malformed(format!(
                    "unexpected line: {}",
                    line.chars().take(40).collect::<String>()
                )))
            }
        }
    }
    let key_id = key_id
        .filter(|k| !k.is_empty() && k.len() <= 64)
        .ok_or_else(|| SignatureError::Malformed("missing key-id".into()))?;
    let bytes: [u8; 64] =
        decode_hex(&sig_hex.ok_or_else(|| SignatureError::Malformed("missing signature".into()))?)?
            .try_into()
            .map_err(|_| SignatureError::Malformed("signature must be 64 bytes".into()))?;
    Ok((key_id, Signature::from_bytes(&bytes)))
}

/// Verifies `pack_bytes` against an optional detached signature. No signature → `Unsigned` (policy decides).
pub fn verify_pack(
    pack_bytes: &[u8],
    signature_file: Option<&str>,
    trusted: &[TrustedKey],
) -> Result<PackTrust, SignatureError> {
    let Some(text) = signature_file else {
        return Ok(PackTrust::Unsigned);
    };
    let (key_id, signature) = parse_signature_file(text)?;
    let key = trusted
        .iter()
        .find(|k| k.id == key_id)
        .ok_or_else(|| SignatureError::UnknownKey(key_id.clone()))?;
    key.key
        .verify(pack_bytes, &signature)
        .map_err(|_| SignatureError::BadSignature {
            key_id: key_id.clone(),
        })?;
    Ok(PackTrust::Verified { key_id })
}

#[cfg(test)]
pub(crate) mod test_keys {
    use ed25519_dalek::{Signer, SigningKey};

    use super::{sha256_hex, TrustedKey, HEX};

    pub fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn hex(bytes: &[u8]) -> String {
        bytes
            .iter()
            .flat_map(|b| [HEX[usize::from(b >> 4)], HEX[usize::from(b & 0x0f)]])
            .map(char::from)
            .collect()
    }

    pub fn trusted(id: &str, seed: u8) -> TrustedKey {
        TrustedKey::from_hex(id, &hex(signing_key(seed).verifying_key().as_bytes())).unwrap()
    }

    pub fn sign(id: &str, seed: u8, bytes: &[u8]) -> String {
        let sig = signing_key(seed).sign(bytes);
        format!("key-id: {id}\nsignature: {}\n", hex(&sig.to_bytes()))
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::test_keys::{sign, trusted};
    use super::*;

    const PACK: &[u8] = b"[pack]\nid = \"opencomply-headers\"\n";

    #[test]
    fn valid_signature_verifies() {
        let keys = [trusted("official-2026", 7)];
        let sig = sign("official-2026", 7, PACK);
        assert_eq!(
            verify_pack(PACK, Some(&sig), &keys),
            Ok(PackTrust::Verified {
                key_id: "official-2026".into()
            })
        );
        assert_eq!(verify_pack(PACK, None, &keys), Ok(PackTrust::Unsigned));
    }

    #[test]
    fn tampering_wrong_key_and_garbage_are_rejected() {
        let keys = [trusted("official-2026", 7)];
        let sig = sign("official-2026", 7, PACK);
        let mut tampered = PACK.to_vec();
        tampered.push(b' ');
        assert!(matches!(
            verify_pack(&tampered, Some(&sig), &keys),
            Err(SignatureError::BadSignature { .. })
        ));
        let forged = sign("official-2026", 9, PACK);
        assert!(matches!(
            verify_pack(PACK, Some(&forged), &keys),
            Err(SignatureError::BadSignature { .. })
        ));
        let unknown = sign("someone", 9, PACK);
        assert_eq!(
            verify_pack(PACK, Some(&unknown), &keys),
            Err(SignatureError::UnknownKey("someone".into()))
        );
        for junk in [
            "",
            "key-id: x",
            "key-id: x\nsignature: zz",
            "evil: 1",
            &"a".repeat(2000),
        ] {
            assert!(
                matches!(
                    verify_pack(PACK, Some(junk), &keys),
                    Err(SignatureError::Malformed(_))
                ),
                "{junk:.20}"
            );
        }
    }

    #[test]
    fn every_official_key_is_a_valid_ed25519_key() {
        let keys = TrustedKey::official();
        assert_eq!(
            keys.len(),
            OFFICIAL_KEYS.len(),
            "an official key failed to parse"
        );
        assert_eq!(keys[0].id, "opencomply-2026");
    }

    #[test]
    fn official_key_rejects_packs_not_signed_by_it() {
        let keys = TrustedKey::official();
        let forged = sign("opencomply-2026", 9, PACK);
        assert!(matches!(
            verify_pack(PACK, Some(&forged), &keys),
            Err(SignatureError::BadSignature { .. })
        ));
    }
}
