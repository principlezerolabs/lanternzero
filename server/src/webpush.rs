//! Web Push message encryption (RFC 8291) and VAPID (RFC 8292).
//!
//! Built from RustCrypto primitives (P-256 ECDH and ECDSA, HKDF-SHA256,
//! AES-128-GCM) rather than a Web Push crate: the available ones pull in
//! `crypto-bigint` 0.5, which has timing leaks (RUSTSEC-2026-0387). The
//! encryption is checked against the RFC 8291 Appendix A test vector.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{PublicKey, SecretKey};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Record size written in the header. One record holds the whole message.
const RECORD_SIZE: u32 = 4096;
/// AES-GCM tag length.
const TAG_LEN: usize = 16;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WebPushError {
    #[error("message too large for one record")]
    TooLarge,
    #[error("invalid key")]
    Key,
    #[error("malformed or unauthentic message")]
    Decrypt,
}

/// Uncompressed SEC1 encoding (65 bytes) of a public key.
pub fn uncompressed(pk: &PublicKey) -> [u8; 65] {
    let point = pk.to_sec1_point(false);
    point
        .as_bytes()
        .try_into()
        .expect("uncompressed P-256 point is 65 bytes")
}

fn random_secret_key() -> SecretKey {
    loop {
        let mut raw = Zeroizing::new([0u8; 32]);
        rand::fill(&mut raw[..]);
        if let Ok(k) = SecretKey::from_slice(&raw[..]) {
            return k;
        }
    }
}

/// Derives the content-encryption key and nonce (RFC 8291 §3.4).
fn derive(
    auth: &[u8; 16],
    ecdh_secret: &[u8],
    ua_public: &[u8; 65],
    as_public: &[u8; 65],
    salt: &[u8; 16],
) -> (Zeroizing<[u8; 16]>, [u8; 12]) {
    let prk_key = Hkdf::<Sha256>::new(Some(auth), ecdh_secret);
    let mut key_info = Vec::with_capacity(14 + 130);
    key_info.extend_from_slice(b"WebPush: info\0");
    key_info.extend_from_slice(ua_public);
    key_info.extend_from_slice(as_public);
    let mut ikm = Zeroizing::new([0u8; 32]);
    prk_key
        .expand(&key_info, &mut ikm[..])
        .expect("32 bytes is a valid HKDF length");

    let prk = Hkdf::<Sha256>::new(Some(salt), &ikm[..]);
    let mut cek = Zeroizing::new([0u8; 16]);
    prk.expand(b"Content-Encoding: aes128gcm\0", &mut cek[..])
        .expect("16 bytes is a valid HKDF length");
    let mut nonce = [0u8; 12];
    prk.expand(b"Content-Encoding: nonce\0", &mut nonce)
        .expect("12 bytes is a valid HKDF length");
    (cek, nonce)
}

/// Encrypts `plaintext` to a user agent (RFC 8291), with a fresh ephemeral
/// key and salt.
pub fn encrypt(
    plaintext: &[u8],
    ua_public: &PublicKey,
    auth: &[u8; 16],
) -> Result<Vec<u8>, WebPushError> {
    let mut salt = [0u8; 16];
    rand::fill(&mut salt);
    encrypt_with(plaintext, ua_public, auth, &random_secret_key(), &salt)
}

fn encrypt_with(
    plaintext: &[u8],
    ua_public: &PublicKey,
    auth: &[u8; 16],
    as_secret: &SecretKey,
    salt: &[u8; 16],
) -> Result<Vec<u8>, WebPushError> {
    if plaintext.len() + 1 + TAG_LEN > RECORD_SIZE as usize {
        return Err(WebPushError::TooLarge);
    }
    let as_public = uncompressed(&as_secret.public_key());
    let ua_bytes = uncompressed(ua_public);
    let shared = p256::ecdh::diffie_hellman(as_secret.to_nonzero_scalar(), ua_public.as_affine());
    let (cek, nonce) = derive(auth, shared.raw_secret_bytes(), &ua_bytes, &as_public, salt);

    // One record: the plaintext, then the last-record delimiter (0x02).
    let mut record = Zeroizing::new(Vec::with_capacity(plaintext.len() + 1));
    record.extend_from_slice(plaintext);
    record.push(0x02);
    let cipher = Aes128Gcm::new_from_slice(&cek[..]).expect("16-byte key");
    let ciphertext = cipher
        .encrypt(&Nonce::from(nonce), record.as_slice())
        .map_err(|_| WebPushError::TooLarge)?;

    // Header: salt (16) || rs (4) || idlen (1) || keyid (65).
    let mut out = Vec::with_capacity(86 + ciphertext.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    out.push(65);
    out.extend_from_slice(&as_public);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts a single-record RFC 8291 message. Wallets do this on the
/// device; the server uses it only in tests.
pub fn decrypt(
    message: &[u8],
    ua_secret: &SecretKey,
    auth: &[u8; 16],
) -> Result<Vec<u8>, WebPushError> {
    if message.len() < 86 + TAG_LEN || message[20] != 65 {
        return Err(WebPushError::Decrypt);
    }
    let salt: [u8; 16] = message[..16].try_into().expect("16 bytes");
    let as_public_bytes: [u8; 65] = message[21..86].try_into().expect("65 bytes");
    let as_public = PublicKey::from_sec1_bytes(&as_public_bytes).map_err(|_| WebPushError::Key)?;
    let ua_bytes = uncompressed(&ua_secret.public_key());
    let shared = p256::ecdh::diffie_hellman(ua_secret.to_nonzero_scalar(), as_public.as_affine());
    let (cek, nonce) = derive(
        auth,
        shared.raw_secret_bytes(),
        &ua_bytes,
        &as_public_bytes,
        &salt,
    );
    let cipher = Aes128Gcm::new_from_slice(&cek[..]).expect("16-byte key");
    let mut record = cipher
        .decrypt(&Nonce::from(nonce), &message[86..])
        .map_err(|_| WebPushError::Decrypt)?;
    // Strip padding back to the delimiter, which must be 0x02 (last record).
    while record.last() == Some(&0) {
        record.pop();
    }
    if record.pop() != Some(0x02) {
        return Err(WebPushError::Decrypt);
    }
    Ok(record)
}

/// A VAPID signing key (RFC 8292).
pub struct Vapid {
    key: SigningKey,
    /// Base64url uncompressed public key, the `k=` parameter.
    pub public_b64: String,
}

impl std::fmt::Debug for Vapid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Vapid(<redacted>)")
    }
}

impl Vapid {
    pub fn from_secret(raw: &[u8; 32]) -> Result<Self, WebPushError> {
        let key = SigningKey::from_slice(raw).map_err(|_| WebPushError::Key)?;
        let public = PublicKey::from(key.verifying_key());
        Ok(Self {
            key,
            public_b64: URL_SAFE_NO_PAD.encode(uncompressed(&public)),
        })
    }

    /// The `Authorization` header value for a push to `endpoint`, valid
    /// until `expires_unix` (at most 24 h ahead, per RFC 8292 §2).
    pub fn authorization(
        &self,
        endpoint: &http::Uri,
        expires_unix: u64,
        contact: &str,
    ) -> Option<String> {
        let scheme = endpoint.scheme_str()?;
        let host = endpoint.host()?;
        // The audience is the origin, including any non-default port.
        let aud = match endpoint.port_u16() {
            Some(p) => format!("{scheme}://{host}:{p}"),
            None => format!("{scheme}://{host}"),
        };
        let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = serde_json::json!({ "aud": aud, "exp": expires_unix, "sub": contact });
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).ok()?);
        let signing_input = format!("{header}.{claims}");
        let sig: Signature = self.key.sign(signing_input.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        Some(format!(
            "vapid t={signing_input}.{sig}, k={}",
            self.public_b64
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier;

    fn b64(s: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(s.replace(' ', "")).unwrap()
    }

    /// RFC 8291 Appendix A, with its fixed keys and salt.
    #[test]
    fn matches_rfc8291_test_vector() {
        let plaintext = b64("V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24");
        let as_secret =
            SecretKey::from_slice(&b64("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")).unwrap();
        let ua_secret =
            SecretKey::from_slice(&b64("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94")).unwrap();
        let ua_public = PublicKey::from_sec1_bytes(&b64(
            "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
        ))
        .unwrap();
        assert_eq!(ua_public, ua_secret.public_key());
        let salt: [u8; 16] = b64("DGv6ra1nlYgDCS1FRnbzlw").try_into().unwrap();
        let auth: [u8; 16] = b64("BTBZMqHH6r4Tts7J_aSIgg").try_into().unwrap();

        let out = encrypt_with(&plaintext, &ua_public, &auth, &as_secret, &salt).unwrap();
        let header = b64(
            "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z 9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml \
             mlMoZIIgDll6e3vCYLocInmYWAmS6Tlz AC8wEqKK6PBru3jl7A8",
        );
        let ciphertext =
            b64("8pfeW0KbunFT06SuDKoJH9Ql87S1QUrd irN6GcG7sFz1y1sqLgVi1VhjVkHsUoEs bI_0LpXMuGvnzQ");
        assert_eq!(&out[..86], &header[..], "header");
        assert_eq!(&out[86..], &ciphertext[..], "ciphertext");

        assert_eq!(decrypt(&out, &ua_secret, &auth).unwrap(), plaintext);
    }

    #[test]
    fn round_trips_and_rejects_tampering() {
        let ua = random_secret_key();
        let auth = [7u8; 16];
        let mut msg = encrypt(b"ping", &ua.public_key(), &auth).unwrap();
        assert_eq!(decrypt(&msg, &ua, &auth).unwrap(), b"ping");
        assert_eq!(decrypt(&msg, &ua, &[8u8; 16]), Err(WebPushError::Decrypt));
        let last = msg.len() - 1;
        msg[last] ^= 1;
        assert_eq!(decrypt(&msg, &ua, &auth), Err(WebPushError::Decrypt));
        assert_eq!(
            encrypt(&[0u8; 4096], &ua.public_key(), &auth),
            Err(WebPushError::TooLarge)
        );
    }

    #[test]
    fn vapid_header_is_a_valid_es256_jwt_for_the_origin() {
        let vapid = Vapid::from_secret(&[0x42; 32]).unwrap();
        let uri: http::Uri = "https://push.example.app:8443/wp/abc".parse().unwrap();
        let value = vapid
            .authorization(&uri, 1_800_000_000, "mailto:ops@lz.test")
            .unwrap();
        let (t, k) = value
            .strip_prefix("vapid t=")
            .unwrap()
            .split_once(", k=")
            .unwrap();
        assert_eq!(k, vapid.public_b64);
        let (signing_input, sig) = t.rsplit_once('.').unwrap();
        let claims: serde_json::Value =
            serde_json::from_slice(&b64(signing_input.split('.').nth(1).unwrap())).unwrap();
        assert_eq!(claims["aud"], "https://push.example.app:8443");
        assert_eq!(claims["sub"], "mailto:ops@lz.test");
        let vk = VerifyingKey::from_sec1_bytes(&b64(k)).unwrap();
        let sig = Signature::from_slice(&b64(sig)).unwrap();
        vk.verify(signing_input.as_bytes(), &sig).unwrap();
        assert_eq!(format!("{vapid:?}"), "Vapid(<redacted>)");
    }
}
