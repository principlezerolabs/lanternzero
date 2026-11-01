//! The device's side of Web Push (RFC 8291; spec §4.1, §5).
//!
//! The wallet registers [`PushReceiver::push_keys`] with the server. Pings
//! arrive through the vendor's gateway and Apple or Google, encrypted to
//! this key pair; the reference gateway puts the ciphertext, base64url, in
//! the `lz` field of the platform payload. [`PushReceiver::open_ping`]
//! decrypts one and checks its fixed size.
//!
//! The app keeps [`PushReceiver::secret_bytes`] in the platform keychain,
//! shared with its notification extension.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use lz_proto::api::{Ping, PushKeys};
use lz_proto::padding::PING_SIZE;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{PublicKey, SecretKey};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Salt, record size, key id length, and a 65-byte key id.
const HEADER_LEN: usize = 16 + 4 + 1 + 65;
const TAG_LEN: usize = 16;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PushError {
    #[error("no randomness available")]
    Random,
    #[error("invalid key")]
    Key,
    /// Altered, truncated, for another device, or not a Lantern Zero ping.
    #[error("cannot decrypt this push")]
    Decrypt,
    /// Decrypted, but not a fixed-size v0 ping.
    #[error("not a valid ping")]
    Ping,
}

/// The device's RFC 8291 receiver key pair and auth secret.
pub struct PushReceiver {
    secret: SecretKey,
    auth: Zeroizing<[u8; 16]>,
}

impl std::fmt::Debug for PushReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PushReceiver(<redacted>)")
    }
}

fn uncompressed(pk: &PublicKey) -> [u8; 65] {
    let mut out = [0u8; 65];
    out.copy_from_slice(pk.to_sec1_point(false).as_bytes());
    out
}

impl PushReceiver {
    /// A fresh key pair and auth secret.
    pub fn generate() -> Result<Self, PushError> {
        let mut auth = Zeroizing::new([0u8; 16]);
        getrandom::fill(&mut auth[..]).map_err(|_| PushError::Random)?;
        loop {
            let mut raw = Zeroizing::new([0u8; 32]);
            getrandom::fill(&mut raw[..]).map_err(|_| PushError::Random)?;
            if let Ok(secret) = SecretKey::from_slice(&raw[..]) {
                return Ok(Self { secret, auth });
            }
        }
    }

    /// Restores a receiver from [`secret_bytes`](Self::secret_bytes) and
    /// [`auth_bytes`](Self::auth_bytes).
    pub fn from_bytes(secret: &[u8; 32], auth: &[u8; 16]) -> Result<Self, PushError> {
        Ok(Self {
            secret: SecretKey::from_slice(secret).map_err(|_| PushError::Key)?,
            auth: Zeroizing::new(*auth),
        })
    }

    /// The private key, for the app's keychain.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&self.secret.to_bytes());
        out
    }

    /// The auth secret, for the app's keychain.
    pub fn auth_bytes(&self) -> Zeroizing<[u8; 16]> {
        self.auth.clone()
    }

    /// The `keys` of a device registration (spec §4.1).
    pub fn push_keys(&self) -> PushKeys {
        PushKeys {
            p256dh: URL_SAFE_NO_PAD.encode(uncompressed(&self.secret.public_key())),
            auth: URL_SAFE_NO_PAD.encode(&self.auth[..]),
        }
    }

    /// Decrypts a single-record `aes128gcm` message (RFC 8291, RFC 8188).
    pub fn decrypt(&self, message: &[u8]) -> Result<Zeroizing<Vec<u8>>, PushError> {
        if message.len() < HEADER_LEN + TAG_LEN || message[20] != 65 {
            return Err(PushError::Decrypt);
        }
        let salt = &message[..16];
        let as_public_bytes = &message[21..HEADER_LEN];
        let as_public =
            PublicKey::from_sec1_bytes(as_public_bytes).map_err(|_| PushError::Decrypt)?;
        let ua_public = uncompressed(&self.secret.public_key());
        let shared =
            p256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), as_public.as_affine());

        // RFC 8291 §3.4.
        let mut key_info = Vec::with_capacity(14 + 130);
        key_info.extend_from_slice(b"WebPush: info\0");
        key_info.extend_from_slice(&ua_public);
        key_info.extend_from_slice(as_public_bytes);
        let mut ikm = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(&self.auth[..]), shared.raw_secret_bytes())
            .expand(&key_info, &mut ikm[..])
            .map_err(|_| PushError::Decrypt)?;
        let prk = Hkdf::<Sha256>::new(Some(salt), &ikm[..]);
        let mut cek = Zeroizing::new([0u8; 16]);
        prk.expand(b"Content-Encoding: aes128gcm\0", &mut cek[..])
            .map_err(|_| PushError::Decrypt)?;
        let mut nonce = [0u8; 12];
        prk.expand(b"Content-Encoding: nonce\0", &mut nonce)
            .map_err(|_| PushError::Decrypt)?;

        let cipher = Aes128Gcm::new_from_slice(&cek[..]).map_err(|_| PushError::Decrypt)?;
        let mut record = Zeroizing::new(
            cipher
                .decrypt(&Nonce::from(nonce), &message[HEADER_LEN..])
                .map_err(|_| PushError::Decrypt)?,
        );
        // Padding runs back to the delimiter, 0x02 for the last record.
        while record.last() == Some(&0) {
            record.pop();
        }
        if record.pop() != Some(0x02) {
            return Err(PushError::Decrypt);
        }
        Ok(record)
    }

    /// Decrypts a ping and parses it. A ping that isn't exactly the fixed
    /// size is refused (spec §5.1, invariant 4).
    pub fn open_ping(&self, message: &[u8]) -> Result<Ping, PushError> {
        let plain = self.decrypt(message)?;
        if plain.len() != PING_SIZE {
            return Err(PushError::Ping);
        }
        let ping: Ping = serde_json::from_slice(&plain).map_err(|_| PushError::Ping)?;
        if ping.v != 0 {
            return Err(PushError::Ping);
        }
        Ok(ping)
    }

    /// [`open_ping`](Self::open_ping) for the base64url `lz` field of a
    /// platform payload.
    pub fn open_ping_b64(&self, lz: &str) -> Result<Ping, PushError> {
        let raw = URL_SAFE_NO_PAD
            .decode(lz.trim())
            .map_err(|_| PushError::Decrypt)?;
        self.open_ping(&raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(s: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(s).unwrap()
    }

    /// RFC 8291 §5 and Appendix A.
    fn rfc_receiver() -> PushReceiver {
        let secret: [u8; 32] = b64("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94")
            .try_into()
            .unwrap();
        let auth: [u8; 16] = b64("BTBZMqHH6r4Tts7J_aSIgg").try_into().unwrap();
        PushReceiver::from_bytes(&secret, &auth).unwrap()
    }

    const RFC_MESSAGE: &str = concat!(
        "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml",
        "mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT",
        "pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN",
    );

    #[test]
    fn decrypts_the_rfc_8291_example() {
        let r = rfc_receiver();
        assert_eq!(
            r.push_keys().p256dh,
            "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
        );
        let plain = r.decrypt(&b64(RFC_MESSAGE)).unwrap();
        assert_eq!(&plain[..], b"When I grow up, I want to be a watermelon");
        // Decrypts, but it isn't a fixed-size ping.
        assert_eq!(r.open_ping_b64(RFC_MESSAGE), Err(PushError::Ping));
    }

    #[test]
    fn refuses_altered_or_foreign_messages() {
        let r = rfc_receiver();
        let mut m = b64(RFC_MESSAGE);
        let last = m.len() - 1;
        m[last] ^= 1;
        assert_eq!(r.decrypt(&m), Err(PushError::Decrypt));
        assert_eq!(r.decrypt(&m[..50]), Err(PushError::Decrypt));
        let other = PushReceiver::generate().unwrap();
        assert_eq!(other.decrypt(&b64(RFC_MESSAGE)), Err(PushError::Decrypt));
        assert_eq!(r.open_ping_b64("!!"), Err(PushError::Decrypt));
    }

    #[test]
    fn round_trips_through_storage_and_redacts() {
        let r = PushReceiver::generate().unwrap();
        let back = PushReceiver::from_bytes(&r.secret_bytes(), &r.auth_bytes()).unwrap();
        assert_eq!(back.push_keys(), r.push_keys());
        assert_eq!(
            URL_SAFE_NO_PAD.decode(r.push_keys().p256dh).unwrap().len(),
            65
        );
        assert_eq!(format!("{r:?}"), "PushReceiver(<redacted>)");
    }
}
