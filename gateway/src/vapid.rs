//! VAPID verification (RFC 8292) and the subscription binding of spec §5.3.
//!
//! A push carries `Authorization: vapid t=<JWT>, k=<public key>`. The
//! gateway accepts it only if `k` is the key the subscription is bound to,
//! the JWT is an ES256 signature by that key, and its claims are current
//! and addressed to this gateway.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;

use crate::seal::KEY_LEN;

/// RFC 8292 §2: `exp` must be no more than 24 hours ahead.
const MAX_LIFETIME_SECS: u64 = 24 * 3600;
/// Allowed clock difference with the signing server.
const CLOCK_SKEW_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VapidError {
    /// Missing or malformed header, bad JWT, bad signature, or wrong claims.
    #[error("invalid VAPID authorization")]
    Invalid,
    /// Valid, but signed by a key other than the subscription's.
    #[error("signed by a key this subscription isn't bound to")]
    WrongKey,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
}

#[derive(Deserialize)]
struct Claims {
    aud: String,
    exp: u64,
    /// Required by RFC 8292 §2.1 in spirit (a contact); checked for presence.
    sub: Option<String>,
}

/// Checks `authorization` for a push to a subscription bound to
/// `bound_key`. `origin` is this gateway's public origin, the expected
/// `aud` (for example `https://push.example.app`).
pub fn verify(
    authorization: &str,
    bound_key: &[u8; KEY_LEN],
    origin: &str,
    now_unix: u64,
) -> Result<(), VapidError> {
    let (token, key_b64) = parse_header(authorization).ok_or(VapidError::Invalid)?;
    let key = URL_SAFE_NO_PAD
        .decode(key_b64)
        .map_err(|_| VapidError::Invalid)?;
    if key.as_slice() != bound_key {
        // Checked before the signature, so a push from another server is
        // refused without our doing its crypto.
        return Err(VapidError::WrongKey);
    }
    let verifying = VerifyingKey::from_sec1_bytes(&key).map_err(|_| VapidError::Invalid)?;

    let mut parts = token.split('.');
    let (Some(h), Some(c), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(VapidError::Invalid);
    };
    let header: Header = decode_json(h)?;
    if header.alg != "ES256" {
        return Err(VapidError::Invalid);
    }
    let sig = URL_SAFE_NO_PAD.decode(s).map_err(|_| VapidError::Invalid)?;
    let sig = Signature::from_slice(&sig).map_err(|_| VapidError::Invalid)?;
    let signing_input = &token[..h.len() + 1 + c.len()];
    verifying
        .verify(signing_input.as_bytes(), &sig)
        .map_err(|_| VapidError::Invalid)?;

    let claims: Claims = decode_json(c)?;
    if claims.aud != origin {
        return Err(VapidError::Invalid);
    }
    // `exp` comes from the network: no arithmetic on it that can overflow.
    if claims.exp.saturating_add(CLOCK_SKEW_SECS) < now_unix
        || claims.exp > now_unix.saturating_add(MAX_LIFETIME_SECS + CLOCK_SKEW_SECS)
    {
        return Err(VapidError::Invalid);
    }
    if claims.sub.as_deref().is_none_or(str::is_empty) {
        return Err(VapidError::Invalid);
    }
    Ok(())
}

/// Splits `vapid t=<jwt>, k=<key>` (parameters in either order, scheme
/// case-insensitive).
fn parse_header(value: &str) -> Option<(&str, &str)> {
    let (scheme, params) = value.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("vapid") {
        return None;
    }
    let mut t = None;
    let mut k = None;
    for part in params.split(',') {
        let (name, val) = part.trim().split_once('=')?;
        match name.trim() {
            "t" => t = Some(val.trim()),
            "k" => k = Some(val.trim()),
            _ => {}
        }
    }
    Some((t?, k?))
}

fn decode_json<T: for<'de> Deserialize<'de>>(b64: &str) -> Result<T, VapidError> {
    let raw = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|_| VapidError::Invalid)?;
    serde_json::from_slice(&raw).map_err(|_| VapidError::Invalid)
}

/// Decodes a base64url uncompressed P-256 public key, as a wallet supplies
/// it from the server's `info` (spec §4.1).
pub fn parse_server_key(b64: &str) -> Option<[u8; KEY_LEN]> {
    let raw = URL_SAFE_NO_PAD.decode(b64.trim()).ok()?;
    let key: [u8; KEY_LEN] = raw.as_slice().try_into().ok()?;
    VerifyingKey::from_sec1_bytes(&key).ok()?;
    Some(key)
}
