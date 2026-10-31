//! Deterministic event ids (spec §4.4).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Shielded pools, with their one-byte codes in the event-id input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pool {
    Sapling,
    Orchard,
    Ironwood,
}

impl Pool {
    pub fn code(self) -> u8 {
        match self {
            Pool::Sapling => 0,
            Pool::Orchard => 1,
            Pool::Ironwood => 2,
        }
    }
}

/// Computes `base64url(HMAC-SHA256(server_secret, account_id || txid || pool
/// || index)[0..16])`.
///
/// `txid` is in the transaction hash's internal byte order. `index` is the
/// output's (Sapling) or action's (Orchard, Ironwood) index in its bundle.
pub fn event_id(
    server_secret: &[u8],
    account_id: &[u8; 16],
    txid: &[u8; 32],
    pool: Pool,
    index: u32,
) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(server_secret).expect("HMAC accepts any key length");
    mac.update(account_id);
    mac.update(txid);
    mac.update(&[pool.code()]);
    mac.update(&index.to_be_bytes());
    let tag = mac.finalize().into_bytes();
    URL_SAFE_NO_PAD.encode(&tag[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_stable_and_input_sensitive() {
        let s = [3u8; 32];
        let a = [1u8; 16];
        let t = [2u8; 32];
        let id = event_id(&s, &a, &t, Pool::Orchard, 0);
        assert_eq!(id.len(), 22);
        assert_eq!(id, event_id(&s, &a, &t, Pool::Orchard, 0));
        assert_ne!(id, event_id(&s, &a, &t, Pool::Ironwood, 0));
        assert_ne!(id, event_id(&s, &a, &t, Pool::Orchard, 1));
        assert_ne!(id, event_id(&[4u8; 32], &a, &t, Pool::Orchard, 0));
    }
}
