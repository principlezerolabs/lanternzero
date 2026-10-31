//! Decodes the viewing keys in a lease (spec §4.2) into the prepared keys
//! that trial decryption needs.
//!
//! Invariant 1: keys live only in memory. The text forms are held in
//! [`ViewingKey`], which zeroes itself; the lowercased copy made here is
//! zeroed too. The decoded Sapling and Orchard key types come from the Zcash
//! crates and don't zero themselves on drop, so deployments must also follow
//! spec §6.2 (no swap, no core dumps).

use lz_proto::lease::{Network, ViewingKey};
use sha2::{Digest, Sha256};
use zcash_address::unified::{self, Container, Encoding};
use zcash_protocol::consensus::NetworkType;
use zeroize::Zeroizing;

/// The prepared incoming viewing keys of one lease.
pub struct ScanKeys {
    pub sapling: Vec<sapling::keys::PreparedIncomingViewingKey>,
    /// Each one decrypts both Orchard and Ironwood notes (ZIP 229, ZIP 326).
    pub orchard: Vec<orchard::keys::PreparedIncomingViewingKey>,
    /// SHA-256 over the normalized key texts, to notice a renewal with the
    /// same keys. Memory only, like the keys.
    fingerprint: [u8; 32],
}

impl std::fmt::Debug for ScanKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScanKeys(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("key {0} is not a valid unified incoming viewing key")]
    Invalid(usize),
    #[error("key {0} is for a different network")]
    WrongNetwork(usize),
    #[error("key {0} has no Sapling or Orchard item")]
    NoShieldedItem(usize),
}

impl ScanKeys {
    /// Decodes Unified Incoming Viewing Keys (ZIP 316 Revision 0 or 2, all
    /// lowercase or all uppercase). Errors name the key by position only.
    pub fn decode(keys: &[ViewingKey], network: Network) -> Result<Self, KeyError> {
        let expected = match network {
            Network::Main => NetworkType::Main,
            Network::Test => NetworkType::Test,
            Network::Regtest => NetworkType::Regtest,
        };
        let mut texts: Vec<Zeroizing<String>> = Vec::with_capacity(keys.len());
        let mut sapling = Vec::new();
        let mut orchard = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let text = Zeroizing::new(key.expose().to_ascii_lowercase());
            let (net, _revision, uivk) =
                unified::Uivk::decode(&text).map_err(|_| KeyError::Invalid(i))?;
            if net != expected {
                return Err(KeyError::WrongNetwork(i));
            }
            let mut shielded = false;
            for item in uivk.items() {
                match item {
                    unified::Ivk::Sapling(bytes) => {
                        let bytes = Zeroizing::new(bytes);
                        let ivk: sapling::zip32::IncomingViewingKey =
                            Option::from(sapling::zip32::IncomingViewingKey::from_bytes(&bytes))
                                .ok_or(KeyError::Invalid(i))?;
                        sapling.push(ivk.prepare());
                        shielded = true;
                    }
                    unified::Ivk::Orchard(bytes) => {
                        let bytes = Zeroizing::new(bytes);
                        let ivk: orchard::keys::IncomingViewingKey =
                            Option::from(orchard::keys::IncomingViewingKey::from_bytes(&bytes))
                                .ok_or(KeyError::Invalid(i))?;
                        orchard.push(orchard::keys::PreparedIncomingViewingKey::new(&ivk));
                        shielded = true;
                    }
                    // Transparent and unknown items are ignored: the scanner
                    // watches shielded pools only.
                    _ => {}
                }
            }
            if !shielded {
                return Err(KeyError::NoShieldedItem(i));
            }
            texts.push(text);
        }
        texts.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));
        let mut h = Sha256::new();
        for t in &texts {
            h.update((t.len() as u32).to_be_bytes());
            h.update(t.as_bytes());
        }
        Ok(Self {
            sapling,
            orchard,
            fingerprint: h.finalize().into(),
        })
    }

    /// Whether `other` came from the same key texts.
    pub fn same_keys(&self, other: &ScanKeys) -> bool {
        use subtle::ConstantTimeEq;
        self.fingerprint.ct_eq(&other.fingerprint).into()
    }
}
