//! Account tokens (spec §2.2, §2.3).
//!
//! `lzt_` + unpadded base64url of 32 random bytes followed by their IEEE
//! CRC-32, big-endian. The token is a bearer secret: this type never prints
//! it, zeroes it on drop, and servers keep only [`TokenHash`].

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// The prefix every token starts with.
pub const PREFIX: &str = "lzt_";
/// Random bytes in a token.
pub const SECRET_LEN: usize = 32;
/// Total length of the text form: prefix + 48 base64url characters.
pub const ENCODED_LEN: usize = 52;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("token must start with `lzt_`")]
    Prefix,
    #[error("token must be 52 characters")]
    Length,
    #[error("token is not valid base64url")]
    Encoding,
    #[error("token checksum does not match; check for a typo")]
    Checksum,
    #[error("the system random number generator failed")]
    Random,
}

/// A bearer account token. Generated on the user's device only.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AccountToken([u8; SECRET_LEN]);

impl AccountToken {
    /// Generates a new token from the OS random number generator.
    pub fn generate() -> Result<Self, TokenError> {
        let mut bytes = [0u8; SECRET_LEN];
        getrandom::fill(&mut bytes).map_err(|_| TokenError::Random)?;
        Ok(Self(bytes))
    }

    /// Builds a token from known bytes. For tests and test vectors.
    pub fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self(bytes)
    }

    /// Parses the text form, checking prefix, length, and checksum.
    pub fn parse(text: &str) -> Result<Self, TokenError> {
        let body = text.strip_prefix(PREFIX).ok_or(TokenError::Prefix)?;
        if text.len() != ENCODED_LEN {
            return Err(TokenError::Length);
        }
        let raw = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(body)
                .map_err(|_| TokenError::Encoding)?,
        );
        if raw.len() != SECRET_LEN + 4 {
            return Err(TokenError::Length);
        }
        let (secret, crc) = raw.split_at(SECRET_LEN);
        if crc32fast::hash(secret).to_be_bytes() != crc {
            return Err(TokenError::Checksum);
        }
        let mut bytes = [0u8; SECRET_LEN];
        bytes.copy_from_slice(secret);
        Ok(Self(bytes))
    }

    /// The text form. Returned in a zeroizing wrapper; never log it.
    pub fn encode(&self) -> Zeroizing<String> {
        let mut raw = Zeroizing::new([0u8; SECRET_LEN + 4]);
        raw[..SECRET_LEN].copy_from_slice(&self.0);
        raw[SECRET_LEN..].copy_from_slice(&crc32fast::hash(&self.0).to_be_bytes());
        let mut out = String::with_capacity(ENCODED_LEN);
        out.push_str(PREFIX);
        URL_SAFE_NO_PAD.encode_string(raw.as_slice(), &mut out);
        Zeroizing::new(out)
    }

    /// `SHA-256` of the text form: the only thing a server stores.
    pub fn hash(&self) -> TokenHash {
        TokenHash(Sha256::digest(self.encode().as_bytes()).into())
    }
}

impl std::fmt::Debug for AccountToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountToken(<redacted>)")
    }
}

/// `SHA-256(token)`. Servers store and compare this, in constant time, and
/// never log it either.
#[derive(Clone, Copy)]
pub struct TokenHash(pub [u8; 32]);

impl TokenHash {
    /// Hashes the text form of a token as received in an `Authorization`
    /// header, without parsing it.
    pub fn of_text(token_text: &str) -> Self {
        Self(Sha256::digest(token_text.as_bytes()).into())
    }

    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }

    /// Lowercase hex, as sent in `new_token_hash` (spec §4.6).
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Parses 64 hex digits (either case).
    pub fn from_hex(hex: &str) -> Option<Self> {
        if hex.len() != 64 || !hex.is_ascii() {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
        }
        Some(Self(out))
    }
}

impl std::fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TokenHash(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_has_fixed_length() {
        let t = AccountToken::generate().unwrap();
        let text = t.encode();
        assert_eq!(text.len(), ENCODED_LEN);
        assert!(text.starts_with(PREFIX));
        let back = AccountToken::parse(&text).unwrap();
        assert!(back.hash().ct_eq(&t.hash()));
    }

    #[test]
    fn rejects_typos() {
        let text = AccountToken::from_bytes([7; 32]).encode();
        let mut chars: Vec<char> = text.chars().collect();
        chars[10] = if chars[10] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert_eq!(
            AccountToken::parse(&typo).unwrap_err(),
            TokenError::Checksum
        );
        assert_eq!(
            AccountToken::parse("lzt_short").unwrap_err(),
            TokenError::Length
        );
        assert_eq!(
            AccountToken::parse(&text[4..]).unwrap_err(),
            TokenError::Prefix
        );
    }

    /// Invariant 6: tokens and their hashes never appear in debug output.
    #[test]
    fn debug_output_is_redacted() {
        let t = AccountToken::from_bytes([0xAB; 32]);
        let text = t.encode();
        let dbg = format!("{t:?} {:?}", t.hash());
        assert!(!dbg.contains(&text[4..12]));
        assert!(!dbg.to_lowercase().contains("abab"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn hash_hex_round_trips() {
        let h = AccountToken::from_bytes([5; 32]).hash();
        let back = TokenHash::from_hex(&h.to_hex()).unwrap();
        assert!(back.ct_eq(&h));
        assert!(TokenHash::from_hex(&h.to_hex().to_uppercase()).is_some());
        assert!(TokenHash::from_hex("zz").is_none());
        assert!(TokenHash::from_hex(&"g".repeat(64)).is_none());
        assert!(TokenHash::from_hex(&"é".repeat(32)).is_none());
    }

    #[test]
    fn hash_of_text_matches_hash_of_token() {
        let t = AccountToken::from_bytes([1; 32]);
        assert!(TokenHash::of_text(&t.encode()).ct_eq(&t.hash()));
    }
}
