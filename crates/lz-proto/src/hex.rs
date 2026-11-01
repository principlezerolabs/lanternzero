//! Lowercase hex, as the protocol and the issuer interface write ids and
//! hashes.

/// Lowercase hex of `bytes`.
pub fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// Parses exactly `2 * N` hex digits (either case).
pub fn decode<const N: usize>(s: &str) -> Option<[u8; N]> {
    // Digits only: `from_str_radix` alone would also take a leading `+`.
    if s.len() != 2 * N || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_rejects_bad_input() {
        let bytes = [0x00, 0x0f, 0xa5, 0xff];
        assert_eq!(encode(&bytes), "000fa5ff");
        assert_eq!(decode::<4>("000fa5ff"), Some(bytes));
        assert_eq!(decode::<4>("000FA5FF"), Some(bytes));
        assert_eq!(decode::<4>("000fa5f"), None);
        assert_eq!(decode::<4>("000fa5fg"), None);
        assert_eq!(decode::<2>("+1ab"), None);
        assert_eq!(decode::<2>("é1a"), None);
    }
}
