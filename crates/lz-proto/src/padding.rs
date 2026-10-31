//! Fixed sizes (spec §3.3, §5.1).
//!
//! Inner OHTTP messages are Binary HTTP (RFC 9292) in known-length form,
//! which allows trailing zero bytes as padding; the decoder knows where the
//! content ends. Push pings are JSON padded with spaces.

/// Every inner request is exactly this many bytes.
pub const REQUEST_SIZE: usize = 4096;
/// Every inner response (and response page) is exactly this many bytes.
pub const RESPONSE_SIZE: usize = 4096;
/// Every push ping plaintext is exactly this many bytes.
pub const PING_SIZE: usize = 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("message is {len} bytes; the limit is {limit}")]
pub struct TooLarge {
    pub len: usize,
    pub limit: usize,
}

/// Pads an encoded known-length Binary HTTP message with zero bytes to
/// exactly `size`.
pub fn pad_bhttp(mut message: Vec<u8>, size: usize) -> Result<Vec<u8>, TooLarge> {
    if message.len() > size {
        return Err(TooLarge {
            len: message.len(),
            limit: size,
        });
    }
    message.resize(size, 0);
    Ok(message)
}

/// Pads a ping's JSON plaintext with trailing spaces to exactly
/// [`PING_SIZE`]. JSON parsers ignore trailing whitespace.
pub fn pad_ping_json(json: &str) -> Result<Vec<u8>, TooLarge> {
    if json.len() > PING_SIZE {
        return Err(TooLarge {
            len: json.len(),
            limit: PING_SIZE,
        });
    }
    let mut out = Vec::with_capacity(PING_SIZE);
    out.extend_from_slice(json.as_bytes());
    out.resize(PING_SIZE, b' ');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_to_exact_size_and_rejects_oversize() {
        assert_eq!(
            pad_bhttp(vec![1, 2, 3], REQUEST_SIZE).unwrap().len(),
            REQUEST_SIZE
        );
        assert_eq!(
            pad_bhttp(vec![0; REQUEST_SIZE], REQUEST_SIZE)
                .unwrap()
                .len(),
            REQUEST_SIZE
        );
        assert_eq!(
            pad_bhttp(vec![0; REQUEST_SIZE + 1], REQUEST_SIZE).unwrap_err(),
            TooLarge {
                len: 4097,
                limit: 4096
            }
        );
    }

    #[test]
    fn padded_ping_is_still_valid_json() {
        let p = pad_ping_json(r#"{"v":0,"t":"wake","events":[]}"#).unwrap();
        assert_eq!(p.len(), PING_SIZE);
        let v: serde_json::Value = serde_json::from_slice(&p).unwrap();
        assert_eq!(v["t"], "wake");
    }
}
