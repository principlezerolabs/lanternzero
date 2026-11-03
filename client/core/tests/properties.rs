//! Property tests: bytes from a push service or a relay are untrusted, so
//! the client core must refuse anything malformed without panicking.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use lz_client::{KeyConfig, PushReceiver};
use proptest::prelude::*;

/// Noise, and noise shaped like an RFC 8188 header (salt, record size,
/// key id length 65, then a key and ciphertext).
fn push_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..300),
        (
            proptest::collection::vec(any::<u8>(), 20..=20),
            proptest::collection::vec(any::<u8>(), 65..400),
        )
            .prop_map(|(head, mut tail)| {
                let mut m = head;
                m.push(65);
                tail[0] = 0x04; // uncompressed point tag
                m.append(&mut tail);
                m
            }),
    ]
}

proptest! {
    #[test]
    fn push_decryption_never_panics(message in push_bytes()) {
        let receiver = PushReceiver::from_bytes(&[7; 32], &[9; 16]).unwrap();
        prop_assert!(receiver.decrypt(&message).is_err());
        prop_assert!(receiver.open_ping(&message).is_err());
        prop_assert!(receiver.open_ping_b64(&URL_SAFE_NO_PAD.encode(&message)).is_err());
    }

    #[test]
    fn ping_text_parsing_never_panics(text in any::<String>()) {
        let receiver = PushReceiver::from_bytes(&[7; 32], &[9; 16]).unwrap();
        prop_assert!(receiver.open_ping_b64(&text).is_err());
    }

    #[test]
    fn key_config_parsing_never_panics(encoded in proptest::collection::vec(any::<u8>(), 0..200)) {
        let _ = KeyConfig::from_cache(&encoded);
        let _ = KeyConfig::from_two_sources(&encoded, &encoded);
    }
}
