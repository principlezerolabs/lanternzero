//! Property tests: what must hold for every input, not just the examples
//! in the unit tests. Everything parsed here can come from the network or
//! from a user's paste, so "never panics" is a property too.

use std::collections::BTreeSet;

use lz_proto::hex;
use lz_proto::padding::{PING_SIZE, REQUEST_SIZE, pad_bhttp, pad_ping_json};
use lz_proto::replay::{SeqWindow, WINDOW, next_seq};
use lz_proto::token::{AccountToken, ENCODED_LEN, TokenError};
use lz_proto::url::ConnectionUrl;
use lz_proto::webhook::SigningSecret;
use proptest::prelude::*;

/// Text that looks like what the parsers expect, mutated, plus plain noise.
fn texty() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<String>(),
        "[a-zA-Z0-9_:/#.?@%-]{0,80}",
        "(lanternzero|https|LanternZero|HTTPS)://[a-z0-9.:\\[\\]/@?-]{0,40}#lzt_[A-Za-z0-9_-]{0,50}",
    ]
}

/// A host, port and path a server could be configured with.
fn server() -> impl Strategy<Value = (String, Option<u16>, String)> {
    (
        "[a-z][a-z0-9-]{0,15}(\\.[a-z][a-z0-9-]{0,15}){0,3}(\\.onion)?",
        proptest::option::of(1u16..),
        "(/[a-z0-9_-]{1,10}){0,3}",
    )
}

proptest! {
    // --- Account tokens (spec §2.2) ---

    #[test]
    fn a_token_survives_its_text_form(bytes: [u8; 32]) {
        let token = AccountToken::from_bytes(bytes);
        let text = token.encode();
        prop_assert_eq!(text.len(), ENCODED_LEN);
        let back = AccountToken::parse(&text).unwrap();
        prop_assert_eq!(&*back.encode(), &*text);
    }

    /// The checksum's promise to users: one mistyped character is caught.
    #[test]
    fn a_one_character_typo_is_always_caught(
        bytes: [u8; 32],
        at in 4..ENCODED_LEN,
        with in "[A-Za-z0-9_-]",
    ) {
        let text = AccountToken::from_bytes(bytes).encode();
        let mut typo = text.to_string();
        typo.replace_range(at..at + 1, &with);
        prop_assume!(typo != *text);
        prop_assert!(AccountToken::parse(&typo).is_err());
    }

    #[test]
    fn token_parsing_never_panics(text in texty()) {
        let _ = AccountToken::parse(&text);
    }

    #[test]
    fn only_52_character_tokens_parse(text in "lzt_[A-Za-z0-9_-]{0,60}") {
        if text.len() != ENCODED_LEN {
            prop_assert_eq!(AccountToken::parse(&text).err(), Some(TokenError::Length));
        }
    }

    // --- Connection URLs (spec §2) ---

    #[test]
    fn url_parsing_never_panics(text in texty()) {
        let _ = ConnectionUrl::parse(&text);
    }

    #[test]
    fn a_connection_url_survives_its_text_form(
        (host, port, path) in server(),
        bytes: [u8; 32],
        scheme in "(lanternzero|https|LanternZero|HTTPS)",
    ) {
        let token = AccountToken::from_bytes(bytes);
        let port_text = port.map(|p| format!(":{p}")).unwrap_or_default();
        let text = format!("{scheme}://{host}{port_text}{path}#{}", &*token.encode());
        let url = ConnectionUrl::parse(&text).unwrap();
        prop_assert_eq!(&url.host, &host);
        prop_assert_eq!(url.onion, host.ends_with(".onion"));

        let again = ConnectionUrl::parse(&url.to_url()).unwrap();
        prop_assert_eq!(&again.base_url, &url.base_url);
        prop_assert_eq!(&again.host, &url.host);
        prop_assert_eq!(again.onion, url.onion);
        prop_assert_eq!(&*again.token.encode(), &*token.encode());
    }

    /// Whatever parses comes back the same from its own text form.
    #[test]
    fn parsing_a_parsed_url_again_changes_nothing(text in texty()) {
        if let Ok(url) = ConnectionUrl::parse(&text) {
            let again = ConnectionUrl::parse(&url.to_url()).unwrap();
            prop_assert_eq!(&again.base_url, &url.base_url);
            prop_assert_eq!(&again.host, &url.host);
            prop_assert_eq!(again.onion, url.onion);
        }
    }

    /// The masked form is what apps show and may end up in screenshots.
    #[test]
    fn the_masked_url_never_shows_the_token((host, port, path) in server(), bytes: [u8; 32]) {
        let token = AccountToken::from_bytes(bytes);
        let text = token.encode();
        let port_text = port.map(|p| format!(":{p}")).unwrap_or_default();
        let url = ConnectionUrl::parse(&format!("lanternzero://{host}{port_text}{path}#{}", &*text)).unwrap();
        let masked = url.masked();
        prop_assert!(masked.ends_with(&text[text.len() - 4..]));
        // No 8 consecutive token characters before the last four.
        let body = &text[4..text.len() - 4];
        for i in 0..=body.len() - 8 {
            prop_assert!(!masked.contains(&body[i..i + 8]));
        }
    }

    // --- Hex and webhook secrets ---

    #[test]
    fn hex_round_trips(bytes: [u8; 16]) {
        let text = hex::encode(&bytes);
        prop_assert_eq!(hex::decode::<16>(&text), Some(bytes));
        prop_assert_eq!(hex::decode::<16>(&text.to_ascii_uppercase()), Some(bytes));
    }

    #[test]
    fn hex_decoding_never_panics(text in texty()) {
        let _ = hex::decode::<16>(&text);
        let _ = hex::decode::<32>(&text);
    }

    #[test]
    fn a_signing_secret_survives_its_text_form(bytes: [u8; 32]) {
        let secret = SigningSecret::from_bytes(bytes);
        let back = SigningSecret::parse(&secret.encode()).unwrap();
        prop_assert_eq!(back.as_bytes(), &bytes);
    }

    #[test]
    fn signing_secret_parsing_never_panics(text in texty()) {
        let _ = SigningSecret::parse(&text);
        let _ = SigningSecret::parse(&format!("whsec_{text}"));
    }

    // --- Padding (spec §3.3, §5.1) ---

    #[test]
    fn bhttp_padding_is_exact_or_refused(message in proptest::collection::vec(any::<u8>(), 0..REQUEST_SIZE + 64)) {
        match pad_bhttp(message.clone(), REQUEST_SIZE) {
            Ok(padded) => {
                prop_assert_eq!(padded.len(), REQUEST_SIZE);
                prop_assert_eq!(&padded[..message.len()], &message[..]);
                prop_assert!(padded[message.len()..].iter().all(|&b| b == 0));
            }
            Err(e) => {
                prop_assert!(message.len() > REQUEST_SIZE);
                prop_assert_eq!(e.len, message.len());
            }
        }
    }

    #[test]
    fn a_padded_ping_is_the_same_json(fields in proptest::collection::btree_map("[a-z]{1,8}", any::<u32>(), 0..40)) {
        let json = serde_json::to_string(&fields).unwrap();
        let padded = pad_ping_json(&json).unwrap();
        prop_assert_eq!(padded.len(), PING_SIZE);
        let back: std::collections::BTreeMap<String, u32> = serde_json::from_slice(&padded).unwrap();
        prop_assert_eq!(back, fields);
    }

    // --- Replay window (spec §3.4) ---

    /// The window against a plain model: a `seq` is accepted exactly when
    /// it was never accepted before and is above the highest accepted
    /// minus the window. Values are offsets from a random base, so they
    /// collide and cross the window edge often.
    #[test]
    fn the_replay_window_matches_its_model(
        base in prop_oneof![Just(0u64), any::<u64>().prop_map(|b| b / 2), Just(u64::MAX - 300)],
        offsets in proptest::collection::vec(0u64..300, 1..200),
    ) {
        let mut window = SeqWindow::default();
        let mut accepted = BTreeSet::new();
        for offset in offsets {
            let seq = base + offset;
            let highest = accepted.last().copied();
            let expect = !accepted.contains(&seq)
                && highest.is_none_or(|h: u64| seq > h || h - seq < WINDOW);
            prop_assert_eq!(window.accept(seq).is_ok(), expect, "seq {}", seq);
            if expect {
                accepted.insert(seq);
            }
            prop_assert_eq!(window.highest, accepted.last().copied());
        }
    }

    #[test]
    fn min_seq_is_accepted_and_never_a_replay(seqs in proptest::collection::vec(any::<u64>(), 1..50)) {
        let mut window = SeqWindow::default();
        for seq in seqs {
            let _ = window.accept(seq);
        }
        let min = window.min_seq();
        if window.highest != Some(u64::MAX) {
            prop_assert!(window.accept(min).is_ok());
            prop_assert!(window.accept(min).is_err());
        }
    }

    /// Never behind the clock, and always past the last value sent (short
    /// of `u64::MAX`, where it saturates).
    #[test]
    fn next_seq_never_goes_backwards(last: Option<u64>, now: u64) {
        let next = next_seq(last, now);
        prop_assert!(next >= now);
        if let Some(l) = last.filter(|&l| l < u64::MAX) {
            prop_assert!(next > l);
        }
    }
}
