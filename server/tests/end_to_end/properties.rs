//! Property tests through the real gateway: whatever anyone sends, the
//! server refuses it with a 4xx (fixed-size when it can be encrypted back)
//! and never with a 5xx or a panic.

use std::time::SystemTime;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use lz_proto::padding::{REQUEST_SIZE, RESPONSE_SIZE};
use lz_server::gateway;
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};
use serde_json::json;

use crate::harness::{HOST, harness};

fn runner(cases: u32) -> TestRunner {
    TestRunner::new(Config {
        cases,
        // A failure is reported with its shrunk input. A bare TestRunner
        // has no source file to keep regression files next to.
        failure_persistence: None,
        ..Config::default()
    })
}

/// Inner requests that decrypt fine but are garbage, or valid requests with
/// a few bytes changed, get an encrypted 4xx problem of the fixed size
/// (spec §3.3, invariant 4), never a 5xx.
#[test]
fn garbage_inner_requests_get_fixed_size_problems() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let h = harness(false);
    let valid = h.inner(
        "POST",
        HOST,
        "/v0/wake",
        Some(&h.token),
        SystemTime::now(),
        Some(&json!({ "seq": 1, "lease": null })),
    );
    let inputs = prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..REQUEST_SIZE + 16),
        proptest::collection::vec(any::<u8>(), REQUEST_SIZE..=REQUEST_SIZE),
        proptest::collection::vec((0..REQUEST_SIZE, any::<u8>()), 1..8).prop_map(move |edits| {
            let mut bytes = valid.clone();
            for (at, value) in edits {
                bytes[at] = value;
            }
            bytes
        }),
    ];
    runner(256)
        .run(&inputs, |inner| {
            let r = rt.block_on(h.send_raw(&inner));
            prop_assert_eq!(r.padded_len, RESPONSE_SIZE);
            prop_assert!(r.status < 500, "status {} for {:?}", r.status, r.json);
            Ok(())
        })
        .unwrap();
}

/// Outer bodies that aren't valid OHTTP get a plain 400 (nothing can be
/// encrypted back), never a 5xx.
#[test]
fn garbage_outer_requests_are_refused() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let h = harness(false);
    let keys = rt.block_on(h.key_config());
    let inner = h.inner("POST", HOST, "/v0/info", None, SystemTime::now(), None);
    let (real, _) = ohttp::ClientRequest::from_encoded_config_list(&keys)
        .unwrap()
        .encapsulate(&inner)
        .unwrap();
    // A real request with a few bytes changed: a known key id and
    // algorithms, so it gets as far as decryption.
    let altered = proptest::collection::vec((0..real.len(), 1u8..), 1..4).prop_map(move |edits| {
        let mut body = real.clone();
        for (at, flip) in edits {
            body[at] ^= flip;
        }
        body
    });
    let inputs = prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..REQUEST_SIZE + 200),
        altered,
    ];
    runner(256)
        .run(&inputs, |body| {
            let resp = rt.block_on(
                h.outer(
                    Request::post(gateway::GATEWAY_PATH)
                        .header("content-type", "message/ohttp-req")
                        .body(Body::from(body))
                        .unwrap(),
                ),
            );
            prop_assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            Ok(())
        })
        .unwrap();
}

/// What the server encrypts to a device (RFC 8291), the client core
/// decrypts to the same bytes; and a message changed anywhere the
/// encryption covers is refused. The 4-byte record size (offsets 16..20)
/// isn't covered by RFC 8188, and a single-record reader doesn't need it.
#[test]
fn push_messages_round_trip_and_resist_tampering() {
    let ((secret, auth), _) = crate::harness::ua_keys();
    let receiver = lz_client::PushReceiver::from_bytes(&secret.to_bytes().into(), &auth).unwrap();
    let public = secret.public_key();
    // The largest plaintext one 4096-byte record holds: less the
    // delimiter byte and the 16-byte tag.
    const MAX_PLAIN: usize = 4096 - 1 - 16;
    let inputs = (
        proptest::collection::vec(any::<u8>(), 0..=MAX_PLAIN),
        any::<prop::sample::Index>(),
        1u8..,
    );
    runner(128)
        .run(&inputs, |(plain, at, flip)| {
            let message = lz_server::webpush::encrypt(&plain, &public, &auth).unwrap();
            prop_assert_eq!(&receiver.decrypt(&message).unwrap()[..], &plain[..]);

            let mut changed = message.clone();
            let i = at.index(changed.len());
            prop_assume!(!(16..20).contains(&i));
            changed[i] ^= flip;
            prop_assert!(receiver.decrypt(&changed).is_err(), "byte {} changed", i);
            Ok(())
        })
        .unwrap();
}
