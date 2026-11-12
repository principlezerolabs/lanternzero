//! The binding layer against a stand-in OHTTP gateway, as client/core's
//! tests do. These check the wrapping (conversions, `Pending` handling,
//! state round trips); the protocol itself is tested in client/core and
//! server/tests.

use bhttp::{Message, Mode};
use lz_client_uniffi::{
    AlertMode, Client, EventKind, EventStatus, HttpRequest, HttpResponse, KeyCheck, Lease, LzError,
    Network, PushReceiver, ViewingKeyKind, classify_viewing_key, connection_url,
    generate_account_token, parse_connection_url,
};
use lz_proto::padding::{REQUEST_SIZE, RESPONSE_SIZE, pad_bhttp};
use ohttp::hpke::{Aead, Kdf, Kem};
use serde_json::{Value, json};

const NOW: u64 = 1_800_000_000_000;

struct Gateway {
    server: ohttp::Server,
    keys: Vec<u8>,
}

impl Gateway {
    fn new(seed: u8) -> Self {
        let config = ohttp::KeyConfig::derive(
            1,
            Kem::X25519Sha256,
            vec![ohttp::SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm)],
            &[seed; 32],
        )
        .unwrap();
        let keys = ohttp::KeyConfig::encode_list(&[&config]).unwrap();
        Self {
            server: ohttp::Server::new(config).unwrap(),
            keys,
        }
    }

    /// Opens the request and answers it; returns the inner path and body.
    fn answer(&self, req: &HttpRequest, status: u16, body: &Value) -> (String, Value, Vec<u8>) {
        assert_eq!(req.method, "POST");
        assert_eq!(req.url, "https://lz.example/.well-known/ohttp-gateway");
        let (plain, reply) = self.server.decapsulate(&req.body).unwrap();
        assert_eq!(plain.len(), REQUEST_SIZE);
        let msg = Message::read_bhttp(&mut std::io::Cursor::new(&plain[..])).unwrap();
        let path = String::from_utf8(msg.control().path().unwrap().to_vec()).unwrap();
        let seen = if msg.content().is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(msg.content()).unwrap()
        };
        let mut out = Message::response(bhttp::StatusCode::try_from(status).unwrap());
        if !body.is_null() {
            out.write_content(serde_json::to_vec(body).unwrap());
        }
        let mut bytes = Vec::new();
        out.write_bhttp(Mode::KnownLength, &mut bytes).unwrap();
        let enc = reply
            .encapsulate(&pad_bhttp(bytes, RESPONSE_SIZE).unwrap())
            .unwrap();
        (path, seen, enc)
    }

    fn info(&self) -> Value {
        json!({
            "versions": ["v0"],
            "network": "main",
            "wake_interval_secs": 1800,
            "long_poll_wait_secs": [25, 30],
            "finality_depth": 10,
            "vapid_public_key": "K1",
            "ohttp_key_config_sha256": lz_proto::key_config_sha256_hex(&self.keys),
            "idle_account_days": 90,
            "attestation": null,
        })
    }
}

fn response(status: u16, body: Vec<u8>) -> HttpResponse {
    HttpResponse {
        status,
        retry_after: None,
        date: None,
        body,
    }
}

fn url() -> String {
    connection_url(
        "https://lz.example".into(),
        generate_account_token().unwrap().token,
    )
    .unwrap()
}

#[test]
fn info_register_wake_poll_round_trip() {
    let gw = Gateway::new(1);
    let c = Client::new_ohttp(url(), Network::Main, gw.keys.clone(), None).unwrap();

    let p = c.info(NOW).unwrap();
    let (path, _, enc) = gw.answer(&p.request().unwrap(), 200, &gw.info());
    assert_eq!(path, "/v0/info");
    let info = c.finish_info(&p, response(200, enc)).unwrap();
    assert_eq!(info.vapid_public_key, "K1");
    assert_eq!(info.idle_account_days, Some(90));
    assert!(!info.vapid_key_changed);

    let rx = PushReceiver::generate().unwrap();
    let p = c
        .register(NOW, "https://push.example/wp/abc".into(), rx.push_keys())
        .unwrap();
    let (path, body, enc) = gw.answer(&p.request().unwrap(), 201, &json!({"device_id": "dev-1"}));
    assert_eq!(path, "/v0/devices");
    assert_eq!(body["vapid_public_key"], "K1");
    assert_eq!(c.finish_register(&p, response(200, enc)).unwrap(), "dev-1");
    assert_eq!(c.device_id().as_deref(), Some("dev-1"));

    let p = c.wake(NOW, None).unwrap();
    let event = json!({
        "id": "e1", "rev": 1, "kind": "received", "status": "mined",
        "height": 100, "confirmations": 3, "compact_tx": "AA"
    });
    let (path, body, enc) = gw.answer(
        &p.request().unwrap(),
        200,
        &json!({
            "tip": 120, "lease": {"active": false}, "hints": [{"start": 90, "end": 110}],
            "events": [event], "cursor": "c1", "next": null
        }),
    );
    assert_eq!(path, "/v0/wake");
    assert_eq!(body["lease"], Value::Null);
    let out = c.finish_wake(&p, response(200, enc)).unwrap();
    assert_eq!(out.tip, 120);
    assert_eq!(out.hints[0].start, 90);
    let e = out.events[0].clone();
    assert_eq!(
        (e.kind, e.status, e.height),
        (EventKind::Received, EventStatus::Mined, Some(100))
    );
    assert!(c.ack(e));

    // The acknowledgement rides on the long-poll.
    let p = c.poll(NOW + 1000).unwrap();
    let (path, body, enc) = gw.answer(
        &p.request().unwrap(),
        200,
        &json!({"cursor": "c2", "events": [], "next": null}),
    );
    assert_eq!(path, "/v0/events");
    assert_eq!(body["ack"], json!(["e1"]));
    assert_eq!(body["cursor"], "c1");
    assert!(
        c.finish_poll(&p, response(200, enc))
            .unwrap()
            .events
            .is_empty()
    );

    // State survives a restart.
    let again = Client::new_ohttp(url(), Network::Main, gw.keys.clone(), Some(c.state())).unwrap();
    assert_eq!(again.device_id().as_deref(), Some("dev-1"));
}

#[test]
fn pending_is_finished_once_by_its_own_call() {
    let gw = Gateway::new(2);
    let c = Client::new_ohttp(url(), Network::Main, gw.keys.clone(), None).unwrap();
    let p = c.info(NOW).unwrap();
    let (_, _, enc) = gw.answer(&p.request().unwrap(), 200, &gw.info());
    assert!(matches!(
        c.finish_wake(&p, response(200, enc.clone())),
        Err(LzError::WrongPending)
    ));
    // The wrong call leaves it for the right one, which takes it.
    c.finish_info(&p, response(200, enc.clone())).unwrap();
    assert!(matches!(
        c.finish_info(&p, response(200, enc)),
        Err(LzError::WrongPending)
    ));
    assert!(matches!(p.request(), Err(LzError::WrongPending)));
}

#[test]
fn server_errors_map_through() {
    let gw = Gateway::new(3);
    let c = Client::new_ohttp(url(), Network::Main, gw.keys.clone(), None).unwrap();
    let p = c.info(NOW).unwrap();
    let mut info = gw.info();
    info["network"] = json!("test");
    let (_, _, enc) = gw.answer(&p.request().unwrap(), 200, &info);
    assert!(matches!(
        c.finish_info(&p, response(200, enc)),
        Err(LzError::WrongNetwork)
    ));
    assert!(matches!(c.poll(NOW), Err(LzError::NotRegistered)));
}

#[test]
fn leases_are_checked_before_sending() {
    let gw = Gateway::new(4);
    let c = Client::new_ohttp(url(), Network::Main, gw.keys.clone(), None).unwrap();
    let full = Lease {
        keys: vec!["uview1abc".into()],
        from_height: 1,
        duration_secs: 604_800,
        spend_alerts: false,
        alert_mode: AlertMode::Private,
    };
    let err = c.wake(NOW, Some(full)).unwrap_err();
    let LzError::Lease { reason } = &err else {
        panic!("expected a lease error, got {err:?}");
    };
    // `reason`, not `message`: that name clashes with Kotlin's
    // `Throwable.message` (issue #14).
    assert!(!reason.is_empty());
    assert_eq!(err.to_string(), format!("invalid lease: {reason}"));
}

#[test]
fn rotation_reuses_the_token_it_was_given() {
    let gw = Gateway::new(5);
    let c = Client::new_ohttp(url(), Network::Main, gw.keys.clone(), None).unwrap();
    let new = generate_account_token().unwrap();
    let p = c.rotate_token(NOW, new.token.clone()).unwrap();
    let stored = p.new_connection_url().unwrap();
    assert!(stored.ends_with(&new.token));
    let (path, body, enc) = gw.answer(&p.request().unwrap(), 204, &Value::Null);
    assert_eq!(path, "/v0/token/rotate");
    assert_eq!(body["new_token_hash"], new.hash_hex);
    assert_eq!(c.finish_rotate(&p, response(200, enc)).unwrap(), stored);
}

#[test]
fn key_config_checks() {
    let gw = Gateway::new(6);
    let other = Gateway::new(7);
    let c = Client::new_ohttp(url(), Network::Main, gw.keys.clone(), None).unwrap();
    assert_eq!(
        c.check_key_config(NOW, gw.keys.clone(), gw.keys.clone())
            .unwrap(),
        KeyCheck::Agreed {
            changed: false,
            recovered: false
        }
    );
    assert!(matches!(
        c.check_key_config(NOW, gw.keys.clone(), other.keys.clone()),
        Ok(KeyCheck::Kept { .. })
    ));
    assert!(matches!(
        c.check_key_config(NOW, vec![1, 2, 3], gw.keys.clone()),
        Err(LzError::KeyConfigInvalid)
    ));
}

#[test]
fn helpers() {
    let t = generate_account_token().unwrap();
    assert_eq!(t.hash_hex.len(), 64);
    assert!(!format!("{t:?}").contains(&t.token));

    let info = parse_connection_url(
        connection_url("https://lz.example/".into(), t.token.clone()).unwrap(),
    )
    .unwrap();
    assert_eq!(info.base_url, "https://lz.example");
    assert!(!info.masked.contains(&t.token));
    // `http://` only for onion hosts, and never the other way round.
    assert!(connection_url("http://lz.example".into(), t.token.clone()).is_err());
    assert!(connection_url("https://lz.example".into(), "lzt_nope".into()).is_err());
    assert!(matches!(
        parse_connection_url("https://lz.example".into()),
        Err(LzError::InvalidUrl)
    ));

    let k = classify_viewing_key("uivk1qqqq".into()).unwrap();
    assert_eq!(
        (k.kind, k.network),
        (ViewingKeyKind::Incoming, Network::Main)
    );
    assert!(classify_viewing_key("zs1abc".into()).is_none());

    let rx = PushReceiver::generate().unwrap();
    let rx2 = PushReceiver::from_bytes(rx.secret_bytes(), rx.auth_bytes()).unwrap();
    assert_eq!(rx.push_keys(), rx2.push_keys());
    assert!(matches!(
        PushReceiver::from_bytes(vec![0; 31], rx.auth_bytes()),
        Err(LzError::PushKey)
    ));
    assert!(matches!(
        rx.open_ping_b64("AAAA".into()),
        Err(LzError::PushDecrypt)
    ));
}
