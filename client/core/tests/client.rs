//! The client core against a stand-in OHTTP gateway that answers with
//! canned responses. The real server is exercised in
//! `server/tests/end_to_end/client.rs`.

use std::io::Cursor;

use bhttp::{Message, Mode};
use lz_client::lz_proto::api::{Event, EventKind, EventStatus, PushKeys};
use lz_client::lz_proto::lease::{AlertMode, LeaseRequest, Network, ViewingKey};
use lz_client::lz_proto::padding::{REQUEST_SIZE, RESPONSE_SIZE, pad_bhttp};
use lz_client::lz_proto::token::AccountToken;
use lz_client::lz_proto::url::ConnectionUrl;
use lz_client::{
    Client, ClientState, Error, HttpRequest, HttpResponse, KeyConfig, KeyConfigError,
    LONG_POLL_WAIT_SECS, Transport,
};
use ohttp::hpke::{Aead, Kdf, Kem};
use serde_json::{Value, json};

const NOW: u64 = 1_800_000_000_000;

fn token() -> AccountToken {
    AccountToken::from_bytes([0x5A; 32])
}

/// A stand-in for the server's OHTTP gateway.
struct Gateway {
    server: ohttp::Server,
    keys: Vec<u8>,
}

/// One request as the gateway saw it.
struct Seen {
    method: String,
    authority: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Value,
    reply: ohttp::ServerResponse,
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

    fn key_config(&self) -> KeyConfig {
        KeyConfig::from_two_relays(&self.keys, &self.keys).unwrap()
    }

    fn receive(&self, req: &HttpRequest) -> Seen {
        assert_eq!(req.method, "POST");
        assert_eq!(req.url, "https://lz.example/.well-known/ohttp-gateway");
        assert_eq!(
            req.headers,
            [("content-type", "message/ohttp-req".to_owned())]
        );
        let (plain, reply) = self.server.decapsulate(&req.body).unwrap();
        // Invariant 4: every inner request is the fixed size.
        assert_eq!(plain.len(), REQUEST_SIZE);
        let mut cursor = Cursor::new(&plain[..]);
        let msg = Message::read_bhttp(&mut cursor).unwrap();
        let used = cursor.position() as usize;
        assert!(plain[used..].iter().all(|&b| b == 0), "padding is zeros");
        let c = msg.control();
        let text = |b: Option<&[u8]>| String::from_utf8(b.unwrap().to_vec()).unwrap();
        Seen {
            method: text(c.method()),
            authority: text(c.authority()),
            path: text(c.path()),
            headers: msg
                .header()
                .fields()
                .iter()
                .map(|f| {
                    (
                        String::from_utf8(f.name().to_vec()).unwrap(),
                        String::from_utf8(f.value().to_vec()).unwrap(),
                    )
                })
                .collect(),
            body: if msg.content().is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(msg.content()).unwrap()
            },
            reply,
        }
    }
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// The encapsulated response for `status` and `body`, padded as the
    /// server pads it.
    fn answer(self, status: u16, body: &Value, retry_after: Option<&str>) -> Vec<u8> {
        self.answer_sized(status, body, retry_after, RESPONSE_SIZE)
    }

    fn answer_sized(
        self,
        status: u16,
        body: &Value,
        retry_after: Option<&str>,
        size: usize,
    ) -> Vec<u8> {
        let mut msg = Message::response(bhttp::StatusCode::try_from(status).unwrap());
        if let Some(r) = retry_after {
            msg.put_header("retry-after", r);
        }
        if !body.is_null() {
            msg.write_content(serde_json::to_vec(body).unwrap());
        }
        let mut out = Vec::new();
        msg.write_bhttp(Mode::KnownLength, &mut out).unwrap();
        self.reply
            .encapsulate(&pad_bhttp(out, size).unwrap())
            .unwrap()
    }
}

fn ok(body: &[u8]) -> HttpResponse<'_> {
    HttpResponse {
        status: 200,
        retry_after: None,
        body,
    }
}

fn client(gw: &Gateway, state: ClientState) -> Client {
    let url = ConnectionUrl::parse(&format!(
        "lanternzero://lz.example/base#{}",
        &*token().encode()
    ))
    .unwrap();
    Client::new(url, Network::Main, Transport::Ohttp(gw.key_config()), state).unwrap()
}

fn registered(gw: &Gateway) -> Client {
    client(
        gw,
        ClientState {
            device_id: Some("dev-1".into()),
            ..ClientState::default()
        },
    )
}

fn problem(slug: &str, status: u16) -> Value {
    json!({ "type": format!("https://lanternzero.com/problems/{slug}"), "title": "x", "status": status })
}

fn event(id: &str, rev: u32, status: &str) -> Value {
    json!({ "id": id, "rev": rev, "kind": "received", "status": status, "height": 101, "confirmations": rev })
}

fn wake_reply(events: Vec<Value>, next: bool) -> Value {
    json!({
        "tip": 120,
        "lease": { "active": false },
        "hints": [{ "start": 101, "end": 102 }],
        "events": events,
        "cursor": "7",
        "next": if next { json!("7") } else { Value::Null },
    })
}

fn lease(keys: Vec<&str>, spend_alerts: bool) -> LeaseRequest {
    LeaseRequest {
        keys: keys
            .into_iter()
            .map(|k| ViewingKey::new(k.into()))
            .collect(),
        from_height: 100,
        duration_secs: 604_800,
        spend_alerts,
        alert_mode: AlertMode::Instant,
    }
}

/// A plausible-looking Revision 2 unified incoming viewing key.
fn uivk() -> String {
    format!("uivk1{}", "q".repeat(300))
}

#[test]
fn every_request_is_padded_and_the_same_size_on_the_wire() {
    let gw = Gateway::new(1);
    let mut c = registered(&gw);
    let info = c.info(NOW).unwrap();
    let plain_wake = c.wake(NOW, None).unwrap();
    let scanning_wake = c.wake(NOW, Some(lease(vec![&uivk()], false))).unwrap();
    let sizes: Vec<usize> = [
        info.request(),
        plain_wake.request(),
        scanning_wake.request(),
    ]
    .iter()
    .map(|r| r.body.len())
    .collect();
    assert!(sizes.iter().all(|&s| s == sizes[0]), "{sizes:?}");

    let seen = gw.receive(scanning_wake.request());
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.authority, "lz.example");
    assert_eq!(seen.path, "/base/v0/wake");
    assert_eq!(
        seen.header("authorization").map(str::to_owned),
        Some(format!("Bearer {}", &*token().encode()))
    );
    assert_eq!(seen.header("content-type"), Some("application/json"));
    assert_eq!(seen.header("date"), Some("Fri, 15 Jan 2027 08:00:00 GMT"));
    assert_eq!(seen.body["device_id"], "dev-1");
    assert_eq!(seen.body["ack"], json!([]));
    assert_eq!(seen.body["lease"]["keys"][0], uivk().as_str());

    let seen = gw.receive(info.request());
    assert_eq!(seen.path, "/base/v0/info");
    assert!(seen.header("authorization").is_none(), "info has no token");
}

#[test]
fn seq_is_time_based_rises_and_recovers_from_stale_seq() {
    let gw = Gateway::new(1);
    let mut c = registered(&gw);
    let a = gw.receive(c.wake(NOW, None).unwrap().request()).body["seq"]
        .as_u64()
        .unwrap();
    assert_eq!(a, NOW);
    // The clock didn't move: still rises.
    let b = gw.receive(c.wake(NOW, None).unwrap().request()).body["seq"]
        .as_u64()
        .unwrap();
    assert_eq!(b, NOW + 1);

    // A restored backup with an old clock: the server's window is ahead.
    let p = c.wake(NOW, None).unwrap();
    let reply = gw.receive(p.request()).answer(
        409,
        &json!({ "type": "https://lanternzero.com/problems/stale-seq", "status": 409, "min_seq": NOW + 500 }),
        None,
    );
    assert_eq!(c.finish_wake(p, ok(&reply)), Err(Error::StaleSeq));
    let retry = gw.receive(c.wake(NOW, None).unwrap().request()).body["seq"]
        .as_u64()
        .unwrap();
    assert_eq!(retry, NOW + 500);
    assert_eq!(c.state().last_seq, Some(NOW + 500));
}

#[test]
fn acks_ride_on_the_next_request_until_one_succeeds() {
    let gw = Gateway::new(1);
    let mut c = registered(&gw);
    let mined: Event = serde_json::from_value(event("e1", 3, "mined")).unwrap();
    let pending: Event = serde_json::from_value(event("e2", 1, "mempool")).unwrap();
    assert!(!c.ack(&pending), "mempool events aren't acknowledged");
    assert!(c.ack(&mined));
    assert!(c.ack(&mined), "queued once");
    assert_eq!(c.pending_acks(), 1);

    // A failed request keeps the acknowledgement queued.
    let p = c.wake(NOW, None).unwrap();
    let seen = gw.receive(p.request());
    assert_eq!(seen.body["ack"], json!(["e1"]));
    let reply = seen.answer(500, &problem("internal", 500), None);
    assert!(matches!(
        c.finish_wake(p, ok(&reply)),
        Err(Error::Server { status: 500, .. })
    ));
    assert_eq!(c.pending_acks(), 1);

    let p = c.wake(NOW, None).unwrap();
    let reply = gw
        .receive(p.request())
        .answer(200, &wake_reply(vec![], false), None);
    c.finish_wake(p, ok(&reply)).unwrap();
    assert_eq!(c.pending_acks(), 0);
    let seen = gw.receive(c.wake(NOW, None).unwrap().request());
    assert_eq!(seen.body["ack"], json!([]));
}

#[test]
fn reports_only_new_or_changed_events_and_follows_next_pages() {
    let gw = Gateway::new(1);
    let mut c = registered(&gw);
    assert_eq!(c.poll(NOW).unwrap_err(), Error::NoCursor);

    let p = c.wake(NOW, None).unwrap();
    let reply = gw.receive(p.request()).answer(
        200,
        &wake_reply(vec![event("e1", 1, "mempool")], true),
        None,
    );
    let w = c.finish_wake(p, ok(&reply)).unwrap();
    assert_eq!(w.tip, 120);
    assert_eq!(w.hints.len(), 1);
    assert_eq!(w.events.len(), 1);
    assert_eq!(w.events[0].kind, EventKind::Received);
    assert!(w.more);
    assert_eq!(c.state().cursor.as_deref(), Some("7"));

    // `next` is fetched at once; then regular long-polls.
    let p = c.poll(NOW).unwrap();
    let seen = gw.receive(p.request());
    assert_eq!(seen.path, "/base/v0/events");
    assert_eq!(
        (seen.body["cursor"].as_str(), seen.body["wait"].as_u64()),
        (Some("7"), Some(0))
    );
    let reply = seen.answer(
        200,
        &json!({ "cursor": "9", "events": [event("e1", 1, "mempool"), event("e1", 2, "mined")], "next": null }),
        None,
    );
    let out = c.finish_poll(p, ok(&reply)).unwrap();
    assert_eq!(out.events.len(), 1, "the unchanged copy is dropped");
    assert_eq!(out.events[0].status, EventStatus::Mined);
    assert!(!out.more);

    let seen = gw.receive(c.poll(NOW).unwrap().request());
    assert_eq!(
        (seen.body["cursor"].as_str(), seen.body["wait"].as_u64()),
        (Some("9"), Some(u64::from(LONG_POLL_WAIT_SECS)))
    );

    // Every wake repeats unacknowledged events; they're reported once.
    let p = c.wake(NOW, None).unwrap();
    let reply = gw.receive(p.request()).answer(
        200,
        &wake_reply(vec![event("e1", 2, "mined")], false),
        None,
    );
    assert!(c.finish_wake(p, ok(&reply)).unwrap().events.is_empty());
}

#[test]
fn unknown_device_rate_limits_and_lease_refusals() {
    let gw = Gateway::new(1);
    let mut c = registered(&gw);

    let p = c.wake(NOW, None).unwrap();
    let reply = gw
        .receive(p.request())
        .answer(429, &problem("rate-limited", 429), Some("17"));
    assert_eq!(
        c.finish_wake(p, ok(&reply)),
        Err(Error::RateLimited {
            retry_after_secs: Some(17)
        })
    );

    let p = c.wake(NOW, Some(lease(vec![&uivk()], false))).unwrap();
    let reply = gw
        .receive(p.request())
        .answer(501, &problem("scanning-unavailable", 501), None);
    assert_eq!(
        c.finish_wake(p, ok(&reply)),
        Err(Error::ScanningUnavailable)
    );

    // The wallet must not send a full viewing key without spend alerts.
    let fvk = format!("uview1{}", "q".repeat(300));
    assert!(matches!(
        c.wake(NOW, Some(lease(vec![&fvk], false))),
        Err(Error::Lease(_))
    ));

    let p = c.wake(NOW, None).unwrap();
    let reply = gw
        .receive(p.request())
        .answer(404, &problem("unknown-device", 404), None);
    assert_eq!(c.finish_wake(p, ok(&reply)), Err(Error::UnknownDevice));
    assert_eq!(c.state().device_id, None);
    assert_eq!(c.wake(NOW, None).unwrap_err(), Error::NotRegistered);
}

#[test]
fn registers_and_unregisters() {
    let gw = Gateway::new(1);
    let mut c = client(&gw, ClientState::default());
    let keys = lz_client::PushReceiver::generate().unwrap().push_keys();
    assert!(matches!(
        c.register(NOW, "http://push.example/wp/x", keys.clone()),
        Err(Error::Registration(_))
    ));
    let p = c.register(NOW, "https://push.example/wp/x", keys).unwrap();
    let seen = gw.receive(p.request());
    assert_eq!(seen.path, "/base/v0/devices");
    assert_eq!(seen.body["endpoint"], "https://push.example/wp/x");
    let reply = seen.answer(201, &json!({ "device_id": "dev-9" }), None);
    assert_eq!(c.finish_register(p, ok(&reply)).unwrap(), "dev-9");
    assert_eq!(c.state().device_id.as_deref(), Some("dev-9"));

    // A device id goes into paths, so odd ones are refused.
    let p = c
        .register(NOW, "https://push.example/wp/y", c_keys())
        .unwrap();
    let reply = gw
        .receive(p.request())
        .answer(201, &json!({ "device_id": "../admin" }), None);
    assert_eq!(c.finish_register(p, ok(&reply)), Err(Error::Malformed));

    let mut c = client(
        &gw,
        ClientState {
            device_id: Some("dev-9".into()),
            ..ClientState::default()
        },
    );
    let p = c.unregister(NOW).unwrap();
    let seen = gw.receive(p.request());
    assert_eq!(
        (seen.method.as_str(), seen.path.as_str()),
        ("DELETE", "/base/v0/devices/dev-9")
    );
    let reply = seen.answer(204, &Value::Null, None);
    c.finish_unregister(p, ok(&reply)).unwrap();
    assert_eq!(c.state().device_id, None);
}

fn c_keys() -> PushKeys {
    lz_client::PushReceiver::generate().unwrap().push_keys()
}

fn info_body(gw: &Gateway, network: &str, vapid: &str) -> Value {
    json!({
        "versions": ["v0"],
        "network": network,
        "wake_interval_secs": 1800,
        "long_poll_wait_secs": [25, 30],
        "finality_depth": 10,
        "vapid_public_key": vapid,
        "ohttp_key_config_sha256": gw.key_config().sha256_hex(),
        "attestation": null,
    })
}

#[test]
fn info_checks_network_key_config_and_vapid_rotation() {
    let gw = Gateway::new(1);
    let mut c = client(&gw, ClientState::default());

    let p = c.info(NOW).unwrap();
    let reply = gw
        .receive(p.request())
        .answer(200, &info_body(&gw, "test", "K1"), None);
    assert_eq!(c.finish_info(p, ok(&reply)), Err(Error::WrongNetwork));

    let p = c.info(NOW).unwrap();
    let reply = gw
        .receive(p.request())
        .answer(200, &info_body(&gw, "main", "K1"), None);
    let out = c.finish_info(p, ok(&reply)).unwrap();
    assert!(!out.vapid_key_changed);
    assert_eq!(c.state().vapid_public_key.as_deref(), Some("K1"));

    let p = c.info(NOW).unwrap();
    let reply = gw
        .receive(p.request())
        .answer(200, &info_body(&gw, "main", "K2"), None);
    assert!(c.finish_info(p, ok(&reply)).unwrap().vapid_key_changed);

    // The server says it now uses another key configuration.
    let other = Gateway::new(2);
    let mut body = info_body(&gw, "main", "K2");
    body["ohttp_key_config_sha256"] = json!(other.key_config().sha256_hex());
    let p = c.info(NOW).unwrap();
    let reply = gw.receive(p.request()).answer(200, &body, None);
    assert_eq!(c.finish_info(p, ok(&reply)), Err(Error::KeyConfigChanged));
}

#[test]
fn refuses_responses_that_are_not_fixed_size_or_not_from_the_gateway() {
    let gw = Gateway::new(1);
    let mut c = registered(&gw);
    let p = c.wake(NOW, None).unwrap();
    let reply = gw
        .receive(p.request())
        .answer_sized(200, &wake_reply(vec![], false), None, 2048);
    assert_eq!(c.finish_wake(p, ok(&reply)), Err(Error::Transport));

    let p = c.wake(NOW, None).unwrap();
    assert_eq!(
        c.finish_wake(
            p,
            HttpResponse {
                status: 502,
                retry_after: None,
                body: b"bad gateway"
            }
        ),
        Err(Error::Relay(502))
    );

    // A response for another request can't be opened.
    let a = c.wake(NOW, None).unwrap();
    let b = c.wake(NOW, None).unwrap();
    let reply_a = gw
        .receive(a.request())
        .answer(200, &wake_reply(vec![], false), None);
    assert_eq!(c.finish_wake(b, ok(&reply_a)), Err(Error::Transport));
}

#[test]
fn key_configs_must_match_across_relays() {
    let a = Gateway::new(1);
    let b = Gateway::new(2);
    assert_eq!(
        KeyConfig::from_two_relays(&a.keys, &b.keys).unwrap_err(),
        KeyConfigError::Mismatch
    );
    assert_eq!(
        KeyConfig::from_cache(b"junk").unwrap_err(),
        KeyConfigError::Invalid
    );
    let k = a.key_config();
    assert_eq!(k.encoded(), &a.keys[..]);
    assert_eq!(k.sha256_hex().len(), 64);
}

#[test]
fn onion_requests_go_direct_and_secrets_stay_out_of_debug() {
    let text = token().encode().to_string();
    let clear = ConnectionUrl::parse(&format!("lanternzero://lz.example#{text}")).unwrap();
    assert_eq!(
        Client::new(
            clear,
            Network::Main,
            Transport::Onion,
            ClientState::default()
        )
        .unwrap_err(),
        Error::OnionOnly
    );

    let onion = ConnectionUrl::parse(&format!("lanternzero://abcdefgh.onion/lz#{text}")).unwrap();
    let mut c = Client::new(
        onion,
        Network::Main,
        Transport::Onion,
        ClientState {
            device_id: Some("dev-1".into()),
            ..ClientState::default()
        },
    )
    .unwrap();
    let key = uivk();
    let p = c.wake(NOW, Some(lease(vec![&key], false))).unwrap();
    let req = p.request();
    assert_eq!(req.url, "http://abcdefgh.onion/lz/v0/wake");
    assert!(
        req.headers
            .iter()
            .any(|(n, v)| *n == "authorization" && v.ends_with(&text[4..]))
    );
    for dbg in [format!("{req:?}"), format!("{p:?}"), format!("{c:?}")] {
        assert!(!dbg.contains(&text[4..]), "token in Debug: {dbg}");
        assert!(!dbg.contains(&key[10..]), "key in Debug: {dbg}");
    }
    let body = serde_json::to_vec(&wake_reply(vec![event("e1", 1, "mined")], false)).unwrap();
    let resp = HttpResponse {
        status: 200,
        retry_after: None,
        body: &body,
    };
    assert!(!format!("{resp:?}").contains("e1"), "body in Debug");
    let out = c.finish_wake(p, resp).unwrap();
    assert_eq!(out.tip, 120);

    // A lease too large for the fixed size is refused, not truncated.
    let huge = format!("uivk1{}", "q".repeat(5000));
    assert_eq!(
        c.wake(NOW, Some(lease(vec![&huge], false))).unwrap_err(),
        Error::TooLarge
    );
}
