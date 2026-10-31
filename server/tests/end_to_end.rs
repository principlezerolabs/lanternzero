//! Drives the server as a wallet would: real OHTTP encapsulation of padded
//! Binary HTTP requests, through the gateway, into the API. Also checks push
//! delivery against a local receiver, and that logs never contain tokens.

use std::io::Cursor;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bhttp::{Message, Mode};
use lz_proto::api::{DeviceRegistration, PushKeys};
use lz_proto::lease::Network;
use lz_proto::padding::{REQUEST_SIZE, RESPONSE_SIZE, pad_bhttp};
use lz_proto::token::AccountToken;
use lz_server::config::{Config, LimitsConfig, PushConfig};
use lz_server::store::Store;
use lz_server::{AppState, gateway, push};
use serde_json::{Value, json};
use tower::ServiceExt;

const HOST: &str = "lz.test";
const BASE: &str = "/lz";

struct Harness {
    state: Arc<AppState>,
    app: axum::Router,
    token: String,
    seq: u64,
}

fn temp_dir() -> PathBuf {
    let mut raw = [0u8; 8];
    rand::fill(&mut raw);
    let name: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let d = std::env::temp_dir().join(format!("lz-e2e-{name}"));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn harness(allow_private_targets: bool) -> Harness {
    harness_with(allow_private_targets, LimitsConfig::default())
}

fn harness_with(allow_private_targets: bool, limits: LimitsConfig) -> Harness {
    let dir = temp_dir();
    let token = AccountToken::generate().unwrap();
    Store::add_account_to_file(&dir, &token.hash()).unwrap();
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        public_host: HOST.into(),
        base_path: BASE.into(),
        network: Network::Main,
        data_dir: dir,
        vapid_contact: "mailto:ops@lz.test".into(),
        direct_api: false,
        push: PushConfig {
            allow_private_targets,
            ..PushConfig::default()
        },
        limits,
    };
    let state = AppState::new(config).unwrap();
    let app = gateway::router(state.clone());
    Harness {
        state,
        app,
        token: token.encode().to_string(),
        seq: 1_000,
    }
}

/// What came back from one OHTTP round trip.
struct Reply {
    status: u16,
    json: Value,
    padded_len: usize,
    retry_after: Option<String>,
}

impl Harness {
    async fn outer(&self, req: Request<Body>) -> axum::response::Response {
        self.app.clone().oneshot(req).await.unwrap()
    }

    async fn key_config(&self) -> Vec<u8> {
        let resp = self
            .outer(
                Request::get(gateway::GATEWAY_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap()
            .to_vec()
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    /// Encapsulates an already-encoded inner request and returns the reply.
    async fn send_raw(&self, inner: &[u8]) -> Reply {
        let keys = self.key_config().await;
        let client = ohttp::ClientRequest::from_encoded_config_list(&keys).unwrap();
        let (enc, ctx) = client.encapsulate(inner).unwrap();
        let resp = self
            .outer(
                Request::post(gateway::GATEWAY_PATH)
                    .header("content-type", "message/ohttp-req")
                    .body(Body::from(enc))
                    .unwrap(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK, "outer status");
        let enc_resp = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        let plain = ctx.decapsulate(&enc_resp).unwrap();
        let padded_len = plain.len();
        let msg = Message::read_bhttp(&mut Cursor::new(&plain[..])).unwrap();
        let status = u16::from(msg.control().status().unwrap());
        let retry_after = msg
            .header()
            .get(b"retry-after")
            .map(|v| String::from_utf8(v.to_vec()).unwrap());
        let json = if msg.content().is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(msg.content()).unwrap()
        };
        Reply {
            status,
            json,
            padded_len,
            retry_after,
        }
    }

    /// Builds a padded inner request the way a wallet does.
    fn inner(
        &self,
        method: &str,
        authority: &str,
        path: &str,
        token: Option<&str>,
        date: SystemTime,
        body: Option<&Value>,
    ) -> Vec<u8> {
        let mut msg = Message::request(
            method.as_bytes().to_vec(),
            b"https".to_vec(),
            authority.as_bytes().to_vec(),
            format!("{BASE}{path}").into_bytes(),
        );
        msg.put_header("date", httpdate::fmt_http_date(date));
        if let Some(t) = token {
            msg.put_header("authorization", format!("Bearer {t}"));
        }
        if let Some(b) = body {
            msg.put_header("content-type", "application/json");
            msg.write_content(serde_json::to_vec(b).unwrap());
        }
        let mut out = Vec::new();
        msg.write_bhttp(Mode::KnownLength, &mut out).unwrap();
        pad_bhttp(out, REQUEST_SIZE).unwrap()
    }

    async fn call(&self, method: &str, path: &str, body: Option<Value>) -> Reply {
        let inner = self.inner(
            method,
            HOST,
            path,
            Some(&self.token),
            SystemTime::now(),
            body.as_ref(),
        );
        self.send_raw(&inner).await
    }

    async fn register(&mut self, endpoint: &str) -> Reply {
        let seq = self.next_seq();
        let (_, keys) = ua_keys();
        self.call(
            "POST",
            "/v0/devices",
            Some(json!({ "seq": seq, "endpoint": endpoint, "keys": keys })),
        )
        .await
    }
}

/// A device's RFC 8291 receiver key pair and auth secret.
fn ua_keys() -> ((p256::SecretKey, [u8; 16]), Value) {
    let secret = loop {
        let mut raw = [0u8; 32];
        rand::fill(&mut raw);
        if let Ok(k) = p256::SecretKey::from_slice(&raw) {
            break k;
        }
    };
    let mut auth = [0u8; 16];
    rand::fill(&mut auth);
    let public = lz_server::webpush::uncompressed(&secret.public_key());
    let keys = json!({
        "p256dh": URL_SAFE_NO_PAD.encode(public),
        "auth": URL_SAFE_NO_PAD.encode(auth),
    });
    ((secret, auth), keys)
}

fn problem_slug(reply: &Reply) -> String {
    reply.json["type"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn serves_key_config_and_relay_purposes() {
    let h = harness(false);
    let keys = h.key_config().await;
    assert_eq!(keys, h.state.ohttp_keys);
    let resp = h
        .outer(
            Request::get(format!("{}?allowed_purposes", gateway::GATEWAY_PATH))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(
        resp.headers()["content-type"],
        "application/x-ohttp-allowed-purposes"
    );
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    assert!(body.ends_with(lz_proto::OHTTP_PURPOSE.as_bytes()));
}

#[tokio::test]
async fn info_works_without_a_token_and_responses_are_fixed_size() {
    let h = harness(false);
    let inner = h.inner("POST", HOST, "/v0/info", None, SystemTime::now(), None);
    let r = h.send_raw(&inner).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.padded_len, RESPONSE_SIZE);
    assert_eq!(r.json["network"], "main");
    assert_eq!(
        r.json["ohttp_key_config_sha256"],
        h.state.ohttp_keys_sha256.as_str()
    );
    assert_eq!(r.json["attestation"], Value::Null);
}

#[tokio::test]
async fn register_then_default_mode_wake() {
    let mut h = harness(false);
    let r = h.register("https://push.example.app/wp/abc").await;
    assert_eq!(r.status, 201, "{:?}", r.json);
    let device_id = r.json["device_id"].as_str().unwrap().to_owned();

    let seq = h.next_seq();
    let wake = json!({ "device_id": device_id, "seq": seq, "ack": [], "lease": null });
    let r = h.call("POST", "/v0/wake", Some(wake.clone())).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.padded_len, RESPONSE_SIZE);
    assert_eq!(r.json["lease"]["active"], false);
    assert_eq!(r.json["hints"], json!([]));

    // A replay of the same request is rejected, with a way to recover.
    let r = h.call("POST", "/v0/wake", Some(wake)).await;
    assert_eq!(r.status, 409);
    assert_eq!(problem_slug(&r), "stale-seq");
    let min = r.json["min_seq"].as_u64().unwrap();
    let retry = json!({ "device_id": device_id, "seq": min, "ack": [], "lease": null });
    assert_eq!(h.call("POST", "/v0/wake", Some(retry)).await.status, 200);

    // Unknown devices are told to register again.
    let other = json!({ "device_id": "nope", "seq": min + 1, "ack": [], "lease": null });
    let r = h.call("POST", "/v0/wake", Some(other)).await;
    assert_eq!(
        (r.status, problem_slug(&r).as_str()),
        (404, "unknown-device")
    );

    // Deleting the device works once.
    let seq = h.next_seq() + min;
    let path = format!("/v0/devices/{device_id}");
    let r = h.call("DELETE", &path, Some(json!({ "seq": seq }))).await;
    assert_eq!(r.status, 204);
    let r = h
        .call("DELETE", &path, Some(json!({ "seq": seq + 1 })))
        .await;
    assert_eq!(r.status, 404);
}

#[tokio::test]
async fn scanning_leases_are_refused_for_now() {
    let mut h = harness(false);
    let device_id = h.register("https://push.example.app/wp/abc").await.json["device_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let lease = |keys: &str, seq: u64| {
        json!({ "device_id": device_id, "seq": seq, "ack": [], "lease": {
            "keys": [keys], "from_height": 1, "duration_secs": 604800, "spend_alerts": false
        }})
    };
    let s = h.next_seq();
    let r = h
        .call("POST", "/v0/wake", Some(lease("uivk1qqqq", s)))
        .await;
    assert_eq!(
        (r.status, problem_slug(&r).as_str()),
        (501, "scanning-unavailable")
    );
    let s = h.next_seq();
    let r = h
        .call("POST", "/v0/wake", Some(lease("uivktest1qqqq", s)))
        .await;
    assert_eq!(r.status, 400);
}

#[tokio::test]
async fn rejects_bad_requests() {
    let mut h = harness(false);
    let now = SystemTime::now();

    let no_token = h.inner("POST", HOST, "/v0/wake", None, now, Some(&json!({})));
    assert_eq!(h.send_raw(&no_token).await.status, 401);
    let bad_token = h.inner(
        "POST",
        HOST,
        "/v0/wake",
        Some(&AccountToken::generate().unwrap().encode()),
        now,
        Some(&json!({})),
    );
    assert_eq!(h.send_raw(&bad_token).await.status, 401);

    let old = h.inner(
        "POST",
        HOST,
        "/v0/info",
        None,
        now - Duration::from_secs(120),
        None,
    );
    let r = h.send_raw(&old).await;
    assert_eq!((r.status, problem_slug(&r).as_str()), (400, "bad-date"));

    let wrong_host = h.inner("POST", "evil.test", "/v0/info", None, now, None);
    let r = h.send_raw(&wrong_host).await;
    assert_eq!((r.status, problem_slug(&r).as_str()), (400, "bad-target"));

    // Unpadded, or padded with non-zero bytes: rejected (invariant 4).
    let mut short = h.inner("POST", HOST, "/v0/info", None, now, None);
    short.truncate(REQUEST_SIZE - 1);
    let r = h.send_raw(&short).await;
    assert_eq!((r.status, problem_slug(&r).as_str()), (400, "bad-size"));
    let mut dirty = h.inner("POST", HOST, "/v0/info", None, now, None);
    *dirty.last_mut().unwrap() = 1;
    assert_eq!(problem_slug(&h.send_raw(&dirty).await), "bad-size");

    // SSRF: an endpoint on a link-local address is refused at registration.
    let r = h.register("https://169.254.169.254/latest/meta-data").await;
    assert_eq!(r.status, 400);
}

#[tokio::test]
async fn api_is_not_reachable_without_ohttp() {
    let h = harness(false);
    let resp = h
        .outer(
            Request::post(format!("{BASE}/v0/info"))
                .header("date", httpdate::fmt_http_date(SystemTime::now()))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<(HeaderMap, Bytes)>>>);

/// Starts a local push receiver that answers every request with `status`.
async fn receiver(status: StatusCode) -> (String, Captured) {
    let captured = Captured::default();
    let c = captured.clone();
    let app = axum::Router::new().route(
        "/push/{id}",
        axum::routing::post(move |headers: HeaderMap, body: Bytes| {
            let c = c.clone();
            async move {
                c.0.lock().unwrap().push((headers, body));
                status
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/push/device-1"), captured)
}

#[tokio::test]
async fn wake_round_delivers_encrypted_fixed_pings_and_drops_gone_devices() {
    let h = harness(true);
    let (endpoint, captured) = receiver(StatusCode::CREATED).await;
    let ((secret, auth), keys) = ua_keys();
    let account = h
        .state
        .store
        .authenticate(&lz_proto::token::TokenHash::of_text(&h.token))
        .unwrap();
    // Registered through the store: the API requires https endpoints, and
    // the local receiver is plain http.
    let reg = DeviceRegistration {
        seq: 1,
        endpoint: endpoint.clone(),
        keys: PushKeys {
            p256dh: keys["p256dh"].as_str().unwrap().into(),
            auth: keys["auth"].as_str().unwrap().into(),
        },
    };
    h.state.store.register_device(account, &reg, 10).unwrap();

    let stats = push::wake_round(&h.state, Duration::ZERO).await;
    assert_eq!(stats.delivered, 1, "{stats:?}");
    let (headers, body) = captured.0.lock().unwrap().pop().unwrap();
    assert_eq!(headers["content-encoding"], "aes128gcm");
    assert_eq!(headers["ttl"], "1800");
    assert_eq!(headers["urgency"], "normal");
    assert_eq!(headers["topic"], "wake");
    assert!(
        headers["authorization"]
            .to_str()
            .unwrap()
            .starts_with("vapid t=")
    );
    let plain = lz_server::webpush::decrypt(&body, &secret, &auth).unwrap();
    assert_eq!(plain, push::wake_plaintext());

    // A gateway that answers 410 makes the server forget the device.
    let (gone_endpoint, _) = receiver(StatusCode::GONE).await;
    let reg = DeviceRegistration {
        endpoint: gone_endpoint,
        ..reg
    };
    h.state.store.register_device(account, &reg, 10).unwrap();
    let stats = push::wake_round(&h.state, Duration::ZERO).await;
    assert_eq!((stats.delivered, stats.gone), (1, 1));
    assert_eq!(h.state.store.devices().len(), 1);
}

/// A `MakeWriter` that appends every log line to a shared buffer.
#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuf {
    type Writer = LogBuf;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Invariant 6: neither the token, its hash, nor a push endpoint appears in
/// logs, even at trace level, across successful, failing, and push paths.
#[tokio::test]
async fn logs_never_contain_tokens() {
    let logs = LogBuf::default();
    // The production filter, at its most verbose.
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(lz_server::log_filter("trace"))
        .with_writer(logs.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let mut h = harness(true);
    let device = h.register("https://push.example.app/wp/abc").await;
    let device_id = device.json["device_id"].as_str().unwrap().to_owned();
    let seq = h.next_seq();
    h.call(
        "POST",
        "/v0/wake",
        Some(json!({ "device_id": device_id, "seq": seq, "ack": [], "lease": null })),
    )
    .await;
    h.call(
        "POST",
        "/v0/wake",
        Some(json!({ "device_id": device_id, "seq": seq, "ack": [], "lease": null })),
    )
    .await;
    push::wake_round(&h.state, Duration::ZERO).await;

    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    // The capture must actually have seen the failing push attempt (the
    // test host doesn't resolve), or the checks below prove nothing.
    assert!(
        text.contains("push send failed"),
        "logs were not captured:\n{text}"
    );
    let hash = lz_proto::token::TokenHash::of_text(&h.token).to_hex();
    assert!(!text.contains(&h.token[4..]), "token found in logs");
    assert!(!text.contains(&hash), "token hash found in logs");
    assert!(
        !text.contains("push.example.app"),
        "push endpoint found in logs"
    );
}

#[tokio::test]
async fn registration_replays_are_rejected_by_the_account_window() {
    let mut h = harness(false);
    let seq = h.next_seq();
    let (_, keys) = ua_keys();
    let body = json!({ "seq": seq, "endpoint": "https://push.example.app/wp/1", "keys": keys });
    assert_eq!(
        h.call("POST", "/v0/devices", Some(body.clone()))
            .await
            .status,
        201
    );
    let r = h.call("POST", "/v0/devices", Some(body)).await;
    assert_eq!((r.status, problem_slug(&r).as_str()), (409, "stale-seq"));
}

#[tokio::test]
async fn bearer_scheme_is_case_insensitive() {
    let mut h = harness(false);
    let seq = h.next_seq();
    let (_, keys) = ua_keys();
    let body = json!({ "seq": seq, "endpoint": "https://push.example.app/wp/1", "keys": keys });
    let mut msg = Message::request(
        b"POST".to_vec(),
        b"https".to_vec(),
        HOST.as_bytes().to_vec(),
        format!("{BASE}/v0/devices").into_bytes(),
    );
    msg.put_header("date", httpdate::fmt_http_date(SystemTime::now()));
    msg.put_header("authorization", format!("bearer {}", h.token));
    msg.write_content(serde_json::to_vec(&body).unwrap());
    let mut out = Vec::new();
    msg.write_bhttp(Mode::KnownLength, &mut out).unwrap();
    let r = h.send_raw(&pad_bhttp(out, REQUEST_SIZE).unwrap()).await;
    assert_eq!(r.status, 201);
}

#[tokio::test]
async fn rate_limits_return_429_with_retry_after_inside_ohttp() {
    let mut h = harness_with(
        false,
        LimitsConfig {
            account_per_minute: 100,
            device_per_minute: 2,
        },
    );
    let device_id = h.register("https://push.example.app/wp/abc").await.json["device_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut last = None;
    for _ in 0..3 {
        let seq = h.next_seq();
        let wake = json!({ "device_id": device_id, "seq": seq, "ack": [], "lease": null });
        last = Some(h.call("POST", "/v0/wake", Some(wake)).await);
    }
    let r = last.unwrap();
    assert_eq!((r.status, problem_slug(&r).as_str()), (429, "rate-limited"));
    let secs: u64 = r
        .retry_after
        .expect("Retry-After reaches the wallet")
        .parse()
        .unwrap();
    assert!((1..=60).contains(&secs));
}

#[tokio::test]
async fn gateway_requires_the_ohttp_media_type() {
    let h = harness(false);
    let resp = h
        .outer(
            Request::post(gateway::GATEWAY_PATH)
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn gateway_429_retry_after_pauses_the_device() {
    let h = harness(true);
    let captured = Captured::default();
    let c = captured.clone();
    let app = axum::Router::new().route(
        "/push/{id}",
        axum::routing::post(move |headers: HeaderMap, body: Bytes| {
            let c = c.clone();
            async move {
                c.0.lock().unwrap().push((headers, body));
                (StatusCode::TOO_MANY_REQUESTS, [("retry-after", "7200")])
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let (_, keys) = ua_keys();
    let account = h
        .state
        .store
        .authenticate(&lz_proto::token::TokenHash::of_text(&h.token))
        .unwrap();
    let reg = DeviceRegistration {
        seq: 1,
        endpoint: format!("http://{addr}/push/d"),
        keys: PushKeys {
            p256dh: keys["p256dh"].as_str().unwrap().into(),
            auth: keys["auth"].as_str().unwrap().into(),
        },
    };
    h.state.store.register_device(account, &reg, 10).unwrap();

    let first = push::wake_round(&h.state, Duration::ZERO).await;
    assert_eq!(first.rate_limited, 1);
    // The next round skips the device instead of contacting the gateway.
    let second = push::wake_round(&h.state, Duration::ZERO).await;
    assert_eq!(second.rate_limited, 1);
    assert_eq!(captured.0.lock().unwrap().len(), 1);
}
