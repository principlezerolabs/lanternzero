//! The gateway against fake APNs and FCM endpoints, with pushes signed and
//! encrypted by the real server code (`lz-server`).

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use lz_gateway::config::{ApnsConfig, Config, FcmConfig, LimitsConfig};
use lz_gateway::{AppState, router};
use lz_server::webpush::Vapid;
use p256::pkcs8::EncodePrivateKey;
use serde_json::{Value, json};

/// Requests a fake platform received, and the reply it gives.
#[derive(Clone)]
struct Platform {
    seen: Arc<Mutex<Vec<(String, HeaderMap, Value)>>>,
    reply: Arc<Mutex<(u16, Value, Option<&'static str>)>>,
}

impl Platform {
    async fn start() -> (String, Self) {
        let p = Platform {
            seen: Arc::default(),
            reply: Arc::new(Mutex::new((200, json!({}), None))),
        };
        let pc = p.clone();
        let app = axum::Router::new().fallback(
            move |uri: axum::http::Uri, headers: HeaderMap, body: Bytes| {
                let p = pc.clone();
                async move {
                    let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    p.seen
                        .lock()
                        .unwrap()
                        .push((uri.path().to_owned(), headers, v));
                    let (status, body, retry) = p.reply.lock().unwrap().clone();
                    let mut resp =
                        axum::response::Response::new(axum::body::Body::from(body.to_string()));
                    *resp.status_mut() = StatusCode::from_u16(status).unwrap();
                    if let Some(r) = retry {
                        resp.headers_mut().insert("retry-after", r.parse().unwrap());
                    }
                    resp
                }
            },
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), p)
    }

    fn reply(&self, status: u16, body: Value, retry: Option<&'static str>) {
        *self.reply.lock().unwrap() = (status, body, retry);
    }

    fn take(&self) -> Vec<(String, HeaderMap, Value)> {
        std::mem::take(&mut *self.seen.lock().unwrap())
    }
}

struct Harness {
    origin: String,
    apns: Platform,
    fcm: Platform,
    apns_public: p256::PublicKey,
    server: Vapid,
    http: reqwest::Client,
    data_dir: std::path::PathBuf,
    config: Config,
    task: tokio::task::JoinHandle<()>,
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let mut raw = [0u8; 8];
    rand::fill(&mut raw);
    let name: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let d = std::env::temp_dir().join(format!("lz-gw-{tag}-{name}"));
    std::fs::create_dir_all(&d).unwrap();
    d
}

async fn harness_with(limits: LimitsConfig) -> Harness {
    let (apns_url, apns) = Platform::start().await;
    let (fcm_url, fcm) = Platform::start().await;
    let dir = temp_dir("gw");
    // A throwaway APNs auth key, as Apple's `.p8` file would hold it.
    let apns_key = p256::SecretKey::from_slice(&[0x11; 32]).unwrap();
    let key_path = dir.join("AuthKey_TEST.p8");
    std::fs::write(
        &key_path,
        apns_key
            .to_pkcs8_pem(Default::default())
            .unwrap()
            .as_bytes(),
    )
    .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let config = Config {
        listen: listener.local_addr().unwrap(),
        public_origin: origin.clone(),
        data_dir: dir.join("data"),
        endpoint_lifetime_days: 90,
        alert_title: "New activity".into(),
        apns: Some(ApnsConfig {
            team_id: "TEAM123456".into(),
            key_id: "KEY1234567".into(),
            key_path,
            topic: "app.example.wallet".into(),
            sandbox: false,
            base_url: Some(apns_url),
        }),
        fcm: Some(FcmConfig {
            project_id: "example-wallet".into(),
            credentials_path: None,
            static_access_token: Some("test-access-token".into()),
            base_url: fcm_url,
        }),
        limits,
    };
    config.validate().unwrap();
    let data_dir = config.data_dir.clone();
    let state = AppState::new(config.clone()).unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
    Harness {
        origin,
        apns,
        fcm,
        apns_public: apns_key.public_key(),
        server: Vapid::from_secret(&[0x22; 32]).unwrap(),
        http: reqwest::Client::new(),
        data_dir,
        config,
        task,
    }
}

async fn harness() -> Harness {
    harness_with(LimitsConfig::default()).await
}

const APNS_TOKEN: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
const FCM_TOKEN: &str = "fcm-registration-token:APA91bExampleExampleExample";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn opaque(endpoint: &str) -> &str {
    endpoint.rsplit('/').next().unwrap()
}

impl Harness {
    /// Stops the gateway and starts it again on the same address and data
    /// directory, as after a deploy.
    async fn restart(&mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
        let state = AppState::new(self.config.clone()).unwrap();
        let listener = tokio::net::TcpListener::bind(self.config.listen)
            .await
            .unwrap();
        self.task =
            tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
        // Pooled connections would still reach the old instance's tasks.
        self.http = reqwest::Client::new();
    }

    /// The whole subscribe response: `endpoint`, `expires`, `revoke_secret`.
    async fn subscription(&self, platform: &str, token: &str) -> Value {
        let r = self
            .subscribe(platform, token, &self.server.public_b64)
            .await;
        assert_eq!(r.status(), 201);
        serde_json::from_slice(&r.bytes().await.unwrap()).unwrap()
    }

    async fn revoke(&self, endpoint: &str, secret: Option<&str>) -> u16 {
        let mut req = self.http.delete(format!(
            "{}/v0/subscriptions/{}",
            self.origin,
            opaque(endpoint)
        ));
        if let Some(s) = secret {
            req = req.header("authorization", format!("Bearer {s}"));
        }
        req.send().await.unwrap().status().as_u16()
    }

    async fn subscribe(&self, platform: &str, token: &str, key: &str) -> reqwest::Response {
        self.http
            .post(format!("{}/v0/subscriptions", self.origin))
            .body(json!({ "platform": platform, "token": token, "server_key": key }).to_string())
            .send()
            .await
            .unwrap()
    }

    async fn endpoint(&self, platform: &str, token: &str) -> String {
        let r = self
            .subscribe(platform, token, &self.server.public_b64)
            .await;
        assert_eq!(r.status(), 201);
        let v: Value = serde_json::from_slice(&r.bytes().await.unwrap()).unwrap();
        v["endpoint"].as_str().unwrap().to_owned()
    }

    /// Sends a push to `endpoint` signed by `vapid`, the way the server does.
    async fn push(
        &self,
        vapid: &Vapid,
        endpoint: &str,
        urgency: &str,
        body: &[u8],
    ) -> reqwest::Response {
        let uri: http::Uri = endpoint.parse().unwrap();
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let auth = vapid
            .authorization(&uri, exp, "mailto:ops@lz.test")
            .unwrap();
        let mut req = self
            .http
            .post(endpoint)
            .header("authorization", auth)
            .header("ttl", "1800")
            .header("urgency", urgency)
            .header("content-encoding", "aes128gcm")
            .body(body.to_vec());
        if urgency == "normal" {
            req = req.header("topic", "wake");
        }
        req.send().await.unwrap()
    }
}

#[tokio::test]
async fn forwards_a_bound_wake_to_apns_unchanged() {
    let h = harness().await;
    let endpoint = h.endpoint("apns", APNS_TOKEN).await;
    assert!(endpoint.starts_with(&format!("{}/wp/", h.origin)));
    assert!(!endpoint.contains(APNS_TOKEN), "the device token is sealed");
    assert!(endpoint.len() <= 1024, "spec §4.1 endpoint limit");

    let body = vec![0x5A; 1110];
    let r = h.push(&h.server, &endpoint, "normal", &body).await;
    assert_eq!(r.status(), 201);
    assert!(r.headers().contains_key("location"));

    let seen = h.apns.take();
    assert_eq!(seen.len(), 1);
    let (path, headers, payload) = &seen[0];
    assert_eq!(path, &format!("/3/device/{APNS_TOKEN}"));
    assert_eq!(headers["apns-push-type"], "background");
    assert_eq!(headers["apns-priority"], "5");
    assert_eq!(headers["apns-topic"], "app.example.wallet");
    assert_eq!(headers["apns-collapse-id"], "wake");
    assert_eq!(payload["aps"], json!({ "content-available": 1 }));
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(payload["lz"].as_str().unwrap())
            .unwrap(),
        body
    );

    // The provider token is an ES256 JWT from the .p8 key.
    let bearer = headers["authorization"]
        .to_str()
        .unwrap()
        .strip_prefix("bearer ")
        .unwrap();
    let parts: Vec<&str> = bearer.split('.').collect();
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(
        (header["alg"].as_str(), header["kid"].as_str()),
        (Some("ES256"), Some("KEY1234567"))
    );
    assert_eq!(claims["iss"], "TEAM123456");
    use p256::ecdsa::signature::Verifier;
    let sig =
        p256::ecdsa::Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
    p256::ecdsa::VerifyingKey::from(h.apns_public)
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
        .unwrap();
}

#[tokio::test]
async fn payment_alerts_are_visible_and_generic() {
    let h = harness().await;
    let endpoint = h.endpoint("apns", APNS_TOKEN).await;
    let r = h.push(&h.server, &endpoint, "high", &[1; 200]).await;
    assert_eq!(r.status(), 201);
    let (_, headers, payload) = h.apns.take().pop().unwrap();
    assert_eq!(headers["apns-push-type"], "alert");
    assert_eq!(headers["apns-priority"], "10");
    assert!(headers.get("apns-collapse-id").is_none());
    assert_eq!(payload["aps"]["alert"], json!({ "title": "New activity" }));
    assert_eq!(payload["aps"]["mutable-content"], 1);
}

#[tokio::test]
async fn only_the_bound_server_can_push() {
    let h = harness().await;
    let endpoint = h.endpoint("apns", APNS_TOKEN).await;
    let other = Vapid::from_secret(&[0x33; 32]).unwrap();
    let r = h.push(&other, &endpoint, "normal", &[1; 100]).await;
    assert_eq!(r.status(), 403);

    // The right key, but a bad signature, wrong audience, or no VAPID.
    let uri: http::Uri = endpoint.parse().unwrap();
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let good = h
        .server
        .authorization(&uri, exp, "mailto:ops@lz.test")
        .unwrap();
    let tampered = good.replacen("t=ey", "t=ez", 1);
    let wrong_aud = h
        .server
        .authorization(
            &"https://elsewhere.example/wp/x".parse().unwrap(),
            exp,
            "mailto:ops@lz.test",
        )
        .unwrap();
    let expired = h
        .server
        .authorization(&uri, exp - 7200, "mailto:ops@lz.test")
        .unwrap();
    let too_long = h
        .server
        .authorization(&uri, exp + 2 * 86_400, "mailto:ops@lz.test")
        .unwrap();
    // Arithmetic on a hostile `exp` must not overflow.
    let max_exp = h
        .server
        .authorization(&uri, u64::MAX, "mailto:ops@lz.test")
        .unwrap();
    for auth in [
        tampered,
        wrong_aud,
        expired,
        too_long,
        max_exp,
        "Bearer nope".to_owned(),
    ] {
        let r = h
            .http
            .post(&endpoint)
            .header("authorization", auth)
            .header("ttl", "60")
            .header("content-encoding", "aes128gcm")
            .body(vec![1; 10])
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);
    }
    assert!(h.apns.take().is_empty(), "nothing reached Apple");

    // A key that isn't a P-256 point can't be bound.
    let r = h.subscribe("apns", APNS_TOKEN, "AAAA").await;
    assert_eq!(r.status(), 400);
}

#[tokio::test]
async fn rejects_bad_endpoints_and_messages() {
    let h = harness().await;
    let endpoint = h.endpoint("apns", APNS_TOKEN).await;
    // Altered or foreign endpoints are unknown.
    let mut altered = endpoint.clone();
    let last = altered.pop().unwrap();
    altered.push(if last == 'A' { 'B' } else { 'A' });
    assert_eq!(
        h.push(&h.server, &altered, "normal", &[1; 10])
            .await
            .status(),
        404
    );

    let uri: http::Uri = endpoint.parse().unwrap();
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let auth = h
        .server
        .authorization(&uri, exp, "mailto:ops@lz.test")
        .unwrap();
    let send = |ttl: Option<&'static str>,
                enc: &'static str,
                urgency: &'static str,
                topic: Option<&'static str>,
                len: usize| {
        let mut req = h
            .http
            .post(&endpoint)
            .header("authorization", auth.clone())
            .header("content-encoding", enc)
            .header("urgency", urgency)
            .body(vec![1; len]);
        if let Some(t) = ttl {
            req = req.header("ttl", t);
        }
        if let Some(t) = topic {
            req = req.header("topic", t);
        }
        req.send()
    };
    assert_eq!(
        send(None, "aes128gcm", "normal", None, 10)
            .await
            .unwrap()
            .status(),
        400,
        "no TTL"
    );
    assert_eq!(
        send(Some("60"), "identity", "normal", None, 10)
            .await
            .unwrap()
            .status(),
        400,
        "plaintext"
    );
    assert_eq!(
        send(Some("60"), "aes128gcm", "urgent", None, 10)
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        send(Some("60"), "aes128gcm", "normal", Some("has space"), 10)
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        send(Some("60"), "aes128gcm", "normal", None, 5000)
            .await
            .unwrap()
            .status(),
        413
    );
    assert!(h.apns.take().is_empty());

    for (platform, token) in [
        ("apns", "zz"),
        ("apns", "abc"),
        ("fcm", ""),
        ("carrier-pigeon", "x"),
    ] {
        assert_eq!(
            h.subscribe(platform, token, &h.server.public_b64)
                .await
                .status(),
            400
        );
    }
}

#[tokio::test]
async fn rate_limits_per_device_with_separate_alert_budget() {
    let h = harness_with(LimitsConfig {
        background_per_hour: 3,
        alerts_per_hour: 2,
        per_server_per_minute: 1000,
    })
    .await;
    let endpoint = h.endpoint("apns", APNS_TOKEN).await;
    for _ in 0..3 {
        assert_eq!(
            h.push(&h.server, &endpoint, "normal", &[1; 10])
                .await
                .status(),
            201
        );
    }
    let r = h.push(&h.server, &endpoint, "normal", &[1; 10]).await;
    assert_eq!(r.status(), 429);
    assert!(
        r.headers()["retry-after"]
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            <= 3600
    );
    // Alerts have their own budget.
    assert_eq!(
        h.push(&h.server, &endpoint, "high", &[1; 10])
            .await
            .status(),
        201
    );
    assert_eq!(
        h.push(&h.server, &endpoint, "high", &[1; 10])
            .await
            .status(),
        201
    );
    assert_eq!(
        h.push(&h.server, &endpoint, "high", &[1; 10])
            .await
            .status(),
        429
    );
    // A new subscription for the same device and server shares the budget.
    let again = h.endpoint("apns", APNS_TOKEN).await;
    assert_ne!(again, endpoint);
    assert_eq!(
        h.push(&h.server, &again, "normal", &[1; 10]).await.status(),
        429
    );
    // A second server the wallet uses gets its own budget, or a wallet with
    // two servers (2 wakes an hour each) would lose wakes.
    let second = Vapid::from_secret(&[0x44; 32]).unwrap();
    let r = h.subscribe("apns", APNS_TOKEN, &second.public_b64).await;
    assert_eq!(r.status(), 201);
    let v: Value = serde_json::from_slice(&r.bytes().await.unwrap()).unwrap();
    let theirs = v["endpoint"].as_str().unwrap().to_owned();
    assert_eq!(
        h.push(&second, &theirs, "normal", &[1; 10]).await.status(),
        201
    );
    assert_eq!(h.apns.take().len(), 6);
}

#[tokio::test]
async fn maps_platform_answers_for_the_server() {
    let h = harness().await;
    let endpoint = h.endpoint("apns", APNS_TOKEN).await;
    let cases: [(u16, Value, Option<&'static str>, u16); 6] = [
        (410, json!({ "reason": "Unregistered" }), None, 410),
        (400, json!({ "reason": "BadDeviceToken" }), None, 410),
        (
            429,
            json!({ "reason": "TooManyRequests" }),
            Some("120"),
            429,
        ),
        // APNs usually sends no Retry-After; the server still gets one.
        (429, json!({ "reason": "TooManyRequests" }), None, 429),
        (400, json!({ "reason": "PayloadTooLarge" }), None, 502),
        (500, json!({}), None, 502),
    ];
    for (status, body, retry, expect) in cases {
        h.apns.reply(status, body, retry);
        let r = h.push(&h.server, &endpoint, "high", &[1; 10]).await;
        assert_eq!(r.status(), expect, "APNs {status}");
        if expect == 429 {
            assert_eq!(r.headers()["retry-after"], retry.unwrap_or("60"));
        }
    }
}

#[tokio::test]
async fn forwards_to_fcm() {
    let h = harness().await;
    let endpoint = h.endpoint("fcm", FCM_TOKEN).await;
    let body = vec![0x42; 300];
    assert_eq!(
        h.push(&h.server, &endpoint, "normal", &body).await.status(),
        201
    );
    let (path, headers, v) = h.fcm.take().pop().unwrap();
    assert_eq!(path, "/v1/projects/example-wallet/messages:send");
    assert_eq!(headers["authorization"], "Bearer test-access-token");
    let m = &v["message"];
    assert_eq!(m["token"], FCM_TOKEN);
    assert_eq!(m["android"]["priority"], "normal");
    assert_eq!(m["android"]["ttl"], "1800s");
    assert_eq!(m["android"]["collapse_key"], "wake");
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(m["data"]["lz"].as_str().unwrap())
            .unwrap(),
        body
    );

    h.fcm
        .reply(404, json!({ "error": { "status": "NOT_FOUND" } }), None);
    assert_eq!(
        h.push(&h.server, &endpoint, "high", &body).await.status(),
        410
    );
}

/// The whole path: the server's scheduled wake round, through the
/// gateway, to APNs; the device decrypts the fixed-size ping.
#[tokio::test]
async fn server_wake_round_reaches_the_device_through_the_gateway() {
    use lz_proto::api::{DeviceRegistration, PushKeys};
    let h = harness().await;
    let server_dir = temp_dir("server");
    let token = lz_proto::token::AccountToken::generate().unwrap();
    lz_server::store::Store::add_account_to_file(&server_dir, &token.hash()).unwrap();
    let server = lz_server::AppState::new(lz_server::config::Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        public_host: "lz.test".into(),
        base_path: String::new(),
        network: lz_proto::lease::Network::Main,
        data_dir: server_dir,
        vapid_contact: "mailto:ops@lz.test".into(),
        direct_api: false,
        chain: None,
        push: lz_server::config::PushConfig {
            allow_private_targets: true,
            ..Default::default()
        },
        limits: Default::default(),
    })
    .unwrap();

    // The wallet subscribes at its gateway with the server's key from
    // `info`, then registers the endpoint with the server.
    let r = h
        .subscribe("apns", APNS_TOKEN, &server.vapid.public_b64)
        .await;
    let endpoint = serde_json::from_slice::<Value>(&r.bytes().await.unwrap()).unwrap()["endpoint"]
        .as_str()
        .unwrap()
        .to_owned();
    let device_secret = p256::SecretKey::from_slice(&[0x44; 32]).unwrap();
    let auth = [0x55u8; 16];
    let account = server.store.authenticate(&token.hash()).unwrap();
    server
        .store
        .register_device(
            account,
            &DeviceRegistration {
                seq: 1,
                endpoint,
                keys: PushKeys {
                    p256dh: URL_SAFE_NO_PAD.encode(lz_server::webpush::uncompressed(
                        &device_secret.public_key(),
                    )),
                    auth: URL_SAFE_NO_PAD.encode(auth),
                },
            },
            10,
        )
        .unwrap();

    let stats = lz_server::push::wake_round(&server, Duration::ZERO).await;
    assert_eq!(stats.delivered, 1, "{stats:?}");
    let (_, headers, payload) = h.apns.take().pop().unwrap();
    assert_eq!(headers["apns-push-type"], "background");
    let ciphertext = URL_SAFE_NO_PAD
        .decode(payload["lz"].as_str().unwrap())
        .unwrap();
    let plain = lz_server::webpush::decrypt(&ciphertext, &device_secret, &auth).unwrap();
    assert_eq!(plain, lz_server::push::wake_plaintext());

    // A device Apple has forgotten is dropped by the server (spec §5.3).
    h.apns.reply(410, json!({ "reason": "Unregistered" }), None);
    let stats = lz_server::push::wake_round(&server, Duration::ZERO).await;
    assert_eq!(stats.gone, 1);
    assert!(server.store.devices().is_empty());
}

#[tokio::test]
async fn keeps_only_sealing_keys_and_revocations_on_disk() {
    let h = harness().await;
    let sub = h.subscription("apns", APNS_TOKEN).await;
    let endpoint = sub["endpoint"].as_str().unwrap();
    let secret = sub["revoke_secret"].as_str().unwrap();
    assert_eq!(h.revoke(endpoint, Some(secret)).await, 204);

    let mut files: Vec<_> = std::fs::read_dir(&h.data_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    files.sort();
    assert_eq!(files, ["endpoint-keys", "revoked"]);
    // One revocation is one 40-byte record: a hash and an expiry, nothing
    // about the device, the server, or the endpoint.
    let revoked = std::fs::read(h.data_dir.join("revoked")).unwrap();
    assert_eq!(revoked.len(), 40);
    let token = (0..APNS_TOKEN.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&APNS_TOKEN[i..i + 2], 16).unwrap())
        .collect::<Vec<u8>>();
    let secret_raw = URL_SAFE_NO_PAD.decode(secret).unwrap();
    let server_key = URL_SAFE_NO_PAD.decode(&h.server.public_b64).unwrap();
    for needle in [
        &token[..],
        &secret_raw[..],
        &server_key[..16],
        opaque(endpoint).as_bytes(),
    ] {
        assert!(
            !revoked.windows(needle.len()).any(|w| w == needle),
            "revocation list holds more than a hash"
        );
    }
    #[cfg(unix)]
    for f in files {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(h.data_dir.join(&f))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{f}");
    }
}

#[tokio::test]
async fn revoked_subscriptions_are_gone_and_stay_gone() {
    let mut h = harness().await;
    let sub = h.subscription("apns", APNS_TOKEN).await;
    let endpoint = sub["endpoint"].as_str().unwrap().to_owned();
    let secret = sub["revoke_secret"].as_str().unwrap().to_owned();
    let expires = sub["expires"].as_u64().unwrap();
    assert!(expires.abs_diff(now() + 90 * 86_400) < 60);
    let other = h.subscription("apns", APNS_TOKEN).await;
    let other_endpoint = other["endpoint"].as_str().unwrap().to_owned();
    assert_eq!(
        h.push(&h.server, &endpoint, "normal", &[1; 10])
            .await
            .status(),
        201
    );

    // The endpoint alone, which the server holds, can't revoke.
    assert_eq!(h.revoke(&endpoint, None).await, 401);
    assert_eq!(h.revoke(&endpoint, Some("not-a-secret")).await, 401);
    assert_eq!(
        h.revoke(&endpoint, other["revoke_secret"].as_str()).await,
        403
    );
    let mut altered = endpoint.clone();
    let last = altered.pop().unwrap();
    altered.push(if last == 'A' { 'B' } else { 'A' });
    assert_eq!(h.revoke(&altered, Some(&secret)).await, 404);

    assert_eq!(h.revoke(&endpoint, Some(&secret)).await, 204);
    assert_eq!(h.revoke(&endpoint, Some(&secret)).await, 204, "idempotent");
    // Spec §4.1: every later push gets 410, so the server drops the device.
    for urgency in ["normal", "high"] {
        assert_eq!(
            h.push(&h.server, &endpoint, urgency, &[1; 10])
                .await
                .status(),
            410
        );
    }
    // Another subscription for the same device is untouched.
    assert_eq!(
        h.push(&h.server, &other_endpoint, "normal", &[1; 10])
            .await
            .status(),
        201
    );
    assert_eq!(h.apns.take().len(), 2);

    // Revocations survive a restart.
    h.restart().await;
    assert_eq!(
        h.push(&h.server, &endpoint, "normal", &[1; 10])
            .await
            .status(),
        410
    );
    assert_eq!(
        h.push(&h.server, &other_endpoint, "normal", &[1; 10])
            .await
            .status(),
        201
    );
}

#[tokio::test]
async fn expired_subscriptions_are_gone() {
    let h = harness().await;
    // Seal one that expired yesterday with the gateway's own key.
    let ring = lz_gateway::keys::KeyRing::load_or_create(&h.data_dir, now()).unwrap();
    let token: Vec<u8> = vec![0xA1; 32];
    let opaque = lz_gateway::seal::Sealer::new(&ring).seal(&lz_gateway::seal::Subscription {
        platform: lz_gateway::seal::Platform::Apns,
        server_key: URL_SAFE_NO_PAD
            .decode(&h.server.public_b64)
            .unwrap()
            .try_into()
            .unwrap(),
        token: token.into(),
        created: now() - 2 * 86_400,
        expires: now() - 86_400,
        revoke_hash: [0; 32],
    });
    let endpoint = format!("{}/wp/{opaque}", h.origin);
    assert_eq!(
        h.push(&h.server, &endpoint, "normal", &[1; 10])
            .await
            .status(),
        410
    );
    // Only the bound server learns that it expired.
    let other = Vapid::from_secret(&[0x33; 32]).unwrap();
    assert_eq!(
        h.push(&other, &endpoint, "normal", &[1; 10]).await.status(),
        403
    );
    assert!(h.apns.take().is_empty());
}

#[tokio::test]
async fn rotating_the_sealing_key_keeps_endpoints_until_dropped() {
    use lz_gateway::keys::KeyRing;
    let mut h = harness().await;
    let old = h.subscription("apns", APNS_TOKEN).await;
    let old_endpoint = old["endpoint"].as_str().unwrap().to_owned();
    let key_id = |e: &str| URL_SAFE_NO_PAD.decode(opaque(e)).unwrap()[0];

    // A routine rotation: old endpoints keep working, new ones use the new
    // key, and old ones can still be revoked.
    let new_id = KeyRing::rotate(&h.data_dir, now(), false).unwrap();
    h.restart().await;
    assert_eq!(
        h.push(&h.server, &old_endpoint, "normal", &[1; 10])
            .await
            .status(),
        201
    );
    let new_endpoint = h.endpoint("apns", APNS_TOKEN).await;
    assert_eq!(key_id(&new_endpoint), new_id);
    assert_ne!(key_id(&old_endpoint), new_id);
    assert_eq!(
        h.push(&h.server, &new_endpoint, "normal", &[1; 10])
            .await
            .status(),
        201
    );
    assert_eq!(
        h.revoke(&old_endpoint, old["revoke_secret"].as_str()).await,
        204
    );
    assert_eq!(
        h.push(&h.server, &old_endpoint, "normal", &[1; 10])
            .await
            .status(),
        410
    );

    // After a suspected leak, every old endpoint stops working at once;
    // servers drop the devices and wallets register again.
    KeyRing::rotate(&h.data_dir, now(), true).unwrap();
    h.restart().await;
    for e in [&old_endpoint, &new_endpoint] {
        assert_eq!(h.push(&h.server, e, "normal", &[1; 10]).await.status(), 404);
    }
    let fresh = h.endpoint("apns", APNS_TOKEN).await;
    assert_eq!(
        h.push(&h.server, &fresh, "normal", &[1; 10]).await.status(),
        201
    );
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

/// Device tokens, endpoints, and revocation secrets never reach the logs, even at trace level
/// and on failure paths (the APNs URL contains the token).
#[tokio::test]
async fn logs_never_contain_tokens_or_endpoints() {
    let logs = LogBuf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(lz_gateway::log_filter("trace"))
        .with_writer(logs.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let h = harness().await;
    let endpoint = h.endpoint("apns", APNS_TOKEN).await;
    let fcm_endpoint = h.endpoint("fcm", FCM_TOKEN).await;
    let revocable = h.subscription("apns", APNS_TOKEN).await;
    let revoke_secret = revocable["revoke_secret"].as_str().unwrap();
    h.revoke(revocable["endpoint"].as_str().unwrap(), Some(revoke_secret))
        .await;
    h.push(&h.server, &endpoint, "normal", &[1; 10]).await;
    h.apns
        .reply(500, json!({ "reason": "InternalServerError" }), None);
    h.push(&h.server, &endpoint, "high", &[1; 10]).await;
    h.fcm.reply(500, json!({}), None);
    h.push(&h.server, &fcm_endpoint, "normal", &[1; 10]).await;

    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(text.contains("APNs error"), "logs not captured:\n{text}");
    for secret in [
        APNS_TOKEN,
        FCM_TOKEN,
        opaque(&endpoint),
        &APNS_TOKEN[..16],
        revoke_secret,
    ] {
        assert!(!text.contains(secret), "found in logs: {secret}");
    }
}
