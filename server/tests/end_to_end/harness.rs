//! Shared OHTTP test harness and local push receiver.

use std::io::Cursor;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bhttp::{Message, Mode};
use lz_proto::lease::Network;
use lz_proto::padding::{REQUEST_SIZE, pad_bhttp};
use lz_proto::token::AccountToken;
use lz_server::config::{Config, LimitsConfig, PushConfig};
use lz_server::store::Store;
use lz_server::{AppState, gateway};
use serde_json::{Value, json};
use tower::ServiceExt;

pub(crate) const HOST: &str = "lz.test";
pub(crate) const BASE: &str = "/lz";

pub(crate) struct Harness {
    pub(crate) state: Arc<AppState>,
    app: axum::Router,
    pub(crate) token: String,
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

pub(crate) fn harness(allow_private_targets: bool) -> Harness {
    harness_with(allow_private_targets, LimitsConfig::default())
}

pub(crate) fn harness_with(allow_private_targets: bool, limits: LimitsConfig) -> Harness {
    harness_full(allow_private_targets, limits, None)
}

pub(crate) fn harness_full(
    allow_private_targets: bool,
    limits: LimitsConfig,
    lightwalletd: Option<String>,
) -> Harness {
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
        chain: lightwalletd.map(|url| lz_server::config::ChainConfig {
            lightwalletd: url,
            poll_secs: 5,
        }),
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
pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) json: Value,
    pub(crate) padded_len: usize,
    pub(crate) retry_after: Option<String>,
}

impl Harness {
    pub(crate) async fn outer(&self, req: Request<Body>) -> axum::response::Response {
        self.app.clone().oneshot(req).await.unwrap()
    }

    pub(crate) async fn key_config(&self) -> Vec<u8> {
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

    pub(crate) fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    /// Encapsulates an already-encoded inner request and returns the reply.
    pub(crate) async fn send_raw(&self, inner: &[u8]) -> Reply {
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
    pub(crate) fn inner(
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

    pub(crate) async fn call(&self, method: &str, path: &str, body: Option<Value>) -> Reply {
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

    pub(crate) async fn register(&mut self, endpoint: &str) -> Reply {
        let seq = self.next_seq();
        let (_, keys) = ua_keys();
        self.call(
            "POST",
            "/v0/devices",
            Some(json!({ "seq": seq, "endpoint": endpoint, "keys": keys })),
        )
        .await
    }

    /// The same server started again on its data directory, as after a
    /// restart (keys, accounts, and devices reload from disk).
    pub(crate) fn restart(&self) -> Self {
        let state = AppState::new(self.state.config.clone()).unwrap();
        Self {
            app: gateway::router(state.clone()),
            state,
            token: self.token.clone(),
            seq: self.seq,
        }
    }

    /// Clone for a concurrent OHTTP round trip without touching `seq`.
    pub(crate) fn fork(&self) -> Self {
        Self {
            state: self.state.clone(),
            app: self.app.clone(),
            token: self.token.clone(),
            seq: self.seq,
        }
    }
}

/// A device's RFC 8291 receiver key pair and auth secret.
pub(crate) fn ua_keys() -> ((p256::SecretKey, [u8; 16]), Value) {
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

pub(crate) fn problem_slug(reply: &Reply) -> String {
    reply.json["type"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned()
}

#[derive(Clone, Default)]
pub(crate) struct Captured(pub(crate) Arc<Mutex<Vec<(HeaderMap, Bytes)>>>);

/// Starts a local push receiver that answers every request with `status`.
pub(crate) async fn receiver(status: StatusCode) -> (String, Captured) {
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

/// A `MakeWriter` that appends every log line to a shared buffer.
#[derive(Clone, Default)]
pub(crate) struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl LogBuf {
    pub(crate) fn snapshot(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

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

/// One process-wide capture with the production filter at its most verbose.
/// Thread-scoped subscribers miss events when tests run in parallel, so
/// every test in this binary logs here, and the leak checks see all of it.
pub(crate) fn global_logs() -> &'static LogBuf {
    static LOGS: std::sync::OnceLock<LogBuf> = std::sync::OnceLock::new();
    LOGS.get_or_init(|| {
        let logs = LogBuf::default();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(lz_server::log_filter("trace"))
            .with_writer(logs.clone())
            .finish();
        tracing::subscriber::set_global_default(subscriber).expect("one global subscriber");
        logs
    })
}
