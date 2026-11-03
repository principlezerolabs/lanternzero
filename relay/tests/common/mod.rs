//! A fake gateway that records what reaches it, and a relay in front of it.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use lz_relay::config::Config;
use lz_relay::{AppState, Timing};

#[derive(Debug, Clone)]
pub struct Seen {
    pub method: Method,
    pub uri: String,
    pub headers: HeaderMap,
    pub body: Bytes,
}

#[derive(Debug)]
pub struct Behavior {
    /// `None`: `?allowed_purposes` answers 404.
    pub purposes: Option<Vec<String>>,
    pub keys: Vec<u8>,
    pub keys_cache_control: Option<String>,
    pub post_status: u16,
    pub post_content_type: String,
    /// `None`: echo the request body.
    pub post_body: Option<Vec<u8>>,
    pub post_delay: Duration,
    pub post_redirect: Option<String>,
}

impl Default for Behavior {
    fn default() -> Self {
        Self {
            purposes: Some(vec![lz_proto::OHTTP_PURPOSE.to_owned()]),
            keys: vec![0x01, 0x02, 0x03, 0x04],
            keys_cache_control: Some("max-age=86400".into()),
            post_status: 200,
            post_content_type: "message/ohttp-res".into(),
            post_body: None,
            post_delay: Duration::ZERO,
            post_redirect: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct FakeState {
    pub behavior: Behavior,
    pub seen: Vec<Seen>,
}

#[derive(Debug, Clone)]
pub struct Fake {
    pub addr: SocketAddr,
    pub state: Arc<Mutex<FakeState>>,
}

impl Fake {
    pub async fn start() -> Self {
        let state = Arc::new(Mutex::new(FakeState::default()));
        let app = Router::new().fallback(fake).with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { addr, state }
    }

    /// The origin clients put in the relay path.
    pub fn origin(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn set(&self, f: impl FnOnce(&mut Behavior)) {
        f(&mut self.state.lock().unwrap().behavior);
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.state.lock().unwrap().seen.clone()
    }

    pub fn count(&self, method: Method, uri: &str) -> usize {
        self.seen()
            .iter()
            .filter(|s| s.method == method && s.uri == uri)
            .count()
    }

    pub fn probes(&self) -> usize {
        self.count(Method::GET, "/.well-known/ohttp-gateway?allowed_purposes")
    }

    pub fn key_fetches(&self) -> usize {
        self.count(Method::GET, "/.well-known/ohttp-gateway")
    }

    pub fn posts(&self) -> usize {
        self.count(Method::POST, "/.well-known/ohttp-gateway")
    }
}

pub fn encode_purposes(purposes: &[String]) -> Vec<u8> {
    let mut out = (purposes.len() as u16).to_be_bytes().to_vec();
    for p in purposes {
        out.push(p.len() as u8);
        out.extend_from_slice(p.as_bytes());
    }
    out
}

async fn fake(State(state): State<Arc<Mutex<FakeState>>>, req: Request) -> Response {
    let method = req.method().clone();
    let uri = req.uri().to_string();
    let headers = req.headers().clone();
    let body = axum::body::to_bytes(req.into_body(), 1 << 20)
        .await
        .unwrap();
    let (purposes, keys, cc, status, ct, post_body, delay, redirect) = {
        let mut st = state.lock().unwrap();
        st.seen.push(Seen {
            method: method.clone(),
            uri: uri.clone(),
            headers,
            body: body.clone(),
        });
        let b = &st.behavior;
        (
            b.purposes.clone(),
            b.keys.clone(),
            b.keys_cache_control.clone(),
            b.post_status,
            b.post_content_type.clone(),
            b.post_body.clone(),
            b.post_delay,
            b.post_redirect.clone(),
        )
    };
    match (method, uri.as_str()) {
        (Method::GET, "/.well-known/ohttp-gateway?allowed_purposes") => match purposes {
            Some(p) => (
                [(header::CONTENT_TYPE, "application/x-ohttp-allowed-purposes")],
                encode_purposes(&p),
            )
                .into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        },
        (Method::GET, "/.well-known/ohttp-gateway") => {
            let mut r = ([(header::CONTENT_TYPE, "application/ohttp-keys")], keys).into_response();
            if let Some(cc) = cc {
                r.headers_mut()
                    .insert(header::CACHE_CONTROL, HeaderValue::from_str(&cc).unwrap());
            }
            r
        }
        (Method::POST, "/.well-known/ohttp-gateway") => {
            tokio::time::sleep(delay).await;
            if let Some(to) = redirect {
                return (StatusCode::TEMPORARY_REDIRECT, [(header::LOCATION, to)]).into_response();
            }
            let mut r = (
                StatusCode::from_u16(status).unwrap(),
                [(header::CONTENT_TYPE, ct)],
                post_body.unwrap_or_else(|| body.to_vec()),
            )
                .into_response();
            // Headers a relay must not pass back.
            let h = r.headers_mut();
            h.insert(header::SET_COOKIE, HeaderValue::from_static("gw=1"));
            h.insert(header::SERVER, HeaderValue::from_static("fake-gateway"));
            h.insert("x-gateway-secret", HeaderValue::from_static("hush"));
            r
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Short timings for tests; production uses [`Timing::default`].
pub fn test_timing() -> Timing {
    Timing {
        first_byte: Duration::from_secs(5),
        total: Duration::from_secs(10),
        probe_timeout: Duration::from_secs(2),
        ..Timing::default()
    }
}

#[derive(Debug, Clone)]
pub struct Relay {
    pub base: String,
    pub state: Arc<AppState>,
    pub client: reqwest::Client,
}

impl Relay {
    /// A relay with `extra` TOML lines, allowing the loopback fake gateway.
    pub async fn start(extra: &str) -> Self {
        Self::start_with("allow_private_targets = true", extra, test_timing()).await
    }

    pub async fn start_with(private: &str, extra: &str, timing: Timing) -> Self {
        let config =
            Config::parse(&format!("listen = \"127.0.0.1:0\"\n{private}\n{extra}")).unwrap();
        let state = AppState::with_timing(config, timing).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let s = state.clone();
        tokio::spawn(async move {
            lz_relay::serve(listener, s, std::future::pending())
                .await
                .unwrap()
        });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        Self {
            base,
            state,
            client,
        }
    }

    pub fn url(&self, target: &str) -> String {
        format!("{}/{target}", self.base)
    }

    pub async fn post(&self, target: &str, body: Vec<u8>) -> reqwest::Response {
        self.client
            .post(self.url(target))
            .header(header::CONTENT_TYPE, "message/ohttp-req")
            .body(body)
            .send()
            .await
            .unwrap()
    }

    pub async fn get(&self, target: &str) -> reqwest::Response {
        self.client.get(self.url(target)).send().await.unwrap()
    }
}
