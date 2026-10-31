//! The OHTTP gateway (RFC 9458, RFC 9540; spec §3.1–3.3).
//!
//! `GET  /.well-known/ohttp-gateway`                  key configuration
//! `GET  /.well-known/ohttp-gateway?allowed_purposes` relay opt-in purposes
//! `POST /.well-known/ohttp-gateway`                  encapsulated requests
//!
//! Every inner request must be exactly [`REQUEST_SIZE`] bytes of padded
//! known-length Binary HTTP, and every inner response is padded to exactly
//! [`RESPONSE_SIZE`]. Inner requests and responses are never logged: they
//! carry tokens and, later, viewing keys. Note that `bhttp::Message`'s
//! `Debug` output includes headers, so never format one.

use std::io::Cursor;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, RawQuery, State};
use axum::http::{HeaderValue, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use bhttp::{Message, Mode};
use lz_proto::padding::{REQUEST_SIZE, RESPONSE_SIZE, pad_bhttp};
use tower::ServiceExt;
use zeroize::Zeroizing;

use crate::AppState;
use crate::api::Problem;

pub const GATEWAY_PATH: &str = "/.well-known/ohttp-gateway";
/// Largest encapsulated request: the fixed inner size plus HPKE overhead.
const MAX_ENCAPSULATED: usize = REQUEST_SIZE + 1024;
/// Largest inner response body before padding.
const MAX_INNER_BODY: usize = RESPONSE_SIZE;
/// Inner request headers the gateway drops: the body comes from the Binary
/// HTTP content, not from these.
const DROPPED_INNER_HEADERS: &[&str] =
    &["content-length", "transfer-encoding", "host", "connection"];
/// Inner response headers copied into the Binary HTTP response.
const KEPT_RESPONSE_HEADERS: &[header::HeaderName] = &[header::CONTENT_TYPE, header::RETRY_AFTER];

/// The outer router: the gateway, plus the API directly when `direct_api`
/// is set (self-hosted onion services only).
pub fn router(state: Arc<AppState>) -> Router {
    let api = crate::api::router(state.clone());
    let mut outer = Router::new()
        .route(GATEWAY_PATH, get(keys_or_purposes).post(relay))
        .layer(DefaultBodyLimit::max(MAX_ENCAPSULATED))
        .with_state(GatewayState {
            app: state.clone(),
            api: api.clone(),
        });
    if state.config.direct_api {
        let api = api.layer(DefaultBodyLimit::max(REQUEST_SIZE));
        outer = if state.config.base_path.is_empty() {
            outer.merge(api)
        } else {
            outer.nest(&state.config.base_path, api)
        };
    }
    outer
}

#[derive(Clone)]
struct GatewayState {
    app: Arc<AppState>,
    api: Router,
}

/// ALPN-style list as payjoin relays parse it: a big-endian `u16` count,
/// then each purpose as a `u8` length and its bytes.
fn encode_purposes(purposes: &[&str]) -> Vec<u8> {
    let mut out = (purposes.len() as u16).to_be_bytes().to_vec();
    for p in purposes {
        out.push(p.len() as u8);
        out.extend_from_slice(p.as_bytes());
    }
    out
}

async fn keys_or_purposes(State(gw): State<GatewayState>, RawQuery(query): RawQuery) -> Response {
    if query.as_deref() == Some("allowed_purposes") {
        return (
            [(header::CONTENT_TYPE, "application/x-ohttp-allowed-purposes")],
            encode_purposes(&[lz_proto::OHTTP_PURPOSE]),
        )
            .into_response();
    }
    (
        [
            (header::CONTENT_TYPE, "application/ohttp-keys"),
            (header::CACHE_CONTROL, "max-age=86400"),
        ],
        gw.app.ohttp_keys.clone(),
    )
        .into_response()
}

async fn relay(
    State(gw): State<GatewayState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let is_ohttp = headers
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"message/ohttp-req"));
    if !is_ohttp {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let Ok((plain, response_ctx)) = gw.app.ohttp.decapsulate(&body) else {
        // Nothing can be encrypted back to the client.
        return StatusCode::BAD_REQUEST.into_response();
    };
    // The plaintext holds the bearer token (and, later, viewing keys).
    let plain = Zeroizing::new(plain);
    let inner = match handle_inner(&gw, plain).await {
        Ok(resp) => resp,
        Err(problem) => problem.into_response(),
    };
    let encoded = match encode_response(inner).await {
        Some(bytes) => bytes,
        None => {
            tracing::error!("inner response too large for the fixed size");
            match encode_response(
                Problem::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "internal error",
                )
                .into_response(),
            )
            .await
            {
                Some(bytes) => bytes,
                None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
        }
    };
    match response_ctx.encapsulate(&encoded) {
        Ok(enc) => (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("message/ohttp-res"),
            )],
            enc,
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Checks size and padding, parses Binary HTTP, and runs the API router.
async fn handle_inner(gw: &GatewayState, plain: Zeroizing<Vec<u8>>) -> Result<Response, Problem> {
    let wrong_size = || {
        Problem::new(
            StatusCode::BAD_REQUEST,
            "bad-size",
            "inner request must be exactly 4096 bytes",
        )
    };
    if plain.len() != REQUEST_SIZE {
        return Err(wrong_size());
    }
    let mut cursor = Cursor::new(&plain[..]);
    let msg = Message::read_bhttp(&mut cursor).map_err(|_| wrong_size())?;
    let used = cursor.position() as usize;
    if plain[used..].iter().any(|&b| b != 0) {
        return Err(wrong_size());
    }
    let control = msg.control();
    let bad_target = || {
        Problem::new(
            StatusCode::BAD_REQUEST,
            "bad-target",
            "wrong request target",
        )
    };
    let cfg = &gw.app.config;
    let authority = control.authority().ok_or_else(bad_target)?;
    let scheme_ok = matches!(control.scheme(), Some(b"https") | Some(b"http"));
    if !scheme_ok || !authority.eq_ignore_ascii_case(cfg.public_host.as_bytes()) {
        return Err(bad_target());
    }
    let path =
        std::str::from_utf8(control.path().ok_or_else(bad_target)?).map_err(|_| bad_target())?;
    let api_path = path
        .strip_prefix(cfg.base_path.as_str())
        .ok_or_else(bad_target)?;
    if !api_path.starts_with('/') {
        return Err(bad_target());
    }
    let method = control.method().ok_or_else(bad_target)?;

    let mut req = Request::builder()
        .method(axum::http::Method::from_bytes(method).map_err(|_| bad_target())?)
        .uri(api_path);
    for field in msg.header().fields() {
        let dropped = DROPPED_INNER_HEADERS
            .iter()
            .any(|h| field.name().eq_ignore_ascii_case(h.as_bytes()));
        if !dropped {
            req = req.header(field.name(), field.value());
        }
    }
    let req = req
        .body(Body::from(msg.content().to_vec()))
        .map_err(|_| Problem::bad_request_public("malformed inner request"))?;
    Ok(gw
        .api
        .clone()
        .oneshot(req)
        .await
        .expect("router is infallible"))
}

/// Encodes a response as padded known-length Binary HTTP, or `None` if it
/// can't fit [`RESPONSE_SIZE`].
async fn encode_response(resp: Response) -> Option<Vec<u8>> {
    let (parts, body) = resp.into_parts();
    let body = axum::body::to_bytes(body, MAX_INNER_BODY).await.ok()?;
    let status = bhttp::StatusCode::try_from(parts.status.as_u16()).ok()?;
    let mut msg = Message::response(status);
    for name in KEPT_RESPONSE_HEADERS {
        if let Some(v) = parts.headers.get(name) {
            msg.put_header(name.as_str(), v.as_bytes());
        }
    }
    msg.write_content(&body);
    let mut out = Vec::new();
    msg.write_bhttp(Mode::KnownLength, &mut out).ok()?;
    pad_bhttp(out, RESPONSE_SIZE).ok()
}

impl Problem {
    fn bad_request_public(title: &'static str) -> Self {
        Problem::new(StatusCode::BAD_REQUEST, "bad-request", title)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purposes_match_the_payjoin_relay_format() {
        let enc = encode_purposes(&[lz_proto::OHTTP_PURPOSE]);
        assert_eq!(&enc[..2], &[0, 1]);
        assert_eq!(enc[2] as usize, lz_proto::OHTTP_PURPOSE.len());
        assert_eq!(&enc[3..], lz_proto::OHTTP_PURPOSE.as_bytes());
    }
}
