//! Oblivious HTTP framing (spec §3.1–3.3), or plain requests over a Tor
//! onion service (the self-host exception in §3.1).
//!
//! The core builds each request as bytes and opens each response from
//! bytes; the app sends them with its own HTTP stack. Over OHTTP the inner
//! request is known-length Binary HTTP padded to exactly
//! [`REQUEST_SIZE`], and every inner response must be exactly
//! [`RESPONSE_SIZE`], so relays see the same sizes from every wallet.

use std::io::Cursor;
use std::time::{Duration, UNIX_EPOCH};

use bhttp::{Message, Mode};
use lz_proto::padding::{REQUEST_SIZE, RESPONSE_SIZE};
use lz_proto::token::AccountToken;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::Error;

/// Where a server's OHTTP gateway lives, at its origin root (spec §3.1).
pub const GATEWAY_PATH: &str = "/.well-known/ohttp-gateway";
/// Content type of an encapsulated request.
pub const OHTTP_REQUEST_TYPE: &str = "message/ohttp-req";
/// Content type of an encapsulated response.
pub const OHTTP_RESPONSE_TYPE: &str = "message/ohttp-res";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyConfigError {
    /// The two relays served different configurations: the server may be
    /// tagging this user (spec §3.2). Don't use either.
    #[error("the two relays returned different key configurations")]
    Mismatch,
    #[error("not a valid OHTTP key configuration")]
    Invalid,
}

/// A server's OHTTP key configuration (`application/ohttp-keys`), checked
/// for consistency (spec §3.2).
#[derive(Clone, PartialEq, Eq)]
pub struct KeyConfig {
    encoded: Vec<u8>,
    sha256_hex: String,
}

impl std::fmt::Debug for KeyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyConfig")
            .field("sha256", &self.sha256_hex)
            .finish()
    }
}

impl KeyConfig {
    /// Accepts the configuration only if the copies fetched through two
    /// different relays are identical (spec §3.2).
    pub fn from_two_relays(first: &[u8], second: &[u8]) -> Result<Self, KeyConfigError> {
        if first != second {
            return Err(KeyConfigError::Mismatch);
        }
        Self::from_cache(first)
    }

    /// A configuration the app cached after an earlier two-relay check.
    pub fn from_cache(encoded: &[u8]) -> Result<Self, KeyConfigError> {
        ohttp::ClientRequest::from_encoded_config_list(encoded)
            .map_err(|_| KeyConfigError::Invalid)?;
        let digest = Sha256::digest(encoded);
        Ok(Self {
            encoded: encoded.to_vec(),
            sha256_hex: digest.iter().map(|b| format!("{b:02x}")).collect(),
        })
    }

    /// The bytes, for the app's cache.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Hex SHA-256, as the server publishes it in `info`.
    pub fn sha256_hex(&self) -> &str {
        &self.sha256_hex
    }
}

/// How requests reach the server.
#[derive(Debug, Clone)]
pub enum Transport {
    /// Through an OHTTP relay (required for hosted servers).
    Ohttp(KeyConfig),
    /// Directly to a `.onion` base URL over Tor (self-hosted servers only).
    /// The app must send these requests through Tor.
    Onion,
}

/// A request for the app to send.
///
/// Over OHTTP, POST `body` to a relay that forwards to `url` (the server's
/// gateway); how a relay is addressed is relay-specific. Over Tor, send it
/// to `url` as is. `Debug` hides header values and the body.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

impl std::fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|(n, _)| *n).collect();
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &names)
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl Drop for HttpRequest {
    // Over Tor the headers carry the bearer token, and bodies may carry
    // viewing keys.
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        for (_, v) in &mut self.headers {
            v.zeroize();
        }
        self.body.zeroize();
    }
}

/// What came back, as the app received it. `Debug` hides the body: over
/// Tor it holds events, which are derived from viewing keys (invariant 3).
#[derive(Clone, Copy)]
pub struct HttpResponse<'a> {
    pub status: u16,
    /// The `Retry-After` header, if any. Only used over Tor; over OHTTP it
    /// travels inside the encrypted response.
    pub retry_after: Option<&'a str>,
    pub body: &'a [u8],
}

impl std::fmt::Debug for HttpResponse<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("retry_after", &self.retry_after)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// The decoded response the API layer works with.
pub(crate) struct Inner {
    pub status: u16,
    pub retry_after: Option<u64>,
    pub body: Zeroizing<Vec<u8>>,
}

/// What's needed to open the response.
pub(crate) enum Opener {
    Ohttp(ohttp::ClientResponse),
    Direct,
}

impl std::fmt::Debug for Opener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Opener::Ohttp(_) => "Opener::Ohttp",
            Opener::Direct => "Opener::Direct",
        })
    }
}

/// `scheme://authority` and the base path of a base URL.
fn split_base(base_url: &str) -> (&str, &str, &str) {
    let (scheme, rest) = base_url.split_once("://").unwrap_or(("https", base_url));
    match rest.find('/') {
        Some(i) => (scheme, &rest[..i], &rest[i..]),
        None => (scheme, rest, ""),
    }
}

fn http_date(now_unix_ms: u64) -> String {
    httpdate::fmt_http_date(UNIX_EPOCH + Duration::from_millis(now_unix_ms))
}

/// Builds one request. `path` is the API path (`/v0/...`); `body` is JSON.
pub(crate) fn build(
    transport: &Transport,
    base_url: &str,
    method: &'static str,
    path: &str,
    token: Option<&AccountToken>,
    now_unix_ms: u64,
    body: Option<&[u8]>,
) -> Result<(HttpRequest, Opener), Error> {
    let (scheme, authority, base_path) = split_base(base_url);
    let date = http_date(now_unix_ms);
    match transport {
        Transport::Onion => {
            // The server's direct API takes the same most bytes (spec §3.3).
            if body.is_some_and(|b| b.len() > REQUEST_SIZE) {
                return Err(Error::TooLarge);
            }
            let mut headers = vec![("date", date)];
            if let Some(t) = token {
                headers.push(("authorization", format!("Bearer {}", &*t.encode())));
            }
            if body.is_some() {
                headers.push(("content-type", "application/json".to_owned()));
            }
            let req = HttpRequest {
                method,
                url: format!("{base_url}{path}"),
                headers,
                body: body.map(<[u8]>::to_vec).unwrap_or_default(),
            };
            Ok((req, Opener::Direct))
        }
        Transport::Ohttp(config) => {
            let mut msg = Message::request(
                method.as_bytes().to_vec(),
                scheme.as_bytes().to_vec(),
                authority.as_bytes().to_vec(),
                format!("{base_path}{path}").into_bytes(),
            );
            msg.put_header("date", date);
            if let Some(t) = token {
                let value = Zeroizing::new(format!("Bearer {}", &*t.encode()));
                msg.put_header("authorization", value.as_bytes());
            }
            if let Some(b) = body {
                msg.put_header("content-type", "application/json");
                msg.write_content(b);
            }
            // Holds the token and any viewing keys: padded in place, so no
            // copy escapes zeroing (`pad_bhttp` would drop an oversized one
            // unzeroed).
            let mut padded = Zeroizing::new(Vec::with_capacity(REQUEST_SIZE));
            msg.write_bhttp(Mode::KnownLength, &mut *padded)
                .map_err(|_| Error::TooLarge)?;
            if padded.len() > REQUEST_SIZE {
                return Err(Error::TooLarge);
            }
            padded.resize(REQUEST_SIZE, 0);
            let client = ohttp::ClientRequest::from_encoded_config_list(config.encoded())
                .map_err(|_| Error::Transport)?;
            let (enc, ctx) = client.encapsulate(&padded).map_err(|_| Error::Transport)?;
            let req = HttpRequest {
                method: "POST",
                url: format!("https://{authority}{GATEWAY_PATH}"),
                headers: vec![("content-type", OHTTP_REQUEST_TYPE.to_owned())],
                body: enc,
            };
            Ok((req, Opener::Ohttp(ctx)))
        }
    }
}

/// Opens a response with the matching [`Opener`].
pub(crate) fn open(opener: Opener, resp: HttpResponse<'_>) -> Result<Inner, Error> {
    match opener {
        Opener::Direct => Ok(Inner {
            status: resp.status,
            retry_after: resp.retry_after.and_then(|v| v.trim().parse().ok()),
            body: Zeroizing::new(resp.body.to_vec()),
        }),
        Opener::Ohttp(ctx) => {
            if resp.status != 200 {
                return Err(Error::Relay(resp.status));
            }
            let plain = Zeroizing::new(ctx.decapsulate(resp.body).map_err(|_| Error::Transport)?);
            // Invariant 4: a server must pad every response the same.
            if plain.len() != RESPONSE_SIZE {
                return Err(Error::Transport);
            }
            let mut cursor = Cursor::new(&plain[..]);
            let msg = Message::read_bhttp(&mut cursor).map_err(|_| Error::Transport)?;
            let used = usize::try_from(cursor.position()).map_err(|_| Error::Transport)?;
            if plain[used..].iter().any(|&b| b != 0) {
                return Err(Error::Transport);
            }
            let status = msg
                .control()
                .status()
                .map(u16::from)
                .ok_or(Error::Transport)?;
            let retry_after = msg
                .header()
                .get(b"retry-after")
                .and_then(|v| std::str::from_utf8(v).ok())
                .and_then(|v| v.trim().parse().ok());
            Ok(Inner {
                status,
                retry_after,
                body: Zeroizing::new(msg.content().to_vec()),
            })
        }
    }
}
