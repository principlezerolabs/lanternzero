//! What the relay remembers about gateways: whether each opted in, and its
//! key configuration. Both are about gateways, never about clients, and
//! both live in memory only.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use axum::body::Bytes;

use crate::origin::Origin;
use crate::{AppState, read_capped};

/// Most gateways remembered in each table. Each new gateway costs one
/// outbound request and is rate-limited per client, so this only bounds
/// memory if many clients name many gateways.
const MAX_ENTRIES: usize = 10_000;
/// Largest `?allowed_purposes` answer read.
const MAX_PURPOSES_BODY: usize = 4096;
/// Largest key configuration read. One key is a few dozen bytes; this
/// leaves room for many.
pub const MAX_KEY_CONFIG: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// The gateway declares one of the relay's purposes.
    Allowed,
    /// It answered, but doesn't declare one.
    Refused,
    /// It couldn't be asked: unreachable, timed out, or a disallowed
    /// address.
    Unreachable,
}

/// A table of gateway answers that expire.
#[derive(Debug)]
struct Table<T> {
    entries: Mutex<HashMap<Origin, Entry<T>>>,
}

#[derive(Debug, Clone)]
struct Entry<T> {
    value: T,
    fetched: Instant,
    expires: Instant,
}

impl<T: Clone> Table<T> {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn get(&self, origin: &Origin, now: Instant) -> Option<T> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries
            .get(origin)
            .filter(|e| e.expires > now)
            .map(|e| e.value.clone())
    }

    fn insert(&self, origin: Origin, value: T, now: Instant, ttl: std::time::Duration) {
        if ttl.is_zero() {
            return;
        }
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() >= MAX_ENTRIES && !entries.contains_key(&origin) {
            entries.retain(|_, e| e.expires > now);
            if entries.len() >= MAX_ENTRIES {
                return;
            }
        }
        entries.insert(
            origin,
            Entry {
                value,
                fetched: now,
                expires: now + ttl,
            },
        );
    }

    /// Drops the entry if it was fetched at least `age` ago.
    fn remove_if_older(&self, origin: &Origin, now: Instant, age: std::time::Duration) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries
            .get(origin)
            .is_some_and(|e| now.saturating_duration_since(e.fetched) >= age)
        {
            entries.remove(origin);
        }
    }
}

#[derive(Debug)]
pub struct Gateways {
    admission: Table<Admission>,
    keys: Table<Bytes>,
}

impl Default for Gateways {
    fn default() -> Self {
        Self {
            admission: Table::new(),
            keys: Table::new(),
        }
    }
}

impl Gateways {
    /// Whether the relay may forward to `origin`, asking it on first use.
    pub async fn admission(&self, state: &AppState, origin: &Origin) -> Admission {
        let now = state.clock.now();
        if let Some(a) = self.admission.get(origin, now) {
            return a;
        }
        let a = probe(state, origin).await;
        let t = &state.timing;
        let ttl = match a {
            Admission::Allowed => t.opted_in,
            Admission::Refused => t.opted_out,
            Admission::Unreachable => t.unreachable,
        };
        self.admission
            .insert(origin.clone(), a, state.clock.now(), ttl);
        a
    }

    /// The gateway's key configuration: the cached copy, so every client
    /// gets the same bytes, or a fresh one. `None` if it can't be fetched.
    pub async fn key_config(&self, state: &AppState, origin: &Origin) -> Option<Bytes> {
        let now = state.clock.now();
        if let Some(k) = self.keys.get(origin, now) {
            return Some(k);
        }
        let (bytes, max_age) = fetch_key_config(state, origin).await?;
        let ttl = max_age.map_or(state.timing.key_max_age, |m| {
            m.min(state.timing.key_max_age)
        });
        self.keys
            .insert(origin.clone(), bytes.clone(), state.clock.now(), ttl);
        Some(bytes)
    }

    /// The gateway said a client used a key it doesn't know (spec §3.2):
    /// it may have dropped its old key. Drop the cached configuration so the
    /// next fetch gets the new one, unless it is fresh; so a stream of bad
    /// requests can't make the relay fetch more than once per
    /// `key_refetch_after`.
    pub fn key_rejected(&self, state: &AppState, origin: &Origin) {
        self.keys
            .remove_if_older(origin, state.clock.now(), state.timing.key_refetch_after);
    }
}

async fn probe(state: &AppState, origin: &Origin) -> Admission {
    let resp = state
        .http
        .get(origin.purposes_url())
        .timeout(state.timing.probe_timeout)
        .send()
        .await;
    let Ok(resp) = resp else {
        return Admission::Unreachable;
    };
    if !resp.status().is_success() {
        return Admission::Refused;
    }
    let Ok(body) = read_capped(resp, MAX_PURPOSES_BODY).await else {
        return Admission::Refused;
    };
    match parse_purposes(&body) {
        Some(list)
            if list.iter().any(|p| {
                state
                    .config
                    .purposes
                    .iter()
                    .any(|ours| ours.as_bytes() == *p)
            }) =>
        {
            Admission::Allowed
        }
        _ => Admission::Refused,
    }
}

/// Parses `?allowed_purposes`: a 2-byte count, then each purpose as a
/// 1-byte length and its bytes (the format payjoin-mailroom reads, and
/// `server/src/gateway.rs` writes). `None` if malformed.
pub fn parse_purposes(mut b: &[u8]) -> Option<Vec<&[u8]>> {
    let (count, rest) = b.split_first_chunk::<2>()?;
    b = rest;
    let mut out = Vec::new();
    for _ in 0..u16::from_be_bytes(*count) {
        let (&len, rest) = b.split_first()?;
        let len = usize::from(len);
        if rest.len() < len {
            return None;
        }
        out.push(&rest[..len]);
        b = &rest[len..];
    }
    b.is_empty().then_some(out)
}

async fn fetch_key_config(
    state: &AppState,
    origin: &Origin,
) -> Option<(Bytes, Option<std::time::Duration>)> {
    let resp = state
        .http
        .get(origin.gateway_url())
        .header(http::header::ACCEPT, "application/ohttp-keys")
        .timeout(state.timing.probe_timeout)
        .send()
        .await
        .ok()?;
    if resp.status() != http::StatusCode::OK {
        return None;
    }
    let headers = resp.headers();
    let is_keys = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/ohttp-keys"));
    if !is_keys {
        return None;
    }
    let max_age = headers
        .get(http::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .and_then(cache_max_age);
    let body = read_capped(resp, MAX_KEY_CONFIG).await.ok()?;
    if body.is_empty() {
        return None;
    }
    Some((body, max_age))
}

/// The time a `Cache-Control` value allows caching for: `max-age`, or zero
/// for `no-store` and `no-cache`. `None` if it says neither.
pub fn cache_max_age(value: &str) -> Option<std::time::Duration> {
    let mut max_age = None;
    for d in value.split(',').map(str::trim) {
        if d.eq_ignore_ascii_case("no-store") || d.eq_ignore_ascii_case("no-cache") {
            return Some(std::time::Duration::ZERO);
        }
        if let Some((name, v)) = d.split_once('=')
            && name.trim().eq_ignore_ascii_case("max-age")
        {
            max_age = v
                .trim()
                .trim_matches('"')
                .parse::<u64>()
                .ok()
                .map(std::time::Duration::from_secs);
        }
    }
    max_age
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn parses_purpose_lists() {
        let mut b = vec![0, 2];
        b.push(3);
        b.extend_from_slice(b"abc");
        b.push(0);
        assert_eq!(parse_purposes(&b), Some(vec![&b"abc"[..], &b""[..]]));
        assert_eq!(parse_purposes(&[0, 0]), Some(vec![]));
        for bad in [&[][..], &[0], &[0, 1], &[0, 1, 4, b'a'], &[0, 0, 9]] {
            assert_eq!(parse_purposes(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn reads_cache_control() {
        assert_eq!(
            cache_max_age("max-age=86400"),
            Some(Duration::from_secs(86400))
        );
        assert_eq!(
            cache_max_age("public, Max-Age=60"),
            Some(Duration::from_secs(60))
        );
        assert_eq!(cache_max_age("no-store"), Some(Duration::ZERO));
        assert_eq!(cache_max_age("max-age=60, no-cache"), Some(Duration::ZERO));
        assert_eq!(cache_max_age("public"), None);
        assert_eq!(cache_max_age("max-age=soon"), None);
    }
}
