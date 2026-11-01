//! Scheduled wake-ups and payment pushes (spec §5.1–5.3).
//!
//! Every 30 minutes, on the half hour, each device gets a fixed-size ping at
//! a random moment within the first 5 minutes of the slot. Under `private`
//! alerts the ping carries the account's unacknowledged events; it is the
//! same size either way. Under `instant` alerts a match also sends an extra
//! payment push.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use lz_proto::api::{Event, Ping, PingType};
use lz_proto::padding::pad_ping_json;
use rand::RngExt;
use tokio::task::JoinSet;

use crate::AppState;
use crate::ssrf;
use crate::store::{AccountId, Device};

pub const WAKE_INTERVAL: Duration = Duration::from_secs(1800);
/// Pings for one slot are spread over this window.
pub const SPREAD: Duration = Duration::from_secs(300);
/// A wake ping is useless after the next slot.
const WAKE_TTL: Duration = WAKE_INTERVAL;
/// A payment push stays useful for a day.
const PAYMENT_TTL: Duration = Duration::from_secs(86_400);

/// Which kind of push to send (spec §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Scheduled: `Urgency: normal`, `TTL: 1800`, `Topic: wake`.
    Wake,
    /// Instant payment alert: `Urgency: high`, `TTL: 86400`, no topic.
    Payment,
}
/// Most pushes in flight at once.
const MAX_CONCURRENT_SENDS: usize = 256;
/// VAPID tokens must expire within 24 h (RFC 8292 §2); an hour is plenty.
const VAPID_VALIDITY: Duration = Duration::from_secs(3600);

/// The result of one push attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Delivered,
    /// `404`/`410`: the subscription is gone, and the device was removed.
    Gone,
    /// `429`: the gateway asked us to slow down.
    RateLimited,
    Failed,
}

/// Counts from one wake round.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RoundStats {
    pub delivered: usize,
    pub gone: usize,
    pub rate_limited: usize,
    pub failed: usize,
}

/// The fixed scheduled-ping plaintext, padded to 1024 bytes.
pub fn wake_plaintext() -> Vec<u8> {
    ping_plaintext(PingType::Wake, vec![])
}

/// A ping plaintext padded to 1024 bytes. Events never carry `compact_tx`
/// here; if they don't fit (they always should), they are dropped rather
/// than changing the size.
fn ping_plaintext(t: PingType, mut events: Vec<Event>) -> Vec<u8> {
    for e in &mut events {
        e.compact_tx = None;
    }
    loop {
        let ping = Ping {
            v: 0,
            t,
            events: events.clone(),
        };
        let json = serde_json::to_string(&ping).expect("ping serializes");
        if let Ok(p) = pad_ping_json(&json) {
            return p;
        }
        events.pop();
    }
}

/// Runs forever: waits for each half-hour boundary, then sends a round.
pub async fn run(state: Arc<AppState>) {
    loop {
        tokio::time::sleep(until_next_slot(SystemTime::now())).await;
        let stats = wake_round(&state, SPREAD).await;
        tracing::info!(?stats, "wake round finished");
        state.store.flush_if_dirty();
    }
}

fn until_next_slot(now: SystemTime) -> Duration {
    let since = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let interval = WAKE_INTERVAL.as_secs();
    let next = (since.as_secs() / interval + 1) * interval;
    Duration::from_secs(next) - since
}

/// Sends one ping to every device, each after a random delay within `spread`.
pub async fn wake_round(state: &Arc<AppState>, spread: Duration) -> RoundStats {
    let empty = Arc::new(wake_plaintext());
    let mut bodies: std::collections::HashMap<AccountId, Arc<Vec<u8>>> = Default::default();
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SENDS));
    let mut tasks = JoinSet::new();
    let mut stats = RoundStats::default();
    for (id, device) in state.store.devices() {
        // A gateway that sent `429` with `Retry-After` is left alone until
        // then (spec §5.3).
        if state.push_backoff.is_paused(&id, SystemTime::now()) {
            stats.rate_limited += 1;
            continue;
        }
        let delay = if spread.is_zero() {
            Duration::ZERO
        } else {
            rand::rng().random_range(Duration::ZERO..spread)
        };
        // `private` alerts ride in the ping (spec §5.2); everyone else gets
        // the empty one. Same size either way.
        let body = bodies
            .entry(device.account)
            .or_insert_with(|| {
                let events = state.scanner.ping_events(device.account, SystemTime::now());
                if events.is_empty() {
                    empty.clone()
                } else {
                    Arc::new(ping_plaintext(PingType::Wake, events))
                }
            })
            .clone();
        let state = state.clone();
        let permits = permits.clone();
        tasks.spawn(async move {
            tokio::time::sleep(delay).await;
            let _permit = permits.acquire_owned().await.expect("semaphore open");
            send(&state, &id, &device, &body, Kind::Wake).await
        });
    }
    while let Some(res) = tasks.join_next().await {
        match res.unwrap_or(Outcome::Failed) {
            Outcome::Delivered => stats.delivered += 1,
            Outcome::Gone => stats.gone += 1,
            Outcome::RateLimited => stats.rate_limited += 1,
            Outcome::Failed => stats.failed += 1,
        }
    }
    stats
}

/// Sends an instant payment push for `event` to each of the account's
/// devices (spec §5.2). The event goes without `compact_tx`.
pub async fn send_payment(state: &Arc<AppState>, account: AccountId, event: &Event) {
    let body = Arc::new(ping_plaintext(PingType::Payment, vec![event.clone()]));
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SENDS));
    let mut tasks = JoinSet::new();
    let now = SystemTime::now();
    for (id, device) in state.store.devices() {
        if device.account != account || state.push_backoff.is_paused(&id, now) {
            continue;
        }
        let state = state.clone();
        let body = body.clone();
        let permits = permits.clone();
        tasks.spawn(async move {
            let _permit = permits.acquire_owned().await.expect("semaphore open");
            send(&state, &id, &device, &body, Kind::Payment).await
        });
    }
    while tasks.join_next().await.is_some() {}
}

/// Encrypts `plaintext` to the device (RFC 8291) and delivers it (RFC 8030,
/// signed with VAPID). Logs only the device id.
pub async fn send(
    state: &AppState,
    device_id: &str,
    device: &Device,
    plaintext: &[u8],
    kind: Kind,
) -> Outcome {
    let push = &state.config.push;
    if ssrf::check_url(
        &device.endpoint,
        push.allow_private_targets,
        &push.gateway_allowlist,
    )
    .is_err()
    {
        tracing::warn!(device_id, "push endpoint no longer allowed");
        return Outcome::Failed;
    }
    let Some(request) = build_request(state, device, plaintext, kind) else {
        tracing::warn!(device_id, "cannot build push request");
        return Outcome::Failed;
    };
    match state.http.execute(request).await {
        Ok(resp) => match resp.status().as_u16() {
            200..=299 => Outcome::Delivered,
            404 | 410 => {
                state.store.remove_device(device_id);
                Outcome::Gone
            }
            429 => {
                let retry_after = resp
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok());
                state
                    .push_backoff
                    .pause(device_id, retry_after, SystemTime::now(), WAKE_INTERVAL);
                tracing::warn!(device_id, "push gateway rate limited us");
                Outcome::RateLimited
            }
            status => {
                tracing::warn!(device_id, status, "push gateway error");
                Outcome::Failed
            }
        },
        Err(e) => {
            // reqwest errors can include the URL; print only the kind.
            tracing::warn!(
                device_id,
                timeout = e.is_timeout(),
                connect = e.is_connect(),
                "push send failed"
            );
            Outcome::Failed
        }
    }
}

fn build_request(
    state: &AppState,
    device: &Device,
    plaintext: &[u8],
    kind: Kind,
) -> Option<reqwest::Request> {
    let endpoint: http::Uri = device.endpoint.parse().ok()?;
    let ua_public =
        p256::PublicKey::from_sec1_bytes(&URL_SAFE_NO_PAD.decode(&device.p256dh).ok()?).ok()?;
    let auth: [u8; 16] = URL_SAFE_NO_PAD.decode(&device.auth).ok()?.try_into().ok()?;
    let body = crate::webpush::encrypt(plaintext, &ua_public, &auth).ok()?;
    let expires =
        SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() + VAPID_VALIDITY.as_secs();
    let authorization =
        state
            .vapid
            .authorization(&endpoint, expires, &state.config.vapid_contact)?;
    let mut req = http::Request::post(endpoint);
    req = match kind {
        Kind::Wake => req
            .header("ttl", WAKE_TTL.as_secs())
            .header("urgency", "normal")
            .header("topic", "wake"),
        Kind::Payment => req
            .header("ttl", PAYMENT_TTL.as_secs())
            .header("urgency", "high"),
    };
    let req = req
        .header("content-encoding", "aes128gcm")
        .header("content-type", "application/octet-stream")
        .header("authorization", authorization)
        .body(body)
        .ok()?;
    reqwest::Request::try_from(req).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wake_plaintext_is_fixed() {
        let p = wake_plaintext();
        assert_eq!(p.len(), lz_proto::padding::PING_SIZE);
        assert!(p.starts_with(br#"{"v":0,"t":"wake","events":[]}"#));
    }

    #[test]
    fn slots_fall_on_the_half_hour() {
        let at = |s| UNIX_EPOCH + Duration::from_secs(s);
        assert_eq!(until_next_slot(at(0)), Duration::from_secs(1800));
        assert_eq!(until_next_slot(at(1799)), Duration::from_secs(1));
        assert_eq!(until_next_slot(at(1800)), Duration::from_secs(1800));
    }
}
