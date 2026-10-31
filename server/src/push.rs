//! Scheduled wake-ups (spec §5.1, §5.3).
//!
//! Every 30 minutes, on the half hour, each device gets the same fixed-size
//! ping at a random moment within the first 5 minutes of the slot.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use lz_proto::api::{Ping, PingType};
use lz_proto::padding::pad_ping_json;
use rand::Rng;
use tokio::task::JoinSet;

use crate::AppState;
use crate::ssrf;
use crate::store::Device;

pub const WAKE_INTERVAL: Duration = Duration::from_secs(1800);
/// Pings for one slot are spread over this window.
pub const SPREAD: Duration = Duration::from_secs(300);
/// A wake ping is useless after the next slot.
const WAKE_TTL: Duration = WAKE_INTERVAL;
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
    let ping = Ping {
        v: 0,
        t: PingType::Wake,
        events: vec![],
    };
    pad_ping_json(&serde_json::to_string(&ping).expect("ping serializes"))
        .expect("an empty ping fits")
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
    let body = Arc::new(wake_plaintext());
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
        let state = state.clone();
        let body = body.clone();
        let permits = permits.clone();
        tasks.spawn(async move {
            tokio::time::sleep(delay).await;
            let _permit = permits.acquire_owned().await.expect("semaphore open");
            send(&state, &id, &device, &body).await
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

/// Encrypts `plaintext` to the device (RFC 8291) and delivers it as a
/// scheduled wake (RFC 8030, signed with VAPID). Logs only the device id.
pub async fn send(state: &AppState, device_id: &str, device: &Device, plaintext: &[u8]) -> Outcome {
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
    let Some(request) = build_request(state, device, plaintext) else {
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

fn build_request(state: &AppState, device: &Device, plaintext: &[u8]) -> Option<reqwest::Request> {
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
    let req = http::Request::post(endpoint)
        .header("ttl", WAKE_TTL.as_secs())
        .header("urgency", "normal")
        .header("topic", "wake")
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
