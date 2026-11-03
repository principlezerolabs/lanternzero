//! Webhook delivery (spec §4.5, Standard Webhooks).
//!
//! Wakes on every long-poll release (a block, match, or reorg) and every
//! [`TICK`] for retries, asks the scanner which events' states are due on
//! each account with a webhook, and sends them. Nothing here logs URLs,
//! bodies, or account ids: only counts and status classes.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use reqwest::header::{CONTENT_TYPE, HeaderValue};
use tokio::sync::Semaphore;

use crate::AppState;
use crate::scanner::Due;
use crate::store::Webhook;

/// How often due retries are looked for, besides every release.
pub const TICK: Duration = Duration::from_secs(5);
/// Most deliveries in flight at once, across all accounts.
const MAX_CONCURRENT: usize = 64;

/// Runs forever.
pub async fn run(state: Arc<AppState>) {
    let mut release = state.scanner.subscribe_release();
    let mut tick = tokio::time::interval(TICK);
    let limit = Arc::new(Semaphore::new(MAX_CONCURRENT));
    loop {
        tokio::select! {
            _ = release.changed() => {}
            _ = tick.tick() => {}
        }
        deliver_due(&state, &limit, state.clock.now());
    }
}

/// Starts every delivery due at `now`.
pub fn deliver_due(state: &Arc<AppState>, limit: &Arc<Semaphore>, now: SystemTime) {
    for hook in state.store.webhooks() {
        for due in state.scanner.webhook_due(hook.account, now) {
            let (task_state, limit, hook) = (state.clone(), limit.clone(), hook.clone());
            state.spawn(async move {
                let state = task_state;
                let Ok(_permit) = limit.acquire_owned().await else {
                    return;
                };
                let outcome = send(&state, &hook, &due).await;
                let delivered = outcome == Outcome::Delivered;
                state.scanner.webhook_done(
                    hook.account,
                    &due.event_id,
                    &due.webhook_id,
                    delivered,
                    state.clock.now(),
                );
                if outcome == Outcome::Gone
                    && state.store.delete_webhook_if(hook.account, &hook.secret)
                {
                    state.scanner.clear_webhook_deliveries(hook.account);
                    tracing::info!("webhook answered 410 Gone; deleted it");
                }
            });
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Delivered,
    /// `410 Gone`: the receiver is gone for good (spec §4.5).
    Gone,
    Failed,
}

/// Signs and posts one delivery.
pub async fn send(state: &AppState, hook: &Webhook, due: &Due) -> Outcome {
    let allow_private = state.config.push.allow_private_targets;
    // Checked again here: the URL was fine when set, but the rules may
    // have changed since. Hostnames are checked at connect time
    // (`ssrf::SafeResolver`), against DNS rebinding.
    if crate::ssrf::check_url(&hook.url, allow_private, &[]).is_err() {
        tracing::warn!("webhook URL no longer allowed");
        return Outcome::Failed;
    }
    let Ok(body) = serde_json::to_vec(&due.body) else {
        return Outcome::Failed;
    };
    let timestamp = state.clock.unix_now();
    let signature = lz_proto::webhook::sign(&hook.secret, &due.webhook_id, timestamp, &body);
    let (Ok(id), Ok(signature)) = (
        HeaderValue::from_str(&due.webhook_id),
        HeaderValue::from_str(&signature),
    ) else {
        return Outcome::Failed;
    };
    let request = state
        .http
        .post(&hook.url)
        .header(CONTENT_TYPE, "application/json")
        .header("webhook-id", id)
        .header("webhook-timestamp", timestamp)
        .header("webhook-signature", signature)
        .body(body);
    match request.send().await {
        Ok(resp) => match resp.status().as_u16() {
            200..=299 => Outcome::Delivered,
            410 => Outcome::Gone,
            status => {
                tracing::warn!(status, "webhook receiver error");
                Outcome::Failed
            }
        },
        Err(e) => {
            // reqwest errors can include the URL; print only the kind.
            tracing::warn!(
                timeout = e.is_timeout(),
                connect = e.is_connect(),
                "webhook send failed"
            );
            Outcome::Failed
        }
    }
}
