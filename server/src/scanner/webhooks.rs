//! Webhook delivery state for each event (spec §4.5). The scanner says
//! which events' current states are due ([`Scanner::webhook_due`]); the
//! delivery worker ([`crate::webhook`]) sends them and reports back
//! ([`Scanner::webhook_done`]). Memory only, like the events (invariant 3).

use lz_proto::api::WebhookDelivery;
use lz_proto::event_id::Pool;
use lz_proto::webhook::webhook_id;
use rand::RngExt;

use super::*;

/// How long one state is retried before it is dropped (spec §4.5).
pub const RETRY_WINDOW: Duration = Duration::from_secs(24 * 3600);
/// Waits after each failed try, then [`MAX_BACKOFF`] until the window ends.
const BACKOFF: [Duration; 6] = [
    Duration::from_secs(5),
    Duration::from_secs(5 * 60),
    Duration::from_secs(30 * 60),
    Duration::from_secs(2 * 3600),
    Duration::from_secs(5 * 3600),
    Duration::from_secs(10 * 3600),
];
const MAX_BACKOFF: Duration = Duration::from_secs(10 * 3600);

/// What a delivery reports beyond the event. Derived from a key.
pub(super) struct Payment {
    /// Internal byte order, as in the event id (spec §4.4).
    pub(super) txid: [u8; 32],
    pub(super) pool: Pool,
    pub(super) value: u64,
}

#[derive(Default)]
pub(super) struct Delivery {
    /// The `webhook-id` last delivered, or given up on after its retries.
    settled: Option<String>,
    /// The state being delivered.
    pending: Option<Pending>,
}

struct Pending {
    webhook_id: String,
    first_try: SystemTime,
    tries: usize,
    next_try: SystemTime,
    in_flight: bool,
}

impl Delivery {
    /// A state is waiting to be delivered, or is being delivered.
    pub(super) fn is_pending(&self) -> bool {
        self.pending.is_some()
    }
}

/// One delivery to send. `Debug` hides the body, which holds payment
/// details.
pub struct Due {
    pub event_id: String,
    pub webhook_id: String,
    pub body: WebhookDelivery,
}

impl std::fmt::Debug for Due {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Due")
            .field("webhook_id", &self.webhook_id)
            .finish_non_exhaustive()
    }
}

/// The txid as hex in display order, as block explorers show it.
fn txid_hex(txid: &[u8; 32]) -> String {
    let mut reversed = *txid;
    reversed.reverse();
    lz_proto::hex::encode(&reversed)
}

impl Scanner {
    /// The account's deliveries due at `now`, marked as in flight: every
    /// event whose current state hasn't been delivered, whose retry time
    /// has come, and that isn't already being sent. States retried for
    /// [`RETRY_WINDOW`] are given up on. Call only for accounts with a
    /// webhook.
    pub fn webhook_due(&self, account: AccountId, now: SystemTime) -> Vec<Due> {
        let mut inner = self.lock();
        let Some(acct) = inner.events.get_mut(&account) else {
            return vec![];
        };
        let mut due = Vec::new();
        let mut given_up = 0u32;
        for s in acct.by_id.values_mut() {
            let e = &s.event;
            let id = webhook_id(&e.id, e.status, e.height, e.confirmations);
            if s.delivery.settled.as_deref() == Some(id.as_str()) {
                continue;
            }
            let pending = match &mut s.delivery.pending {
                Some(p) if p.webhook_id == id => p,
                // A new state replaces one still being retried.
                slot => slot.insert(Pending {
                    webhook_id: id.clone(),
                    first_try: now,
                    tries: 0,
                    next_try: now,
                    in_flight: false,
                }),
            };
            if pending.in_flight || pending.next_try > now {
                continue;
            }
            if now
                .duration_since(pending.first_try)
                .is_ok_and(|d| d >= RETRY_WINDOW)
            {
                s.delivery.settled = Some(id);
                s.delivery.pending = None;
                given_up += 1;
                continue;
            }
            pending.in_flight = true;
            pending.tries += 1;
            due.push(Due {
                event_id: e.id.clone(),
                webhook_id: id,
                body: WebhookDelivery {
                    event: e.clone(),
                    txid: txid_hex(&s.payment.txid),
                    pool: s.payment.pool,
                    amount: s.payment.value,
                    // Compact blocks carry no memo, and fetching the full
                    // transaction by txid would show which one matters
                    // (invariant 7).
                    memo: None,
                },
            });
        }
        if given_up > 0 {
            tracing::warn!(given_up, "webhook deliveries dropped after their retries");
        }
        due
    }

    /// Records how a delivery from [`webhook_due`](Self::webhook_due)
    /// went. A delivered final state deletes the event (spec §4.4); a
    /// failure is retried later, with backoff and jitter.
    pub fn webhook_done(
        &self,
        account: AccountId,
        event_id: &str,
        webhook_id: &str,
        delivered: bool,
        now: SystemTime,
    ) {
        let mut inner = self.lock();
        let Some(acct) = inner.events.get_mut(&account) else {
            return;
        };
        let Some(s) = acct.by_id.get_mut(event_id) else {
            return;
        };
        let Some(pending) = s
            .delivery
            .pending
            .as_mut()
            .filter(|p| p.webhook_id == webhook_id)
        else {
            // The event changed while this state was being sent; its new
            // state has its own delivery.
            return;
        };
        if !delivered {
            pending.in_flight = false;
            let wait = BACKOFF
                .get(pending.tries.saturating_sub(1))
                .copied()
                .unwrap_or(MAX_BACKOFF);
            let jitter = rand::rng().random_range(Duration::ZERO..=wait / 10);
            pending.next_try = now + wait + jitter;
            return;
        }
        s.delivery.settled = Some(webhook_id.to_owned());
        s.delivery.pending = None;
        let e = &s.event;
        if e.status == EventStatus::Mined && e.confirmations >= FINALITY_DEPTH {
            acct.by_id.remove(event_id);
            untrack_unfinalized(&mut inner, account, event_id);
        }
    }

    /// Forgets the account's deliveries in progress, after its webhook was
    /// deleted, so its events count toward the cap again.
    pub fn clear_webhook_deliveries(&self, account: AccountId) {
        let mut inner = self.lock();
        if let Some(acct) = inner.events.get_mut(&account) {
            for s in acct.by_id.values_mut() {
                s.delivery = Delivery::default();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txids_are_shown_in_display_order() {
        let mut internal = [0u8; 32];
        internal[0] = 0x01;
        internal[31] = 0xff;
        let shown = txid_hex(&internal);
        assert!(shown.starts_with("ff") && shown.ends_with("01"), "{shown}");
    }
}
