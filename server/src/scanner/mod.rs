//! The opt-in scanner: viewing-key leases, trial decryption, events, and
//! hints (spec §4.2–4.4, §5.2, §6.1).
//!
//! Everything here lives in memory only (invariants 1–3). Nothing is written
//! to `data_dir` or logged except counts and heights.
//!
//! - **Leases** hold prepared viewing keys and expire after 24 h to 7 days.
//!   `lease: null` drops the lease and the account's events at once.
//! - **Live scanning:** every block the chain follower connects is
//!   trial-decrypted with every active lease's keys.
//! - **Mempool:** [`crate::mempool`] checks each new mempool transaction
//!   the same way, so payments appear as `mempool` events before they are
//!   mined.
//! - **Backfill:** a new lease (or a lease after a restart) is scanned from
//!   its `from_height`, clamped to [`MAX_BACKFILL_BLOCKS`] below the tip,
//!   and against the current mempool.
//!   Payments found this way don't trigger instant pushes: the wallet just
//!   woke and gets them from `wake` or the long-poll.
//! - **Events** are per account, keyed by their deterministic id, and
//!   deleted on acknowledgement or after [`EVENT_TTL`].
//! - **Release rule** (spec §4.3): every new block, match, or reorg bumps a
//!   counter that releases all waiting long-polls, at most once every
//!   [`MIN_RELEASE_GAP`].
//!
//! Layout: `leases` and `events` hold the [`Scanner`] methods for each;
//! `release` spaces out long-poll releases;
//! `decrypt` does trial decryption; `live` runs scanning, backfills, and
//! instant pushes.

mod decrypt;
mod events;
mod leases;
mod live;
mod release;
mod webhooks;

pub use decrypt::{MEMO_LEN, Match, Memo, trial_decrypt, trial_decrypt_txs};
pub(crate) use decrypt::{memo_of, trial_decrypt_txs_refs};
pub use live::{
    PAYMENT_PUSHES_PER_MINUTE, alert, backfill, run, scan_block, scan_block_at, scan_blocks,
    scan_blocks_at, sweep_loop,
};
pub use release::MIN_RELEASE_GAP;
pub use webhooks::{Due, RETRY_WINDOW};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use lz_proto::api::{Event, EventKind, EventStatus, Hint, LeaseStatus, MAX_PING_EVENTS};
use lz_proto::event_id::event_id;
use lz_proto::lease::{AlertMode, LeaseRequest};
use prost::Message as _;
use tokio::sync::{Semaphore, watch};
use zcash_client_backend::proto::compact_formats::{CompactBlock, CompactTx};
use zeroize::Zeroizing;

use crate::store::AccountId;
use crate::viewkey::ScanKeys;

/// Unacknowledged events are deleted this long after creation (invariant 3).
pub const EVENT_TTL: Duration = Duration::from_secs(7 * 86_400);
/// Deepest backfill: 7 days of 25-second blocks (after NU7).
pub const MAX_BACKFILL_BLOCKS: u64 = 7 * 86_400 / 25;
/// Confirmations after which an event stops changing. A placeholder until
/// post-NU7 reorg behavior is known (spec §9).
pub const FINALITY_DEPTH: u32 = 10;
/// Most mempool data kept for checking new leases against, in encoded
/// `CompactTx` bytes. A spam wave can't exhaust memory; past this, new
/// transactions are still scanned live, just not kept.
const MAX_MEMPOOL_BYTES: usize = 64 * 1024 * 1024;
/// Backfills running at once, to spare the chain source.
const MAX_CONCURRENT_BACKFILLS: usize = 4;
/// Unacknowledged events kept per account; oldest drop when over (spec §6.1).
pub const MAX_EVENTS_PER_ACCOUNT: usize = 1024;
/// Chain blocks trial-decrypted together after coalescing broadcasts.
const BLOCK_COALESCE: usize = 8;

struct Lease {
    keys: Arc<ScanKeys>,
    expires_at: SystemTime,
    alert_mode: AlertMode,
    /// Changes whenever the keys do, so a backfill can tell its lease was
    /// replaced or ended.
    generation: u64,
    /// No backfill has been started yet (the tip was unknown at the start).
    needs_backfill: bool,
}

#[derive(Default)]
struct MempoolSnapshot {
    txs: HashMap<Vec<u8>, Arc<CompactTx>>,
    bytes: usize,
}

struct Stored {
    event: Event,
    /// Position in the account's update order; cursors refer to it.
    seq: u64,
    created: SystemTime,
    /// Cached JSON size for paging without reserializing under the lock.
    json_len: usize,
    /// What a webhook delivery reports beyond the event (spec §4.5).
    payment: webhooks::Payment,
    /// Webhook delivery of the event's current state, on accounts with a
    /// webhook (spec §4.5).
    delivery: webhooks::Delivery,
}

#[derive(Default)]
struct AccountEvents {
    last_seq: u64,
    by_id: HashMap<String, Stored>,
}

#[derive(Default)]
struct Inner {
    leases: HashMap<AccountId, Lease>,
    events: HashMap<AccountId, AccountEvents>,
    next_generation: u64,
    /// Mined events still gaining confirmations (spec §4.3 finality).
    unfinalized: Vec<(AccountId, String)>,
}

/// Scanner state, shared through [`crate::AppState`].
pub struct Scanner {
    /// Server secret for event ids (spec §4.4).
    secret: Zeroizing<[u8; 32]>,
    inner: Mutex<Inner>,
    /// The current mempool in compact form, by txid. Public chain data, not
    /// key-derived.
    mempool: Mutex<MempoolSnapshot>,
    release: Arc<release::Release>,
    backfills: Arc<Semaphore>,
}

impl std::fmt::Debug for Scanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scanner").finish_non_exhaustive()
    }
}

/// Work a new lease needs: scanning `from..=to` with its keys.
#[derive(Debug)]
pub struct Backfill {
    pub account: AccountId,
    pub keys: Arc<ScanKeys>,
    pub generation: u64,
    pub from: u64,
    pub to: u64,
}

/// A page of events and the cursor after it.
#[derive(Debug)]
pub struct Page {
    pub events: Vec<Event>,
    pub cursor: u64,
    /// More events remain after `cursor`.
    pub more: bool,
}

impl Scanner {
    pub fn new(secret: Zeroizing<[u8; 32]>) -> Self {
        Self {
            secret,
            inner: Mutex::new(Inner::default()),
            mempool: Mutex::new(MempoolSnapshot::default()),
            release: release::Release::new(),
            backfills: Arc::new(Semaphore::new(MAX_CONCURRENT_BACKFILLS)),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic while holding the lock leaves plain data behind; keep going.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Drops expired leases and events older than [`EVENT_TTL`].
    pub fn sweep(&self, now: SystemTime) {
        let mut inner = self.lock();
        drop_expired_leases(&mut inner, now);
        for acct in inner.events.values_mut() {
            acct.by_id.retain(|_, s| s.created + EVENT_TTL > now);
        }
        inner.events.retain(|_, a| !a.by_id.is_empty());
        let Inner {
            events,
            unfinalized,
            ..
        } = &mut *inner;
        unfinalized.retain(|(account, id)| {
            events
                .get(account)
                .is_some_and(|a| a.by_id.contains_key(id))
        });
    }

    /// Replaces the mempool snapshot (a new stream starts with the whole
    /// mempool).
    pub fn mempool_clear(&self) {
        *self.mempool.lock().unwrap_or_else(|e| e.into_inner()) = MempoolSnapshot::default();
    }

    /// Adds a transaction to the mempool snapshot. Beyond
    /// [`MAX_MEMPOOL_BYTES`], new ones are scanned live but not kept.
    pub fn mempool_insert(&self, tx: Arc<CompactTx>) {
        let size = tx.encoded_len();
        let mut m = self.mempool.lock().unwrap_or_else(|e| e.into_inner());
        if m.txs.contains_key(&tx.txid) || m.bytes + size > MAX_MEMPOOL_BYTES {
            return;
        }
        m.bytes += size;
        m.txs.insert(tx.txid.clone(), tx);
    }

    /// The current mempool snapshot.
    pub fn mempool_snapshot(&self) -> Vec<Arc<CompactTx>> {
        self.mempool
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .txs
            .values()
            .cloned()
            .collect()
    }

    /// Releases every waiting long-poll (spec §4.3): now, or once
    /// [`MIN_RELEASE_GAP`] has passed since the last release.
    pub fn release(&self) {
        self.release.trigger();
    }

    pub fn subscribe_release(&self) -> watch::Receiver<u64> {
        self.release.subscribe()
    }
}

fn drop_expired_leases(inner: &mut Inner, now: SystemTime) {
    inner.leases.retain(|_, l| l.expires_at > now);
}

fn maybe_trim_events(inner: &mut Inner, account: AccountId) {
    let mut dropped = 0u32;
    while inner
        .events
        .get(&account)
        .is_some_and(|a| a.by_id.len() > MAX_EVENTS_PER_ACCOUNT)
    {
        // Events still being delivered to a webhook are kept until delivered
        // or given up on, so a merchant isn't silently denied a payment
        // (spec §6.1). Until then the account may hold more than the cap.
        let drop_id = inner.events.get(&account).and_then(|acct| {
            acct.by_id
                .iter()
                .filter(|(_, s)| !s.delivery.is_pending())
                .min_by_key(|(_, s)| (s.created, s.seq))
                .map(|(id, _)| id.clone())
        });
        let Some(drop_id) = drop_id else {
            break;
        };
        if let Some(acct) = inner.events.get_mut(&account) {
            acct.by_id.remove(&drop_id);
        }
        untrack_unfinalized(inner, account, &drop_id);
        dropped += 1;
    }
    if dropped > 0 {
        // No account id: it would tie that account to scanning mode in the
        // logs (invariant 4).
        tracing::info!(dropped, "event cap discarded oldest events");
    }
}

fn untrack_unfinalized(inner: &mut Inner, account: AccountId, id: &str) {
    inner
        .unfinalized
        .retain(|(a, i)| !(*a == account && i == id));
}

fn track_unfinalized(inner: &mut Inner, account: AccountId, id: &str, conf: u32) {
    if conf >= FINALITY_DEPTH {
        untrack_unfinalized(inner, account, id);
        return;
    }
    if !inner
        .unfinalized
        .iter()
        .any(|(a, i)| *a == account && i == id)
    {
        inner.unfinalized.push((account, id.to_owned()));
    }
}

fn confirmations(height: u64, tip: u64) -> u32 {
    let c = tip.saturating_sub(height).saturating_add(1);
    u32::try_from(c).unwrap_or(u32::MAX).min(FINALITY_DEPTH)
}

fn json_len(event: &Event) -> usize {
    serde_json::to_vec(event).map_or(usize::MAX / 2, |v| v.len())
}

fn rfc3339(t: SystemTime) -> String {
    let secs = crate::clock::unix_secs(t);
    time::OffsetDateTime::from_unix_timestamp(secs as i64)
        .ok()
        .and_then(|d| {
            d.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}
