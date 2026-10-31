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
//!   counter that releases all waiting long-polls.

mod decrypt;
mod live;

pub(crate) use decrypt::trial_decrypt_txs_refs;
pub use decrypt::{Match, trial_decrypt, trial_decrypt_txs};
pub use live::{
    PAYMENT_PUSHES_PER_MINUTE, alert, backfill, run, scan_block, scan_blocks, sweep_loop,
};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

/// Scanner state, shared through [`AppState`].
pub struct Scanner {
    /// Server secret for event ids (spec §4.4).
    secret: Zeroizing<[u8; 32]>,
    inner: Mutex<Inner>,
    /// The current mempool in compact form, by txid. Public chain data, not
    /// key-derived.
    mempool: Mutex<MempoolSnapshot>,
    release: watch::Sender<u64>,
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
            release: watch::channel(0).0,
            backfills: Arc::new(Semaphore::new(MAX_CONCURRENT_BACKFILLS)),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic while holding the lock leaves plain data behind; keep going.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Starts or renews a lease. Same keys: the expiry and alert mode are
    /// updated. New keys (or no lease before): returns the backfill to run.
    pub fn set_lease(
        &self,
        account: AccountId,
        keys: ScanKeys,
        req: &LeaseRequest,
        duration: Duration,
        tip: u64,
        now: SystemTime,
    ) -> Option<Backfill> {
        let mut inner = self.lock();
        drop_expired_leases(&mut inner, now);
        let expires_at = now + duration;
        let from = req
            .from_height
            .max(tip.saturating_sub(MAX_BACKFILL_BLOCKS))
            .max(1);
        let can_backfill = tip > 0 && from <= tip;
        if let Some(lease) = inner.leases.get_mut(&account)
            && lease.expires_at > now
            && lease.keys.same_keys(&keys)
        {
            lease.expires_at = expires_at;
            lease.alert_mode = req.alert_mode;
            if !(lease.needs_backfill && can_backfill) {
                return None;
            }
            lease.needs_backfill = false;
            return Some(Backfill {
                account,
                keys: lease.keys.clone(),
                generation: lease.generation,
                from,
                to: tip,
            });
        }
        inner.next_generation += 1;
        let generation = inner.next_generation;
        let keys = Arc::new(keys);
        inner.leases.insert(
            account,
            Lease {
                keys: keys.clone(),
                expires_at,
                alert_mode: req.alert_mode,
                generation,
                needs_backfill: !can_backfill,
            },
        );
        can_backfill.then_some(Backfill {
            account,
            keys,
            generation,
            from,
            to: tip,
        })
    }

    /// Opt-out (`lease: null`): drops the lease, its keys, and the account's
    /// events and hints at once.
    pub fn end_lease(&self, account: AccountId) {
        let mut inner = self.lock();
        drop_expired_leases(&mut inner, SystemTime::now());
        inner.leases.remove(&account);
        inner.events.remove(&account);
        inner.unfinalized.retain(|(a, _)| *a != account);
    }

    pub fn lease_status(&self, account: AccountId, now: SystemTime) -> LeaseStatus {
        let mut inner = self.lock();
        drop_expired_leases(&mut inner, now);
        match inner.leases.get(&account).filter(|l| l.expires_at > now) {
            Some(l) => LeaseStatus {
                active: true,
                expires_at: Some(rfc3339(l.expires_at)),
            },
            None => LeaseStatus {
                active: false,
                expires_at: None,
            },
        }
    }

    /// Whether the account has an active (unexpired) lease.
    pub fn has_lease(&self, account: AccountId) -> bool {
        let now = SystemTime::now();
        let mut inner = self.lock();
        drop_expired_leases(&mut inner, now);
        inner.leases.contains_key(&account)
    }

    /// Deletes acknowledged events (and so their hints) for the account.
    pub fn ack(&self, account: AccountId, ids: &[String]) {
        if ids.is_empty() {
            return;
        }
        let mut inner = self.lock();
        if let Some(acct) = inner.events.get_mut(&account) {
            for id in ids {
                acct.by_id.remove(id);
            }
        }
        for id in ids {
            untrack_unfinalized(&mut inner, account, id);
        }
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

    /// Generation of an active lease, for a backfill that must stop if the
    /// lease is replaced.
    fn lease_generation(&self, account: AccountId) -> Option<u64> {
        self.lock().leases.get(&account).map(|l| l.generation)
    }

    /// The keys of every active lease.
    pub fn active_keys(&self, now: SystemTime) -> Vec<(AccountId, Arc<ScanKeys>)> {
        let mut inner = self.lock();
        drop_expired_leases(&mut inner, now);
        inner
            .leases
            .iter()
            .map(|(a, l)| (*a, l.keys.clone()))
            .collect()
    }

    fn is_current(&self, account: AccountId, generation: u64, now: SystemTime) -> bool {
        self.lock()
            .leases
            .get(&account)
            .is_some_and(|l| l.generation == generation && l.expires_at > now)
    }

    /// Records matches from a block at `height`. Returns the events that are
    /// new, for alerts. Accounts without an active lease are skipped.
    pub fn record(
        &self,
        block: &CompactBlock,
        matches: &[Match],
        tip: u64,
        now: SystemTime,
    ) -> Vec<(AccountId, Event)> {
        let mut new = Vec::new();
        let mut inner = self.lock();
        for m in matches {
            if inner
                .leases
                .get(&m.account)
                .is_none_or(|l| l.expires_at <= now)
            {
                continue;
            }
            let Some(tx) = block.vtx.get(m.tx) else {
                continue;
            };
            let Ok(txid) = <[u8; 32]>::try_from(&tx.txid[..]) else {
                continue;
            };
            let id = event_id(&self.secret[..], &m.account, &txid, m.pool, m.index);
            let confirmations = confirmations(block.height, tip);
            let compact_tx = URL_SAFE_NO_PAD.encode(tx.encode_to_vec());
            let acct = inner.events.entry(m.account).or_default();
            match acct.by_id.get_mut(&id) {
                Some(s) => {
                    let e = &mut s.event;
                    if e.status == EventStatus::Mined && e.height == Some(block.height) {
                        continue;
                    }
                    e.status = EventStatus::Mined;
                    e.height = Some(block.height);
                    e.confirmations = confirmations;
                    // The block's copy has the transaction's real index.
                    e.compact_tx = Some(compact_tx.clone());
                    e.rev += 1;
                    acct.last_seq += 1;
                    s.seq = acct.last_seq;
                    s.json_len = json_len(e);
                    untrack_unfinalized(&mut inner, m.account, &id);
                    track_unfinalized(&mut inner, m.account, &id, confirmations);
                }
                None => {
                    let event = Event {
                        id: id.clone(),
                        rev: 1,
                        kind: EventKind::Received,
                        status: EventStatus::Mined,
                        height: Some(block.height),
                        confirmations,
                        compact_tx: Some(compact_tx),
                    };
                    let json_len = json_len(&event);
                    acct.last_seq += 1;
                    new.push((m.account, event.clone()));
                    acct.by_id.insert(
                        id.clone(),
                        Stored {
                            event,
                            seq: acct.last_seq,
                            created: now,
                            json_len,
                        },
                    );
                    track_unfinalized(&mut inner, m.account, &id, confirmations);
                    maybe_trim_events(&mut inner, m.account);
                }
            }
        }
        new
    }

    /// Records matches in a mempool transaction as `mempool` events. Returns
    /// the new ones, for alerts. An event already known keeps its status,
    /// except that a `reorged` one moves back to `mempool` (spec §4.3).
    pub fn record_mempool(
        &self,
        tx: &CompactTx,
        matches: &[Match],
        now: SystemTime,
    ) -> Vec<(AccountId, Event)> {
        let Ok(txid) = <[u8; 32]>::try_from(&tx.txid[..]) else {
            return vec![];
        };
        let mut new = Vec::new();
        let mut inner = self.lock();
        for m in matches {
            if inner
                .leases
                .get(&m.account)
                .is_none_or(|l| l.expires_at <= now)
            {
                continue;
            }
            let id = event_id(&self.secret[..], &m.account, &txid, m.pool, m.index);
            let acct = inner.events.entry(m.account).or_default();
            match acct.by_id.get_mut(&id) {
                Some(s) if s.event.status == EventStatus::Reorged => {
                    s.event.status = EventStatus::Mempool;
                    s.event.rev += 1;
                    acct.last_seq += 1;
                    s.seq = acct.last_seq;
                    s.json_len = json_len(&s.event);
                }
                Some(_) => {}
                None => {
                    let event = Event {
                        id: id.clone(),
                        rev: 1,
                        kind: EventKind::Received,
                        status: EventStatus::Mempool,
                        height: None,
                        confirmations: 0,
                        compact_tx: Some(URL_SAFE_NO_PAD.encode(tx.encode_to_vec())),
                    };
                    let json_len = json_len(&event);
                    acct.last_seq += 1;
                    new.push((m.account, event.clone()));
                    acct.by_id.insert(
                        id,
                        Stored {
                            event,
                            seq: acct.last_seq,
                            created: now,
                            json_len,
                        },
                    );
                    maybe_trim_events(&mut inner, m.account);
                }
            }
        }
        new
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

    /// Updates confirmations after the tip moved to `tip`.
    pub fn on_tip(&self, tip: u64) {
        let mut inner = self.lock();
        let pending: Vec<_> = inner.unfinalized.clone();
        let mut done = Vec::new();
        for (account, id) in pending {
            let Some(acct) = inner.events.get_mut(&account) else {
                done.push((account, id));
                continue;
            };
            let Some(s) = acct.by_id.get_mut(&id) else {
                done.push((account, id));
                continue;
            };
            let Some(h) = s.event.height else {
                done.push((account, id));
                continue;
            };
            let c = confirmations(h, tip);
            if c != s.event.confirmations {
                s.event.confirmations = c;
                s.event.rev += 1;
                acct.last_seq += 1;
                s.seq = acct.last_seq;
                s.json_len = json_len(&s.event);
            }
            if c >= FINALITY_DEPTH {
                done.push((account, id));
            }
        }
        for (account, id) in done {
            untrack_unfinalized(&mut inner, account, &id);
        }
    }

    /// Marks events in a block that left the best chain as `reorged`.
    pub fn on_disconnect(&self, height: u64) {
        let mut inner = self.lock();
        let accounts: Vec<AccountId> = inner.events.keys().copied().collect();
        let mut remove_unfinalized = Vec::new();
        for account in accounts {
            let Some(acct) = inner.events.get_mut(&account) else {
                continue;
            };
            let ids: Vec<String> = acct
                .by_id
                .iter()
                .filter(|(_, s)| s.event.height == Some(height))
                .map(|(id, _)| id.clone())
                .collect();
            for id in ids {
                if let Some(s) = acct.by_id.get_mut(&id) {
                    let e = &mut s.event;
                    e.status = EventStatus::Reorged;
                    e.height = None;
                    e.confirmations = 0;
                    e.rev += 1;
                    acct.last_seq += 1;
                    s.seq = acct.last_seq;
                    s.json_len = json_len(e);
                }
                remove_unfinalized.push((account, id));
            }
        }
        for (account, id) in remove_unfinalized {
            untrack_unfinalized(&mut inner, account, &id);
        }
    }

    /// Events after `after` (all unacknowledged events if `None`), in update
    /// order, as many as fit in `budget` bytes of JSON. An event too large
    /// for a page on its own is sent without its `compact_tx`.
    pub fn page(&self, account: AccountId, after: Option<u64>, budget: usize) -> Page {
        let inner = self.lock();
        let Some(acct) = inner.events.get(&account) else {
            return Page {
                events: vec![],
                cursor: after.unwrap_or(0),
                more: false,
            };
        };
        let mut pending: Vec<&Stored> = acct
            .by_id
            .values()
            .filter(|s| after.is_none_or(|a| s.seq > a))
            .collect();
        pending.sort_unstable_by_key(|s| s.seq);
        let mut events = Vec::new();
        let mut used = 2; // `[]`
        let mut cursor = after.unwrap_or(acct.last_seq);
        let mut taken = 0;
        for s in &pending {
            let mut event = s.event.clone();
            let mut size = s.json_len + 1;
            if size > budget.saturating_sub(2) {
                event.compact_tx = None;
                size = json_len(&event) + 1;
            }
            if used + size > budget {
                break;
            }
            used += size;
            cursor = s.seq;
            events.push(event);
            taken += 1;
        }
        if taken == pending.len() {
            cursor = cursor.max(acct.last_seq);
        }
        Page {
            events,
            cursor,
            more: taken < pending.len(),
        }
    }

    /// Whether the account has events after `after`.
    pub fn has_after(&self, account: AccountId, after: u64) -> bool {
        self.lock()
            .events
            .get(&account)
            .is_some_and(|a| a.by_id.values().any(|s| s.seq > after))
    }

    /// Half-open height ranges holding the account's mined events.
    pub fn hints(&self, account: AccountId) -> Vec<Hint> {
        let inner = self.lock();
        let mut heights: Vec<u64> = inner
            .events
            .get(&account)
            .map(|a| a.by_id.values().filter_map(|s| s.event.height).collect())
            .unwrap_or_default();
        heights.sort_unstable();
        heights.dedup();
        let mut hints: Vec<Hint> = Vec::new();
        for h in heights {
            match hints.last_mut() {
                Some(last) if last.end == h => last.end = h + 1,
                _ => hints.push(Hint {
                    start: h,
                    end: h + 1,
                }),
            }
        }
        hints
    }

    /// Events for the next scheduled ping of a `private`-mode lease (spec
    /// §5.2): up to [`MAX_PING_EVENTS`] unacknowledged ones, oldest first,
    /// without `compact_tx`. Empty for other accounts.
    pub fn ping_events(&self, account: AccountId, now: SystemTime) -> Vec<Event> {
        let inner = self.lock();
        let private = inner
            .leases
            .get(&account)
            .is_some_and(|l| l.expires_at > now && l.alert_mode == AlertMode::Private);
        if !private {
            return vec![];
        }
        let mut stored: Vec<&Stored> = inner
            .events
            .get(&account)
            .map(|a| a.by_id.values().collect())
            .unwrap_or_default();
        stored.sort_unstable_by_key(|s| (s.created, s.seq));
        stored
            .into_iter()
            .take(MAX_PING_EVENTS)
            .map(|s| Event {
                compact_tx: None,
                ..s.event.clone()
            })
            .collect()
    }

    pub fn alert_mode(&self, account: AccountId) -> Option<AlertMode> {
        let now = SystemTime::now();
        let mut inner = self.lock();
        drop_expired_leases(&mut inner, now);
        inner.leases.get(&account).map(|l| l.alert_mode)
    }

    /// Releases every waiting long-poll (spec §4.3).
    pub fn release(&self) {
        self.release.send_modify(|g| *g = g.wrapping_add(1));
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
        let drop_id = inner.events.get(&account).and_then(|acct| {
            acct.by_id
                .iter()
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
        let account_hex: String = account.iter().map(|b| format!("{b:02x}")).collect();
        tracing::info!(account = %account_hex, dropped, "event cap discarded oldest events");
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
    let secs = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    time::OffsetDateTime::from_unix_timestamp(secs as i64)
        .ok()
        .and_then(|d| {
            d.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}
