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
//! - **Backfill:** a new lease (or a lease after a restart) is scanned from
//!   its `from_height`, clamped to [`MAX_BACKFILL_BLOCKS`] below the tip.
//!   Payments found this way don't trigger instant pushes: the wallet just
//!   woke and gets them from `wake` or the long-poll.
//! - **Events** are per account, keyed by their deterministic id, and
//!   deleted on acknowledgement or after [`EVENT_TTL`].
//! - **Release rule** (spec §4.3): every new block, match, or reorg bumps a
//!   counter that releases all waiting long-polls.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use lz_proto::api::{Event, EventKind, EventStatus, Hint, LeaseStatus};
use lz_proto::event_id::{Pool, event_id};
use lz_proto::lease::{AlertMode, LeaseRequest};
use prost::Message as _;
use tokio::sync::{Semaphore, broadcast, watch};
use zcash_client_backend::proto::compact_formats::{CompactBlock, CompactOrchardAction};
use zcash_note_encryption::EphemeralKeyBytes;
use zcash_note_encryption::batch::try_compact_note_decryption;
use zeroize::Zeroizing;

use crate::AppState;
use crate::chain::{BATCH, ChainEvent};
use crate::store::AccountId;
use crate::viewkey::ScanKeys;

/// Unacknowledged events are deleted this long after creation (invariant 3).
pub const EVENT_TTL: Duration = Duration::from_secs(7 * 86_400);
/// Deepest backfill: 7 days of 25-second blocks (after NU7).
pub const MAX_BACKFILL_BLOCKS: u64 = 7 * 86_400 / 25;
/// Confirmations after which an event stops changing. A placeholder until
/// post-NU7 reorg behavior is known (spec §9).
pub const FINALITY_DEPTH: u32 = 10;
/// Backfills running at once, to spare the chain source.
const MAX_CONCURRENT_BACKFILLS: usize = 4;
use lz_proto::api::MAX_PING_EVENTS;

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

struct Stored {
    event: Event,
    /// Position in the account's update order; cursors refer to it.
    seq: u64,
    created: SystemTime,
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
}

/// Scanner state, shared through [`AppState`].
pub struct Scanner {
    /// Server secret for event ids (spec §4.4).
    secret: Zeroizing<[u8; 32]>,
    inner: Mutex<Inner>,
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

/// One trial-decryption hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match {
    pub account: AccountId,
    /// Position of the transaction in `CompactBlock::vtx`.
    pub tx: usize,
    pub pool: Pool,
    /// Output (Sapling) or action (Orchard, Ironwood) index in its bundle.
    pub index: u32,
}

impl Scanner {
    pub fn new(secret: Zeroizing<[u8; 32]>) -> Self {
        Self {
            secret,
            inner: Mutex::new(Inner::default()),
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
        inner.leases.remove(&account);
        inner.events.remove(&account);
    }

    pub fn lease_status(&self, account: AccountId, now: SystemTime) -> LeaseStatus {
        let inner = self.lock();
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

    /// Whether the account has a lease (expired or not) still in memory.
    pub fn has_lease(&self, account: AccountId) -> bool {
        self.lock().leases.contains_key(&account)
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
    }

    /// Drops expired leases and events older than [`EVENT_TTL`].
    pub fn sweep(&self, now: SystemTime) {
        let mut inner = self.lock();
        inner.leases.retain(|_, l| l.expires_at > now);
        for acct in inner.events.values_mut() {
            acct.by_id.retain(|_, s| s.created + EVENT_TTL > now);
        }
        inner.events.retain(|_, a| !a.by_id.is_empty());
    }

    /// The keys of every active lease.
    pub fn active_keys(&self, now: SystemTime) -> Vec<(AccountId, Arc<ScanKeys>)> {
        self.lock()
            .leases
            .iter()
            .filter(|(_, l)| l.expires_at > now)
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
                    e.rev += 1;
                    acct.last_seq += 1;
                    s.seq = acct.last_seq;
                }
                None => {
                    let event = Event {
                        id: id.clone(),
                        rev: 1,
                        kind: EventKind::Received,
                        status: EventStatus::Mined,
                        height: Some(block.height),
                        confirmations,
                        compact_tx: Some(URL_SAFE_NO_PAD.encode(tx.encode_to_vec())),
                    };
                    acct.last_seq += 1;
                    new.push((m.account, event.clone()));
                    acct.by_id.insert(
                        id,
                        Stored {
                            event,
                            seq: acct.last_seq,
                            created: now,
                        },
                    );
                }
            }
        }
        new
    }

    /// Updates confirmations after the tip moved to `tip`.
    pub fn on_tip(&self, tip: u64) {
        let mut inner = self.lock();
        for acct in inner.events.values_mut() {
            for s in acct.by_id.values_mut() {
                let e = &mut s.event;
                let Some(h) = e.height else { continue };
                let c = confirmations(h, tip);
                if e.confirmations < FINALITY_DEPTH && c != e.confirmations {
                    e.confirmations = c;
                    e.rev += 1;
                    acct.last_seq += 1;
                    s.seq = acct.last_seq;
                }
            }
        }
    }

    /// Marks events in a block that left the best chain as `reorged`.
    pub fn on_disconnect(&self, height: u64) {
        let mut inner = self.lock();
        for acct in inner.events.values_mut() {
            for s in acct.by_id.values_mut() {
                let e = &mut s.event;
                if e.height == Some(height) {
                    e.status = EventStatus::Reorged;
                    e.height = None;
                    e.confirmations = 0;
                    e.rev += 1;
                    acct.last_seq += 1;
                    s.seq = acct.last_seq;
                }
            }
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
            let mut size = json_len(&event) + 1;
            if size > budget - 2 {
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
        self.lock().leases.get(&account).map(|l| l.alert_mode)
    }

    /// Releases every waiting long-poll (spec §4.3).
    pub fn release(&self) {
        self.release.send_modify(|g| *g = g.wrapping_add(1));
    }

    pub fn subscribe_release(&self) -> watch::Receiver<u64> {
        self.release.subscribe()
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

/// Trial-decrypts every shielded output in `block` with each lease's keys.
/// CPU-bound: call it from a blocking thread.
pub fn trial_decrypt(block: &CompactBlock, leases: &[(AccountId, Arc<ScanKeys>)]) -> Vec<Match> {
    use orchard::note_encryption::{IronwoodDomain, OrchardDomain};
    use sapling::note_encryption::{CompactOutputDescription, SaplingDomain, Zip212Enforcement};

    if leases.is_empty() {
        return vec![];
    }
    // (tx position, index in bundle) for each output, in the same order as
    // the decryption inputs.
    let mut sapling_at = Vec::new();
    let mut sapling_out = Vec::new();
    let mut orchard_at = Vec::new();
    let mut orchard_out = Vec::new();
    let mut ironwood_at = Vec::new();
    let mut ironwood_out = Vec::new();
    for (t, tx) in block.vtx.iter().enumerate() {
        for (i, out) in tx.outputs.iter().enumerate() {
            if let Ok(desc) = CompactOutputDescription::try_from(out) {
                // Every block the scanner sees is long past Canopy (ZIP 212).
                sapling_out.push((SaplingDomain::new(Zip212Enforcement::On), desc));
                sapling_at.push((t, i));
            }
        }
        for (i, act) in tx.actions.iter().enumerate() {
            if let Some(a) = compact_action(act) {
                orchard_out.push((OrchardDomain::for_compact_action(&a), a));
                orchard_at.push((t, i));
            }
        }
        for (i, act) in tx.ironwood_actions.iter().enumerate() {
            if let Some(a) = compact_action(act) {
                ironwood_out.push((IronwoodDomain::for_compact_action(&a), a));
                ironwood_at.push((t, i));
            }
        }
    }

    let mut matches = Vec::new();
    let mut push = |account, hits: Vec<Option<_>>, at: &[(usize, usize)], pool| {
        for (hit, &(tx, index)) in hits.iter().zip(at) {
            if hit.is_some() {
                matches.push(Match {
                    account,
                    tx,
                    pool,
                    index: index as u32,
                });
            }
        }
    };
    for (account, keys) in leases {
        if !keys.sapling.is_empty() && !sapling_out.is_empty() {
            let hits = try_compact_note_decryption(&keys.sapling, &sapling_out);
            push(
                *account,
                hits.into_iter().map(|h| h.map(|_| ())).collect(),
                &sapling_at,
                Pool::Sapling,
            );
        }
        if !keys.orchard.is_empty() {
            if !orchard_out.is_empty() {
                let hits = try_compact_note_decryption(&keys.orchard, &orchard_out);
                push(
                    *account,
                    hits.into_iter().map(|h| h.map(|_| ())).collect(),
                    &orchard_at,
                    Pool::Orchard,
                );
            }
            if !ironwood_out.is_empty() {
                let hits = try_compact_note_decryption(&keys.orchard, &ironwood_out);
                push(
                    *account,
                    hits.into_iter().map(|h| h.map(|_| ())).collect(),
                    &ironwood_at,
                    Pool::Ironwood,
                );
            }
        }
    }
    matches
}

fn compact_action(act: &CompactOrchardAction) -> Option<orchard::note_encryption::CompactAction> {
    let nf = Option::from(orchard::note::Nullifier::from_bytes(
        act.nullifier.as_slice().try_into().ok()?,
    ))?;
    let cmx = Option::from(orchard::note::ExtractedNoteCommitment::from_bytes(
        act.cmx.as_slice().try_into().ok()?,
    ))?;
    let epk = EphemeralKeyBytes(act.ephemeral_key.as_slice().try_into().ok()?);
    let ct: [u8; 52] = act.ciphertext.as_slice().try_into().ok()?;
    Some(orchard::note_encryption::CompactAction::from_parts(
        nf, cmx, epk, ct,
    ))
}

/// Scans one block with every active lease, records the matches, and sends
/// instant alerts. Used by [`run`] and by tests.
pub async fn scan_block(state: &Arc<AppState>, block: Arc<CompactBlock>) {
    let now = SystemTime::now();
    let leases = state.scanner.active_keys(now);
    let found = if leases.is_empty() {
        vec![]
    } else {
        let b = block.clone();
        tokio::task::spawn_blocking(move || trial_decrypt(&b, &leases))
            .await
            .unwrap_or_default()
    };
    let tip = state.chain.tip().max(block.height);
    let new = state.scanner.record(&block, &found, tip, now);
    state.scanner.on_tip(tip);
    state.scanner.release();
    if !new.is_empty() {
        tracing::info!(height = block.height, matches = new.len(), "lease matches");
    }
    for (account, event) in new {
        if state.scanner.alert_mode(account) == Some(AlertMode::Instant) {
            let state = state.clone();
            tokio::spawn(async move { crate::push::send_payment(&state, account, &event).await });
        }
    }
}

/// Scans `bf.from..=bf.to` for one lease. Stops early if the lease ends or
/// is replaced, so its keys aren't held longer than needed.
pub async fn backfill(state: Arc<AppState>, bf: Backfill) {
    let Some(source) = state.chain_source.clone() else {
        return;
    };
    let Ok(_permit) = state.scanner.backfills.clone().acquire_owned().await else {
        return;
    };
    let mut start = bf.from;
    let mut found_any = false;
    while start <= bf.to {
        if !state
            .scanner
            .is_current(bf.account, bf.generation, SystemTime::now())
        {
            return;
        }
        let end = bf.to.min(start + BATCH - 1);
        let blocks = match source.blocks(start, end).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "backfill stopped");
                return;
            }
        };
        if blocks.is_empty() {
            break;
        }
        let leases = vec![(bf.account, bf.keys.clone())];
        let blocks = Arc::new(blocks);
        let b = blocks.clone();
        let matches: Vec<(usize, Vec<Match>)> = tokio::task::spawn_blocking(move || {
            b.iter()
                .enumerate()
                .map(|(i, block)| (i, trial_decrypt(block, &leases)))
                .filter(|(_, m)| !m.is_empty())
                .collect()
        })
        .await
        .unwrap_or_default();
        let tip = state.chain.tip();
        for (i, m) in matches {
            if !state
                .scanner
                .is_current(bf.account, bf.generation, SystemTime::now())
            {
                return;
            }
            let new = state.scanner.record(&blocks[i], &m, tip, SystemTime::now());
            found_any |= !new.is_empty();
        }
        start = end + 1;
    }
    if found_any {
        state.scanner.release();
    }
}

/// Follows chain events until the process exits.
pub async fn run(state: Arc<AppState>) {
    let mut rx = state.chain.subscribe();
    let mut last_height = 0u64;
    loop {
        match rx.recv().await {
            Ok(ChainEvent::Connected(block)) => {
                last_height = block.height;
                scan_block(&state, block).await;
            }
            Ok(ChainEvent::Disconnected(b)) => {
                last_height = b.height.saturating_sub(1);
                state.scanner.on_disconnect(b.height);
                state.scanner.release();
            }
            Ok(ChainEvent::Reset(b)) => last_height = b.height,
            Err(broadcast::error::RecvError::Lagged(n)) => {
                // Spam policy: fall behind, then catch up. Rescan what was
                // skipped for every lease.
                tracing::warn!(skipped = n, "scanner fell behind the chain");
                let tip = state.chain.tip();
                for (account, keys) in state.scanner.active_keys(SystemTime::now()) {
                    let generation = state
                        .scanner
                        .lock()
                        .leases
                        .get(&account)
                        .map(|l| l.generation);
                    if let Some(generation) = generation
                        && last_height < tip
                    {
                        tokio::spawn(backfill(
                            state.clone(),
                            Backfill {
                                account,
                                keys,
                                generation,
                                from: last_height + 1,
                                to: tip,
                            },
                        ));
                    }
                }
                last_height = tip;
            }
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}

/// Drops expired leases and events every minute.
pub async fn sweep_loop(state: Arc<AppState>) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        state.scanner.sweep(SystemTime::now());
    }
}
