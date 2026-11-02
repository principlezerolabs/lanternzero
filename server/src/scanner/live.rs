//! Live chain scanning, backfill, alerts, and background loops.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use lz_proto::api::Event;
use lz_proto::lease::AlertMode;
use tokio::sync::broadcast;
use zcash_client_backend::proto::compact_formats::{CompactBlock, CompactTx};

use crate::AppState;
use crate::chain::{BATCH, ChainEvent};
use crate::store::AccountId;

use super::decrypt::{self, Match};
use super::{BLOCK_COALESCE, Backfill};

/// Scans one or more blocks with every active lease, records matches, and
/// sends instant alerts. Used by [`run`] and by tests.
pub async fn scan_blocks(state: &Arc<AppState>, blocks: Vec<Arc<CompactBlock>>) {
    scan_blocks_at(state, blocks, SystemTime::now()).await;
}

pub async fn scan_blocks_at(
    state: &Arc<AppState>,
    blocks: Vec<Arc<CompactBlock>>,
    now: SystemTime,
) {
    if blocks.is_empty() {
        return;
    }
    let leases = state.scanner.active_keys(now);
    let per_block = if leases.is_empty() {
        vec![]
    } else {
        let blocks = blocks.clone();
        tokio::task::spawn_blocking(move || {
            blocks
                .iter()
                .enumerate()
                .map(|(i, block)| (i, decrypt::trial_decrypt(block, &leases)))
                .collect::<Vec<_>>()
        })
        .await
        .unwrap_or_default()
    };
    let tip = state
        .chain
        .tip()
        .max(blocks.last().map(|b| b.height).unwrap_or(0));
    let mut all_new = Vec::new();
    let mut match_count = 0usize;
    for (i, found) in per_block {
        let new = state.scanner.record(&blocks[i], &found, tip, now);
        match_count += found.len();
        all_new.extend(new);
    }
    state.scanner.on_tip(tip);
    state.scanner.release();
    if match_count > 0 {
        tracing::info!(
            matches = match_count,
            blocks = blocks.len(),
            "lease matches"
        );
    }
    alert(state, all_new, now);
}

/// Scans one block. Convenience wrapper for tests.
pub async fn scan_block(state: &Arc<AppState>, block: Arc<CompactBlock>) {
    scan_block_at(state, block, SystemTime::now()).await;
}

/// Like [`scan_block`], with a fixed clock for rate-limit tests.
pub async fn scan_block_at(state: &Arc<AppState>, block: Arc<CompactBlock>, now: SystemTime) {
    scan_blocks_at(state, vec![block], now).await;
}

/// Most instant payment pushes per account per minute. A burst of payments
/// (or spam aimed at one address) still reaches the wallet through `wake`
/// and the long-poll, but can't burn its push budget with Apple or Google.
pub const PAYMENT_PUSHES_PER_MINUTE: u32 = 2;

/// Sends instant alerts for newly found events: one push per transaction
/// per account (a transaction paying several of the account's outputs
/// yields several events), within [`PAYMENT_PUSHES_PER_MINUTE`].
pub fn alert(state: &Arc<AppState>, new: Vec<(AccountId, Event)>, now: SystemTime) {
    let mut seen = std::collections::HashSet::new();
    for (account, event) in new {
        if state.scanner.alert_mode(account) != Some(AlertMode::Instant) {
            continue;
        }
        if !seen.insert((account, event.compact_tx.clone())) {
            continue;
        }
        if state.payment_push_limiter.check(&account, now).is_err() {
            continue;
        }
        let state = state.clone();
        tokio::spawn(async move { crate::push::send_payment(&state, account, &event).await });
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
                .map(|(i, block)| (i, decrypt::trial_decrypt(block, &leases)))
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
    // Payments sent but not yet mined. No pushes here either.
    let pending = state.scanner.mempool_snapshot();
    if !pending.is_empty()
        && state
            .scanner
            .is_current(bf.account, bf.generation, SystemTime::now())
    {
        let leases = vec![(bf.account, bf.keys.clone())];
        let pending = Arc::new(pending);
        let pending2 = pending.clone();
        let matches = tokio::task::spawn_blocking(move || {
            let refs: Vec<&CompactTx> = pending2.iter().map(|t| t.as_ref()).collect();
            decrypt::trial_decrypt_txs_refs(&refs, &leases)
        })
        .await
        .unwrap_or_default();
        for m in matches {
            // The snapshot is compact, so no memo (spec §4.5).
            let new = state.scanner.record_mempool(
                &pending[m.tx],
                vec![(Match { tx: 0, ..m }, None)],
                SystemTime::now(),
            );
            found_any |= !new.is_empty();
        }
    }
    if found_any {
        state.scanner.release();
    }
}

fn catch_up_after_lag(state: &Arc<AppState>, last_height: &mut u64, skipped: u64) {
    tracing::warn!(skipped, "scanner fell behind the chain");
    let tip = state.chain.tip();
    for (account, keys) in state.scanner.active_keys(SystemTime::now()) {
        let generation = state.scanner.lease_generation(account);
        if let Some(generation) = generation
            && *last_height < tip
        {
            tokio::spawn(backfill(
                state.clone(),
                Backfill {
                    account,
                    keys,
                    generation,
                    from: *last_height + 1,
                    to: tip,
                },
            ));
        }
    }
    *last_height = tip;
}

/// Follows chain events until the process exits.
pub async fn run(state: Arc<AppState>) {
    let mut rx = state.chain.subscribe();
    let mut last_height = 0u64;
    loop {
        match rx.recv().await {
            Ok(ChainEvent::Connected(first)) => {
                let mut batch = vec![first];
                let mut after_scan: Option<ChainEvent> = None;
                let mut lagged: Option<u64> = None;
                while batch.len() < BLOCK_COALESCE {
                    match rx.try_recv() {
                        Ok(ChainEvent::Connected(block)) => batch.push(block),
                        Ok(other @ (ChainEvent::Disconnected(_) | ChainEvent::Reset(_))) => {
                            after_scan = Some(other);
                            break;
                        }
                        Err(broadcast::error::TryRecvError::Lagged(n)) => {
                            lagged = Some(n);
                            break;
                        }
                        Err(broadcast::error::TryRecvError::Closed) => return,
                        Err(broadcast::error::TryRecvError::Empty) => break,
                    }
                }
                last_height = batch.last().map(|b| b.height).unwrap_or(last_height);
                scan_blocks(&state, batch).await;
                match after_scan {
                    Some(ChainEvent::Disconnected(b)) => {
                        last_height = b.height.saturating_sub(1);
                        state.scanner.on_disconnect(b.height);
                        state.scanner.release();
                    }
                    Some(ChainEvent::Reset(b)) => last_height = b.height,
                    _ => {}
                }
                if let Some(n) = lagged {
                    catch_up_after_lag(&state, &mut last_height, n);
                }
            }
            Ok(ChainEvent::Disconnected(b)) => {
                last_height = b.height.saturating_sub(1);
                state.scanner.on_disconnect(b.height);
                state.scanner.release();
            }
            Ok(ChainEvent::Reset(b)) => last_height = b.height,
            Err(broadcast::error::RecvError::Lagged(n)) => {
                catch_up_after_lag(&state, &mut last_height, n);
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
