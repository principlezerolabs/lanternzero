//! Mempool scanning: payments show up as `mempool` events seconds after
//! they are sent, before they are mined (spec §4.3).
//!
//! - It reads the whole mempool with `GetMempoolStream`, never one
//!   transaction at a time (invariant 7, spec §6.1). The server closes the
//!   stream when a block is mined, and the loop opens a new one, which
//!   starts with the whole current mempool again.
//! - Each full transaction is cut down to its `CompactTx` form, so mempool
//!   events carry the same `compact_tx` field that mined ones do. The full
//!   form is kept only while its chunk is scanned, to decrypt the memos of
//!   matched outputs for webhooks (spec §4.5).
//! - The current mempool is kept, in compact form, so a lease that starts
//!   mid-block is checked against it too (see [`crate::scanner::backfill`]).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use zcash_client_backend::proto::compact_formats::{
    CompactOrchardAction, CompactSaplingOutput, CompactSaplingSpend, CompactTx,
};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

use crate::AppState;
use crate::scanner::{self, Match, Memo};

/// Mempool transactions parsed and trial-decrypted together.
const DECRYPT_CHUNK: usize = 32;
/// Longest wait between retries after an error.
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// Pause before reopening a stream that ended normally (a new block).
const REOPEN_DELAY: Duration = Duration::from_secs(1);

/// Parses a full transaction and keeps what trial decryption needs, as a
/// `CompactTx`. `None` if it doesn't parse.
pub fn to_compact(raw: &[u8], branch: BranchId) -> Option<CompactTx> {
    parse(raw, branch).map(|(compact, _)| compact)
}

/// A mempool transaction in compact form, with its full form when it came
/// from the stream.
type Parsed = (Arc<CompactTx>, Option<Transaction>);

fn parse(raw: &[u8], branch: BranchId) -> Option<(CompactTx, Transaction)> {
    let tx = Transaction::read(raw, branch).ok()?;
    let compact = compact_of(&tx);
    Some((compact, tx))
}

fn compact_of(tx: &Transaction) -> CompactTx {
    let mut out = CompactTx {
        txid: tx.txid().as_ref().to_vec(),
        ..CompactTx::default()
    };
    if let Some(bundle) = tx.sapling_bundle() {
        out.spends = bundle
            .shielded_spends()
            .iter()
            .map(|s| CompactSaplingSpend {
                nf: s.nullifier().to_vec(),
            })
            .collect();
        out.outputs = bundle
            .shielded_outputs()
            .iter()
            .map(|o| CompactSaplingOutput {
                cmu: o.cmu().to_bytes().to_vec(),
                ephemeral_key: o.ephemeral_key().0.to_vec(),
                ciphertext: o.enc_ciphertext()[..COMPACT_NOTE_SIZE].to_vec(),
            })
            .collect();
    }
    let compact_actions = |bundle: &orchard::Bundle<_, _>| -> Vec<CompactOrchardAction> {
        bundle
            .actions()
            .iter()
            .map(|a| CompactOrchardAction {
                nullifier: a.nullifier().to_bytes().to_vec(),
                cmx: a.cmx().to_bytes().to_vec(),
                ephemeral_key: a.encrypted_note().epk_bytes.to_vec(),
                ciphertext: a.encrypted_note().enc_ciphertext.0[..COMPACT_NOTE_SIZE].to_vec(),
            })
            .collect()
    };
    if let Some(bundle) = tx.orchard_bundle() {
        out.actions = compact_actions(bundle);
    }
    if let Some(bundle) = tx.ironwood_bundle() {
        out.ironwood_actions = compact_actions(bundle);
    }
    out
}

/// Bytes of note ciphertext in compact form (ZIP 307).
const COMPACT_NOTE_SIZE: usize = 52;

/// Parses a batch from the stream. Returns the transactions that parsed
/// and how many didn't.
fn parse_batch(raw: Vec<Vec<u8>>, branch: BranchId) -> (Vec<Parsed>, usize) {
    let mut failed = 0usize;
    let parsed = raw
        .into_iter()
        .filter_map(|data| {
            let parsed = parse(&data, branch).map(|(c, full)| (Arc::new(c), Some(full)));
            if parsed.is_none() {
                failed += 1;
            }
            parsed
        })
        .collect();
    (parsed, failed)
}

/// Parses and scans full transactions as the stream does, memos included.
/// Returns how many didn't parse.
pub async fn scan_raw(state: &Arc<AppState>, raw: Vec<Vec<u8>>, branch: BranchId) -> usize {
    let (parsed, failed) = tokio::task::spawn_blocking(move || parse_batch(raw, branch))
        .await
        .unwrap_or((vec![], 0));
    scan_chunk_at(state, parsed, state.clock.now()).await;
    failed
}

/// Checks one mempool transaction in compact form (so without memos)
/// against every active lease. Used by tests.
pub async fn scan_tx(state: &Arc<AppState>, tx: CompactTx) {
    scan_tx_at(state, tx, state.clock.now()).await;
}

/// Like [`scan_tx`], with a fixed clock for rate-limit tests.
pub async fn scan_tx_at(state: &Arc<AppState>, tx: CompactTx, now: SystemTime) {
    scan_chunk_at(state, vec![(Arc::new(tx), None)], now).await;
}

async fn scan_chunk_at(state: &Arc<AppState>, txs: Vec<Parsed>, now: SystemTime) {
    if txs.is_empty() {
        return;
    }
    let leases = state.scanner.active_keys(now);
    let chunk: Vec<Arc<CompactTx>> = txs.iter().map(|(c, _)| c.clone()).collect();
    let found: Vec<(Match, Option<Memo>)> = if leases.is_empty() {
        vec![]
    } else {
        // Memos only go in webhook deliveries; keep none for accounts
        // without a webhook (spec §4.5).
        let with_webhook: std::collections::HashSet<_> = leases
            .iter()
            .map(|(account, _)| *account)
            .filter(|account| state.store.has_webhook(*account))
            .collect();
        tokio::task::spawn_blocking(move || {
            let refs: Vec<&CompactTx> = txs.iter().map(|(c, _)| c.as_ref()).collect();
            scanner::trial_decrypt_txs_refs(&refs, &leases)
                .into_iter()
                .map(|m| {
                    let memo = txs[m.tx]
                        .1
                        .as_ref()
                        .filter(|_| with_webhook.contains(&m.account))
                        .and_then(|full| scanner::memo_of(full, &m, &leases));
                    (m, memo)
                })
                .collect()
        })
        .await
        .unwrap_or_default()
    };
    let mut by_tx: std::collections::HashMap<usize, Vec<(Match, Option<Memo>)>> =
        Default::default();
    for (m, memo) in found {
        by_tx.entry(m.tx).or_default().push((m, memo));
    }
    let mut new_all = Vec::new();
    for (i, tx) in chunk.iter().enumerate() {
        let matches = by_tx.remove(&i).unwrap_or_default();
        let new = if matches.is_empty() {
            vec![]
        } else {
            state.scanner.record_mempool(tx, matches, now)
        };
        state.scanner.mempool_insert(tx.clone());
        new_all.extend(new);
    }
    if new_all.is_empty() {
        return;
    }
    state.scanner.release();
    tracing::info!(matches = new_all.len(), "mempool lease matches");
    scanner::alert(state, new_all, now);
}

/// Streams the mempool until the process exits. Errors are logged and
/// retried with back-off.
pub async fn run(state: Arc<AppState>) {
    let Some(source) = state.chain_source.clone() else {
        return;
    };
    let mut backoff = Duration::from_secs(1);
    loop {
        let result: Result<(), crate::chain::ChainError> = async {
            // Only v4 transactions use the branch id, and only for
            // signature hashes, never for the txid. An unknown one isn't
            // worth stopping for.
            let branch = match source.consensus_branch_id().await {
                Ok(b) => b,
                Err(e @ crate::chain::ChainError::Rpc(_)) => return Err(e),
                Err(e) => {
                    tracing::warn!(error = %e, "assuming the NU6.3 branch id");
                    BranchId::Nu6_3
                }
            };
            let mut stream = source.mempool_stream().await?;
            state.scanner.mempool_clear();
            let mut unparsed = 0usize;
            let mut batch_raw: Vec<Vec<u8>> = Vec::new();
            while let Some(raw) = stream.message().await? {
                if raw.height != 0 {
                    continue;
                }
                batch_raw.push(raw.data);
                if batch_raw.len() >= DECRYPT_CHUNK {
                    unparsed += scan_raw(&state, std::mem::take(&mut batch_raw), branch).await;
                }
            }
            if !batch_raw.is_empty() {
                unparsed += scan_raw(&state, std::mem::take(&mut batch_raw), branch).await;
            }
            if unparsed > 0 {
                tracing::warn!(unparsed, "mempool transactions that didn't parse");
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => {
                backoff = Duration::from_secs(1);
                tokio::time::sleep(REOPEN_DELAY).await;
            }
            Err(e) => {
                tracing::warn!(error = %e, retry_secs = backoff.as_secs(), "mempool stream");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}
