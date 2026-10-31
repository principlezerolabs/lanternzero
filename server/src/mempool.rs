//! Mempool scanning: payments show up as `mempool` events seconds after
//! they are sent, before they are mined (spec §4.3).
//!
//! - It reads the whole mempool with `GetMempoolStream`, never one
//!   transaction at a time (invariant 7, spec §6.1). The server closes the
//!   stream when a block is mined, and the loop opens a new one, which
//!   starts with the whole current mempool again.
//! - Each full transaction is cut down to its `CompactTx` form, so mempool
//!   events carry the same `compact_tx` field that mined ones do.
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

/// Longest wait between retries after an error.
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// Pause before reopening a stream that ended normally (a new block).
const REOPEN_DELAY: Duration = Duration::from_secs(1);

/// Parses a full transaction and keeps what trial decryption needs, as a
/// `CompactTx`. `None` if it doesn't parse.
pub fn to_compact(raw: &[u8], branch: BranchId) -> Option<CompactTx> {
    let tx = Transaction::read(raw, branch).ok()?;
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
    Some(out)
}

/// Bytes of note ciphertext in compact form (ZIP 307).
const COMPACT_NOTE_SIZE: usize = 52;

/// Checks one mempool transaction against every active lease, records
/// matches as `mempool` events, and sends instant alerts. Used by [`run`]
/// and by tests.
///
/// The transaction joins the mempool snapshot only after this check, so a
/// new lease's catch-up scan (which reads the snapshot and never pushes)
/// can't record a payment first and swallow its instant alert. The cost:
/// a transaction that arrives while a lease is being set up can miss both
/// paths until the stream reopens at the next block, which rescans it.
pub async fn scan_tx(state: &Arc<AppState>, tx: CompactTx) {
    let tx = Arc::new(tx);
    let now = SystemTime::now();
    let leases = state.scanner.active_keys(now);
    let matches = if leases.is_empty() {
        vec![]
    } else {
        let t = tx.clone();
        tokio::task::spawn_blocking(move || {
            crate::scanner::trial_decrypt_txs(std::slice::from_ref(&*t), &leases)
        })
        .await
        .unwrap_or_default()
    };
    let new = if matches.is_empty() {
        vec![]
    } else {
        state.scanner.record_mempool(&tx, &matches, now)
    };
    state.scanner.mempool_insert(tx);
    if matches.is_empty() {
        return;
    }
    state.scanner.release();
    if !new.is_empty() {
        tracing::info!(matches = new.len(), "mempool lease matches");
    }
    crate::scanner::alert(state, new);
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
            // A new stream starts with the whole mempool.
            state.scanner.mempool_clear();
            let mut unparsed = 0usize;
            while let Some(raw) = stream.message().await? {
                // Height 0 means "in the mempool"; anything else was mined.
                if raw.height != 0 {
                    continue;
                }
                match to_compact(&raw.data, branch) {
                    Some(tx) => scan_tx(&state, tx).await,
                    None => unparsed += 1,
                }
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
