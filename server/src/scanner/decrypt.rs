//! Trial decryption of compact blocks and transactions (CPU-bound).

use std::sync::Arc;

use lz_proto::event_id::Pool;
use zcash_client_backend::proto::compact_formats::{CompactBlock, CompactOrchardAction, CompactTx};
use zcash_note_encryption::EphemeralKeyBytes;
use zcash_note_encryption::batch::try_compact_note_decryption;

use crate::store::AccountId;
use crate::viewkey::ScanKeys;

/// One trial-decryption hit. `Debug` hides the value.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Match {
    pub account: AccountId,
    /// Position of the transaction in `CompactBlock::vtx`.
    pub tx: usize,
    pub pool: Pool,
    /// Output (Sapling) or action (Orchard, Ironwood) index in its bundle.
    pub index: u32,
    /// The note's value in zatoshis, for webhooks (spec §4.5). Derived
    /// from a key: memory only (invariant 3).
    pub value: u64,
}

impl std::fmt::Debug for Match {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Match")
            .field("tx", &self.tx)
            .field("pool", &self.pool)
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

/// Trial-decrypts every shielded output in `block` with each lease's keys.
/// CPU-bound: call it from a blocking thread.
pub fn trial_decrypt(block: &CompactBlock, leases: &[(AccountId, Arc<ScanKeys>)]) -> Vec<Match> {
    trial_decrypt_txs(&block.vtx, leases)
}

/// [`trial_decrypt`] over a list of transactions; [`Match::tx`] indexes
/// `txs`.
pub fn trial_decrypt_txs(txs: &[CompactTx], leases: &[(AccountId, Arc<ScanKeys>)]) -> Vec<Match> {
    let refs: Vec<&CompactTx> = txs.iter().collect();
    trial_decrypt_txs_refs(&refs, leases)
}

pub(crate) fn trial_decrypt_txs_refs(
    txs: &[&CompactTx],
    leases: &[(AccountId, Arc<ScanKeys>)],
) -> Vec<Match> {
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
    for (t, tx) in txs.iter().enumerate() {
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
    let mut sapling_ivks = Vec::new();
    let mut sapling_owner = Vec::new();
    let mut orchard_ivks = Vec::new();
    let mut orchard_owner = Vec::new();
    for (account, keys) in leases {
        for ivk in &keys.sapling {
            sapling_ivks.push(ivk.clone());
            sapling_owner.push(*account);
        }
        for ivk in &keys.orchard {
            orchard_ivks.push(ivk.clone());
            orchard_owner.push(*account);
        }
    }
    if !sapling_ivks.is_empty() && !sapling_out.is_empty() {
        record_hits(
            &mut matches,
            try_compact_note_decryption(&sapling_ivks, &sapling_out),
            &sapling_at,
            &sapling_owner,
            Pool::Sapling,
            |(note, _)| note.value().inner(),
        );
    }
    if !orchard_ivks.is_empty() && !orchard_out.is_empty() {
        record_hits(
            &mut matches,
            try_compact_note_decryption(&orchard_ivks, &orchard_out),
            &orchard_at,
            &orchard_owner,
            Pool::Orchard,
            |(note, _)| note.value().inner(),
        );
    }
    if !orchard_ivks.is_empty() && !ironwood_out.is_empty() {
        record_hits(
            &mut matches,
            try_compact_note_decryption(&orchard_ivks, &ironwood_out),
            &ironwood_at,
            &orchard_owner,
            Pool::Ironwood,
            |(note, _)| note.value().inner(),
        );
    }
    matches
}

fn record_hits<T>(
    matches: &mut Vec<Match>,
    hits: Vec<Option<(T, usize)>>,
    at: &[(usize, usize)],
    owners: &[AccountId],
    pool: Pool,
    value: impl Fn(&T) -> u64,
) {
    for (hit, &(tx, index)) in hits.iter().zip(at) {
        if let Some((decrypted, ivk_idx)) = hit.as_ref() {
            matches.push(Match {
                account: owners[*ivk_idx],
                tx,
                pool,
                index: index as u32,
                value: value(decrypted),
            });
        }
    }
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
