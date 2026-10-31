//! Test wallets: fake keys from fixed seeds, their UIVK text, and compact
//! outputs encrypted to them. Never use these patterns for real funds.

use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use orchard::note::{ExtractedNoteCommitment, Nullifier, RandomSeed, Rho};
use orchard::note_encryption::{IronwoodDomain, OrchardDomain};
use orchard::value::NoteValue;
use orchard::{Note, NoteVersion};
use sapling::note_encryption::SaplingDomain;
use zcash_address::unified::{self, Encoding};
use zcash_client_backend::proto::compact_formats::{
    CompactBlock, CompactOrchardAction, CompactSaplingOutput, CompactTx,
};
use zcash_note_encryption::{Domain, NoteEncryption};
use zcash_protocol::consensus::NetworkType;

pub struct Wallet {
    pub orchard: orchard::Address,
    pub sapling: sapling::PaymentAddress,
    pub orchard_ivk: [u8; 64],
    pub sapling_ivk: [u8; 64],
}

impl Wallet {
    pub fn new(seed: u8) -> Self {
        let sk = SpendingKey::from_bytes([seed; 32]).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let xsk = sapling::zip32::ExtendedSpendingKey::master(&[seed; 32]).unwrap();
        let dfvk = xsk.to_diversifiable_full_viewing_key();
        Self {
            orchard: fvk.address_at(0u32, Scope::External),
            sapling: dfvk.default_address().1,
            orchard_ivk: fvk.to_ivk(Scope::External).to_bytes(),
            sapling_ivk: dfvk.to_external_ivk().to_bytes(),
        }
    }

    /// The UIVK text, ZIP 316 Revision 0 or 2.
    pub fn uivk(&self, network: NetworkType, revision: unified::Revision) -> String {
        unified::Uivk::try_from_items(
            revision,
            vec![
                unified::Uitem::Data(unified::Ivk::Orchard(self.orchard_ivk)),
                unified::Uitem::Data(unified::Ivk::Sapling(self.sapling_ivk)),
            ],
        )
        .unwrap()
        .encode(&network)
    }

    pub fn uivk_main(&self) -> String {
        self.uivk(NetworkType::Main, unified::Revision::R0)
    }

    /// A UIVK with only the Sapling item.
    pub fn sapling_only_uivk(&self) -> String {
        unified::Uivk::try_from_items(
            unified::Revision::R0,
            vec![unified::Uitem::Data(unified::Ivk::Sapling(
                self.sapling_ivk,
            ))],
        )
        .unwrap()
        .encode(&NetworkType::Main)
    }
}

/// An Orchard (or, with `ironwood`, Ironwood) compact action paying `to`.
/// `nf` picks the spent nullifier, which makes each action distinct.
pub fn action(to: &orchard::Address, nf: u8, ironwood: bool) -> CompactOrchardAction {
    let mut nf_bytes = [0u8; 32];
    nf_bytes[0] = nf;
    // A note's rho is the nullifier its action spends (as bytes).
    assert!(bool::from(Nullifier::from_bytes(&nf_bytes).is_some()));
    let rho = Rho::from_bytes(&nf_bytes).unwrap();
    let rseed = RandomSeed::from_bytes([nf.wrapping_add(9); 32], &rho).unwrap();
    let version = if ironwood {
        NoteVersion::V3
    } else {
        NoteVersion::V2
    };
    let note = Note::from_parts(*to, NoteValue::from_raw(5_000), rho, rseed, version).unwrap();
    let cmx = ExtractedNoteCommitment::from(note.commitment());
    let (epk, ct) = if ironwood {
        let enc = NoteEncryption::<IronwoodDomain>::new(None, note, [0; 512]);
        (
            IronwoodDomain::epk_bytes(enc.epk()).0,
            enc.encrypt_note_plaintext().as_ref()[..52].to_vec(),
        )
    } else {
        let enc = NoteEncryption::<OrchardDomain>::new(None, note, [0; 512]);
        (
            OrchardDomain::epk_bytes(enc.epk()).0,
            enc.encrypt_note_plaintext().as_ref()[..52].to_vec(),
        )
    };
    CompactOrchardAction {
        nullifier: nf_bytes.to_vec(),
        cmx: cmx.to_bytes().to_vec(),
        ephemeral_key: epk.to_vec(),
        ciphertext: ct,
    }
}

/// A Sapling compact output paying `to`.
pub fn sapling_output(to: &sapling::PaymentAddress, salt: u8) -> CompactSaplingOutput {
    let note = sapling::Note::from_parts(
        *to,
        sapling::value::NoteValue::from_raw(7_000),
        sapling::Rseed::AfterZip212([salt; 32]),
    );
    let enc = NoteEncryption::<SaplingDomain>::new(None, note.clone(), [0; 512]);
    CompactSaplingOutput {
        cmu: note.cmu().to_bytes().to_vec(),
        ephemeral_key: SaplingDomain::epk_bytes(enc.epk()).0.to_vec(),
        ciphertext: enc.encrypt_note_plaintext().as_ref()[..52].to_vec(),
    }
}

/// A transaction with the given outputs; `id` fills the txid.
pub fn tx(
    id: u8,
    outputs: Vec<CompactSaplingOutput>,
    actions: Vec<CompactOrchardAction>,
    ironwood_actions: Vec<CompactOrchardAction>,
) -> CompactTx {
    CompactTx {
        txid: vec![id; 32],
        outputs,
        actions,
        ironwood_actions,
        ..CompactTx::default()
    }
}

/// A block at `height` holding `vtx`; hashes are made up.
pub fn block(height: u64, vtx: Vec<CompactTx>) -> CompactBlock {
    let mut hash = vec![0xB0; 32];
    hash[24..].copy_from_slice(&height.to_be_bytes());
    let mut prev_hash = vec![0xB0; 32];
    prev_hash[24..].copy_from_slice(&height.wrapping_sub(1).to_be_bytes());
    CompactBlock {
        height,
        hash,
        prev_hash,
        vtx,
        ..CompactBlock::default()
    }
}
