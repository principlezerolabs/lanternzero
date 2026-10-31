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

    /// A Unified Address with only this wallet's Sapling receiver.
    pub fn sapling_ua(&self, network: NetworkType) -> String {
        unified::Address::try_from_items(
            unified::Revision::R0,
            vec![unified::Uitem::Data(unified::Receiver::Sapling(
                self.sapling.to_bytes(),
            ))],
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

/// A real v6 transaction (NU6.3 rules) paying `to` once in each pool asked
/// for. Proofs and signatures are dummies: it parses, but would never
/// verify. Returns the serialized transaction.
///
/// There's no Orchard option: since NU6.3 the Orchard pool takes only a
/// wallet's change to itself (cross-address transfers are disabled), so new
/// payments land in Sapling or Ironwood. Orchard and Ironwood actions are
/// parsed by the same code.
pub fn full_tx(to: &Wallet, sapling_out: bool, ironwood_out: bool) -> Vec<u8> {
    use orchard::builder::{Builder as OBuilder, BundleType as OBundleType};
    use orchard::bundle::{Authorized as OAuthorized, BundleVersion};
    use orchard::primitives::redpallas;
    use rand010::SeedableRng;
    use zcash_primitives::transaction::TransactionData;
    use zcash_protocol::consensus::{BlockHeight, BranchId};
    use zcash_protocol::value::ZatBalance;

    let mut rng = rand010::rngs::StdRng::seed_from_u64(7);

    let orchard_bundle = |version: BundleVersion, rng: &mut rand010::rngs::StdRng| {
        let mut b = OBuilder::new(
            OBundleType::DEFAULT,
            version,
            version.default_flags(),
            orchard::Anchor::empty_tree(),
        )
        .unwrap();
        b.add_output(None, to.orchard, NoteValue::from_raw(5_000), [0; 512])
            .unwrap();
        let (bundle, _) = b.build::<ZatBalance>(&mut *rng).unwrap().unwrap();
        // Parsers check that the proof has its canonical size.
        let proof_len = orchard::Proof::expected_proof_size(bundle.actions().len());
        bundle.map_authorization(
            &mut (),
            |_, _, _| redpallas::Signature::<redpallas::SpendAuth>::from([0u8; 64]),
            |_, _| {
                OAuthorized::from_parts(
                    orchard::Proof::new(vec![0; proof_len]),
                    redpallas::Signature::<redpallas::Binding>::from([0u8; 64]),
                )
            },
        )
    };
    let orchard = None;
    let ironwood = ironwood_out.then(|| orchard_bundle(BundleVersion::ironwood_v3(), &mut rng));

    let sapling = sapling_out.then(|| {
        use sapling::builder::{Builder as SBuilder, BundleType as SBundleType};
        use sapling::prover::mock::{MockOutputProver, MockSpendProver};
        let mut b = SBuilder::new(
            sapling::note_encryption::Zip212Enforcement::On,
            SBundleType::DEFAULT,
            sapling::Anchor::empty_tree(),
        );
        b.add_output(
            None,
            to.sapling,
            sapling::value::NoteValue::from_raw(7_000),
            [0; 512],
        )
        .unwrap();
        let (bundle, _) = b
            .build::<MockSpendProver, MockOutputProver, _, ZatBalance>(&[], &mut rng)
            .unwrap()
            .unwrap();
        bundle.map_authorization(
            (),
            |_, _| [0u8; 192],
            |_, _| [0u8; 192],
            |_, _| redjubjub::Signature::<redjubjub::SpendAuth>::from([0u8; 64]),
            |_, _| sapling::bundle::Authorized {
                binding_sig: redjubjub::Signature::<redjubjub::Binding>::from([0u8; 64]),
            },
        )
    });

    let tx = TransactionData::<zcash_primitives::transaction::Authorized>::from_parts_v6(
        BranchId::Nu6_3,
        0,
        BlockHeight::from_u32(3_600_000),
        None,
        sapling,
        orchard,
        ironwood,
    )
    .freeze()
    .unwrap();
    let mut out = Vec::new();
    tx.write(&mut out).unwrap();
    out
}
