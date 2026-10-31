//! Chain follower: tracks the best chain on a Zaino or lightwalletd server
//! (the `CompactTxStreamer` gRPC API) and announces each block.
//!
//! - It reads blocks in bulk only, with `GetLatestBlock` and `GetBlockRange`
//!   (and, for [`crate::mempool`], `GetMempoolStream`).
//!   It never asks for a transaction (invariant 7, spec §6.1).
//! - It starts at the current tip; it keeps no history on disk. A scanner
//!   that needs older blocks for a lease's `from_height` fetches them
//!   itself with [`Lightwalletd::blocks`].
//! - It remembers the last [`REORG_WINDOW`] blocks, so it can roll back a
//!   reorg and announce the blocks that left the best chain. A deeper reorg
//!   makes it start over at the tip ([`ChainEvent::Reset`]).
//! - It compares hashes only between compact blocks, never with
//!   `GetLatestBlock`'s hash, whose byte order servers don't agree on. A
//!   block replaced at the same height is therefore noticed when the next
//!   block arrives.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use lz_proto::lease::Network;
use tokio::sync::broadcast;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_client_backend::proto::service::{
    BlockId, BlockRange, ChainSpec, Empty, LightdInfo, RawTransaction,
};
use zcash_protocol::consensus::BranchId;

/// Blocks remembered for reorg handling. zcashd and Zebra refuse reorgs
/// deeper than 99 blocks.
pub const REORG_WINDOW: usize = 100;
/// Most blocks fetched in one `GetBlockRange` call.
pub const BATCH: u64 = 50;
/// Largest gRPC message accepted. A full 2 MB block's compact form fits.
const MAX_MESSAGE: usize = 16 * 1024 * 1024;
/// Longest wait between retries after an error.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// A block on the best chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRef {
    pub height: u64,
    pub hash: [u8; 32],
}

/// What the follower announces, in chain order.
#[derive(Debug, Clone)]
pub enum ChainEvent {
    /// A block joined the best chain, on top of the previous one.
    Connected(Arc<CompactBlock>),
    /// A block left the best chain (a reorg). Sent from the top down, before
    /// the replacement blocks are connected.
    Disconnected(BlockRef),
    /// The follower started, or lost track of the chain (a reorg deeper than
    /// [`REORG_WINDOW`]), and now continues from this block. Consumers
    /// should treat anything they derived from blocks after it as unsure.
    Reset(BlockRef),
}

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("bad lightwalletd URL: {0}")]
    Url(#[from] tonic::transport::Error),
    #[error("lightwalletd call failed: {0}")]
    Rpc(#[from] tonic::Status),
    #[error("lightwalletd is on network {found:?}, expected {expected:?}")]
    WrongNetwork { expected: String, found: String },
    #[error("lightwalletd sent an invalid block: {0}")]
    InvalidBlock(&'static str),
}

/// State shared with the rest of the server.
#[derive(Debug)]
pub struct Chain {
    tip: AtomicU64,
    events: broadcast::Sender<ChainEvent>,
}

impl Default for Chain {
    fn default() -> Self {
        Self {
            tip: AtomicU64::new(0),
            events: broadcast::channel(1024).0,
        }
    }
}

impl Chain {
    /// Height of the best block the server knows, or 0 before the follower
    /// has reached the chain source.
    pub fn tip(&self) -> u64 {
        self.tip.load(Ordering::Relaxed)
    }

    /// Chain events from now on. A receiver that falls more than 1024
    /// events behind gets `Lagged` and should resynchronize.
    pub fn subscribe(&self) -> broadcast::Receiver<ChainEvent> {
        self.events.subscribe()
    }

    fn announce(&self, event: ChainEvent, tip: u64) {
        self.tip.store(tip, Ordering::Relaxed);
        // No receivers is fine.
        let _ = self.events.send(event);
    }
}

/// A `CompactTxStreamer` client.
#[derive(Debug, Clone)]
pub struct Lightwalletd {
    client: CompactTxStreamerClient<Channel>,
}

impl Lightwalletd {
    /// Connects lazily: errors show up on the first call. `https://` URLs use
    /// the Mozilla root store; `http://` is for a server on the same host or
    /// private network.
    pub fn new(url: &str) -> Result<Self, ChainError> {
        let mut endpoint = Endpoint::from_shared(url.to_owned())?
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(120))
            .tcp_keepalive(Some(Duration::from_secs(60)));
        if url
            .get(..8)
            .is_some_and(|s| s.eq_ignore_ascii_case("https://"))
        {
            endpoint = endpoint.tls_config(ClientTlsConfig::new().with_webpki_roots())?;
        }
        let client = CompactTxStreamerClient::new(endpoint.connect_lazy())
            .max_decoding_message_size(MAX_MESSAGE);
        Ok(Self { client })
    }

    /// The server's `GetLightdInfo` answer.
    pub async fn info(&self) -> Result<LightdInfo, ChainError> {
        Ok(self
            .client
            .clone()
            .get_lightd_info(Empty {})
            .await?
            .into_inner())
    }

    /// Fails unless the server follows `network`.
    ///
    /// `chain_name` alone can't tell testnet from regtest: Zaino (like
    /// lightwalletd before it) reports `"test"` for both. Sapling's
    /// activation height can, because it's fixed on the public networks.
    pub async fn check_network(&self, network: Network) -> Result<(), ChainError> {
        let info = self.info().await?;
        let found = network_of(&info.chain_name, info.sapling_activation_height);
        if found != Some(network) {
            return Err(ChainError::WrongNetwork {
                expected: format!("{network:?}"),
                found: format!(
                    "{:?} (sapling activation {})",
                    info.chain_name, info.sapling_activation_height
                ),
            });
        }
        Ok(())
    }

    /// The current consensus branch id, for parsing mempool transactions.
    pub async fn consensus_branch_id(&self) -> Result<BranchId, ChainError> {
        let info = self.client.clone().get_lightd_info(Empty {}).await?;
        u32::from_str_radix(info.get_ref().consensus_branch_id.trim(), 16)
            .ok()
            .and_then(|id| BranchId::try_from(id).ok())
            .ok_or(ChainError::InvalidBlock("unknown consensus branch id"))
    }

    /// The whole mempool, then new transactions as they arrive. The server
    /// ends the stream when a block is mined.
    pub async fn mempool_stream(
        &self,
    ) -> Result<tonic::codec::Streaming<RawTransaction>, ChainError> {
        Ok(self
            .client
            .clone()
            .get_mempool_stream(Empty {})
            .await?
            .into_inner())
    }

    pub async fn latest_height(&self) -> Result<u64, ChainError> {
        let id = self.client.clone().get_latest_block(ChainSpec {}).await?;
        Ok(id.get_ref().height)
    }

    /// Blocks `start..=end` of the server's best chain, checked for height
    /// order and hash lengths. Returns fewer blocks if the server's chain is
    /// shorter than `end`.
    pub async fn blocks(&self, start: u64, end: u64) -> Result<Vec<CompactBlock>, ChainError> {
        let range = BlockRange {
            start: Some(BlockId {
                height: start,
                hash: Vec::new(),
            }),
            end: Some(BlockId {
                height: end,
                hash: Vec::new(),
            }),
            // Empty means the shielded pools only.
            pool_types: Vec::new(),
        };
        let mut stream = self
            .client
            .clone()
            .get_block_range(range)
            .await?
            .into_inner();
        let mut blocks = Vec::new();
        let mut expected = start;
        while let Some(block) = stream.message().await? {
            if block.height != expected || expected > end {
                return Err(ChainError::InvalidBlock("height out of order"));
            }
            if block.hash.len() != 32 || block.prev_hash.len() != 32 {
                return Err(ChainError::InvalidBlock("hash is not 32 bytes"));
            }
            blocks.push(block);
            expected += 1;
        }
        Ok(blocks)
    }
}

/// Sapling activation heights of the public networks.
const MAINNET_SAPLING: u64 = 419_200;
const TESTNET_SAPLING: u64 = 280_000;

/// Which network a `GetLightdInfo` answer describes.
pub fn network_of(chain_name: &str, sapling_activation: u64) -> Option<Network> {
    match chain_name {
        "main" if sapling_activation == MAINNET_SAPLING => Some(Network::Main),
        "test" if sapling_activation == TESTNET_SAPLING => Some(Network::Test),
        // zcashd-style servers say "regtest"; Zaino and lightwalletd say
        // "test" with regtest's own activation heights.
        "regtest" | "test" => Some(Network::Regtest),
        _ => None,
    }
}

/// Follows the chain until the process exits. Errors are logged and
/// retried with back-off; the server keeps serving meanwhile.
pub async fn run(chain: Arc<Chain>, source: Lightwalletd, network: Network, poll: Duration) {
    let mut follower = Follower::new(chain, source);
    let mut backoff = Duration::from_secs(1);
    let mut network_ok = false;
    loop {
        let result = if network_ok {
            follower.step().await
        } else {
            follower.source.check_network(network).await.map(|()| {
                network_ok = true;
                Step::Behind
            })
        };
        match result {
            Ok(Step::Behind) => backoff = Duration::from_secs(1),
            Ok(Step::CaughtUp) => {
                backoff = Duration::from_secs(1);
                tokio::time::sleep(poll).await;
            }
            Err(e) => {
                tracing::warn!(error = %e, retry_secs = backoff.as_secs(), "chain follower");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

/// Whether the follower has more to do right away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Behind,
    CaughtUp,
}

/// The follower's state machine, separate from the loop so tests can drive
/// it one step at a time.
#[derive(Debug)]
pub struct Follower {
    chain: Arc<Chain>,
    source: Lightwalletd,
    /// The last blocks of our view of the best chain, oldest first.
    recent: VecDeque<BlockRef>,
}

impl Follower {
    pub fn new(chain: Arc<Chain>, source: Lightwalletd) -> Self {
        Self {
            chain,
            source,
            recent: VecDeque::new(),
        }
    }

    /// One round: asks for the tip, then rolls back or fetches up to
    /// [`BATCH`] blocks.
    pub async fn step(&mut self) -> Result<Step, ChainError> {
        let tip = self.source.latest_height().await?;
        // Blocks above the server's tip have left its best chain.
        let mut trimmed = false;
        while self.recent.back().is_some_and(|b| b.height > tip) {
            self.disconnect_last();
            trimmed = true;
        }
        let Some(last) = self.recent.back().copied() else {
            self.reset_at(tip).await?;
            return Ok(Step::CaughtUp);
        };
        if last.height == tip {
            if trimmed {
                // The chain got shorter, so the block at the new tip may
                // have changed too.
                let theirs = self.source.blocks(tip, tip).await?;
                if theirs.first().is_none_or(|b| b.hash[..] != last.hash) {
                    self.disconnect_last();
                    return Ok(Step::Behind);
                }
            }
            return Ok(Step::CaughtUp);
        }

        let end = tip.min(last.height + BATCH);
        let blocks = self.source.blocks(last.height + 1, end).await?;
        let mut connected = 0;
        for block in blocks {
            let top = self.recent.back().copied().expect("not empty");
            if block.prev_hash[..] != top.hash {
                if connected == 0 {
                    // Our top block is no longer on the best chain.
                    self.disconnect_last();
                }
                // Otherwise the server's chain changed while streaming; the
                // next round sorts it out.
                return Ok(Step::Behind);
            }
            self.connect(block);
            connected += 1;
        }
        if connected == 0 {
            // The server's tip ran ahead of the blocks it can serve.
            return Ok(Step::CaughtUp);
        }
        Ok(if end == tip {
            Step::CaughtUp
        } else {
            Step::Behind
        })
    }

    /// Starts over at `height`, loading the blocks below it into the window
    /// (without announcing them) so a reorg right after can be rolled back.
    async fn reset_at(&mut self, height: u64) -> Result<(), ChainError> {
        let from = height.saturating_sub(REORG_WINDOW as u64 - 1);
        let blocks = self.source.blocks(from, height).await?;
        if blocks.last().is_none_or(|b| b.height != height) {
            return Err(ChainError::InvalidBlock("tip block missing"));
        }
        let refs: Vec<BlockRef> = blocks.iter().map(block_ref).collect();
        if refs
            .windows(2)
            .zip(&blocks[1..])
            .any(|(pair, child)| child.prev_hash[..] != pair[0].hash)
        {
            return Err(ChainError::InvalidBlock("chain changed while loading"));
        }
        let at = refs[refs.len() - 1];
        self.recent = refs.into();
        tracing::info!(height = at.height, "chain follower at tip");
        self.chain.announce(ChainEvent::Reset(at), at.height);
        Ok(())
    }

    fn connect(&mut self, block: CompactBlock) {
        let at = block_ref(&block);
        if self.recent.len() == REORG_WINDOW {
            self.recent.pop_front();
        }
        self.recent.push_back(at);
        tracing::debug!(height = at.height, "block connected");
        self.chain
            .announce(ChainEvent::Connected(Arc::new(block)), at.height);
    }

    fn disconnect_last(&mut self) {
        if let Some(gone) = self.recent.pop_back() {
            tracing::info!(height = gone.height, "block disconnected (reorg)");
            // The parent is on the best chain even if it is outside our window.
            let tip = gone.height.saturating_sub(1);
            self.chain.announce(ChainEvent::Disconnected(gone), tip);
        }
    }
}

fn block_ref(block: &CompactBlock) -> BlockRef {
    let mut hash = [0; 32];
    // Lengths were checked in `Lightwalletd::blocks`.
    hash.copy_from_slice(&block.hash);
    BlockRef {
        height: block.height,
        hash,
    }
}
