//! Chain follower against a fake `CompactTxStreamer` over real gRPC.

mod common;

use std::sync::{Arc, Mutex};

use common::fake_lwd::{FakeChain, genesis, serve};
use lz_proto::lease::Network;
use lz_server::chain::{BATCH, Chain, ChainError, ChainEvent, Follower, Lightwalletd, Step};
use tokio::sync::broadcast::Receiver;

struct Harness {
    fake: Arc<Mutex<FakeChain>>,
    source: Lightwalletd,
    follower: Follower,
    chain: Arc<Chain>,
    events: Receiver<ChainEvent>,
}

async fn harness() -> Harness {
    let fake = genesis();
    let source = Lightwalletd::new(&serve(fake.clone()).await).unwrap();
    let chain = Arc::new(Chain::default());
    let events = chain.subscribe();
    Harness {
        fake,
        follower: Follower::new(chain.clone(), source.clone()),
        source,
        chain,
        events,
    }
}

impl Harness {
    /// Steps until caught up, then returns the events as short strings:
    /// `+h` connected, `-h` disconnected, `=h` reset.
    async fn sync(&mut self) -> Vec<String> {
        for _ in 0..1000 {
            if self.follower.step().await.unwrap() == Step::CaughtUp {
                break;
            }
        }
        let mut out = Vec::new();
        while let Ok(e) = self.events.try_recv() {
            out.push(match e {
                ChainEvent::Connected(b) => format!("+{}", b.height),
                ChainEvent::Disconnected(b) => format!("-{}", b.height),
                ChainEvent::Reset(b) => format!("={}", b.height),
            });
        }
        out
    }

    fn build(&self, from: u64, count: u64, fork: u8) {
        self.fake.lock().unwrap().build(from, count, fork);
    }
}

#[tokio::test]
async fn starts_at_tip_then_follows() {
    let mut h = harness().await;
    h.build(1, 10, 1);
    assert_eq!(h.chain.tip(), 0);
    assert_eq!(h.sync().await, ["=10"]);
    assert_eq!(h.chain.tip(), 10);

    h.build(11, 3, 1);
    assert_eq!(h.sync().await, ["+11", "+12", "+13"]);
    assert_eq!(h.chain.tip(), 13);
    assert!(h.sync().await.is_empty());
}

#[tokio::test]
async fn rolls_back_a_reorg_and_connects_the_new_branch() {
    let mut h = harness().await;
    h.build(1, 10, 1);
    h.sync().await;
    // Blocks 8..=10 are replaced by a longer fork.
    h.build(8, 5, 2);
    assert_eq!(
        h.sync().await,
        ["-10", "-9", "-8", "+8", "+9", "+10", "+11", "+12"]
    );
    assert_eq!(h.chain.tip(), 12);
}

#[tokio::test]
async fn handles_a_shorter_best_chain() {
    let mut h = harness().await;
    h.build(1, 10, 1);
    h.sync().await;
    // The new best chain forks at 7 and is only 8 high.
    h.build(7, 2, 2);
    assert_eq!(h.sync().await, ["-10", "-9", "-8", "-7", "+7", "+8"]);
    assert_eq!(h.chain.tip(), 8);
}

#[tokio::test]
async fn same_height_replacement_is_caught_at_the_next_block() {
    let mut h = harness().await;
    h.build(1, 10, 1);
    h.sync().await;
    h.build(10, 1, 2);
    assert!(h.sync().await.is_empty(), "invisible until a child arrives");
    h.build(11, 1, 2);
    assert_eq!(h.sync().await, ["-10", "+10", "+11"]);
}

#[tokio::test]
async fn reorg_deeper_than_the_window_resets() {
    let mut h = harness().await;
    h.build(1, 50, 1);
    h.sync().await;
    h.build(51, 150, 1);
    h.sync().await;
    // Replace everything above 10: deeper than the 100-block window.
    h.build(11, 200, 2);
    let events = h.sync().await;
    assert_eq!(events.iter().filter(|e| e.starts_with('-')).count(), 100);
    assert_eq!(events.last().unwrap(), "=210");
    assert_eq!(h.chain.tip(), 210);
    // Then it follows the new chain normally.
    h.build(211, 1, 2);
    assert_eq!(h.sync().await, ["+211"]);
}

#[tokio::test]
async fn catches_up_in_batches() {
    let mut h = harness().await;
    h.build(1, 1, 1);
    h.sync().await;
    h.build(2, 2 * BATCH + 5, 1);
    let events = h.sync().await;
    assert_eq!(events.len() as u64, 2 * BATCH + 5);
    let calls = h.fake.lock().unwrap().range_calls.clone();
    assert!(calls.iter().all(|(s, e)| e - s < BATCH), "{calls:?}");
}

#[tokio::test]
async fn tip_ahead_of_served_blocks_is_not_an_error() {
    let mut h = harness().await;
    h.build(1, 5, 1);
    h.sync().await;
    h.fake.lock().unwrap().tip_lead = 3;
    assert_eq!(h.follower.step().await.unwrap(), Step::CaughtUp);
    assert_eq!(h.chain.tip(), 5);
}

#[tokio::test]
async fn refuses_the_wrong_network() {
    let h = harness().await;
    assert!(h.source.check_network(Network::Main).await.is_ok());
    h.fake.lock().unwrap().chain_name = "test".into();
    assert!(matches!(
        h.source.check_network(Network::Main).await,
        Err(ChainError::WrongNetwork { .. })
    ));
    assert!(h.source.check_network(Network::Test).await.is_ok());
    assert!(h.source.check_network(Network::Regtest).await.is_err());
}

#[test]
fn tells_testnet_from_regtest_by_sapling_activation() {
    use lz_server::chain::network_of;
    assert_eq!(network_of("main", 419_200), Some(Network::Main));
    assert_eq!(network_of("main", 1), None);
    assert_eq!(network_of("test", 280_000), Some(Network::Test));
    // What Zaino 0.10 reports for a Zebra regtest node.
    assert_eq!(network_of("test", 1), Some(Network::Regtest));
    assert_eq!(network_of("regtest", 1), Some(Network::Regtest));
    assert_eq!(network_of("other", 1), None);
}

#[tokio::test]
async fn rejects_malformed_blocks() {
    let h = harness().await;
    h.build(1, 3, 1);
    h.fake.lock().unwrap().blocks[1].hash.truncate(31);
    assert!(matches!(
        h.source.blocks(1, 3).await,
        Err(ChainError::InvalidBlock(_))
    ));
    // Out of order heights.
    h.build(1, 3, 1);
    h.fake.lock().unwrap().blocks.swap(1, 2);
    assert!(matches!(
        h.source.blocks(1, 3).await,
        Err(ChainError::InvalidBlock(_))
    ));
}

#[tokio::test]
async fn unreachable_source_is_an_error_not_a_panic() {
    let source = Lightwalletd::new("http://127.0.0.1:1").unwrap();
    let mut f = Follower::new(Arc::new(Chain::default()), source);
    assert!(matches!(f.step().await, Err(ChainError::Rpc(_))));
}

#[test]
fn warns_when_the_tip_stops_moving() {
    use lz_server::chain::{STALL_WARNING, StallWatch};
    use std::time::{Duration, Instant};
    let t0 = Instant::now();
    let mut w = StallWatch::new(t0);
    assert_eq!(w.check(10, t0), None);
    assert_eq!(
        w.check(10, t0 + STALL_WARNING - Duration::from_secs(1)),
        None
    );
    assert_eq!(w.check(10, t0 + STALL_WARNING), Some(10));
    // Once per interval while stuck, not on every poll.
    assert_eq!(
        w.check(10, t0 + STALL_WARNING + Duration::from_secs(5)),
        None
    );
    assert_eq!(w.check(10, t0 + 2 * STALL_WARNING), Some(20));
    // A new block resets it.
    assert_eq!(
        w.check(11, t0 + 2 * STALL_WARNING + Duration::from_secs(1)),
        None
    );
    assert_eq!(
        w.check(11, t0 + 2 * STALL_WARNING + Duration::from_secs(2)),
        None
    );
}
