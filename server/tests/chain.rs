//! Chain follower against a fake `CompactTxStreamer` over real gRPC.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use lz_proto::lease::Network;
use lz_server::chain::{BATCH, Chain, ChainError, ChainEvent, Follower, Lightwalletd, Step};
use tokio::sync::broadcast::Receiver;
use tonic::body::Body;
use tonic::server::{Grpc, NamedService, ServerStreamingService, UnaryService};
use tonic::{Request, Response, Status};
use tonic_prost::ProstCodec;
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::proto::service::{BlockId, BlockRange, ChainSpec, Empty, LightdInfo};

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// A best chain the test can change. Block hashes are `[fork, height
/// bytes...]`, so two forks never share a hash above their split point.
#[derive(Default)]
struct FakeChain {
    blocks: Vec<CompactBlock>,
    chain_name: String,
    /// Report a higher tip than the blocks we serve.
    tip_lead: u64,
    range_calls: Vec<(u64, u64)>,
}

impl FakeChain {
    fn hash(fork: u8, height: u64) -> Vec<u8> {
        let mut h = vec![fork; 32];
        h[24..].copy_from_slice(&height.to_be_bytes());
        h
    }

    /// Replaces everything from `from` up with `count` blocks of `fork`.
    fn build(&mut self, from: u64, count: u64, fork: u8) {
        self.blocks.retain(|b| b.height < from);
        for height in from..from + count {
            let prev_hash = self
                .blocks
                .last()
                .map_or_else(|| vec![0; 32], |b| b.hash.clone());
            self.blocks.push(CompactBlock {
                height,
                hash: Self::hash(fork, height),
                prev_hash,
                ..CompactBlock::default()
            });
        }
    }

    fn tip(&self) -> u64 {
        self.blocks.last().map_or(0, |b| b.height) + self.tip_lead
    }
}

#[derive(Clone)]
struct Fake(Arc<Mutex<FakeChain>>);

impl NamedService for Fake {
    const NAME: &'static str = "cash.z.wallet.sdk.rpc.CompactTxStreamer";
}

struct Latest(Fake);
impl UnaryService<ChainSpec> for Latest {
    type Response = BlockId;
    type Future = BoxFuture<Result<Response<BlockId>, Status>>;
    fn call(&mut self, _: Request<ChainSpec>) -> Self::Future {
        let height = self.0.0.lock().unwrap().tip();
        Box::pin(async move {
            Ok(Response::new(BlockId {
                height,
                // Deliberately junk: the follower must not rely on it.
                hash: vec![0xEE; 32],
            }))
        })
    }
}

struct Info(Fake);
impl UnaryService<Empty> for Info {
    type Response = LightdInfo;
    type Future = BoxFuture<Result<Response<LightdInfo>, Status>>;
    fn call(&mut self, _: Request<Empty>) -> Self::Future {
        let chain_name = self.0.0.lock().unwrap().chain_name.clone();
        Box::pin(async move {
            Ok(Response::new(LightdInfo {
                chain_name,
                ..LightdInfo::default()
            }))
        })
    }
}

struct Range(Fake);
impl ServerStreamingService<BlockRange> for Range {
    type Response = CompactBlock;
    type ResponseStream = tokio_stream::Iter<std::vec::IntoIter<Result<CompactBlock, Status>>>;
    type Future = BoxFuture<Result<Response<Self::ResponseStream>, Status>>;
    fn call(&mut self, req: Request<BlockRange>) -> Self::Future {
        let r = req.into_inner();
        let (start, end) = (r.start.unwrap().height, r.end.unwrap().height);
        let mut chain = self.0.0.lock().unwrap();
        chain.range_calls.push((start, end));
        let blocks: Vec<_> = chain
            .blocks
            .iter()
            .filter(|b| (start..=end).contains(&b.height))
            .cloned()
            .map(Ok)
            .collect();
        Box::pin(async move { Ok(Response::new(tokio_stream::iter(blocks))) })
    }
}

impl tower::Service<http::Request<Body>> for Fake {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture<Result<Self::Response, Infallible>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<Body>) -> Self::Future {
        let me = self.clone();
        let method = req.uri().path().rsplit('/').next().unwrap_or("").to_owned();
        Box::pin(async move {
            // One codec per method, because each has its own message types.
            fn grpc<A, B>() -> Grpc<ProstCodec<A, B>>
            where
                A: prost::Message + Send + 'static,
                B: prost::Message + Default + Send + 'static,
            {
                Grpc::new(ProstCodec::default())
            }
            Ok(match method.as_str() {
                "GetLatestBlock" => grpc().unary(Latest(me), req).await,
                "GetLightdInfo" => grpc().unary(Info(me), req).await,
                "GetBlockRange" => grpc().server_streaming(Range(me), req).await,
                _ => Status::unimplemented("not faked").into_http(),
            })
        })
    }
}

struct Harness {
    fake: Arc<Mutex<FakeChain>>,
    source: Lightwalletd,
    follower: Follower,
    chain: Arc<Chain>,
    events: Receiver<ChainEvent>,
}

async fn harness() -> Harness {
    let mut genesis = FakeChain {
        chain_name: "main".into(),
        ..FakeChain::default()
    };
    genesis.build(0, 1, 0);
    let fake = Arc::new(Mutex::new(genesis));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let svc = Fake(fake.clone());
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let source = Lightwalletd::new(&format!("http://{addr}")).unwrap();
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
