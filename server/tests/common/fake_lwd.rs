//! A fake `CompactTxStreamer` (Zaino or lightwalletd) served over real gRPC.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tonic::body::Body;
use tonic::server::{Grpc, NamedService, ServerStreamingService, UnaryService};
use tonic::{Request, Response, Status};
use tonic_prost::ProstCodec;
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::proto::service::{
    BlockId, BlockRange, ChainSpec, Empty, LightdInfo, RawTransaction,
};

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// A best chain the test can change. Block hashes are `[fork, height
/// bytes...]`, so two forks never share a hash above their split point.
#[derive(Default)]
pub struct FakeChain {
    pub blocks: Vec<CompactBlock>,
    pub chain_name: String,
    /// Report a higher tip than the blocks we serve.
    pub tip_lead: u64,
    pub range_calls: Vec<(u64, u64)>,
    /// Raw transactions `GetMempoolStream` sends before ending the stream.
    pub mempool: Vec<Vec<u8>>,
    /// Overrides the reported consensus branch id (hex).
    pub branch_id: Option<String>,
}

impl FakeChain {
    pub fn hash(fork: u8, height: u64) -> Vec<u8> {
        let mut h = vec![fork; 32];
        h[24..].copy_from_slice(&height.to_be_bytes());
        h
    }

    /// Replaces everything from `from` up with `count` blocks of `fork`.
    pub fn build(&mut self, from: u64, count: u64, fork: u8) {
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

    pub fn tip(&self) -> u64 {
        self.blocks.last().map_or(0, |b| b.height) + self.tip_lead
    }
}

#[derive(Clone)]
pub struct Fake(pub Arc<Mutex<FakeChain>>);

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
        let (chain_name, branch_id) = {
            let c = self.0.0.lock().unwrap();
            (c.chain_name.clone(), c.branch_id.clone())
        };
        Box::pin(async move {
            Ok(Response::new(LightdInfo {
                sapling_activation_height: match chain_name.as_str() {
                    "main" => 419_200,
                    "test" => 280_000,
                    _ => 1,
                },
                chain_name,
                // NU6.3, as lightwalletd reports it (hex).
                consensus_branch_id: branch_id.unwrap_or_else(|| {
                    format!(
                        "{:08x}",
                        u32::from(zcash_protocol::consensus::BranchId::Nu6_3)
                    )
                }),
                ..LightdInfo::default()
            }))
        })
    }
}

struct Mempool(Fake);
impl ServerStreamingService<Empty> for Mempool {
    type Response = RawTransaction;
    type ResponseStream = tokio_stream::Iter<std::vec::IntoIter<Result<RawTransaction, Status>>>;
    type Future = BoxFuture<Result<Response<Self::ResponseStream>, Status>>;
    fn call(&mut self, _: Request<Empty>) -> Self::Future {
        let txs: Vec<_> = self
            .0
            .0
            .lock()
            .unwrap()
            .mempool
            .iter()
            .map(|data| {
                Ok(RawTransaction {
                    data: data.clone(),
                    height: 0,
                })
            })
            .collect();
        Box::pin(async move { Ok(Response::new(tokio_stream::iter(txs))) })
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
                "GetMempoolStream" => grpc().server_streaming(Mempool(me), req).await,
                _ => Status::unimplemented("not faked").into_http(),
            })
        })
    }
}

/// Serves `chain` on a local port; returns its `http://` URL.
pub async fn serve(chain: Arc<Mutex<FakeChain>>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let svc = Fake(chain);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    format!("http://{addr}")
}

/// A mainnet fake holding only a genesis block.
pub fn genesis() -> Arc<Mutex<FakeChain>> {
    let mut c = FakeChain {
        chain_name: "main".into(),
        ..FakeChain::default()
    };
    c.build(0, 1, 0);
    Arc::new(Mutex::new(c))
}
