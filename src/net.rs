//! Authenticated point-to-point channels over TCP.
//!
//! One outgoing connection per peer carries our frames to it; one incoming
//! connection per peer carries theirs to us. A connection is authenticated
//! once, when it opens: the acceptor sends a 32-byte nonce and the connector
//! answers with an Ed25519 signature over `nonce || from || to` under the run's
//! handshake tag, checked against the bulletin-board key of the claimed
//! sender. After that the stream is trusted, as the model's authenticated
//! channels are, and nothing is signed per message.
//!
//! Frames: `u32` big-endian length, then a postcard `Frame` carrying the
//! run id, the round the message is sent in, and the protocol payload.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use polaris_core::{NodeId, NodeSet, Round, wire};
use polaris_crypto::keyring::{Keyring, NodeKeys};
use polaris_crypto::{domain, ed25519};
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const NONCE_LEN: usize = 32;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Serialize, Deserialize)]
struct Frame {
    run_id: u64,
    round: Round,
    payload: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Hello {
    from: NodeId,
    to: NodeId,
    run_id: u64,
    sig: ed25519::Sig,
}

fn handshake_body(nonce: &[u8; NONCE_LEN], from: NodeId, to: NodeId) -> Vec<u8> {
    [nonce.as_slice(), &from.to_le_bytes(), &to.to_le_bytes()].concat()
}

/// A protocol message that arrived, as the runner sees it.
#[derive(Debug)]
pub struct Received {
    pub from: NodeId,
    pub round: Round,
    pub payload: Vec<u8>,
    pub at: Instant,
}

pub struct Transport {
    me: NodeId,
    run_id: u64,
    rx: mpsc::UnboundedReceiver<Received>,
    loopback: mpsc::UnboundedSender<Received>,
    peers: Vec<Option<mpsc::UnboundedSender<Vec<u8>>>>,
}

impl Transport {
    pub async fn bind(addr: &str) -> anyhow::Result<TcpListener> {
        TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding {addr}"))
    }

    /// Opens an authenticated connection to every peer and waits until every
    /// peer has opened one to us; `peers[j]` is node j's listen address.
    pub async fn connect(
        keys: Arc<NodeKeys>,
        keyring: Arc<Keyring>,
        listener: TcpListener,
        peers: Vec<SocketAddr>,
        max_frame: usize,
        connect_timeout: Duration,
    ) -> anyhow::Result<Self> {
        let me = keys.id;
        let run_id = keyring.run_id;
        let n = keyring.n();
        if peers.len() != n {
            bail!("expected {n} peer addresses, got {}", peers.len());
        }
        let (tx, rx) = mpsc::unbounded_channel();
        let (ready_tx, mut ready_rx) = mpsc::unbounded_channel::<NodeId>();
        tokio::spawn(accept_loop(
            listener,
            keyring.clone(),
            me,
            tx.clone(),
            ready_tx,
            max_frame,
        ));

        let deadline = Instant::now() + connect_timeout;
        let mut dials = Vec::new();
        for (j, addr) in peers.iter().enumerate() {
            let j = NodeId::try_from(j).expect("n fits a NodeId");
            if j == me {
                continue;
            }
            let keys = keys.clone();
            let addr = *addr;
            dials.push((j, tokio::spawn(dial(addr, keys, j, run_id, deadline))));
        }
        let mut senders: Vec<Option<mpsc::UnboundedSender<Vec<u8>>>> =
            (0..n).map(|_| None).collect();
        for (j, handle) in dials {
            let sender = handle
                .await
                .context("dial task")?
                .with_context(|| format!("connecting to node {j}"))?;
            senders[usize::from(j)] = Some(sender);
        }

        let mut seen = NodeSet::empty(n);
        while seen.count() < n - 1 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, ready_rx.recv()).await {
                Ok(Some(from)) => {
                    seen.insert(from);
                }
                Ok(None) => bail!("acceptor stopped"),
                Err(_) => bail!(
                    "timed out waiting for incoming connections; missing {:?}",
                    (0..n)
                        .map(|j| NodeId::try_from(j).expect("fits"))
                        .filter(|&j| j != me && !seen.contains(j))
                        .collect::<Vec<_>>()
                ),
            }
        }
        Ok(Self {
            me,
            run_id,
            rx,
            loopback: tx,
            peers: senders,
        })
    }

    /// Queues `payload` for `to`, labeled with the round it is sent in.
    /// A message to ourselves is delivered without touching the network.
    pub fn send(&self, to: NodeId, round: Round, payload: Vec<u8>) {
        if to == self.me {
            let _ = self.loopback.send(Received {
                from: self.me,
                round,
                payload,
                at: Instant::now(),
            });
            return;
        }
        let frame = wire::encode(&Frame {
            run_id: self.run_id,
            round,
            payload,
        })
        .expect("frame serializes");
        if let Some(tx) = &self.peers[usize::from(to)] {
            let _ = tx.send(framed(&frame));
        }
    }

    pub async fn recv(&mut self) -> Option<Received> {
        self.rx.recv().await
    }

    pub fn try_recv(&mut self) -> Option<Received> {
        self.rx.try_recv().ok()
    }
}

fn framed(bytes: &[u8]) -> Vec<u8> {
    let len = u32::try_from(bytes.len()).expect("frame fits u32");
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

async fn read_frame(
    stream: &mut (impl AsyncReadExt + Unpin),
    max: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > max {
        bail!("frame of {len} bytes exceeds the {max}-byte limit");
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn dial(
    addr: SocketAddr,
    keys: Arc<NodeKeys>,
    to: NodeId,
    run_id: u64,
    deadline: Instant,
) -> anyhow::Result<mpsc::UnboundedSender<Vec<u8>>> {
    let started = Instant::now();
    let mut stream = loop {
        match TcpStream::connect(addr).await {
            Ok(s) => break s,
            Err(e) if Instant::now() < deadline => {
                tracing::debug!(%addr, error = %e, "connect failed, retrying");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "no connection to {addr} after retrying for {:.0?}; is that node running?",
                        started.elapsed()
                    )
                });
            }
        }
    };
    stream.set_nodelay(true)?;
    let mut nonce = [0u8; NONCE_LEN];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut nonce))
        .await
        .context("waiting for the handshake nonce")??;
    let hello = Hello {
        from: keys.id,
        to,
        run_id,
        sig: ed25519::sign(
            &keys.ed25519,
            domain::HANDSHAKE,
            run_id,
            &handshake_body(&nonce, keys.id, to),
        ),
    };
    stream.write_all(&framed(&wire::encode(&hello)?)).await?;

    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if let Err(e) = stream.write_all(&bytes).await {
                tracing::warn!(peer = to, error = %e, "write failed; dropping connection");
                return;
            }
        }
    });
    Ok(tx)
}

async fn accept_loop(
    listener: TcpListener,
    keyring: Arc<Keyring>,
    me: NodeId,
    tx: mpsc::UnboundedSender<Received>,
    ready_tx: mpsc::UnboundedSender<NodeId>,
    max_frame: usize,
) {
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let keyring = keyring.clone();
                let tx = tx.clone();
                let ready_tx = ready_tx.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_incoming(stream, keyring, me, tx, ready_tx, max_frame).await
                    {
                        tracing::debug!(%addr, error = %e, "incoming connection ended");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

async fn handle_incoming(
    mut stream: TcpStream,
    keyring: Arc<Keyring>,
    me: NodeId,
    tx: mpsc::UnboundedSender<Received>,
    ready_tx: mpsc::UnboundedSender<NodeId>,
    max_frame: usize,
) -> anyhow::Result<()> {
    stream.set_nodelay(true)?;
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    stream.write_all(&nonce).await?;
    let hello: Hello = wire::decode(
        &tokio::time::timeout(HANDSHAKE_TIMEOUT, read_frame(&mut stream, 4096))
            .await
            .context("waiting for hello")??,
    )?;
    if hello.to != me || hello.run_id != keyring.run_id || usize::from(hello.from) >= keyring.n() {
        bail!("hello for the wrong node or run");
    }
    if !ed25519::verify(
        keyring.ed25519(hello.from),
        domain::HANDSHAKE,
        keyring.run_id,
        &handshake_body(&nonce, hello.from, me),
        &hello.sig,
    ) {
        bail!(
            "handshake signature of claimed node {} does not verify",
            hello.from
        );
    }
    let from = hello.from;
    let _ = ready_tx.send(from);
    loop {
        let bytes = read_frame(&mut stream, max_frame).await?;
        let frame: Frame = wire::decode(&bytes)?;
        if frame.run_id != keyring.run_id {
            continue;
        }
        if tx
            .send(Received {
                from,
                round: frame.round,
                payload: frame.payload,
                at: Instant::now(),
            })
            .is_err()
        {
            return Ok(());
        }
    }
}
