//! Drives one [`RoundMachine`] on the network under a wall-clock round schedule.
//!
//! Round `r` is the interval `[start + r*Delta, start + (r+1)*Delta)`. A message is
//! labeled with the round it is sent in; the inbox of round `r` is every
//! message labeled `r` that arrived before the round ended. A message
//! labeled `r` that arrives after that is *late*: it is counted, and
//! delivered in the round it arrived in, which is a synchrony violation the
//! protocol may or may not survive. Messages labeled with a future round are
//! held until that round. Everything delivered is recorded in a transcript
//! whose per-round inbox fingerprints can be compared with the simulator's.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use polaris_core::{Ctx, Dest, Metrics, NodeId, Params, Round, RoundMachine, wire};
use polaris_sim::{Entry, Transcript};
use serde::Serialize;

use crate::net::{Received, Transport};

#[derive(Clone, Debug)]
pub struct Schedule {
    pub params: Params,
    pub run_id: u64,
    pub round: Duration,
    /// Stop after this many rounds even without a decision.
    pub max_rounds: u32,
    /// Rounds to keep running after deciding, so peers still get our last messages.
    pub linger_rounds: u32,
}

#[derive(Debug)]
pub struct Outcome<O> {
    pub me: NodeId,
    pub output: Option<O>,
    pub decision_round: Option<Round>,
    pub rounds_run: u32,
    pub metrics: Metrics,
    pub transcript: Transcript,
}

pub async fn run_node<M>(
    me: NodeId,
    schedule: &Schedule,
    mut transport: Transport,
    start: Instant,
    mut machine: M,
) -> Outcome<M::Output>
where
    M: RoundMachine,
    M::Output: Clone + Serialize,
{
    let mut ctx = Ctx::new(me, schedule.params, schedule.run_id);
    let mut transcript = Transcript::default();
    let mut future: BTreeMap<Round, Vec<Received>> = BTreeMap::new();
    let mut decided_at: Option<Round> = None;

    tokio::time::sleep_until(start.into()).await;
    let first = machine.start(&mut ctx);
    send_all(&transport, &mut ctx, 0, first);

    let mut round: Round = 0;
    loop {
        let end = start + schedule.round * (round + 1);
        let mut inbox: Vec<Received> = future.remove(&round).unwrap_or_default();
        loop {
            let remaining = end.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, transport.recv()).await {
                Ok(Some(msg)) => classify(msg, round, &mut inbox, &mut future, &mut ctx.metrics),
                Ok(None) => break,
                Err(_) => break,
            }
        }
        // Whatever is already queued at the deadline counts as arrived in time.
        while let Some(msg) = transport.try_recv() {
            classify(msg, round, &mut inbox, &mut future, &mut ctx.metrics);
        }

        inbox.sort_by_key(|m| m.from);
        let mut decoded: Vec<(NodeId, M::Msg)> = Vec::with_capacity(inbox.len());
        let mut bytes = 0u64;
        for m in &inbox {
            match wire::decode::<M::Msg>(&m.payload) {
                Ok(msg) => {
                    transcript.record(Entry::new(m.round, m.from, me, &m.payload));
                    bytes += m.payload.len() as u64;
                    decoded.push((m.from, msg));
                }
                Err(e) => tracing::warn!(from = m.from, error = %e, "undecodable message dropped"),
            }
        }
        ctx.metrics.received(decoded.len() as u64, bytes);

        let out = if machine.is_halted() {
            vec![]
        } else {
            machine.end_round(&mut ctx, round, decoded)
        };
        ctx.metrics.end_round(round);
        send_all(&transport, &mut ctx, round + 1, out);

        if decided_at.is_none() && machine.output().is_some() {
            decided_at = Some(round);
            ctx.metrics.decided(round);
            tracing::debug!(node = me, round, "decided");
        }
        round += 1;
        let done = decided_at.is_some_and(|d| round > d + schedule.linger_rounds);
        if done || round >= schedule.max_rounds {
            break;
        }
    }

    Outcome {
        me,
        output: machine.output().cloned(),
        decision_round: decided_at,
        rounds_run: round,
        metrics: ctx.metrics,
        transcript,
    }
}

fn classify(
    msg: Received,
    round: Round,
    inbox: &mut Vec<Received>,
    future: &mut BTreeMap<Round, Vec<Received>>,
    metrics: &mut Metrics,
) {
    if msg.round > round {
        future.entry(msg.round).or_default().push(msg);
    } else {
        if msg.round < round {
            metrics.late(1);
            tracing::warn!(from = msg.from, labeled = msg.round, round, "late message");
        }
        inbox.push(msg);
    }
}

fn send_all<M: Serialize>(
    transport: &Transport,
    ctx: &mut Ctx,
    round: Round,
    out: Vec<polaris_core::Outgoing<M>>,
) {
    let n = ctx.params.n;
    let mut batches: Vec<Vec<Vec<u8>>> = (0..n).map(|_| Vec::new()).collect();
    let (mut msgs, mut bytes) = (0u64, 0u64);
    for o in out {
        let payload = wire::encode(&o.msg).expect("protocol messages serialize");
        let recipients: Vec<usize> = match o.to {
            Dest::All => (0..n).collect(),
            Dest::One(j) => vec![usize::from(j)],
        };
        msgs += recipients.len() as u64;
        bytes += payload.len() as u64 * recipients.len() as u64;
        for to in recipients {
            batches[to].push(payload.clone());
        }
    }
    ctx.metrics.sent(msgs, bytes);
    for (to, payloads) in batches.into_iter().enumerate() {
        transport.send_batch(NodeId::try_from(to).expect("fits"), round, payloads);
    }
}

impl<O: Serialize> Outcome<O> {
    /// Writes `node-<id>.metrics.jsonl`, `node-<id>.transcript.jsonl` and
    /// `node-<id>.output.json` into `dir`.
    pub fn write_to(&self, dir: &std::path::Path) -> anyhow::Result<()> {
        std::fs::create_dir_all(dir)?;
        let mut metrics = String::new();
        for rec in self.metrics.records(self.me) {
            metrics.push_str(&serde_json::to_string(&rec)?);
            metrics.push('\n');
        }
        std::fs::write(dir.join(format!("node-{}.metrics.jsonl", self.me)), metrics)?;
        std::fs::write(
            dir.join(format!("node-{}.transcript.jsonl", self.me)),
            self.transcript.to_json_lines(),
        )?;
        std::fs::write(
            dir.join(format!("node-{}.output.json", self.me)),
            serde_json::to_string_pretty(&serde_json::json!({
                "node": self.me,
                "decision_round": self.decision_round,
                "rounds_run": self.rounds_run,
                "output": self.output,
            }))?,
        )?;
        Ok(())
    }
}
