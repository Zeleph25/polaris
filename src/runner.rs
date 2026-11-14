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
use serde::de::DeserializeOwned;

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
    /// Wall-clock time from round 0 to the decision.
    pub decided_after: Option<Duration>,
    /// Wall-clock time from round 0 to the end of the last round.
    pub ran_for: Duration,
    /// CPU time and peak memory of this process at the end of the run.
    pub resources: Resources,
}

/// What the process has used so far, from `getrusage`.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Resources {
    pub cpu_user_ms: u64,
    pub cpu_sys_ms: u64,
    /// Peak resident set, in kilobytes.
    pub max_rss_kb: u64,
}

impl Resources {
    #[allow(unsafe_code)]
    pub fn now() -> Self {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        // SAFETY: getrusage fills a complete rusage for RUSAGE_SELF and
        // returns 0; the struct is only read after that.
        let usage = unsafe {
            if libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) != 0 {
                return Self::default();
            }
            usage.assume_init()
        };
        let ms = |tv: libc::timeval| {
            u64::try_from(tv.tv_sec).unwrap_or(0) * 1000
                + u64::try_from(tv.tv_usec).unwrap_or(0) / 1000
        };
        let rss = u64::try_from(usage.ru_maxrss).unwrap_or(0);
        Self {
            cpu_user_ms: ms(usage.ru_utime),
            cpu_sys_ms: ms(usage.ru_stime),
            // macOS reports bytes, Linux kilobytes.
            max_rss_kb: if cfg!(target_os = "macos") {
                rss / 1024
            } else {
                rss
            },
        }
    }
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
    let mut decided_after: Option<Duration> = None;

    tokio::time::sleep_until(start.into()).await;
    let first = machine.start(&mut ctx);
    send_all(&transport, &mut ctx, 0, first);

    let mut round: Round = 0;
    loop {
        let end = start + schedule.round * (round + 1);
        let mut inbox: Inbox<M::Msg> = Inbox::default();
        for msg in future.remove(&round).unwrap_or_default() {
            inbox.accept(msg, me);
        }
        loop {
            let remaining = end.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, transport.recv()).await {
                Ok(Some(msg)) => {
                    if let Some(msg) = classify(msg, round, &mut future, &mut ctx.metrics) {
                        inbox.accept(msg, me);
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        // Whatever is already queued at the deadline counts as arrived in time.
        while let Some(msg) = transport.try_recv() {
            if let Some(msg) = classify(msg, round, &mut future, &mut ctx.metrics) {
                inbox.accept(msg, me);
            }
        }

        let Inbox { msgs, entries } = inbox.sorted_by_sender(schedule.params.n);
        let bytes = entries.iter().map(|e| u64::from(e.bytes)).sum();
        for e in entries {
            transcript.record(e);
        }
        ctx.metrics.received(msgs.len() as u64, bytes);

        let out = if machine.is_halted() {
            vec![]
        } else {
            machine.end_round(&mut ctx, round, msgs)
        };
        ctx.metrics.end_round(round);
        send_all(&transport, &mut ctx, round + 1, out);

        if decided_at.is_none() && machine.output().is_some() {
            decided_at = Some(round);
            decided_after = Some(start.elapsed());
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
        decided_after,
        ran_for: start.elapsed(),
        resources: Resources::now(),
    }
}

/// The round being collected. Messages are decoded as they arrive, so that
/// their wire bytes are freed at once instead of being held next to the
/// decoded inbox, which is the largest thing a node keeps.
struct Inbox<Msg> {
    msgs: Vec<(NodeId, Msg)>,
    entries: Vec<Entry>,
}

impl<Msg> Default for Inbox<Msg> {
    fn default() -> Self {
        Self {
            msgs: Vec::new(),
            entries: Vec::new(),
        }
    }
}

impl<Msg: DeserializeOwned> Inbox<Msg> {
    fn accept(&mut self, m: Received, me: NodeId) {
        match wire::decode::<Msg>(&m.payload) {
            Ok(msg) => {
                self.entries
                    .push(Entry::new(m.round, m.from, me, &m.payload));
                self.msgs.push((m.from, msg));
            }
            Err(e) => tracing::warn!(from = m.from, error = %e, "undecodable message dropped"),
        }
    }
}

impl<Msg> Inbox<Msg> {
    /// Orders the messages by sender, each sender's in arrival order, and
    /// the transcript entries with them. Done in place: a stable sort of the
    /// messages would allocate a buffer of up to half the inbox.
    fn sorted_by_sender(mut self, n: usize) -> Self {
        let mut start = vec![0usize; n + 1];
        for (from, _) in &self.msgs {
            start[usize::from(*from) + 1] += 1;
        }
        for i in 0..n {
            start[i + 1] += start[i];
        }
        // dest[k]: where the message now at k belongs.
        let mut dest: Vec<usize> = self
            .msgs
            .iter()
            .map(|(from, _)| {
                let slot = &mut start[usize::from(*from)];
                *slot += 1;
                *slot - 1
            })
            .collect();
        for k in 0..dest.len() {
            while dest[k] != k {
                let d = dest[k];
                self.msgs.swap(k, d);
                self.entries.swap(k, d);
                dest.swap(k, d);
            }
        }
        self
    }
}

/// Holds a message labeled with a later round until then; returns it for
/// the current round otherwise, counting it as late if labeled earlier.
fn classify(
    msg: Received,
    round: Round,
    future: &mut BTreeMap<Round, Vec<Received>>,
    metrics: &mut Metrics,
) -> Option<Received> {
    if msg.round > round {
        future.entry(msg.round).or_default().push(msg);
        return None;
    }
    if msg.round < round {
        metrics.late(1);
        tracing::warn!(from = msg.from, labeled = msg.round, round, "late message");
    }
    Some(msg)
}

fn send_all<M: Serialize>(
    transport: &Transport,
    ctx: &mut Ctx,
    round: Round,
    out: Vec<polaris_core::Outgoing<M>>,
) {
    let n = ctx.params.n;
    let mut common: Vec<Vec<u8>> = Vec::new();
    let mut extra: Vec<Vec<Vec<u8>>> = Vec::new();
    let (mut msgs, mut bytes) = (0u64, 0u64);
    for o in out {
        let payload = wire::encode(&o.msg).expect("protocol messages serialize");
        match o.to {
            Dest::All => {
                msgs += n as u64;
                bytes += payload.len() as u64 * n as u64;
                common.push(payload);
            }
            Dest::One(j) => {
                extra.resize_with(n, Vec::new);
                if let Some(e) = extra.get_mut(usize::from(j)) {
                    msgs += 1;
                    bytes += payload.len() as u64;
                    e.push(payload);
                }
            }
        }
    }
    ctx.metrics.sent(msgs, bytes);
    transport.send_round(round, common, extra);
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
        let mut transcript = std::io::BufWriter::new(std::fs::File::create(
            dir.join(format!("node-{}.transcript.jsonl", self.me)),
        )?);
        self.transcript.write_json_lines(&mut transcript)?;
        std::io::Write::flush(&mut transcript)?;
        std::fs::write(
            dir.join(format!("node-{}.output.json", self.me)),
            serde_json::to_string_pretty(&serde_json::json!({
                "node": self.me,
                "decision_round": self.decision_round,
                "rounds_run": self.rounds_run,
                "decided_after_ms": self.decided_after.map(|d| d.as_millis()),
                "ran_for_ms": self.ran_for.as_millis(),
                "resources": self.resources,
                "output": self.output,
            }))?,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rand::{RngExt as _, SeedableRng as _};

    use super::*;

    #[test]
    fn inbox_order_is_a_stable_sort_by_sender() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(7);
        let n = 9;
        let mut inbox: Inbox<u32> = Inbox::default();
        for k in 0..500u32 {
            let from: NodeId = rng.random_range(0..n as NodeId);
            inbox.msgs.push((from, k));
            inbox.entries.push(Entry::new(1, from, 0, &k.to_le_bytes()));
        }
        let mut expected = inbox.msgs.clone();
        expected.sort_by_key(|m| m.0);
        let sorted = inbox.sorted_by_sender(n);
        assert_eq!(sorted.msgs, expected);
        for ((from, k), e) in sorted.msgs.iter().zip(&sorted.entries) {
            assert_eq!(*e, Entry::new(1, *from, 0, &k.to_le_bytes()));
        }
    }
}
