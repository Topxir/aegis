//! Cover traffic scheduler (spec section 26). Pure logic: the client owns the clock, the
//! timer, the queue and the network, and asks the scheduler what the next slot is for.

use crate::{Error, Result};
use std::collections::VecDeque;

pub const MIN_GAP_MS: u64 = 2000;
pub const SIZE_HISTORY: usize = 16;
pub const DEFAULT_SIZE: u32 = 1024;
pub const MAX_RESP_LEN: u32 = 1_048_592;

/// Largest `resp_len` the server answers for a nop whose body is `req_len` bytes. Real
/// responses reach the same size whatever the request (a blob chunk answers a body-less GET), so
/// the limit does not depend on `req_len`; `nop` is no cheaper to abuse than `blob/get`.
pub fn max_resp_len(_req_len: usize) -> u32 {
    MAX_RESP_LEN
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Off,
    Standard,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Desktop,
    Android,
}

/// Mean gap between slots in milliseconds; `None` when cover traffic is off.
pub fn mean_gap_ms(platform: Platform, mode: Mode) -> Option<u64> {
    match (platform, mode) {
        (_, Mode::Off) => None,
        (Platform::Desktop, Mode::Standard) => Some(20_000),
        (Platform::Android, Mode::Standard) => Some(30_000),
        (Platform::Desktop, Mode::High) => Some(8_000),
        (Platform::Android, Mode::High) => Some(12_000),
    }
}

/// Largest dummy request body: the server's body limit for everything but blob uploads.
pub const MAX_NOP_BODY: u32 = 64 * 1024;

/// Random source injected into the scheduler.
pub trait CoverRng {
    /// Uniform in the open interval (0, 1).
    fn unit(&mut self) -> f64;
    /// Uniform in `0..n` (`n > 0`).
    fn below(&mut self, n: u64) -> u64;
    /// True if the source could not deliver real randomness since the last call. The scheduler
    /// then switches cover off for that tick rather than send predictable sizes and gaps.
    fn failed(&mut self) -> bool {
        false
    }
}

static OS_RNG_FAILED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Operating system randomness.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsCoverRng;

impl OsCoverRng {
    fn next(&mut self) -> u64 {
        crate::random_bytes::<8>().map(u64::from_le_bytes).unwrap_or_else(|_| {
            OS_RNG_FAILED.store(true, std::sync::atomic::Ordering::SeqCst);
            0
        })
    }
}

impl CoverRng for OsCoverRng {
    fn unit(&mut self) -> f64 {
        unit_from(self.next())
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn failed(&mut self) -> bool {
        OS_RNG_FAILED.swap(false, std::sync::atomic::Ordering::SeqCst)
    }
}

/// Seeded generator for tests and vectors (SplitMix64). Not for production use.
#[derive(Debug, Clone)]
pub struct SeededRng(pub u64);

impl SeededRng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl CoverRng for SeededRng {
    fn unit(&mut self) -> f64 {
        unit_from(self.next())
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

fn unit_from(x: u64) -> f64 {
    // 53 random bits, shifted into (0, 1).
    (((x >> 11) as f64) + 0.5) / ((1u64 << 53) as f64)
}

/// What a slot carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// Send the oldest queued real request.
    Real,
    /// Run the due poll.
    Poll,
    /// Send `POST /api/v2/nop` with a body of `req_len` bytes asking for `resp_len` bytes back.
    Dummy { req_len: u32, resp_len: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tick {
    /// Cover traffic is off: the client sends and polls on its own schedule.
    Off,
    /// Nothing to do before `until_ms`.
    Wait { until_ms: u64 },
    Slot(Slot),
}

#[derive(Debug, Clone)]
pub struct Scheduler {
    platform: Platform,
    mode: Mode,
    next_ms: u64,
    last_ms: Option<u64>,
    /// Set after an early slot: the regular slot it replaced, which is skipped.
    displaced_ms: Option<u64>,
    reqs: VecDeque<u32>,
    resps: VecDeque<u32>,
}

impl Scheduler {
    pub fn new(platform: Platform, mode: Mode, now_ms: u64, rng: &mut dyn CoverRng) -> Self {
        let mut s = Self {
            platform,
            mode,
            next_ms: now_ms,
            last_ms: None,
            displaced_ms: None,
            reqs: VecDeque::new(),
            resps: VecDeque::new(),
        };
        s.schedule_from(now_ms, rng);
        s
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn set_mode(&mut self, mode: Mode, now_ms: u64, rng: &mut dyn CoverRng) {
        self.mode = mode;
        self.displaced_ms = None;
        self.schedule_from(now_ms, rng);
    }

    /// Time of the next slot, if cover traffic is on.
    pub fn next_slot_ms(&self) -> Option<u64> {
        (self.mode != Mode::Off).then_some(self.next_ms)
    }

    /// `2 s + Exp(mean − 2 s)`: the mean gap is exactly the configured mean.
    pub fn gap_ms(&self, rng: &mut dyn CoverRng) -> u64 {
        match mean_gap_ms(self.platform, self.mode) {
            None => 0,
            Some(mean) => {
                let extra = -rng.unit().ln() * (mean - MIN_GAP_MS) as f64;
                MIN_GAP_MS + extra as u64
            }
        }
    }

    fn schedule_from(&mut self, base_ms: u64, rng: &mut dyn CoverRng) {
        if self.mode != Mode::Off {
            self.next_ms = base_ms.saturating_add(self.gap_ms(rng));
        }
    }

    /// Call whenever the timer fires or the state changes. `queue_len` is the number of queued
    /// real requests, `poll_due` whether a poll is due.
    pub fn tick(&mut self, now_ms: u64, queue_len: usize, poll_due: bool, rng: &mut dyn CoverRng) -> Tick {
        if self.mode == Mode::Off {
            return Tick::Off;
        }
        if now_ms < self.next_ms {
            return Tick::Wait { until_ms: self.next_ms };
        }
        let slot = if queue_len > 0 {
            Slot::Real
        } else if poll_due {
            Slot::Poll
        } else {
            let req_len = self.sample(&self.reqs, rng).clamp(4, MAX_NOP_BODY);
            let resp_len = self.sample(&self.resps, rng).min(max_resp_len(req_len as usize));
            Slot::Dummy { req_len, resp_len }
        };
        let gap = if queue_len > 1 { MIN_GAP_MS } else { self.gap_ms(rng) };
        if rng.failed() {
            return Tick::Off;
        }
        // A burst runs at the minimum gap from now; the displaced slot is only used once it ends.
        let base = if queue_len > 1 { now_ms } else { self.displaced_ms.take().unwrap_or(now_ms) };
        self.next_ms = base.saturating_add(gap).max(now_ms.saturating_add(MIN_GAP_MS));
        self.last_ms = Some(now_ms);
        Tick::Slot(slot)
    }

    fn earliest(&self, now_ms: u64) -> u64 {
        self.last_ms.map_or(now_ms, |l| now_ms.max(l.saturating_add(MIN_GAP_MS)))
    }

    /// A user-visible action needs the network now. If the next slot is more than 2 s away it
    /// moves to the earliest allowed time and the slot it replaced is skipped, so the average
    /// rate stays the same.
    pub fn early_slot(&mut self, now_ms: u64) {
        if self.mode == Mode::Off || self.next_ms <= now_ms.saturating_add(MIN_GAP_MS) {
            return;
        }
        let e = self.earliest(now_ms);
        if e < self.next_ms {
            self.displaced_ms.get_or_insert(self.next_ms);
            self.next_ms = e;
        }
    }

    /// Call after queueing a request: with more than one queued, slots run at the 2 s minimum.
    pub fn queue_grew(&mut self, now_ms: u64, queue_len: usize) {
        if self.mode == Mode::Off || queue_len < 2 {
            return;
        }
        self.next_ms = self.next_ms.min(self.earliest(now_ms));
    }

    /// Records the body length of a real request that was sent.
    pub fn record_request(&mut self, body_len: usize) {
        push(&mut self.reqs, body_len);
    }

    /// Records the body length of a real response that was received.
    pub fn record_response(&mut self, body_len: usize) {
        push(&mut self.resps, body_len);
    }

    fn sample(&self, q: &VecDeque<u32>, rng: &mut dyn CoverRng) -> u32 {
        if q.is_empty() {
            return DEFAULT_SIZE;
        }
        q[rng.below(q.len() as u64) as usize]
    }
}

fn push(q: &mut VecDeque<u32>, len: usize) {
    q.push_back(u32::try_from(len).unwrap_or(u32::MAX));
    while q.len() > SIZE_HISTORY {
        q.pop_front();
    }
}

/// Body of `POST /api/v2/nop`: `BE32(resp_len) || random bytes`, `req_len` bytes in total.
pub fn nop_body(req_len: u32, resp_len: u32) -> Result<Vec<u8>> {
    use rand_core::{OsRng, RngCore};
    let total = (req_len as usize).clamp(4, MAX_NOP_BODY as usize);
    let mut body = vec![0u8; total];
    body[..4].copy_from_slice(&resp_len.min(max_resp_len(total)).to_be_bytes());
    OsRng.try_fill_bytes(&mut body[4..]).map_err(|_| Error::Rng)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_idle(platform: Platform, mode: Mode, slots: usize, seed: u64) -> Vec<u64> {
        let mut rng = SeededRng(seed);
        let mut s = Scheduler::new(platform, mode, 0, &mut rng);
        let mut times = Vec::new();
        let mut now = 0;
        while times.len() < slots {
            match s.tick(now, 0, false, &mut rng) {
                Tick::Wait { until_ms } => now = until_ms,
                Tick::Slot(Slot::Dummy { .. }) => times.push(now),
                other => panic!("{other:?}"),
            }
        }
        times
    }

    #[test]
    fn rate_matches_the_mean_and_respects_the_minimum() {
        for (p, m, mean) in [
            (Platform::Desktop, Mode::Standard, 20_000.0),
            (Platform::Android, Mode::Standard, 30_000.0),
            (Platform::Desktop, Mode::High, 8_000.0),
            (Platform::Android, Mode::High, 12_000.0),
        ] {
            let t = run_idle(p, m, 50_000, 7);
            let gaps: Vec<u64> = t.windows(2).map(|w| w[1] - w[0]).collect();
            assert!(gaps.iter().all(|g| *g >= MIN_GAP_MS), "minimum gap");
            let avg = gaps.iter().sum::<u64>() as f64 / gaps.len() as f64;
            assert!((avg / mean - 1.0).abs() < 0.02, "{p:?} {m:?}: {avg}");
            let var = gaps.iter().map(|g| (*g as f64 - avg).powi(2)).sum::<f64>() / gaps.len() as f64;
            let expect = (mean - MIN_GAP_MS as f64).powi(2);
            assert!((var / expect - 1.0).abs() < 0.08, "exponential spread {var} vs {expect}");
        }
    }

    #[test]
    fn rate_does_not_depend_on_activity() {
        // Idle and busy sessions send the same number of slots over the same time.
        let horizon = 20_000_000u64;
        let count = |busy: bool| {
            let mut rng = SeededRng(11);
            let mut act = SeededRng(99);
            let mut s = Scheduler::new(Platform::Desktop, Mode::Standard, 0, &mut rng);
            let (mut slots, mut queue) = (0u32, 0usize);
            let mut next_action = if busy { 1000 } else { u64::MAX };
            let mut now = 0u64;
            while now < horizon {
                let slot_at = s.next_slot_ms().unwrap();
                if next_action < slot_at {
                    now = next_action;
                    queue += 1;
                    s.early_slot(now);
                    next_action += 5000 + act.below(60_000);
                } else {
                    now = slot_at;
                    if let Tick::Slot(slot) = s.tick(now, queue, false, &mut rng) {
                        slots += 1;
                        if slot == Slot::Real {
                            queue -= 1;
                        }
                    }
                }
            }
            f64::from(slots)
        };
        let (idle, busy) = (count(false), count(true));
        assert!((busy / idle - 1.0).abs() < 0.05, "idle {idle}, busy {busy}");
        assert!((idle / (horizon as f64 / 20_000.0) - 1.0).abs() < 0.05);
    }

    #[test]
    fn priorities_real_then_poll_then_dummy() {
        let mut rng = SeededRng(1);
        let mut s = Scheduler::new(Platform::Desktop, Mode::Standard, 0, &mut rng);
        let at = s.next_slot_ms().unwrap();
        assert!(matches!(s.tick(at - 1, 5, true, &mut rng), Tick::Wait { .. }));
        assert_eq!(s.tick(at, 1, true, &mut rng), Tick::Slot(Slot::Real));
        let at = s.next_slot_ms().unwrap();
        assert_eq!(s.tick(at, 0, true, &mut rng), Tick::Slot(Slot::Poll));
        let at = s.next_slot_ms().unwrap();
        assert!(matches!(s.tick(at, 0, false, &mut rng), Tick::Slot(Slot::Dummy { .. })));
    }

    #[test]
    fn early_slot_skips_the_regular_one() {
        let mut rng = SeededRng(5);
        let mut s = Scheduler::new(Platform::Desktop, Mode::Standard, 0, &mut rng);
        s.next_ms = 60_000;
        s.early_slot(1000);
        assert_eq!(s.next_slot_ms(), Some(1000));
        s.early_slot(1200);
        assert_eq!(s.displaced_ms, Some(60_000), "a second request does not displace another slot");
        assert_eq!(s.tick(1000, 1, false, &mut rng), Tick::Slot(Slot::Real));
        let n = s.next_slot_ms().unwrap();
        assert!(n >= 60_000 + MIN_GAP_MS, "next slot follows the skipped one: {n}");
        // Nothing to pull in when the slot is already close.
        s.next_ms = 3000;
        s.early_slot(1500);
        assert_eq!(s.next_slot_ms(), Some(3000));
        // Never earlier than 2 s after the previous slot.
        s.next_ms = 90_000;
        s.last_ms = Some(10_000);
        s.early_slot(10_500);
        assert_eq!(s.next_slot_ms(), Some(12_000));
    }

    #[test]
    fn long_queue_runs_at_the_minimum_gap() {
        let mut rng = SeededRng(3);
        let mut s = Scheduler::new(Platform::Android, Mode::Standard, 0, &mut rng);
        let mut now = s.next_slot_ms().unwrap();
        assert_eq!(s.tick(now, 3, false, &mut rng), Tick::Slot(Slot::Real));
        assert_eq!(s.next_slot_ms(), Some(now + MIN_GAP_MS));
        now += MIN_GAP_MS;
        assert_eq!(s.tick(now, 2, false, &mut rng), Tick::Slot(Slot::Real));
        assert_eq!(s.next_slot_ms(), Some(now + MIN_GAP_MS));
        now += MIN_GAP_MS;
        assert_eq!(s.tick(now, 1, false, &mut rng), Tick::Slot(Slot::Real));
        assert!(s.next_slot_ms().unwrap() >= now + MIN_GAP_MS);
        s.next_ms = 100_000;
        s.last_ms = Some(50_000);
        s.queue_grew(50_100, 2);
        assert_eq!(s.next_slot_ms(), Some(52_000));
        s.next_ms = 100_000;
        s.queue_grew(50_100, 1);
        assert_eq!(s.next_slot_ms(), Some(100_000));
    }

    #[test]
    fn sizes_follow_recent_real_traffic() {
        let mut rng = SeededRng(9);
        let mut s = Scheduler::new(Platform::Desktop, Mode::Standard, 0, &mut rng);
        let dummy = |s: &mut Scheduler, rng: &mut SeededRng| {
            let at = s.next_slot_ms().unwrap();
            match s.tick(at, 0, false, rng) {
                Tick::Slot(Slot::Dummy { req_len, resp_len }) => (req_len, resp_len),
                t => panic!("{t:?}"),
            }
        };
        assert_eq!(dummy(&mut s, &mut rng), (1024, 1024));
        for _ in 0..40 {
            s.record_request(5000);
            s.record_response(1_000_000);
        }
        for _ in 0..16 {
            s.record_request(300);
            s.record_response(70);
        }
        for _ in 0..20 {
            assert_eq!(dummy(&mut s, &mut rng), (300, 70));
        }
        s.record_response(900_000);
        let seen: Vec<u32> = (0..200).map(|_| dummy(&mut s, &mut rng).1).collect();
        assert!(seen.contains(&900_000), "a small request may ask for a large response");
        assert!(seen.contains(&70));
        assert!(seen.iter().all(|r| *r == 70 || *r == 900_000));
    }

    #[test]
    fn off_mode_and_mode_changes() {
        let mut rng = SeededRng(2);
        let mut s = Scheduler::new(Platform::Desktop, Mode::Off, 0, &mut rng);
        assert_eq!(s.tick(1_000_000, 3, true, &mut rng), Tick::Off);
        assert_eq!(s.next_slot_ms(), None);
        s.early_slot(5);
        s.set_mode(Mode::High, 100, &mut rng);
        assert!(s.next_slot_ms().unwrap() >= 100 + MIN_GAP_MS);
        s.set_mode(Mode::Off, 200, &mut rng);
        assert_eq!(s.tick(1_000_000, 0, false, &mut rng), Tick::Off);
    }

    #[test]
    fn nop_body_shape() {
        let b = nop_body(1024, 70_000).unwrap();
        assert_eq!(b.len(), 1024);
        assert_eq!(u32::from_be_bytes([b[0], b[1], b[2], b[3]]), 70_000);
        let b = nop_body(1024, 2_000_000).unwrap();
        assert_eq!(u32::from_be_bytes([b[0], b[1], b[2], b[3]]), MAX_RESP_LEN);
        assert_eq!(max_resp_len(10), MAX_RESP_LEN);
        assert_eq!(nop_body(1 << 20, 5).unwrap().len(), MAX_NOP_BODY as usize);
        assert_eq!(nop_body(0, 5).unwrap().len(), 4);
        assert_ne!(nop_body(64, 1).unwrap()[4..], nop_body(64, 1).unwrap()[4..]);
    }
}
