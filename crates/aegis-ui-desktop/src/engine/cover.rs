//! Cover traffic (spec section 26) for the desktop: while the app is unlocked and on screen,
//! the network thread sends on the schedule of `aegis_core::cover::Scheduler`. A slot is a poll
//! when one is due and a dummy request of a size like the real ones otherwise.
//!
//! Real requests from the worker (a message send, a blob upload) wait in the `Gate` for a
//! `Slot::Real`; the first one waiting takes the next slot early. If no slot comes within
//! `GATE_WAIT` the request goes out anyway, so sending never hangs. Dummy request sizes follow
//! the last 16 real request bodies; response sizes are not recorded (the default 1024 is used),
//! and a Poll slot is a burst of requests where a Dummy slot is one. Nothing runs while the app
//! is locked or minimized.

use super::*;
use aegis_core::cover::{Mode, OsCoverRng, Platform, Scheduler, Slot, Tick};
use std::sync::Condvar;

/// How long a real request waits for its slot before it goes out regardless.
const GATE_WAIT: Duration = Duration::from_secs(12);

#[derive(Debug, Default)]
struct GateState {
    on: bool,
    queued: usize,
    grants: usize,
    sizes: Vec<usize>,
}

/// Lets real requests wait for their slot. The network thread grants one per `Slot::Real`.
#[derive(Debug, Default)]
pub struct Gate {
    st: Mutex<GateState>,
    cv: Condvar,
}

impl Gate {
    fn lock(&self) -> MutexGuard<'_, GateState> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Called by the network thread each round: whether cover traffic runs. Turning it off
    /// frees everybody waiting.
    pub fn set_on(&self, on: bool) {
        let mut g = self.lock();
        g.on = on;
        if !on {
            g.grants = g.queued;
            self.cv.notify_all();
        }
    }

    pub fn queued(&self) -> usize {
        self.lock().queued
    }

    pub fn grant(&self) {
        let mut g = self.lock();
        if g.queued > g.grants {
            g.grants += 1;
            self.cv.notify_one();
        }
    }

    pub fn take_sizes(&self) -> Vec<usize> {
        std::mem::take(&mut self.lock().sizes)
    }

    /// Blocks until this request's slot, or until the wait runs out. `len` is the body size.
    pub fn pass(&self, len: usize, wait: Duration) {
        let mut g = self.lock();
        g.sizes.push(len);
        if !g.on {
            return;
        }
        g.queued += 1;
        let deadline = Instant::now() + wait;
        while g.grants == 0 {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            g = self.cv.wait_timeout(g, left).unwrap_or_else(|e| e.into_inner()).0;
        }
        g.grants = g.grants.saturating_sub(1);
        g.queued = g.queued.saturating_sub(1);
    }
}

/// What the network thread should do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Cover traffic is off or paused: use the plain polling schedule.
    Plain,
    /// Nothing before the next slot.
    Wait,
    Poll,
    /// A queued real request may go: the gate grants it.
    Real,
    Dummy { req_len: u32, resp_len: u32 },
}

fn mode_of(level: u8) -> Mode {
    match level {
        0 => Mode::Off,
        2 => Mode::High,
        _ => Mode::Standard,
    }
}

/// How long since the last poll before a slot is spent on a poll rather than a dummy.
fn poll_every_ms(level: u8) -> u64 {
    if level >= 2 {
        4_000
    } else {
        10_000
    }
}

/// Owned by the network thread.
#[derive(Debug, Default)]
pub struct Driver {
    sched: Option<Scheduler>,
    last_poll_ms: u64,
    seen_queued: usize,
}

impl Driver {
    pub fn new() -> Self {
        Self::default()
    }

    /// `active`: unlocked and visible. `level`: 0 off, 1 standard, 2 high.
    pub fn step(&mut self, now_ms: u64, active: bool, level: u8, queued: usize, sizes: &[usize]) -> Step {
        self.step_with(now_ms, active, level, queued, sizes, &mut OsCoverRng)
    }

    pub fn step_with(
        &mut self,
        now_ms: u64,
        active: bool,
        level: u8,
        queued: usize,
        sizes: &[usize],
        rng: &mut dyn aegis_core::cover::CoverRng,
    ) -> Step {
        if !active || level == 0 {
            // A fresh schedule when it starts again, so a pause is not followed by a burst.
            self.sched = None;
            return Step::Plain;
        }
        let mode = mode_of(level);
        match self.sched.as_mut() {
            None => self.sched = Some(Scheduler::new(Platform::Desktop, mode, now_ms, rng)),
            Some(s) if s.mode() != mode => s.set_mode(mode, now_ms, rng),
            Some(_) => {}
        }
        if let Some(sc) = self.sched.as_mut() {
            for n in sizes {
                sc.record_request(*n);
            }
            if queued > self.seen_queued {
                sc.early_slot(now_ms);
            }
            sc.queue_grew(now_ms, queued);
        }
        self.seen_queued = queued;
        let due = now_ms.saturating_sub(self.last_poll_ms) >= poll_every_ms(level);
        let Some(s) = self.sched.as_mut() else {
            return Step::Plain;
        };
        match s.tick(now_ms, queued, due, rng) {
            Tick::Off => Step::Plain,
            Tick::Wait { .. } => Step::Wait,
            Tick::Slot(Slot::Real) => {
                self.seen_queued = self.seen_queued.saturating_sub(1);
                Step::Real
            }
            Tick::Slot(Slot::Poll) => {
                self.last_poll_ms = now_ms;
                Step::Poll
            }
            Tick::Slot(Slot::Dummy { req_len, resp_len }) => Step::Dummy { req_len, resp_len },
        }
    }
}

impl Engine {
    /// Tells the engine whether the window is on screen. Cover traffic stops while it is not.
    pub fn set_visible(&self, on: bool) {
        self.visible.store(on, Ordering::SeqCst);
    }

    /// The cover level (0 to 2) when cover traffic may run now: unlocked, on screen, key not
    /// in question. `None` otherwise.
    pub fn cover_active(&self) -> Option<u8> {
        if !self.visible.load(Ordering::SeqCst) || self.key_alert.load(Ordering::SeqCst) {
            return None;
        }
        let app = self.app();
        let s = app.session.as_ref()?;
        Some(s.data.settings.cover)
    }

    /// Real requests call this before they go out; it waits for the slot when cover runs.
    pub(super) fn slot(&self, len: usize) {
        self.gate.pass(len, GATE_WAIT);
    }

    /// Sends one dummy request. Errors are ignored: it is only cover.
    pub fn send_dummy(&self, req_len: u32, resp_len: u32) {
        let client = {
            let app = self.app();
            let Some(s) = app.session.as_ref() else {
                return;
            };
            match self.client_for(&s.data.settings) {
                Ok(c) => c,
                Err(_) => return,
            }
        };
        let _ = client.nop(req_len, resp_len);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use aegis_core::cover::SeededRng;

    fn run(d: &mut Driver, rng: &mut SeededRng, active: bool, level: u8, from: u64, to: u64) -> (u32, u32) {
        let (mut polls, mut dummies) = (0, 0);
        let mut t = from;
        while t < to {
            match d.step_with(t, active, level, 0, &[], rng) {
                Step::Poll => polls += 1,
                Step::Dummy { .. } => dummies += 1,
                _ => {}
            }
            t += 500;
        }
        (polls, dummies)
    }

    #[test]
    fn off_and_paused_stay_plain() {
        let mut d = Driver::new();
        let mut rng = SeededRng(1);
        assert_eq!(d.step_with(0, true, 0, 0, &[], &mut rng), Step::Plain);
        assert_eq!(d.step_with(0, false, 1, 0, &[], &mut rng), Step::Plain);
        assert_eq!(run(&mut d, &mut rng, false, 2, 0, 600_000), (0, 0));
        assert_eq!(run(&mut d, &mut rng, true, 0, 0, 600_000), (0, 0));
    }

    #[test]
    fn slots_follow_the_mean_gap_and_mix_polls_with_dummies() {
        let mut d = Driver::new();
        let mut rng = SeededRng(7);
        let (p, n) = run(&mut d, &mut rng, true, 1, 0, 3_600_000);
        let slots = p + n;
        // Mean gap 20 s: about 180 slots an hour.
        assert!((120..260).contains(&slots), "{slots}");
        assert!(p > 0 && n > 0, "{p} {n}");
        let mut h = Driver::new();
        let (p2, n2) = run(&mut h, &mut rng, true, 2, 0, 3_600_000);
        assert!(p2 + n2 > slots, "high is busier");
    }

    #[test]
    fn dummy_sizes_are_within_what_the_server_answers() {
        let mut d = Driver::new();
        let mut rng = SeededRng(3);
        let mut t = 0;
        while t < 1_800_000 {
            if let Step::Dummy { req_len, resp_len } = d.step_with(t, true, 1, 0, &[], &mut rng) {
                assert!(req_len >= 4);
                assert!(resp_len <= aegis_core::cover::max_resp_len(req_len as usize));
            }
            t += 500;
        }
    }

    #[test]
    fn pausing_restarts_the_schedule() {
        let mut d = Driver::new();
        let mut rng = SeededRng(5);
        run(&mut d, &mut rng, true, 1, 0, 120_000);
        assert_eq!(d.step_with(130_000, false, 1, 0, &[], &mut rng), Step::Plain);
        // First step after resuming never fires at once: the next slot is a full gap away.
        assert_eq!(d.step_with(10_000_000, true, 1, 0, &[], &mut rng), Step::Wait);
    }

    #[test]
    fn queued_requests_get_real_slots_at_the_minimum_gap() {
        let mut d = Driver::new();
        let mut rng = SeededRng(9);
        d.step_with(0, true, 1, 0, &[], &mut rng);
        let mut t = 0;
        let mut reals = Vec::new();
        let mut left = 3usize;
        while t < 60_000 && left > 0 {
            if d.step_with(t, true, 1, left, &[], &mut rng) == Step::Real {
                reals.push(t);
                left -= 1;
            }
            t += 100;
        }
        assert_eq!(reals.len(), 3);
        assert!(reals[1] - reals[0] >= 2000 && reals[2] - reals[1] >= 2000);
        assert!(reals[0] <= 2100, "the first one takes the next slot early: {reals:?}");
    }

    #[test]
    fn dummy_sizes_follow_recorded_requests() {
        let mut d = Driver::new();
        let mut rng = SeededRng(2);
        d.step_with(0, true, 1, 0, &[4000; 16], &mut rng);
        let mut t = 0;
        while t < 600_000 {
            if let Step::Dummy { req_len, .. } = d.step_with(t, true, 1, 0, &[], &mut rng) {
                assert_eq!(req_len, 4000);
            }
            t += 500;
        }
    }

    #[test]
    fn a_waiting_request_is_freed_when_cover_stops() {
        let g = std::sync::Arc::new(Gate::default());
        g.set_on(true);
        let g2 = std::sync::Arc::clone(&g);
        let h = std::thread::spawn(move || g2.pass(10, Duration::from_secs(30)));
        while g.queued() == 0 {
            std::thread::sleep(Duration::from_millis(5));
        }
        g.set_on(false);
        h.join().unwrap();
        assert_eq!(g.queued(), 0);
        g.pass(1, Duration::from_secs(30));
    }

    #[test]
    fn a_grant_frees_exactly_one() {
        let g = std::sync::Arc::new(Gate::default());
        g.set_on(true);
        let g2 = std::sync::Arc::clone(&g);
        let h = std::thread::spawn(move || g2.pass(10, Duration::from_secs(30)));
        while g.queued() == 0 {
            std::thread::sleep(Duration::from_millis(5));
        }
        g.grant();
        h.join().unwrap();
        assert_eq!(g.take_sizes(), vec![10]);
    }
}
