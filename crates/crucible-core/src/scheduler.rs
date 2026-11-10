//! Crucible Custom Schedulers: Causal-Priority Scheduling (CPS),
//! Probabilistic Concurrency Testing (PCT), and Adaptive Contention Quanta.

use crate::{Seed, ThreadId};
use serde::{Deserialize, Serialize};

/// Synchronization events that trigger causal priority boosts and quantum adaptations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncEvent {
    FutexWake { count: u32 },
    FutexWait,
    ChannelSend,
    ChannelRecv,
    SocketWrite,
    SocketRead,
    LockAcquire,
    LockRelease,
    Yield,
}

/// Scheduling strategy configured for the simulation/emulation run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchedulingPolicy {
    /// Pure uniform round-robin baseline.
    RoundRobin,
    /// Probabilistic Concurrency Testing (PCT) with provable bug depth d.
    Pct { bug_depth: usize },
    /// Causal Priority Scheduling with direct consumer handoff.
    CausalPriority {
        base_quantum: u64,
        contention_quantum: u64,
    },
    /// Flagship Crucible Adaptive Engine: PCT + Causal Handoff + Contention Quanta.
    CrucibleAdaptive {
        bug_depth: usize,
        base_quantum: u64,
        contention_quantum: u64,
    },
}

impl Default for SchedulingPolicy {
    fn default() -> Self {
        Self::CrucibleAdaptive {
            bug_depth: 3,
            base_quantum: 500,
            contention_quantum: 25,
        }
    }
}

/// Dynamic scheduling state for an emulated or simulated thread.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThreadScheduleState {
    pub id: ThreadId,
    pub base_priority: u32,
    pub causal_boost: u32,
    pub is_blocked: bool,
    pub halted: bool,
    pub total_steps_executed: u64,
}

impl ThreadScheduleState {
    pub fn new(id: ThreadId, base_priority: u32) -> Self {
        Self {
            id,
            base_priority,
            causal_boost: 0,
            is_blocked: false,
            halted: false,
            total_steps_executed: 0,
        }
    }

    pub fn effective_priority(&self) -> u32 {
        self.base_priority.saturating_add(self.causal_boost)
    }

    pub fn is_runnable(&self) -> bool {
        !self.is_blocked && !self.halted
    }
}

/// Deterministic Pseudo-Random Number Generator (PCG-style xorshift64).
#[derive(Debug, Clone)]
pub struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    pub fn new(seed: Seed) -> Self {
        let state = if seed.0 == 0 { 0x853c49e6748fea9b } else { seed.0 };
        Self { state }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    pub fn next_bounded(&mut self, bound: u64) -> u64 {
        if bound <= 1 {
            0
        } else {
            self.next_u64() % bound
        }
    }
}

/// Scheduled PCT priority drop event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PctPriorityDrop {
    pub step_milestone: u64,
    pub new_priority: u32,
}

/// The Custom Crucible Scheduler Engine.
#[derive(Debug, Clone)]
pub struct CrucibleScheduler {
    pub policy: SchedulingPolicy,
    pub threads: Vec<ThreadScheduleState>,
    pub current_thread_idx: usize,
    pub steps_in_current_quantum: u64,
    pub active_quantum: u64,
    pub total_system_steps: u64,
    pub pct_drop_points: Vec<PctPriorityDrop>,
    pub rng: DeterministicRng,
}

impl CrucibleScheduler {
    pub fn new(policy: SchedulingPolicy, seed: Seed, max_expected_steps: u64) -> Self {
        let mut rng = DeterministicRng::new(seed);
        let mut pct_drop_points = Vec::new();

        let bug_depth = match policy {
            SchedulingPolicy::Pct { bug_depth } => bug_depth,
            SchedulingPolicy::CrucibleAdaptive { bug_depth, .. } => bug_depth,
            _ => 0,
        };

        if bug_depth >= 2 && max_expected_steps > 100 {
            // Generate (bug_depth - 1) random step milestones
            for d in 1..bug_depth {
                let milestone = rng.next_bounded(max_expected_steps.max(1_000));
                let new_prio = d as u32;
                pct_drop_points.push(PctPriorityDrop {
                    step_milestone: milestone,
                    new_priority: new_prio,
                });
            }
            // Sort by step milestone
            pct_drop_points.sort_by_key(|p| p.step_milestone);
        }

        let initial_quantum = match policy {
            SchedulingPolicy::RoundRobin => 500,
            SchedulingPolicy::Pct { .. } => 100,
            SchedulingPolicy::CausalPriority { base_quantum, .. } => base_quantum,
            SchedulingPolicy::CrucibleAdaptive { base_quantum, .. } => base_quantum,
        };

        Self {
            policy,
            threads: Vec::new(),
            current_thread_idx: 0,
            steps_in_current_quantum: 0,
            active_quantum: initial_quantum,
            total_system_steps: 0,
            pct_drop_points,
            rng,
        }
    }

    /// Register a new thread into the scheduler.
    pub fn register_thread(&mut self, id: ThreadId) {
        let num_existing = self.threads.len();
        // In PCT, threads get initial distinct priorities d, d+1, ..., d+n-1
        let base_prio = match self.policy {
            SchedulingPolicy::Pct { bug_depth } | SchedulingPolicy::CrucibleAdaptive { bug_depth, .. } => {
                (bug_depth as u32) + (num_existing as u32) + 1
            }
            _ => 10,
        };
        self.threads.push(ThreadScheduleState::new(id, base_prio));
    }

    /// Notify that a thread has blocked (e.g. futex wait).
    pub fn mark_blocked(&mut self, id: ThreadId) {
        if let Some(t) = self.threads.iter_mut().find(|t| t.id == id) {
            t.is_blocked = true;
            t.causal_boost = 0;
        }
    }

    /// Notify that a thread has unblocked.
    pub fn mark_unblocked(&mut self, id: ThreadId) {
        if let Some(t) = self.threads.iter_mut().find(|t| t.id == id) {
            t.is_blocked = false;
        }
    }

    /// Notify that a thread has halted.
    pub fn mark_halted(&mut self, id: ThreadId) {
        if let Some(t) = self.threads.iter_mut().find(|t| t.id == id) {
            t.halted = true;
            t.causal_boost = 0;
        }
    }

    /// Injects a causal handoff: when thread A wakes thread B or produces data for B,
    /// elevate thread B's priority and shrink quantum to focus on synchronization races.
    pub fn notify_sync_event(&mut self, source: ThreadId, target: Option<ThreadId>, event: SyncEvent) {
        match self.policy {
            SchedulingPolicy::CausalPriority { contention_quantum, .. }
            | SchedulingPolicy::CrucibleAdaptive { contention_quantum, .. } => {
                if let Some(target_id) = target {
                    if let Some(t) = self.threads.iter_mut().find(|t| t.id == target_id) {
                        t.is_blocked = false;
                        // Massive causal elevation to prioritize consumer right at the wake window
                        t.causal_boost = 100;
                    }
                }
                // Adapt to contention quantum for race search
                self.active_quantum = contention_quantum;
            }
            _ => {}
        }

        // On yield or wait, reset source boost
        if matches!(event, SyncEvent::Yield | SyncEvent::FutexWait) {
            if let Some(src) = self.threads.iter_mut().find(|t| t.id == source) {
                src.causal_boost = 0;
            }
        }
    }

    /// Advances instruction count for the currently active thread.
    /// Returns true if a preemption or context switch is required.
    pub fn step(&mut self) -> bool {
        self.total_system_steps += 1;
        self.steps_in_current_quantum += 1;

        if let Some(current_t) = self.threads.get_mut(self.current_thread_idx) {
            current_t.total_steps_executed += 1;
            // Decay causal boost gradually
            if current_t.causal_boost > 0 {
                current_t.causal_boost = current_t.causal_boost.saturating_sub(1);
            }
        }

        // Check if current thread must yield because it blocked or halted
        if let Some(current_t) = self.threads.get(self.current_thread_idx) {
            if !current_t.is_runnable() {
                return true;
            }
        }

        // Check PCT priority drop milestones
        let mut drop_triggered = false;
        let sys_step = self.total_system_steps;
        for drop in &self.pct_drop_points {
            if drop.step_milestone == sys_step {
                if let Some(curr) = self.threads.get_mut(self.current_thread_idx) {
                    curr.base_priority = drop.new_priority;
                    drop_triggered = true;
                }
            }
        }

        if drop_triggered {
            return true;
        }

        // Check quantum expiration
        if self.steps_in_current_quantum >= self.active_quantum {
            return true;
        }

        false
    }

    /// Selects the next runnable thread based on the active policy.
    /// Returns true if a runnable thread was found, false if deadlock / all threads inactive.
    pub fn schedule_next(&mut self) -> bool {
        if self.threads.is_empty() {
            return false;
        }

        self.steps_in_current_quantum = 0;

        // Reset quantum to base unless causal boost is still active
        match self.policy {
            SchedulingPolicy::CausalPriority { base_quantum, .. }
            | SchedulingPolicy::CrucibleAdaptive { base_quantum, .. } => {
                let has_boost = self.threads.iter().any(|t| t.causal_boost > 0);
                if !has_boost {
                    self.active_quantum = base_quantum;
                }
            }
            _ => {}
        }

        match self.policy {
            SchedulingPolicy::RoundRobin => {
                let n = self.threads.len();
                for i in 1..=n {
                    let next_idx = (self.current_thread_idx + i) % n;
                    if self.threads[next_idx].is_runnable() {
                        self.current_thread_idx = next_idx;
                        return true;
                    }
                }
                // Check if current thread is still runnable
                self.threads[self.current_thread_idx].is_runnable()
            }
            SchedulingPolicy::Pct { .. }
            | SchedulingPolicy::CausalPriority { .. }
            | SchedulingPolicy::CrucibleAdaptive { .. } => {
                // Priority-based selection: highest effective priority among runnable threads
                let mut best_idx = None;
                let mut highest_prio = 0;

                for (idx, thread) in self.threads.iter().enumerate() {
                    if thread.is_runnable() {
                        let eff = thread.effective_priority();
                        if best_idx.is_none() || eff > highest_prio {
                            highest_prio = eff;
                            best_idx = Some(idx);
                        }
                    }
                }

                if let Some(idx) = best_idx {
                    self.current_thread_idx = idx;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Returns the currently active thread ID, if any.
    pub fn current_thread_id(&self) -> Option<ThreadId> {
        self.threads.get(self.current_thread_idx).map(|t| t.id)
    }

    /// Returns whether any thread is currently runnable.
    pub fn has_runnable_threads(&self) -> bool {
        self.threads.iter().any(|t| t.is_runnable())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pct_priority_drop_inversion() {
        let mut sched = CrucibleScheduler::new(
            SchedulingPolicy::Pct { bug_depth: 2 },
            Seed(42),
            100,
        );
        sched.register_thread(ThreadId(1));
        sched.register_thread(ThreadId(2));

        // Thread 2 should have higher initial priority (d + n = 2 + 1 + 1 = 4 vs 3)
        assert!(sched.schedule_next());
        assert_eq!(sched.current_thread_id(), Some(ThreadId(2)));

        // Inject priority drop milestone
        sched.pct_drop_points = vec![PctPriorityDrop {
            step_milestone: 5,
            new_priority: 1, // drops below Thread 1's priority of 3
        }];

        for _ in 0..5 {
            let preempt = sched.step();
            if preempt {
                sched.schedule_next();
            }
        }

        // Thread 2 dropped to priority 1; Thread 1 with priority 3 must preempt!
        assert!(sched.schedule_next());
        assert_eq!(sched.current_thread_id(), Some(ThreadId(1)));
    }

    #[test]
    fn test_causal_handoff_boost() {
        let mut sched = CrucibleScheduler::new(
            SchedulingPolicy::CausalPriority {
                base_quantum: 500,
                contention_quantum: 20,
            },
            Seed(123),
            10_000,
        );
        sched.register_thread(ThreadId(1));
        sched.register_thread(ThreadId(2));

        sched.mark_blocked(ThreadId(2));
        assert!(sched.schedule_next());
        assert_eq!(sched.current_thread_id(), Some(ThreadId(1)));

        // Thread 1 wakes Thread 2 via FutexWake
        sched.notify_sync_event(ThreadId(1), Some(ThreadId(2)), SyncEvent::FutexWake { count: 1 });

        // Thread 2 receives causal elevation and must be scheduled immediately
        assert!(sched.schedule_next());
        assert_eq!(sched.current_thread_id(), Some(ThreadId(2)));
        assert_eq!(sched.active_quantum, 20); // contention quantum applied
    }
}
