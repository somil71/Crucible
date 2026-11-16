//! Crucible Delta Debugger / Fault Schedule Minimizer.
//! Implements Zeller's ddmin algorithm for finding 1-minimal fault schedules.

pub struct DeltaDebugger;

impl DeltaDebugger {
    /// Minimizes an input sequence of items using the ddmin algorithm.
    /// `predicate` must return `true` if the failure condition is reproduced.
    pub fn minimize<T: Clone, F>(items: &[T], predicate: F) -> Vec<T>
    where
        F: Fn(&[T]) -> bool,
    {
        if items.is_empty() || !predicate(items) {
            return items.to_vec();
        }

        let mut current = items.to_vec();
        let mut n = 2;

        while current.len() >= 2 && n <= current.len() {
            let chunks = Self::split_into_chunks(&current, n);
            let mut reduced = false;

            // 1. Test each chunk directly
            for chunk in &chunks {
                if predicate(chunk) {
                    current = chunk.clone();
                    n = 2;
                    reduced = true;
                    break;
                }
            }

            if reduced {
                continue;
            }

            // 2. Test each complement (everything except chunk)
            for i in 0..chunks.len() {
                let mut complement = Vec::new();
                for (j, chunk) in chunks.iter().enumerate() {
                    if i != j {
                        complement.extend(chunk.iter().cloned());
                    }
                }

                if !complement.is_empty() && predicate(&complement) {
                    current = complement;
                    n = (n - 1).max(2);
                    reduced = true;
                    break;
                }
            }

            if reduced {
                continue;
            }

            // 3. Increase granularity if possible
            if n < current.len() {
                n = (2 * n).min(current.len());
            } else {
                break; // 1-minimal
            }
        }

        current
    }

    fn split_into_chunks<T: Clone>(items: &[T], n: usize) -> Vec<Vec<T>> {
        let n = n.min(items.len()).max(1);
        let mut chunks = Vec::with_capacity(n);
        let total = items.len();
        let base_size = total / n;
        let remainder = total % n;

        let mut start = 0;
        for i in 0..n {
            let chunk_size = base_size + if i < remainder { 1 } else { 0 };
            let end = start + chunk_size;
            chunks.push(items[start..end].to_vec());
            start = end;
        }

        chunks
    }
}

/// Multi-stage Hierarchical Fault Schedule Minimizer.
/// Executes: Stage 1 (Category/Actor Pruning) -> Stage 2 (Fine-grained DDMin) -> Stage 3 (Timeline Compression).
pub struct HierarchicalMinimizer;

impl HierarchicalMinimizer {
    /// Stage 1: Coarse/Categorical Pruning.
    /// Eliminates entire categories or actors in single steps if the failure still reproduces.
    pub fn prune_categories<T, K, F, G>(items: &[T], key_fn: G, predicate: F) -> Vec<T>
    where
        T: Clone,
        K: Eq + std::hash::Hash + Clone,
        F: Fn(&[T]) -> bool,
        G: Fn(&T) -> K,
    {
        if items.is_empty() || !predicate(items) {
            return items.to_vec();
        }

        let mut current = items.to_vec();
        let mut categories: Vec<K> = Vec::new();
        for item in items {
            let cat = key_fn(item);
            if !categories.contains(&cat) {
                categories.push(cat);
            }
        }

        for cat in categories {
            let candidate: Vec<T> = current.iter().filter(|item| key_fn(item) != cat).cloned().collect();
            if !candidate.is_empty() && predicate(&candidate) {
                current = candidate;
            }
        }

        current
    }

    /// Stage 2: Fine-grained Delta Debugging.
    pub fn minimize_fine<T, F>(items: &[T], predicate: F) -> Vec<T>
    where
        T: Clone,
        F: Fn(&[T]) -> bool,
    {
        DeltaDebugger::minimize(items, predicate)
    }

    /// Stage 3: Timeline Compression.
    /// Shrinks inter-event time delays towards minimal intervals while preserving violation reproduction.
    pub fn compress_timeline<T, F, G, S>(
        items: &[T],
        time_fn: G,
        set_time_fn: S,
        predicate: F,
    ) -> Vec<T>
    where
        T: Clone,
        F: Fn(&[T]) -> bool,
        G: Fn(&T) -> crate::VirtualTime,
        S: Fn(&mut T, crate::VirtualTime),
    {
        if items.len() <= 1 || !predicate(items) {
            return items.to_vec();
        }

        let mut current = items.to_vec();

        for i in 1..current.len() {
            let prev_time = time_fn(&current[i - 1]);
            let curr_time = time_fn(&current[i]);

            if curr_time.0 > prev_time.0 + 1_000_000 {
                // Try compressing gap to 1ms
                let compressed_time = crate::VirtualTime(prev_time.0 + 1_000_000);
                let mut candidate = current.clone();
                set_time_fn(&mut candidate[i], compressed_time);

                if predicate(&candidate) {
                    current = candidate;
                }
            }
        }

        current
    }

    /// Complete Multi-Stage Hierarchical Minimization Pipeline.
    pub fn minimize_hierarchical<T, K, F, KeyFn, TimeFn, SetTimeFn>(
        items: &[T],
        key_fn: KeyFn,
        time_fn: TimeFn,
        set_time_fn: SetTimeFn,
        predicate: F,
    ) -> Vec<T>
    where
        T: Clone,
        K: Eq + std::hash::Hash + Clone,
        F: Fn(&[T]) -> bool,
        KeyFn: Fn(&T) -> K,
        TimeFn: Fn(&T) -> crate::VirtualTime,
        SetTimeFn: Fn(&mut T, crate::VirtualTime),
    {
        let pruned = Self::prune_categories(items, key_fn, &predicate);
        let fine = Self::minimize_fine(&pruned, &predicate);
        Self::compress_timeline(&fine, time_fn, set_time_fn, predicate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ddmin_basic_shrink() {
        // Suppose elements 3 and 7 together cause failure
        let original: Vec<u32> = (0..20).collect();
        let predicate = |slice: &[u32]| slice.contains(&3) && slice.contains(&7);

        let minimized = DeltaDebugger::minimize(&original, predicate);
        assert_eq!(minimized.len(), 2);
        assert!(minimized.contains(&3));
        assert!(minimized.contains(&7));
    }

    #[test]
    fn test_ddmin_single_failing_element() {
        let original: Vec<u32> = (0..50).collect();
        let predicate = |slice: &[u32]| slice.contains(&42);

        let minimized = DeltaDebugger::minimize(&original, predicate);
        assert_eq!(minimized, vec![42]);
    }

    #[test]
    fn test_ddmin_already_minimal() {
        let original = vec![1, 2];
        let predicate = |slice: &[u32]| slice.len() == 2;

        let minimized = DeltaDebugger::minimize(&original, predicate);
        assert_eq!(minimized, vec![1, 2]);
    }

    #[test]
    fn test_hierarchical_prune_and_compress() {
        #[derive(Debug, Clone, PartialEq, Eq)]
        struct TimedFault {
            category: &'static str,
            id: u32,
            time: crate::VirtualTime,
        }

        // 10 faults: 5 in "network" (unrelated), 5 in "disk" (critical: id 42 and 99)
        let mut faults = Vec::new();
        for i in 0..5 {
            faults.push(TimedFault {
                category: "network",
                id: i,
                time: crate::VirtualTime::from_millis(100 * (i as u64 + 1)),
            });
        }
        faults.push(TimedFault {
            category: "disk",
            id: 42,
            time: crate::VirtualTime::from_millis(1000),
        });
        faults.push(TimedFault {
            category: "disk",
            id: 99,
            time: crate::VirtualTime::from_millis(5000), // large gap
        });

        let predicate = |items: &[TimedFault]| {
            items.iter().any(|f| f.id == 42) && items.iter().any(|f| f.id == 99)
        };

        let result = HierarchicalMinimizer::minimize_hierarchical(
            &faults,
            |f| f.category,
            |f| f.time,
            |f, t| f.time = t,
            predicate,
        );

        // Network category was completely pruned!
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].id, 42);
        assert_eq!(result[1].id, 99);
        // Time gap of 4000ms was compressed to 1ms
        assert_eq!(result[1].time, crate::VirtualTime(result[0].time.0 + 1_000_000));
    }
}
