use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// A 2nd-order Markov Chain predictor for AST node transitions and descendant reachability.
///
/// It models:
/// 1. Direct child transitions: P(Child | Parent, Current)
/// 2. Descendant reachability: P(Descendant in Subtree | Parent, Current)
#[derive(Debug, Default, Clone)]
pub struct MarkovAstPredictor {
    // Map: (parent_kind_id, current_kind_id) -> Map<next_kind_id, frequency_count>
    transitions: HashMap<(u16, u16), HashMap<u16, u64>>,
    // Map: (parent_kind_id, current_kind_id) -> Map<descendant_kind_id, frequency_count>
    descendants: HashMap<(u16, u16), HashMap<u16, u64>>,
    // Map: (parent_kind_id, current_kind_id) -> total_observations
    totals: HashMap<(u16, u16), u64>,
}

#[allow(dead_code)]
impl MarkovAstPredictor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an observed 2nd-order AST transition (parent, current, next).
    pub fn observe_transition(&mut self, parent: u16, current: u16, next: u16) {
        let key = (parent, current);
        *self.totals.entry(key).or_insert(0) += 1;
        *self
            .transitions
            .entry(key)
            .or_default()
            .entry(next)
            .or_insert(0) += 1;
    }

    /// Recursively observe node transitions and descendant reachability in a Tree-sitter AST.
    pub fn observe_tree(&mut self, root: tree_sitter::Node<'_>) {
        self.traverse_and_observe(0, root);
    }

    fn traverse_and_observe(
        &mut self,
        parent_kind: u16,
        current_node: tree_sitter::Node<'_>,
    ) -> Vec<u16> {
        let current_kind = current_node.kind_id();
        let key = (parent_kind, current_kind);

        let mut current_descendants = vec![current_kind];

        let mut cursor = current_node.walk();
        let mut prev_child_kind: Option<u16> = None;
        for child in current_node.children(&mut cursor) {
            let child_kind = child.kind_id();
            // Parent -> Current -> Child transition
            self.observe_transition(parent_kind, current_kind, child_kind);

            // Sibling -> Sibling transition if any
            if let Some(prev) = prev_child_kind {
                self.observe_transition(current_kind, prev, child_kind);
            }
            prev_child_kind = Some(child_kind);

            // Recurse down and aggregate descendant node kinds
            let child_descendants = self.traverse_and_observe(current_kind, child);
            current_descendants.extend(child_descendants);
        }

        let desc_map = self.descendants.entry(key).or_default();
        for &desc in &current_descendants {
            *desc_map.entry(desc).or_insert(0) += 1;
        }

        current_descendants
    }

    /// Predict next probable child node kind IDs given (parent, current) context above `threshold` (0.0 to 1.0).
    pub fn predict_next(&self, parent: u16, current: u16, threshold: f64) -> Vec<(u16, f64)> {
        let key = (parent, current);
        let mut predictions = Vec::new();

        if let (Some(next_map), Some(&total)) = (self.transitions.get(&key), self.totals.get(&key))
        {
            if total == 0 {
                return predictions;
            }
            for (&next_kind, &count) in next_map {
                let prob = count as f64 / total as f64;
                if prob >= threshold {
                    predictions.push((next_kind, prob));
                }
            }
        }
        predictions.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        predictions
    }

    /// Determine if a subtree under (parent, current) should be pruned because
    /// the probability of finding any of `target_kinds` among descendants is below `threshold`.
    pub fn should_prune_subtree(
        &self,
        parent: u16,
        current: u16,
        target_kinds: &[u16],
        threshold: f64,
    ) -> bool {
        let key = (parent, current);
        if let (Some(desc_map), Some(&total)) = (self.descendants.get(&key), self.totals.get(&key))
        {
            if total < 3 {
                // Insufficient samples to safely prune
                return false;
            }
            let mut target_prob_sum = 0.0;
            for &target in target_kinds {
                if let Some(&count) = desc_map.get(&target) {
                    target_prob_sum += count as f64 / total as f64;
                }
            }
            target_prob_sum < threshold
        } else {
            false
        }
    }

    /// Total number of observed transition pairs.
    pub fn total_observations(&self) -> u64 {
        self.totals.values().sum()
    }
}

/// Shared thread-safe Markov Predictor wrapper for global server state.
#[derive(Clone, Debug, Default)]
pub struct SharedMarkovPredictor {
    inner: Arc<RwLock<MarkovAstPredictor>>,
}

#[allow(dead_code)]
impl SharedMarkovPredictor {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(MarkovAstPredictor::new())),
        }
    }

    pub fn observe_tree(&self, root: tree_sitter::Node<'_>) {
        if let Ok(mut lock) = self.inner.write() {
            lock.observe_tree(root);
        }
    }

    pub fn predict_next(&self, parent: u16, current: u16, threshold: f64) -> Vec<(u16, f64)> {
        if let Ok(lock) = self.inner.read() {
            lock.predict_next(parent, current, threshold)
        } else {
            Vec::new()
        }
    }

    pub fn should_prune_subtree(
        &self,
        parent: u16,
        current: u16,
        target_kinds: &[u16],
        threshold: f64,
    ) -> bool {
        if let Ok(lock) = self.inner.read() {
            lock.should_prune_subtree(parent, current, target_kinds, threshold)
        } else {
            false
        }
    }

    pub fn total_observations(&self) -> u64 {
        if let Ok(lock) = self.inner.read() {
            lock.total_observations()
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_markov_predictor_basic() {
        let mut predictor = MarkovAstPredictor::new();
        predictor.observe_transition(10, 20, 30);
        predictor.observe_transition(10, 20, 30);
        predictor.observe_transition(10, 20, 40);

        let predictions = predictor.predict_next(10, 20, 0.1);
        assert_eq!(predictions.len(), 2);
        assert_eq!(predictions[0].0, 30);
        assert!((predictions[0].1 - 0.666).abs() < 0.01);
        assert_eq!(predictions[1].0, 40);
        assert!((predictions[1].1 - 0.333).abs() < 0.01);
    }
}
