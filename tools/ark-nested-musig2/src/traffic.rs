use serde::Serialize;

use crate::policy::AggTree;

/// Message accounting for one coordinator topology. Every tree edge carries a
/// public nonce up, a session context down and a partial signature up.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Traffic {
    pub sessions: u64,
    pub messages: u64,
    pub bytes: u64,
    pub nonce_messages: u64,
    pub context_messages: u64,
    pub partial_messages: u64,
    pub root_fan_in: usize,
    pub max_fan_in: usize,
    pub max_depth: usize,
    pub critical_path_hops: u64,
    pub seconds: f64,
}

impl Traffic {
    pub fn record_session(&mut self, tree: &AggTree, seconds: f64) {
        self.sessions += 1;
        self.seconds += seconds;
        self.root_fan_in = self.root_fan_in.max(tree.nodes[0].children.len());
        self.max_fan_in = self.max_fan_in.max(tree.max_fan_in());
        let depth = tree.depth();
        self.max_depth = self.max_depth.max(depth);
        self.critical_path_hops += 3 * u64::try_from(depth).unwrap_or(u64::MAX);
        for (index, node) in tree.nodes.iter().enumerate() {
            if node.parent.is_none() {
                continue;
            }
            let edges = tree.path_edges(index);
            let siblings: usize = edges
                .iter()
                .map(|(ancestor, child)| tree.sibling_keys(*ancestor, *child).len())
                .sum();
            let context = 66 * edges.len() + 33 * siblings + 64;
            self.nonce_messages += 1;
            self.context_messages += 1;
            self.partial_messages += 1;
            self.messages += 3;
            self.bytes += 66 + 32 + u64::try_from(context).unwrap_or(u64::MAX);
        }
    }

    pub fn merge(&mut self, other: &Self) {
        self.sessions += other.sessions;
        self.messages += other.messages;
        self.bytes += other.bytes;
        self.nonce_messages += other.nonce_messages;
        self.context_messages += other.context_messages;
        self.partial_messages += other.partial_messages;
        self.root_fan_in = self.root_fan_in.max(other.root_fan_in);
        self.max_fan_in = self.max_fan_in.max(other.max_fan_in);
        self.max_depth = self.max_depth.max(other.max_depth);
        self.critical_path_hops += other.critical_path_hops;
        self.seconds += other.seconds;
    }
}
