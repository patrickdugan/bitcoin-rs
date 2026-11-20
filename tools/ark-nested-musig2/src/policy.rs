use bitcoin_rs_nested_musig2::{self as nested, KeyAggContext, PlainPublicKey};
use serde::Serialize;

use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum SignerId {
    Asp,
    User(u16),
}

impl SignerId {
    pub fn label(self) -> String {
        match self {
            Self::Asp => "asp".to_owned(),
            Self::User(index) => format!("user-{index}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Shape {
    Nested,
    Flat,
}

impl Shape {
    pub fn code(self) -> u8 {
        match self {
            Self::Nested => 1,
            Self::Flat => 2,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Nested),
            2 => Some(Self::Flat),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Nested => "nested",
            Self::Flat => "flat",
        }
    }
}

#[derive(Clone, Debug)]
pub struct AggNode {
    pub parent: Option<usize>,
    pub children: Vec<usize>,
    pub key: PlainPublicKey,
    pub signer: Option<SignerId>,
}

/// Node 0 is the root. Every group key is the BIP327 KeyAgg of its children's
/// compressed keys, so a nested root commits to the grouping, while a flat root
/// is invariant under participant reordering.
#[derive(Clone, Debug)]
pub struct AggTree {
    pub nodes: Vec<AggNode>,
}

impl AggTree {
    pub fn build(
        shape: Shape,
        users: &[(SignerId, PlainPublicKey)],
        asp: PlainPublicKey,
    ) -> Result<Self> {
        if users.is_empty() {
            return Err(Error::Construction(
                "a cosigner tree needs at least one user".to_owned(),
            ));
        }
        let mut tree = Self {
            nodes: vec![AggNode {
                parent: None,
                children: Vec::new(),
                key: asp,
                signer: None,
            }],
        };
        match shape {
            Shape::Flat => {
                for (signer, key) in users {
                    tree.push_leaf(0, *signer, *key);
                }
            }
            Shape::Nested => {
                if users.len() == 1 {
                    tree.push_leaf(0, users[0].0, users[0].1);
                } else {
                    let split = users.len().div_ceil(2);
                    tree.push_users(0, &users[..split])?;
                    tree.push_users(0, &users[split..])?;
                }
            }
        }
        tree.push_leaf(0, SignerId::Asp, asp);
        tree.nodes[0].key = tree.group_key(0)?;
        Ok(tree)
    }

    fn push_leaf(&mut self, parent: usize, signer: SignerId, key: PlainPublicKey) -> usize {
        let index = self.nodes.len();
        self.nodes.push(AggNode {
            parent: Some(parent),
            children: Vec::new(),
            key,
            signer: Some(signer),
        });
        self.nodes[parent].children.push(index);
        index
    }

    fn push_users(&mut self, parent: usize, users: &[(SignerId, PlainPublicKey)]) -> Result<usize> {
        if users.len() == 1 {
            return Ok(self.push_leaf(parent, users[0].0, users[0].1));
        }
        let index = self.nodes.len();
        self.nodes.push(AggNode {
            parent: Some(parent),
            children: Vec::new(),
            key: users[0].1,
            signer: None,
        });
        self.nodes[parent].children.push(index);
        let split = users.len().div_ceil(2);
        self.push_users(index, &users[..split])?;
        self.push_users(index, &users[split..])?;
        self.nodes[index].key = self.group_key(index)?;
        Ok(index)
    }

    fn group_key(&self, index: usize) -> Result<PlainPublicKey> {
        Ok(nested::key_agg(&self.child_keys(index))?.plain_key())
    }

    pub fn child_keys(&self, index: usize) -> Vec<PlainPublicKey> {
        self.nodes[index]
            .children
            .iter()
            .map(|child| self.nodes[*child].key)
            .collect()
    }

    pub fn root_context(&self) -> Result<KeyAggContext> {
        Ok(nested::key_agg(&self.child_keys(0))?)
    }

    pub fn leaves(&self) -> Vec<usize> {
        (0..self.nodes.len())
            .filter(|index| self.nodes[*index].signer.is_some())
            .collect()
    }

    pub fn groups_post_order(&self) -> Vec<usize> {
        let mut order = Vec::new();
        self.post_order(0, &mut order);
        order
    }

    fn post_order(&self, index: usize, order: &mut Vec<usize>) {
        for child in &self.nodes[index].children {
            self.post_order(*child, order);
        }
        if self.nodes[index].signer.is_none() {
            order.push(index);
        }
    }

    /// Ancestors of `index`, root first, ending with its parent.
    pub fn ancestors(&self, index: usize) -> Vec<usize> {
        let mut chain = Vec::new();
        let mut current = self.nodes[index].parent;
        while let Some(parent) = current {
            chain.push(parent);
            current = self.nodes[parent].parent;
        }
        chain.reverse();
        chain
    }

    /// The `(ancestor, child-on-path)` pairs from the root down to `index`.
    pub fn path_edges(&self, index: usize) -> Vec<(usize, usize)> {
        let ancestors = self.ancestors(index);
        let mut edges = Vec::with_capacity(ancestors.len());
        for (position, ancestor) in ancestors.iter().enumerate() {
            let child = ancestors.get(position + 1).copied().unwrap_or(index);
            edges.push((*ancestor, child));
        }
        edges
    }

    pub fn sibling_keys(&self, ancestor: usize, child: usize) -> Vec<PlainPublicKey> {
        let mut keys = Vec::new();
        let mut skipped = false;
        for sibling in &self.nodes[ancestor].children {
            if *sibling == child && !skipped {
                skipped = true;
                continue;
            }
            keys.push(self.nodes[*sibling].key);
        }
        keys
    }

    pub fn depth(&self) -> usize {
        self.leaves()
            .into_iter()
            .map(|leaf| self.ancestors(leaf).len())
            .max()
            .unwrap_or(0)
    }

    pub fn edge_count(&self) -> usize {
        self.nodes.len() - 1
    }

    pub fn max_fan_in(&self) -> usize {
        self.nodes
            .iter()
            .map(|node| node.children.len())
            .max()
            .unwrap_or(0)
    }
}
