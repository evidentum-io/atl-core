//! Cryptographic primitive tests for Merkle tree operations
//!
//! Tests for leaf hash, node hash, and root computation.

use crate::core::merkle::crypto::{LEAF_PREFIX, NODE_PREFIX};
use crate::core::merkle::{Hash, Leaf, compute_leaf_hash, compute_root, hash_children};
use sha2::{Digest, Sha256};

// Test constants
const ZERO_HASH: Hash = [0u8; 32];
const ONE_HASH: Hash = [1u8; 32];
const TWO_HASH: Hash = [2u8; 32];

#[test]
fn test_leaf_hash_prefix() {
    let payload = ZERO_HASH;
    let metadata = ONE_HASH;
    let hash = compute_leaf_hash(&payload, &metadata);

    // Manually compute expected
    let mut expected_input = vec![LEAF_PREFIX];
    expected_input.extend_from_slice(&payload);
    expected_input.extend_from_slice(&metadata);
    let expected: Hash = Sha256::digest(&expected_input).into();

    assert_eq!(hash, expected);
}

#[test]
fn test_node_hash_prefix() {
    let left = ZERO_HASH;
    let right = ONE_HASH;
    let hash = hash_children(&left, &right);

    let mut expected_input = vec![NODE_PREFIX];
    expected_input.extend_from_slice(&left);
    expected_input.extend_from_slice(&right);
    let expected: Hash = Sha256::digest(&expected_input).into();

    assert_eq!(hash, expected);
}

#[test]
fn test_leaf_struct() {
    let leaf = Leaf::new(ZERO_HASH, ONE_HASH);
    assert_eq!(leaf.payload_hash, ZERO_HASH);
    assert_eq!(leaf.metadata_hash, ONE_HASH);

    let hash = leaf.hash();
    let expected = compute_leaf_hash(&ZERO_HASH, &ONE_HASH);
    assert_eq!(hash, expected);
}

#[test]
fn test_empty_tree_root() {
    let root = compute_root(&[]);
    let expected: Hash = Sha256::digest([]).into();
    assert_eq!(root, expected);
}

#[test]
fn test_single_leaf_root() {
    let leaf = [42u8; 32];
    let root = compute_root(&[leaf]);
    assert_eq!(root, leaf);
}

#[test]
fn test_two_leaves_root() {
    let leaf0 = ZERO_HASH;
    let leaf1 = ONE_HASH;
    let root = compute_root(&[leaf0, leaf1]);
    let expected = hash_children(&leaf0, &leaf1);
    assert_eq!(root, expected);
}

#[test]
fn test_three_leaves_root() {
    let leaves = [ZERO_HASH, ONE_HASH, TWO_HASH];
    let root = compute_root(&leaves);

    let left = hash_children(&leaves[0], &leaves[1]);
    let expected = hash_children(&left, &leaves[2]);
    assert_eq!(root, expected);
}

#[test]
fn test_four_leaves_root() {
    let leaves = [ZERO_HASH, ONE_HASH, TWO_HASH, [3u8; 32]];
    let root = compute_root(&leaves);

    let left = hash_children(&leaves[0], &leaves[1]);
    let right = hash_children(&leaves[2], &leaves[3]);
    let expected = hash_children(&left, &right);
    assert_eq!(root, expected);
}
