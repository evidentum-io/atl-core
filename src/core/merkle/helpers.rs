//! Utility functions for Merkle tree operations
//!
//! This module provides pure mathematical helper functions used in RFC 6962/9162
//! Merkle tree implementations.

use crate::{
    core::merkle::crypto::{hash_children, Hash},
    error::AtlError,
};

/// Find the largest power of 2 less than n
///
/// Used for RFC 6962 tree navigation to determine subtree boundaries.
///
/// # Arguments
/// * `n` - Input value (must be > 0)
///
/// # Returns
/// * Largest power of 2 strictly less than n
///
/// # Examples
///
/// ```
/// use atl_core::core::merkle::largest_power_of_2_less_than;
///
/// assert_eq!(largest_power_of_2_less_than(1), 0);
/// assert_eq!(largest_power_of_2_less_than(2), 1);
/// assert_eq!(largest_power_of_2_less_than(3), 2);
/// assert_eq!(largest_power_of_2_less_than(5), 4);
/// assert_eq!(largest_power_of_2_less_than(8), 4);
/// ```
#[must_use]
pub const fn largest_power_of_2_less_than(n: u64) -> u64 {
    if n <= 1 {
        return 0;
    }
    // Find the highest set bit position
    let bits = 64 - n.leading_zeros();
    // Calculate 2^(bits-1)
    let power = 1u64 << (bits - 1);

    // If n is exactly a power of 2, we need the next smaller power
    if power == n {
        power >> 1
    } else {
        power
    }
}

/// Check if n is a power of two (and n > 0)
///
/// Used in RFC 9162 consistency proof verification to determine
/// whether to prepend `first_hash` to `consistency_path`.
///
/// Note: Returns false for n=0, unlike `u64::is_power_of_two()`.
///
/// # Arguments
/// * `n` - The number to check
///
/// # Returns
/// * true if n is a power of two and n > 0, false otherwise
///
/// # Examples
///
/// ```
/// use atl_core::core::merkle::is_power_of_two;
///
/// assert!(!is_power_of_two(0));
/// assert!(is_power_of_two(1));
/// assert!(is_power_of_two(2));
/// assert!(!is_power_of_two(3));
/// assert!(is_power_of_two(4));
/// ```
#[must_use]
#[allow(clippy::manual_is_power_of_two)]
pub const fn is_power_of_two(n: u64) -> bool {
    n > 0 && (n & (n - 1)) == 0
}

/// Compute root of a subtree using storage callback
///
/// Helper function for proof generation that computes the root hash
/// of a subtree spanning leaves [offset..offset+size).
///
/// ## Optimization: Intermediate Node Lookup
///
/// For power-of-2 aligned subtrees (size is power of 2 AND offset % size == 0),
/// this function first tries to retrieve the pre-computed intermediate node
/// via `get_node(level, index)`. If available, this converts O(n) recursion
/// to O(1) lookup.
///
/// Callers that store intermediate nodes (like atl-server's `SlabFile`) benefit
/// from this optimization automatically. Callers that only support level 0
/// (leaves) simply return `None` for higher levels, triggering fallback to
/// the original recursive algorithm.
///
/// # Arguments
/// * `offset` - Starting leaf index of subtree
/// * `size` - Number of leaves in subtree
/// * `get_node` - Storage callback that can return nodes at any level:
///   - Level 0: leaf nodes (required)
///   - Level > 0: intermediate nodes (optional, enables O(1) optimization)
///
/// # Returns
/// * Root hash of subtree or error if required nodes are missing
///
/// # Errors
/// * `InvalidArgument` - If size is 0
/// * `MissingNode` - If required leaf node is not found via `get_node`
pub fn compute_subtree_root<F>(offset: u64, size: u64, get_node: &F) -> Result<Hash, AtlError>
where
    F: Fn(u32, u64) -> Option<Hash>,
{
    if size == 0 {
        return Err(AtlError::InvalidArgument(format!("invalid tree size: {size}")));
    }

    if size == 1 {
        // Single leaf - always retrieve from level 0
        return get_node(0, offset).ok_or(AtlError::MissingNode { level: 0, index: offset });
    }

    // Optimization: Try stored intermediate node for power-of-2 aligned subtrees
    // This converts O(n) recursion to O(1) lookup when intermediate nodes are available
    if size.is_power_of_two() && offset.is_multiple_of(size) {
        // size is power of 2 AND offset is aligned to size
        // Compute level = log2(size) for u64
        let level = 63 - size.leading_zeros();
        // Compute index at that level
        let index = offset >> level;

        if let Some(stored_hash) = get_node(level, index) {
            return Ok(stored_hash);
        }
        // Fallback: intermediate node not available, continue with recursion
    }

    // Recursively compute subtree root using RFC 6962 algorithm
    let k = largest_power_of_2_less_than(size);
    let left_root = compute_subtree_root(offset, k, get_node)?;

    let right_offset = offset
        .checked_add(k)
        .ok_or(AtlError::ArithmeticOverflow { operation: "subtree root: offset + k" })?;
    let right_size = size
        .checked_sub(k)
        .ok_or(AtlError::ArithmeticOverflow { operation: "subtree root: size - k" })?;
    let right_root = compute_subtree_root(right_offset, right_size, get_node)?;

    Ok(hash_children(&left_root, &right_root))
}
