//! RFC 9162 consistency proof operations
//!
//! This module implements consistency proof generation and verification per
//! RFC 9162 Section 2.1.4. Consistency proofs demonstrate that a tree of size
//! `from_size` is a prefix of a tree of size `to_size`, ensuring the append-only
//! property of the log.

use crate::{
    core::merkle::{
        crypto::{hash_children, Hash},
        helpers::{compute_subtree_root, is_power_of_two, largest_power_of_2_less_than},
    },
    error::{AtlError, AtlResult},
};

/// Proves that a tree of size `from_size` is a prefix of a tree of size `to_size`.
/// This ensures append-only property of the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsistencyProof {
    /// Size of the older tree
    pub from_size: u64,
    /// Size of the newer tree
    pub to_size: u64,
    /// Proof hashes connecting old root to new root
    pub path: Vec<Hash>,
}

/// Generate a consistency proof between two tree sizes
///
/// Generates a proof that demonstrates a tree of size `from_size` is a prefix
/// of a tree of size `to_size`. The proof contains hashes that allow verifying
/// both the old and new roots are consistent with the append-only property.
///
/// # Arguments
/// * `from_size` - Size of older tree (must be <= `to_size`)
/// * `to_size` - Size of newer tree
/// * `get_node` - Storage callback function: (level, index) -> `Option<Hash>`
///
/// # Returns
/// * Consistency proof with empty path for trivial cases (same size or zero old size)
/// * Consistency proof with hashes for non-trivial cases
///
/// # Errors
/// * `InvalidArgument` - if `from_size` > `to_size`
/// * `MissingNode` - if required node is not in storage
/// * `ArithmeticOverflow` - if computation overflows
///
/// # Example
///
/// ```
/// use atl_core::core::merkle::{generate_consistency_proof, Hash};
///
/// // Same size: empty proof
/// let proof = generate_consistency_proof(5, 5, |_, _| None).unwrap();
/// assert!(proof.path.is_empty());
/// ```
pub fn generate_consistency_proof<F>(
    from_size: u64,
    to_size: u64,
    get_node: F,
) -> Result<ConsistencyProof, AtlError>
where
    F: Fn(u32, u64) -> Option<Hash>,
{
    // Validate inputs
    if from_size > to_size {
        return Err(AtlError::InvalidArgument(format!(
            "invalid consistency proof: from_size {from_size} > to_size {to_size}"
        )));
    }

    // Same size: empty proof
    if from_size == to_size {
        return Ok(ConsistencyProof { from_size, to_size, path: Vec::new() });
    }

    // Zero old size: also empty proof (any tree is consistent with empty tree)
    if from_size == 0 {
        return Ok(ConsistencyProof { from_size, to_size, path: Vec::new() });
    }

    let path = generate_consistency_path(from_size, to_size, &get_node)?;

    Ok(ConsistencyProof { from_size, to_size, path })
}

/// Generate consistency proof path recursively
///
/// Helper function implementing RFC 9162 SUBPROOF algorithm.
/// The `b` flag determines behavior when ``from_size`` == ``to_size``:
/// - b=true (top level): return empty
/// - b=false (recursion into right subtree): return [MTH(subtree)]
fn generate_consistency_path<F>(
    from_size: u64,
    to_size: u64,
    get_node: &F,
) -> Result<Vec<Hash>, AtlError>
where
    F: Fn(u32, u64) -> Option<Hash>,
{
    // Initial call with b=true, offset=0
    generate_consistency_path_inner(from_size, to_size, 0, true, get_node)
}

/// Internal recursive helper implementing RFC 9162 SUBPROOF(m, D\[n\], b)
///
/// # Arguments
/// * `from_size` - m in RFC notation
/// * `to_size` - n in RFC notation
/// * `offset` - starting index of this subtree in the full tree
/// * `b` - boolean flag per RFC 9162
/// * `get_node` - node accessor
fn generate_consistency_path_inner<F>(
    from_size: u64,
    to_size: u64,
    offset: u64,
    b: bool,
    get_node: &F,
) -> Result<Vec<Hash>, AtlError>
where
    F: Fn(u32, u64) -> Option<Hash>,
{
    // RFC 9162 SUBPROOF base case: m == n
    if from_size == to_size {
        if b {
            // b=true: return empty (at top level or left recursion)
            return Ok(Vec::new());
        }
        // b=false: return [MTH(D[n])] (right subtree recursion needs the root)
        let root = compute_subtree_root(offset, to_size, get_node)?;
        return Ok(vec![root]);
    }

    // from_size == 0 is handled by caller, but be defensive
    if from_size == 0 {
        return Ok(Vec::new());
    }

    // Split at largest power of 2 less than to_size
    let k = largest_power_of_2_less_than(to_size);

    let mut path = Vec::new();

    if from_size <= k {
        // RFC 9162: SUBPROOF(m, D[0:k], b) + MTH(D[k:n])
        // Recurse into left subtree with same b flag
        let left_path = generate_consistency_path_inner(from_size, k, offset, b, get_node)?;
        path.extend(left_path);

        // Add right subtree root
        let right_size = to_size
            .checked_sub(k)
            .ok_or(AtlError::ArithmeticOverflow { operation: "consistency path: to_size - k" })?;
        let right_offset = offset
            .checked_add(k)
            .ok_or(AtlError::ArithmeticOverflow { operation: "consistency path: offset + k" })?;
        let right_root = compute_subtree_root(right_offset, right_size, get_node)?;
        path.push(right_root);
    } else {
        // RFC 9162: SUBPROOF(m-k, D[k:n], false) + MTH(D[0:k])
        // Recurse into right subtree with b=false
        let right_from = from_size
            .checked_sub(k)
            .ok_or(AtlError::ArithmeticOverflow { operation: "consistency path: from_size - k" })?;
        let right_to = to_size.checked_sub(k).ok_or(AtlError::ArithmeticOverflow {
            operation: "consistency path: to_size - k (right)",
        })?;
        let right_offset = offset.checked_add(k).ok_or(AtlError::ArithmeticOverflow {
            operation: "consistency path: offset + k (right)",
        })?;
        // Note: b=false when recursing into right subtree
        let right_path =
            generate_consistency_path_inner(right_from, right_to, right_offset, false, get_node)?;
        path.extend(right_path);

        // Add left subtree root AFTER recursive result
        let left_root = compute_subtree_root(offset, k, get_node)?;
        path.push(left_root);
    }

    Ok(path)
}

/// Verify a consistency proof
///
/// Verifies that a tree with `old_root` and size `proof.from_size` is a prefix
/// of a tree with `new_root` and size `proof.to_size`.
///
/// # Arguments
/// * `proof` - The consistency proof
/// * `old_root` - Root hash of older tree
/// * `new_root` - Root hash of newer tree
///
/// # Returns
/// * `Ok(true)` - proof is mathematically valid
/// * `Ok(false)` - proof is mathematically invalid (hash mismatch)
/// * `Err(InvalidConsistencyBounds)` - `from_size` > `to_size`
/// * `Err(InvalidProofStructure)` - structurally impossible proof
///
/// # Errors
///
/// Returns error if the proof structure is invalid and cannot be verified.
/// Returns `Ok(false)` if the proof structure is valid but doesn't prove consistency.
///
/// # Example
///
/// ```
/// use atl_core::core::merkle::{ConsistencyProof, verify_consistency};
///
/// let old_root = [0u8; 32];
/// let new_root = [1u8; 32];
/// let proof = ConsistencyProof {
///     from_size: 5,
///     to_size: 5,
///     path: vec![],
/// };
///
/// // Same size and same root: valid
/// assert!(verify_consistency(&proof, &old_root, &old_root).unwrap());
///
/// // Same size, different roots: invalid
/// assert!(!verify_consistency(&proof, &old_root, &new_root).unwrap());
/// ```
pub fn verify_consistency(
    proof: &ConsistencyProof,
    old_root: &Hash,
    new_root: &Hash,
) -> AtlResult<bool> {
    // INVARIANT 1: Valid bounds (from <= to)
    if proof.from_size > proof.to_size {
        return Err(AtlError::InvalidConsistencyBounds {
            from_size: proof.from_size,
            to_size: proof.to_size,
        });
    }

    // INVARIANT 2: Same size requires empty path
    if proof.from_size == proof.to_size {
        if !proof.path.is_empty() {
            return Err(AtlError::InvalidProofStructure {
                reason: format!(
                    "same-size consistency (from={}, to={}) requires empty path, got {} hashes",
                    proof.from_size,
                    proof.to_size,
                    proof.path.len()
                ),
            });
        }
        return Ok(use_constant_time_eq(old_root, new_root));
    }

    // INVARIANT 3: Zero old size requires empty path
    if proof.from_size == 0 {
        if !proof.path.is_empty() {
            return Err(AtlError::InvalidProofStructure {
                reason: format!(
                    "zero-size consistency requires empty path, got {} hashes",
                    proof.path.len()
                ),
            });
        }
        return Ok(true); // Any tree is consistent with empty tree
    }

    // INVARIANT 4: Non-trivial consistency with non-power-of-2 from_size needs at least one hash
    // When from_size IS a power of 2, RFC 9162 verification prepends old_root,
    // so empty path can be valid in some edge cases (handled by verify_consistency_path)
    if proof.path.is_empty() && !is_power_of_two(proof.from_size) {
        return Err(AtlError::InvalidProofStructure {
            reason: format!(
                "non-trivial consistency (from={}, to={}) requires at least one hash",
                proof.from_size, proof.to_size
            ),
        });
    }

    // INVARIANT 5: Path length bounded by O(log n)
    // SAFETY: Maximum value is 64 * 2 = 128, always fits in usize.
    // leading_zeros() returns 0..=64, so (64 - leading_zeros) is at most 64.
    #[allow(clippy::cast_possible_truncation)]
    let max_proof_len = ((64 - proof.to_size.leading_zeros()) as usize).saturating_mul(2);
    if proof.path.len() > max_proof_len {
        return Err(AtlError::InvalidProofStructure {
            reason: format!(
                "path length {} exceeds maximum {} for tree sizes ({}, {})",
                proof.path.len(),
                max_proof_len,
                proof.from_size,
                proof.to_size
            ),
        });
    }

    // Verify the proof by reconstructing both old and new roots
    verify_consistency_path(proof.from_size, proof.to_size, &proof.path, old_root, new_root)
}

/// Verify consistency proof path per RFC 9162 Section 2.1.4.2
///
/// Reconstructs both old and new roots from the proof path and verifies
/// they match the provided root hashes.
///
/// # Algorithm
///
/// Implements RFC 9162 Section 2.1.4.2:
/// 1. Validate inputs (sizes, bounds)
/// 2. Handle empty proof (fail for non-trivial cases)
/// 3. Prepend `old_root` if `from_size` is power of 2
/// 4. Initialize fn, sn, fr, sr
/// 5. Align by shifting while LSB(fn) set
/// 6. Process each proof element
/// 7. Verify fr == `old_root`, sr == `new_root`, sn == 0
///
/// # Arguments
/// * `from_size` - Size of older tree
/// * `to_size` - Size of newer tree
/// * `path` - Proof hashes
/// * `old_root` - Root hash of older tree
/// * `new_root` - Root hash of newer tree
///
/// # Returns
/// * `Ok(true)` - proof is mathematically valid
/// * `Ok(false)` - proof is mathematically invalid (hash mismatch or sn != 0)
///
/// # Errors
///
/// Returns error if:
/// - `from_size` is 0 (checked by caller but re-validated for safety)
/// - `from_size` > `to_size` (checked by caller but re-validated for safety)
/// - Arithmetic overflow occurs during computation
///
/// # Note
/// This function implements the core RFC 9162 verification algorithm.
/// Input validation is primarily done by the caller `verify_consistency()`,
/// but critical invariants are re-checked here for defense in depth.
fn verify_consistency_path(
    from_size: u64,
    to_size: u64,
    path: &[Hash],
    old_root: &Hash,
    new_root: &Hash,
) -> AtlResult<bool> {
    // RFC 9162 Step 1: Empty proof always fails for non-trivial case
    // (Trivial cases from_size == to_size and from_size == 0 are handled by caller)
    if path.is_empty() {
        return Ok(false);
    }

    // RFC 9162 Step 2: Prepend first_hash if first is exact power of 2
    let path_vec: Vec<Hash> = if is_power_of_two(from_size) {
        let mut v = vec![*old_root];
        v.extend_from_slice(path);
        v
    } else {
        path.to_vec()
    };

    // RFC 9162 Step 3: Initialize with checked arithmetic
    let mut fn_ = from_size.checked_sub(1).ok_or(AtlError::ArithmeticOverflow {
        operation: "consistency verification: from_size - 1",
    })?;
    let mut sn = to_size.checked_sub(1).ok_or(AtlError::ArithmeticOverflow {
        operation: "consistency verification: to_size - 1",
    })?;

    // RFC 9162 Step 4: Align - shift while LSB(fn) is set (fn is odd)
    while fn_ & 1 == 1 {
        fn_ >>= 1;
        sn >>= 1;
    }

    // RFC 9162 Step 5: Initialize fr and sr
    let mut fr = path_vec[0];
    let mut sr = path_vec[0];

    // RFC 9162 Step 6: Process each subsequent element
    for c in path_vec.iter().skip(1) {
        // Step 6a: If sn == 0, proof is invalid
        if sn == 0 {
            return Ok(false);
        }

        // Step 6b/6c: Compute new fr and sr
        if fn_ & 1 == 1 || fn_ == sn {
            // Step 6b: LSB(fn) set OR fn == sn
            // Hash c on LEFT: HASH(c || current)
            fr = hash_children(c, &fr);
            sr = hash_children(c, &sr);

            // Inner loop: shift while LSB(fn) NOT set and fn != 0
            while fn_ & 1 == 0 && fn_ != 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            // Step 6c: Hash current on LEFT: HASH(current || c)
            sr = hash_children(&sr, c);
        }

        // Step 6d: Shift both
        fn_ >>= 1;
        sn >>= 1;
    }

    // RFC 9162 Step 7: Final verification (constant-time)
    Ok(use_constant_time_eq(&fr, old_root) && use_constant_time_eq(&sr, new_root) && sn == 0)
}

/// Constant-time equality comparison
///
/// Prevents timing attacks by comparing hashes in constant time.
fn use_constant_time_eq(a: &Hash, b: &Hash) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}
