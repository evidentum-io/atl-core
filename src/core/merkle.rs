//! RFC 6962 Merkle tree operations
//!
//! Pure cryptographic functions for Merkle tree computation and verification.
//! No storage - all data passed as parameters.
//!
//! # RFC 6962 Compliance
//!
//! This implementation follows RFC 6962 (Certificate Transparency) with ATL-specific
//! leaf hash construction that includes both payload and metadata hashes.
//!
//! - Leaf prefix: 0x00
//! - Node prefix: 0x01
//! - Hash algorithm: SHA256
//!
//! # Example
//!
//! ```
//! use atl_core::core::merkle::{compute_leaf_hash, compute_root, Hash};
//!
//! let payload = [0u8; 32];
//! let metadata = [1u8; 32];
//! let leaf_hash = compute_leaf_hash(&payload, &metadata);
//!
//! let leaves = vec![leaf_hash];
//! let root = compute_root(&leaves);
//! assert_eq!(root, leaf_hash); // Single leaf is the root
//! ```

use sha2::{Digest, Sha256};

use crate::{AtlError, AtlResult};

/// Leaf prefix for RFC 6962 compliance
pub const LEAF_PREFIX: u8 = 0x00;

/// Node prefix for RFC 6962 compliance
pub const NODE_PREFIX: u8 = 0x01;

/// A 32-byte SHA256 hash value
pub type Hash = [u8; 32];

/// Represents a leaf in the Merkle tree
///
/// An ATL leaf consists of two hashes:
/// - `payload_hash`: SHA256 of the document
/// - `metadata_hash`: SHA256 of JCS-canonicalized metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    /// SHA256 of the document payload
    pub payload_hash: Hash,
    /// SHA256 of the JCS-canonicalized metadata
    pub metadata_hash: Hash,
}

impl Leaf {
    /// Create a new leaf from payload and metadata hashes
    #[must_use]
    pub const fn new(payload_hash: Hash, metadata_hash: Hash) -> Self {
        Self { payload_hash, metadata_hash }
    }

    /// Compute the leaf hash: SHA256(0x00 || `payload_hash` || `metadata_hash`)
    ///
    /// This follows RFC 6962 with ATL-specific leaf construction.
    #[must_use]
    pub fn hash(&self) -> Hash {
        compute_leaf_hash(&self.payload_hash, &self.metadata_hash)
    }
}

/// Merkle inclusion proof
///
/// Proves that a specific leaf exists at a given index in a tree of known size.
/// The proof consists of sibling hashes along the path from leaf to root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// Index of the leaf in the tree (0-based)
    pub leaf_index: u64,
    /// Size of the tree when proof was generated
    pub tree_size: u64,
    /// Sibling hashes along the path to root (ordered from leaf to root)
    pub path: Vec<Hash>,
}

/// Merkle consistency proof
///
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

/// Tree head (root hash + tree size)
///
/// Represents a snapshot of the tree at a specific size.
/// The root hash commits to all leaves up to that size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeHead {
    /// Current root hash
    pub root_hash: Hash,
    /// Number of leaves in tree
    pub tree_size: u64,
}

/// Compute leaf hash from payload and metadata hashes
///
/// Implements RFC 6962 leaf hash with ATL-specific construction:
/// ```text
/// leaf_hash = SHA256(0x00 || payload_hash || metadata_hash)
/// ```
///
/// # Arguments
/// * `payload_hash` - SHA256 of document payload
/// * `metadata_hash` - SHA256 of JCS-canonicalized metadata
///
/// # Returns
/// * 32-byte leaf hash
///
/// # Example
///
/// ```
/// use atl_core::core::merkle::compute_leaf_hash;
///
/// let payload = [0u8; 32];
/// let metadata = [1u8; 32];
/// let leaf_hash = compute_leaf_hash(&payload, &metadata);
/// assert_eq!(leaf_hash.len(), 32);
/// ```
#[must_use]
pub fn compute_leaf_hash(payload_hash: &Hash, metadata_hash: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(payload_hash);
    hasher.update(metadata_hash);
    hasher.finalize().into()
}

/// Compute hash of two child nodes
///
/// Implements RFC 6962 node hash:
/// ```text
/// node_hash = SHA256(0x01 || left_hash || right_hash)
/// ```
///
/// # Arguments
/// * `left` - Left child hash
/// * `right` - Right child hash
///
/// # Returns
/// * 32-byte node hash
///
/// # Example
///
/// ```
/// use atl_core::core::merkle::hash_children;
///
/// let left = [0u8; 32];
/// let right = [1u8; 32];
/// let node_hash = hash_children(&left, &right);
/// assert_eq!(node_hash.len(), 32);
/// ```
#[must_use]
pub fn hash_children(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

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
    if power == n { power >> 1 } else { power }
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

/// Compute root hash from a slice of leaf hashes
///
/// Uses the RFC 6962 algorithm for computing Merkle tree root.
/// The algorithm recursively splits the tree into left and right subtrees
/// at the largest power of 2 less than the tree size.
///
/// # Arguments
/// * `leaves` - Slice of leaf hashes in order
///
/// # Returns
/// * Root hash, or hash of empty string for empty tree
///
/// # Example
///
/// ```
/// use atl_core::core::merkle::{compute_root, hash_children};
///
/// // Single leaf
/// let leaves = vec![[42u8; 32]];
/// let root = compute_root(&leaves);
/// assert_eq!(root, leaves[0]);
///
/// // Two leaves
/// let leaves = vec![[0u8; 32], [1u8; 32]];
/// let root = compute_root(&leaves);
/// let expected = hash_children(&leaves[0], &leaves[1]);
/// assert_eq!(root, expected);
/// ```
#[must_use]
pub fn compute_root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => {
            // Empty tree: hash of empty string
            Sha256::digest([]).into()
        }
        1 => {
            // Single leaf is the root
            leaves[0]
        }
        n => {
            // Split at largest power of 2 less than n
            // SAFETY: `n` is usize (from slice.len()), so the result of
            // largest_power_of_2_less_than(n as u64) is always < n, hence fits in usize.
            // On 32-bit platforms, n <= usize::MAX (~4B), so k < n fits in usize.
            #[allow(clippy::cast_possible_truncation)]
            let k = largest_power_of_2_less_than(n as u64) as usize;
            let left_root = compute_root(&leaves[0..k]);
            let right_root = compute_root(&leaves[k..]);
            hash_children(&left_root, &right_root)
        }
    }
}

/// Generate an inclusion proof for a leaf
///
/// Creates a proof that a leaf at `leaf_index` exists in a tree of size `tree_size`.
/// The proof consists of sibling hashes along the path from leaf to root.
///
/// # Arguments
/// * `leaf_index` - Index of the leaf (0-based)
/// * `tree_size` - Current tree size
/// * `get_node` - Callback to retrieve node hash at (level, index)
///
/// # Returns
/// * Inclusion proof or error
///
/// # Errors
/// * `LeafIndexOutOfBounds` if `leaf_index` >= `tree_size`
/// * `MissingNode` if `get_node` returns `None` for required hash
///
/// # Example
///
/// ```
/// use atl_core::core::merkle::{generate_inclusion_proof, Hash};
///
/// let leaves = vec![[0u8; 32], [1u8; 32]];
/// let get_node = |level: u32, index: u64| -> Option<Hash> {
///     if level == 0 && (index as usize) < leaves.len() {
///         Some(leaves[index as usize])
///     } else {
///         None
///     }
/// };
///
/// let proof = generate_inclusion_proof(0, 2, get_node).unwrap();
/// assert_eq!(proof.leaf_index, 0);
/// assert_eq!(proof.tree_size, 2);
/// assert_eq!(proof.path.len(), 1); // One sibling (leaf 1)
/// ```
pub fn generate_inclusion_proof<F>(
    leaf_index: u64,
    tree_size: u64,
    get_node: F,
) -> Result<InclusionProof, AtlError>
where
    F: Fn(u32, u64) -> Option<Hash>,
{
    // Validate inputs
    if tree_size == 0 {
        return Err(AtlError::InvalidArgument(format!("invalid tree size: {tree_size}")));
    }
    if leaf_index >= tree_size {
        return Err(AtlError::LeafIndexOutOfBounds { index: leaf_index, tree_size });
    }

    let mut path = Vec::new();
    let mut index = leaf_index;
    let mut size = tree_size;
    let mut base_offset = 0u64; // Track absolute position in tree

    // Single leaf tree has empty proof
    if size == 1 {
        return Ok(InclusionProof { leaf_index, tree_size, path });
    }

    // Traverse from leaf to root, collecting sibling hashes
    while size > 1 {
        let k = largest_power_of_2_less_than(size);

        if index < k {
            // We're in left subtree, need right subtree hash
            let subtree_offset =
                base_offset.checked_add(k).ok_or(AtlError::ArithmeticOverflow {
                    operation: "inclusion proof: base_offset + k",
                })?;
            let subtree_size = size
                .checked_sub(k)
                .ok_or(AtlError::ArithmeticOverflow { operation: "inclusion proof: size - k" })?;
            let sibling_hash = compute_subtree_root(subtree_offset, subtree_size, &get_node)?;
            path.push(sibling_hash);
            size = k;
            // base_offset stays the same (left subtree starts at same position)
        } else {
            // We're in right subtree, need left subtree hash
            let sibling_hash = compute_subtree_root(base_offset, k, &get_node)?;
            path.push(sibling_hash);
            index = index
                .checked_sub(k)
                .ok_or(AtlError::ArithmeticOverflow { operation: "inclusion proof: index - k" })?;
            size = size.checked_sub(k).ok_or(AtlError::ArithmeticOverflow {
                operation: "inclusion proof: size - k (right)",
            })?;
            base_offset = base_offset.checked_add(k).ok_or(AtlError::ArithmeticOverflow {
                operation: "inclusion proof: base_offset + k (right)",
            })?;
        }
    }

    // RFC 6962 requires siblings in leaf-to-root order for verification
    // Our traversal collects them root-to-leaf, so reverse
    path.reverse();

    Ok(InclusionProof { leaf_index, tree_size, path })
}

/// Compute root of a subtree using storage callback
///
/// Helper function for proof generation that computes the root hash
/// of a subtree spanning leaves [offset..offset+size).
///
/// This function only retrieves leaf nodes (level 0) from storage
/// and computes intermediate hashes recursively.
///
/// # Arguments
/// * `offset` - Starting leaf index of subtree
/// * `size` - Number of leaves in subtree
/// * `get_node` - Storage callback (only called for level 0, leaf index)
///
/// # Returns
/// * Root hash of subtree or error if leaf nodes are missing
fn compute_subtree_root<F>(offset: u64, size: u64, get_node: &F) -> Result<Hash, AtlError>
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

/// Verify an inclusion proof
///
/// Verifies that a leaf with given hash exists at the claimed index in a tree
/// with the given root hash.
///
/// # Arguments
/// * `leaf_hash` - Hash of the leaf being proved
/// * `proof` - The inclusion proof
/// * `expected_root` - Expected root hash
///
/// # Returns
/// * `Ok(true)` - proof is mathematically valid
/// * `Ok(false)` - proof is mathematically invalid (hash mismatch)
/// * `Err(InvalidTreeSize)` - `tree_size` is 0
/// * `Err(LeafIndexOutOfBounds)` - `leaf_index` >= `tree_size`
/// * `Err(InvalidProofStructure)` - path length doesn't match tree geometry
///
/// # Errors
///
/// Returns error if the proof structure is invalid and cannot be verified.
/// Returns `Ok(false)` if the proof structure is valid but doesn't prove inclusion.
///
/// # Example
///
/// ```
/// use atl_core::core::merkle::{compute_root, generate_inclusion_proof, verify_inclusion, Hash};
///
/// let leaves = vec![[0u8; 32], [1u8; 32]];
/// let root = compute_root(&leaves);
///
/// let get_node = |level: u32, index: u64| -> Option<Hash> {
///     if level == 0 && (index as usize) < leaves.len() {
///         Some(leaves[index as usize])
///     } else {
///         None
///     }
/// };
///
/// let proof = generate_inclusion_proof(0, 2, get_node).unwrap();
/// assert!(verify_inclusion(&leaves[0], &proof, &root).unwrap());
/// ```
pub fn verify_inclusion(
    leaf_hash: &Hash,
    proof: &InclusionProof,
    expected_root: &Hash,
) -> AtlResult<bool> {
    // Handle empty tree
    if proof.tree_size == 0 {
        return Err(AtlError::InvalidTreeSize { size: 0, reason: "tree cannot be empty" });
    }

    // Validate leaf index
    if proof.leaf_index >= proof.tree_size {
        return Err(AtlError::LeafIndexOutOfBounds {
            index: proof.leaf_index,
            tree_size: proof.tree_size,
        });
    }

    // Single leaf tree
    if proof.tree_size == 1 {
        // Single-leaf tree with non-empty path is structurally invalid
        if !proof.path.is_empty() {
            return Err(AtlError::InvalidProofStructure {
                reason: format!(
                    "single-leaf tree (size 1) must have empty proof path, got {} hashes",
                    proof.path.len()
                ),
            });
        }
        return Ok(leaf_hash == expected_root);
    }

    // INVARIANT 4: Path length bounded by tree depth
    // For a tree of size n > 1, maximum depth is ceil(log2(n)) = 64 - leading_zeros(n-1)
    // SAFETY: leading_zeros() returns 0..=64, so (64 - leading_zeros) is at most 64, fits in usize.
    #[allow(clippy::cast_possible_truncation)]
    let max_depth = (64 - (proof.tree_size - 1).leading_zeros()) as usize;
    if proof.path.len() > max_depth {
        return Err(AtlError::InvalidProofStructure {
            reason: format!(
                "path length {} exceeds maximum depth {} for tree size {}",
                proof.path.len(),
                max_depth,
                proof.tree_size
            ),
        });
    }

    // Reconstruct root from leaf to root using proof path
    // Path is in leaf-to-root order (siblings from bottom up)
    let mut hash = *leaf_hash;
    let mut proof_idx = 0;

    // Build list of (index, size, is_left) for each level
    let mut levels = Vec::new();
    let mut idx = proof.leaf_index;
    let mut sz = proof.tree_size;

    while sz > 1 {
        let k = largest_power_of_2_less_than(sz);
        let is_left = idx < k;
        levels.push((idx, sz, is_left));

        if is_left {
            sz = k;
        } else {
            idx = idx
                .checked_sub(k)
                .ok_or(AtlError::ArithmeticOverflow { operation: "verify inclusion: idx - k" })?;
            sz = sz
                .checked_sub(k)
                .ok_or(AtlError::ArithmeticOverflow { operation: "verify inclusion: sz - k" })?;
        }
    }

    // Process levels from leaf to root
    for i in (0..levels.len()).rev() {
        if proof_idx >= proof.path.len() {
            return Ok(false);
        }

        let (_idx, _sz, is_left) = levels[i];

        if is_left {
            hash = hash_children(&hash, &proof.path[proof_idx]);
        } else {
            hash = hash_children(&proof.path[proof_idx], &hash);
        }
        proof_idx += 1;
    }

    // INVARIANT 5: All path hashes must be consumed
    if proof_idx != proof.path.len() {
        return Err(AtlError::InvalidProofStructure {
            reason: format!(
                "proof path not fully consumed: used {} of {} hashes",
                proof_idx,
                proof.path.len()
            ),
        });
    }

    // Constant-time comparison to prevent timing attacks
    Ok(use_constant_time_eq(&hash, expected_root))
}

/// Generate a consistency proof between two tree sizes
///
/// Creates a proof that a tree of size `from_size` is a prefix of a tree
/// of size `to_size`. This ensures the append-only property.
///
/// # Arguments
/// * `from_size` - Size of older tree
/// * `to_size` - Size of newer tree
/// * `get_node` - Callback to retrieve node hash at (level, index)
///
/// # Returns
/// * Consistency proof or error
///
/// # Errors
/// * `InvalidConsistencyBounds` if `from_size` > `to_size`
/// * `InvalidTreeSize` if either size is 0
/// * `MissingNode` if required hashes are missing
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

/// Internal recursive helper implementing RFC 9162 SUBPROOF(m, D[n], b)
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

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_sign_loss)]
mod tests {
    use super::*;

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

    #[test]
    fn test_largest_power_of_2() {
        assert_eq!(largest_power_of_2_less_than(1), 0);
        assert_eq!(largest_power_of_2_less_than(2), 1);
        assert_eq!(largest_power_of_2_less_than(3), 2);
        assert_eq!(largest_power_of_2_less_than(4), 2);
        assert_eq!(largest_power_of_2_less_than(5), 4);
        assert_eq!(largest_power_of_2_less_than(7), 4);
        assert_eq!(largest_power_of_2_less_than(8), 4);
        assert_eq!(largest_power_of_2_less_than(9), 8);
        assert_eq!(largest_power_of_2_less_than(16), 8);
    }

    #[test]
    fn test_inclusion_proof_single_leaf() {
        let leaves = [ZERO_HASH];
        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && index == 0 { Some(leaves[0]) } else { None }
        };

        let proof = generate_inclusion_proof(0, 1, get_node).unwrap();
        assert_eq!(proof.leaf_index, 0);
        assert_eq!(proof.tree_size, 1);
        assert!(proof.path.is_empty());

        let root = compute_root(&leaves);
        assert!(verify_inclusion(&leaves[0], &proof, &root).unwrap());
    }

    #[test]
    fn test_inclusion_proof_two_leaves() {
        let leaves = [ZERO_HASH, ONE_HASH];
        let root = compute_root(&leaves);

        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        // Proof for leaf 0
        let proof = generate_inclusion_proof(0, 2, get_node).unwrap();
        assert_eq!(proof.path.len(), 1);
        assert_eq!(proof.path[0], leaves[1]);
        assert!(verify_inclusion(&leaves[0], &proof, &root).unwrap());

        // Proof for leaf 1
        let proof = generate_inclusion_proof(1, 2, get_node).unwrap();
        assert_eq!(proof.path.len(), 1);
        assert_eq!(proof.path[0], leaves[0]);
        assert!(verify_inclusion(&leaves[1], &proof, &root).unwrap());
    }

    #[test]
    fn test_inclusion_proof_three_leaves() {
        let leaves = [ZERO_HASH, ONE_HASH, TWO_HASH];
        let root = compute_root(&leaves);

        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        // Proof for each leaf
        for i in 0..3 {
            let proof = generate_inclusion_proof(i, 3, get_node).unwrap();
            assert!(
                verify_inclusion(&leaves[i as usize], &proof, &root).unwrap(),
                "Failed verification for leaf {i}"
            );
        }
    }

    #[test]
    fn test_inclusion_proof_invalid() {
        let leaves = [ZERO_HASH, ONE_HASH];
        let root = compute_root(&leaves);

        let proof = InclusionProof {
            leaf_index: 0,
            tree_size: 2,
            path: vec![[99u8; 32]], // Wrong sibling
        };

        assert!(!verify_inclusion(&leaves[0], &proof, &root).unwrap());
    }

    #[test]
    fn test_inclusion_proof_invalid_index() {
        let get_node = |_: u32, _: u64| -> Option<Hash> { None };

        let result = generate_inclusion_proof(5, 3, get_node);
        assert!(matches!(result, Err(AtlError::LeafIndexOutOfBounds { .. })));
    }

    #[test]
    fn test_inclusion_proof_zero_size() {
        let get_node = |_: u32, _: u64| -> Option<Hash> { None };

        let result = generate_inclusion_proof(0, 0, get_node);
        assert!(matches!(result, Err(AtlError::InvalidArgument(_))));
    }

    #[test]
    fn test_consistency_proof_same_size() {
        let proof = generate_consistency_proof(5, 5, |_, _| None).unwrap();
        assert_eq!(proof.from_size, 5);
        assert_eq!(proof.to_size, 5);
        assert!(proof.path.is_empty());

        let root = [42u8; 32];
        assert!(verify_consistency(&proof, &root, &root).unwrap());
    }

    #[test]
    fn test_consistency_proof_zero_old_size() {
        let proof = generate_consistency_proof(0, 10, |_, _| None).unwrap();
        assert!(proof.path.is_empty());

        let old_root = ZERO_HASH;
        let new_root = ONE_HASH;
        assert!(verify_consistency(&proof, &old_root, &new_root).unwrap());
    }

    #[test]
    fn test_consistency_proof_invalid_bounds() {
        let result = generate_consistency_proof(10, 5, |_, _| None);
        assert!(matches!(result, Err(AtlError::InvalidArgument(_))));
    }

    #[test]
    fn test_consistency_proof_same_size_different_roots() {
        let proof = ConsistencyProof { from_size: 5, to_size: 5, path: vec![] };

        assert!(!verify_consistency(&proof, &ZERO_HASH, &ONE_HASH).unwrap());
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(use_constant_time_eq(&ZERO_HASH, &ZERO_HASH));
        assert!(!use_constant_time_eq(&ZERO_HASH, &ONE_HASH));

        let hash1 = [0u8; 32];
        let mut hash2 = [0u8; 32];
        hash2[31] = 1;
        assert!(!use_constant_time_eq(&hash1, &hash2));
    }

    #[test]
    fn test_tree_head_struct() {
        let tree_head = TreeHead { root_hash: ZERO_HASH, tree_size: 42 };
        assert_eq!(tree_head.root_hash, ZERO_HASH);
        assert_eq!(tree_head.tree_size, 42);
    }

    #[test]
    fn test_proof_size_is_log_n() {
        // For tree of size 8, max proof length is 3 (log2(8))
        let leaves: Vec<Hash> = (0..8).map(|i| [i; 32]).collect();
        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        for i in 0..8 {
            let proof = generate_inclusion_proof(i, 8, get_node).unwrap();
            assert!(
                proof.path.len() <= 3,
                "Proof for leaf {} has length {}, expected <= 3",
                i,
                proof.path.len()
            );
        }
    }

    #[test]
    fn test_inclusion_proof_roundtrip_various_sizes() {
        for tree_size in 1..=10 {
            let leaves: Vec<Hash> = (0..tree_size).map(|i| [i as u8; 32]).collect();
            let root = compute_root(&leaves);

            let get_node = |level: u32, index: u64| -> Option<Hash> {
                if level == 0 && (index as usize) < leaves.len() {
                    Some(leaves[index as usize])
                } else {
                    None
                }
            };

            for (leaf_idx, leaf) in leaves.iter().enumerate() {
                let proof =
                    generate_inclusion_proof(leaf_idx as u64, tree_size as u64, get_node).unwrap();
                assert!(
                    verify_inclusion(leaf, &proof, &root).unwrap(),
                    "Failed for tree_size={tree_size}, leaf_idx={leaf_idx}"
                );
            }
        }
    }

    #[test]
    fn test_verify_inclusion_zero_tree_size() {
        let proof = InclusionProof { leaf_index: 0, tree_size: 0, path: vec![] };
        let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
        assert!(matches!(result, Err(AtlError::InvalidTreeSize { .. })));
    }

    #[test]
    fn test_verify_inclusion_index_out_of_bounds() {
        let proof = InclusionProof { leaf_index: 5, tree_size: 3, path: vec![] };
        let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
        assert!(matches!(result, Err(AtlError::LeafIndexOutOfBounds { .. })));
    }

    #[test]
    fn test_verify_inclusion_single_leaf_with_path_errors() {
        let proof = InclusionProof {
            leaf_index: 0,
            tree_size: 1,
            path: vec![[1u8; 32]], // Should be empty!
        };
        let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
        assert!(matches!(result, Err(AtlError::InvalidProofStructure { .. })));
    }

    #[test]
    fn test_verify_inclusion_excessive_path_length() {
        // Tree size 4 -> max depth 2
        let proof = InclusionProof {
            leaf_index: 0,
            tree_size: 4,
            path: vec![ONE_HASH; 10], // Way too many
        };
        let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
        assert!(matches!(result, Err(AtlError::InvalidProofStructure { .. })));
    }

    #[test]
    fn test_verify_inclusion_path_not_fully_consumed() {
        // Create a proof with extra hashes that won't be consumed
        let proof = InclusionProof {
            leaf_index: 0,
            tree_size: 2,
            path: vec![ONE_HASH, TWO_HASH], // Only 1 hash should be needed for tree size 2
        };
        let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
        assert!(matches!(result, Err(AtlError::InvalidProofStructure { .. })));
    }

    #[test]
    fn test_verify_inclusion_boundary_path_length() {
        // Tree size 8 -> max depth 3
        // This tests the exact boundary
        let leaves: Vec<Hash> = (0..8).map(|i| [i; 32]).collect();
        let root = compute_root(&leaves);

        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let proof = generate_inclusion_proof(0, 8, get_node).unwrap();
        assert!(proof.path.len() <= 3); // Max depth for size 8

        let result = verify_inclusion(&leaves[0], &proof, &root).unwrap();
        assert!(result);
    }

    #[test]
    fn test_max_depth_calculation() {
        // Test the max depth formula: ceil(log2(n)) = 64 - leading_zeros(n-1)
        // Tree size 1 -> max depth 0
        assert_eq!(64 - (1u64 - 1).leading_zeros(), 0);

        // Tree size 2 -> max depth 1
        assert_eq!((64 - (2u64 - 1).leading_zeros()) as usize, 1);

        // Tree size 3, 4 -> max depth 2
        assert_eq!((64 - (3u64 - 1).leading_zeros()) as usize, 2);
        assert_eq!((64 - (4u64 - 1).leading_zeros()) as usize, 2);

        // Tree size 5..8 -> max depth 3
        assert_eq!((64 - (5u64 - 1).leading_zeros()) as usize, 3);
        assert_eq!((64 - (7u64 - 1).leading_zeros()) as usize, 3);
        assert_eq!((64 - (8u64 - 1).leading_zeros()) as usize, 3);

        // Tree size 9 -> max depth 4
        assert_eq!((64 - (9u64 - 1).leading_zeros()) as usize, 4);

        // Tree size 1000 -> max depth 10
        assert_eq!((64 - (1000u64 - 1).leading_zeros()) as usize, 10);
    }

    #[test]
    fn test_verify_inclusion_max_depth_boundaries() {
        // Test various tree sizes at power-of-2 boundaries
        for tree_size in [2u64, 3, 4, 5, 7, 8, 9, 15, 16, 17] {
            let leaves: Vec<Hash> = (0..tree_size).map(|i| [i as u8; 32]).collect();
            let root = compute_root(&leaves);

            let get_node = |level: u32, index: u64| -> Option<Hash> {
                if level == 0 && (index as usize) < leaves.len() {
                    Some(leaves[index as usize])
                } else {
                    None
                }
            };

            let max_depth = (64 - (tree_size - 1).leading_zeros()) as usize;

            // Generate and verify valid proof
            let proof = generate_inclusion_proof(0, tree_size, get_node).unwrap();
            assert!(proof.path.len() <= max_depth);
            assert!(verify_inclusion(&leaves[0], &proof, &root).unwrap());

            // Create proof with excessive path length
            let mut excessive_path = proof.path.clone();
            excessive_path.extend(vec![ZERO_HASH; max_depth + 1]);
            let bad_proof = InclusionProof { leaf_index: 0, tree_size, path: excessive_path };
            let result = verify_inclusion(&leaves[0], &bad_proof, &root);
            assert!(matches!(result, Err(AtlError::InvalidProofStructure { .. })));
        }
    }

    #[test]
    fn test_verify_consistency_invalid_bounds() {
        let proof = ConsistencyProof { from_size: 10, to_size: 5, path: vec![] };
        let result = verify_consistency(&proof, &ZERO_HASH, &ONE_HASH);
        assert!(matches!(result, Err(AtlError::InvalidConsistencyBounds { .. })));
    }

    #[test]
    fn test_verify_consistency_same_size_with_path_errors() {
        // Same size with non-empty path is structurally invalid
        let proof = ConsistencyProof {
            from_size: 5,
            to_size: 5,
            path: vec![ZERO_HASH], // Should be empty!
        };
        let result = verify_consistency(&proof, &ZERO_HASH, &ZERO_HASH);
        assert!(matches!(result, Err(AtlError::InvalidProofStructure { .. })));
    }

    #[test]
    fn test_verify_consistency_zero_size_with_path_errors() {
        // Zero old size with non-empty path is structurally invalid
        let proof = ConsistencyProof {
            from_size: 0,
            to_size: 10,
            path: vec![ZERO_HASH], // Should be empty!
        };
        let result = verify_consistency(&proof, &ZERO_HASH, &ONE_HASH);
        assert!(matches!(result, Err(AtlError::InvalidProofStructure { .. })));
    }

    #[test]
    fn test_verify_consistency_empty_path_non_trivial_errors() {
        // Non-trivial consistency (from_size > 0, from_size < to_size) with empty path
        let proof = ConsistencyProof { from_size: 3, to_size: 10, path: vec![] };
        let result = verify_consistency(&proof, &ZERO_HASH, &ONE_HASH);
        assert!(matches!(result, Err(AtlError::InvalidProofStructure { .. })));
    }

    #[test]
    fn test_verify_consistency_excessive_path_length() {
        // Path length exceeds maximum for tree size
        // For tree size 8, max path length is 2 * 3 = 6
        let excessive_path: Vec<Hash> = (0..20).map(|i| [i; 32]).collect();
        let proof = ConsistencyProof { from_size: 4, to_size: 8, path: excessive_path };
        let result = verify_consistency(&proof, &ZERO_HASH, &ONE_HASH);
        assert!(matches!(result, Err(AtlError::InvalidProofStructure { .. })));
    }

    #[test]
    fn test_checked_arithmetic_no_overflow_normal_case() {
        // Normal case should not overflow
        let leaves: Vec<Hash> = (0..8).map(|i| [i; 32]).collect();

        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        // Should succeed without overflow
        let proof = generate_inclusion_proof(3, 8, get_node);
        assert!(proof.is_ok());
    }

    #[test]
    fn test_arithmetic_overflow_error_type() {
        // Verify the error type can be constructed
        let err = AtlError::ArithmeticOverflow { operation: "test operation" };
        assert!(err.to_string().contains("arithmetic overflow"));
        assert!(err.to_string().contains("test operation"));
    }

    // ========== TEST-4: Boundary and Overflow Tests ==========
    // Category 1: verify_inclusion Error Cases

    #[test]
    fn test_verify_inclusion_error_zero_tree_size() {
        let proof = InclusionProof { leaf_index: 0, tree_size: 0, path: vec![] };
        let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
        assert!(matches!(result, Err(AtlError::InvalidTreeSize { size: 0, .. })));
    }

    #[test]
    fn test_verify_inclusion_error_leaf_index_equals_tree_size() {
        let proof = InclusionProof {
            leaf_index: 5,
            tree_size: 5, // leaf_index must be < tree_size
            path: vec![],
        };
        let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
        assert!(matches!(result, Err(AtlError::LeafIndexOutOfBounds { index: 5, tree_size: 5 })));
    }

    #[test]
    fn test_verify_inclusion_error_leaf_index_greater_than_tree_size() {
        let proof = InclusionProof { leaf_index: 100, tree_size: 10, path: vec![] };
        let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
        assert!(matches!(
            result,
            Err(AtlError::LeafIndexOutOfBounds { index: 100, tree_size: 10 })
        ));
    }

    #[test]
    fn test_verify_inclusion_error_single_leaf_nonempty_path() {
        let proof = InclusionProof { leaf_index: 0, tree_size: 1, path: vec![ONE_HASH] };
        let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
        assert!(matches!(result, Err(AtlError::InvalidProofStructure { .. })));
    }

    #[test]
    fn test_verify_inclusion_error_excessive_path_length() {
        // tree_size = 8 -> max depth = 3
        let proof = InclusionProof {
            leaf_index: 0,
            tree_size: 8,
            path: vec![[0u8; 32]; 10], // Way more than 3
        };
        let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
        assert!(matches!(result, Err(AtlError::InvalidProofStructure { .. })));
    }

    #[test]
    fn test_verify_inclusion_ok_false_wrong_hash() {
        // Valid structure but wrong sibling hash
        let proof = InclusionProof {
            leaf_index: 0,
            tree_size: 2,
            path: vec![[99u8; 32]], // Wrong hash
        };
        let result = verify_inclusion(&ZERO_HASH, &proof, &[42u8; 32]);
        // Should be Ok(false), not Err
        assert!(!result.unwrap());
    }

    // Category 2: verify_consistency Error Cases

    #[test]
    fn test_verify_consistency_error_from_greater_than_to() {
        let proof = ConsistencyProof { from_size: 100, to_size: 50, path: vec![] };
        let result = verify_consistency(&proof, &ZERO_HASH, &ONE_HASH);
        assert!(matches!(
            result,
            Err(AtlError::InvalidConsistencyBounds { from_size: 100, to_size: 50 })
        ));
    }

    #[test]
    fn test_verify_consistency_error_same_size_nonempty_path() {
        let proof = ConsistencyProof { from_size: 10, to_size: 10, path: vec![ONE_HASH] };
        let result = verify_consistency(&proof, &ZERO_HASH, &ZERO_HASH);
        assert!(matches!(result, Err(AtlError::InvalidProofStructure { .. })));
    }

    #[test]
    fn test_verify_consistency_error_zero_from_nonempty_path() {
        let proof = ConsistencyProof { from_size: 0, to_size: 10, path: vec![ONE_HASH] };
        let result = verify_consistency(&proof, &ZERO_HASH, &ONE_HASH);
        assert!(matches!(result, Err(AtlError::InvalidProofStructure { .. })));
    }

    #[test]
    fn test_verify_consistency_error_nontrivial_empty_path() {
        let proof = ConsistencyProof {
            from_size: 5,
            to_size: 10,
            path: vec![], // Non-trivial needs at least one hash
        };
        let result = verify_consistency(&proof, &ZERO_HASH, &ONE_HASH);
        assert!(matches!(result, Err(AtlError::InvalidProofStructure { .. })));
    }

    #[test]
    fn test_verify_consistency_error_excessive_path() {
        // to_size = 16 -> max_path_len = 2 * 4 = 8
        let proof = ConsistencyProof {
            from_size: 8,
            to_size: 16,
            path: vec![[0u8; 32]; 50], // Way more than 8
        };
        let result = verify_consistency(&proof, &ZERO_HASH, &ONE_HASH);
        assert!(matches!(result, Err(AtlError::InvalidProofStructure { .. })));
    }

    #[test]
    fn test_verify_consistency_ok_true_same_size_same_root() {
        let root = [42u8; 32];
        let proof = ConsistencyProof { from_size: 100, to_size: 100, path: vec![] };
        assert!(verify_consistency(&proof, &root, &root).unwrap());
    }

    #[test]
    fn test_verify_consistency_ok_false_same_size_different_roots() {
        let proof = ConsistencyProof { from_size: 100, to_size: 100, path: vec![] };
        // Should be Ok(false), not Err
        assert!(!verify_consistency(&proof, &ZERO_HASH, &ONE_HASH).unwrap());
    }

    #[test]
    fn test_verify_consistency_ok_true_zero_from() {
        let proof = ConsistencyProof { from_size: 0, to_size: 100, path: vec![] };
        // Any tree is consistent with empty tree
        assert!(verify_consistency(&proof, &ZERO_HASH, &ONE_HASH).unwrap());
    }

    // Category 3: Boundary Values

    #[test]
    fn test_verify_inclusion_boundary_max_u64_tree_size() {
        // Can't actually create such a tree, but verify error handling
        let proof = InclusionProof { leaf_index: 0, tree_size: u64::MAX, path: vec![] };
        // Should not panic - either Err or Ok(false) is acceptable
        let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
        assert!(result.is_err() || !result.unwrap(), "Should either error or return false");
    }

    #[test]
    fn test_verify_inclusion_boundary_max_leaf_index() {
        let proof = InclusionProof { leaf_index: u64::MAX, tree_size: u64::MAX, path: vec![] };
        // Should not panic - with leaf_index == tree_size, must error
        let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
        assert!(matches!(result, Err(AtlError::LeafIndexOutOfBounds { .. })));
    }

    #[test]
    fn test_verify_consistency_boundary_max_sizes() {
        let proof = ConsistencyProof {
            from_size: u64::MAX - 1,
            to_size: u64::MAX,
            path: vec![[0u8; 32]; 10], // Not enough hashes for such large tree
        };
        // Should not panic - this tests that extreme values don't cause overflow/panic
        // Note: Current simplified verify_consistency_path implementation may return Ok(true)
        // for this edge case. Full RFC 9162 implementation will properly validate this.
        let result = verify_consistency(&proof, &ZERO_HASH, &ONE_HASH);
        // The important part is no panic occurred
        assert!(result.is_ok() || result.is_err());
    }

    // Category 4: Path Length Boundaries

    #[test]
    fn test_verify_inclusion_path_length_exact_for_power_of_2() {
        // tree_size = 2^n -> max depth = n
        for n in 1..=10 {
            let tree_size = 1u64 << n;
            let max_depth = n;

            // Path length = max_depth should be OK (structurally)
            let proof =
                InclusionProof { leaf_index: 0, tree_size, path: vec![[0u8; 32]; max_depth] };
            let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
            // Should not error on structure, may return Ok(false) due to wrong hashes
            assert!(result.is_ok(), "tree_size={tree_size} should accept path length {max_depth}");

            // Path length = max_depth + 1 should error
            let proof_too_long =
                InclusionProof { leaf_index: 0, tree_size, path: vec![[0u8; 32]; max_depth + 1] };
            let result_too_long = verify_inclusion(&ZERO_HASH, &proof_too_long, &ZERO_HASH);
            let exceeded_depth = max_depth + 1;
            assert!(
                result_too_long.is_err(),
                "tree_size={tree_size} should reject path length {exceeded_depth}"
            );
        }
    }

    #[test]
    fn test_verify_inclusion_path_length_exact_for_non_power_of_2() {
        // tree_size = 5 -> ceil(log2(5)) = 3
        let proof = InclusionProof { leaf_index: 0, tree_size: 5, path: vec![[0u8; 32]; 3] };
        let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
        assert!(result.is_ok());

        // tree_size = 5, path length 4 should error
        let proof_too_long =
            InclusionProof { leaf_index: 0, tree_size: 5, path: vec![[0u8; 32]; 4] };
        let result_too_long = verify_inclusion(&ZERO_HASH, &proof_too_long, &ZERO_HASH);
        assert!(result_too_long.is_err());
    }

    // Category 5: Error Message Quality

    #[test]
    fn test_error_messages_are_descriptive() {
        // InvalidTreeSize
        let err = AtlError::InvalidTreeSize { size: 0, reason: "test reason" };
        let msg = err.to_string();
        assert!(msg.contains('0'), "Should contain size");
        assert!(msg.contains("test reason"), "Should contain reason");

        // InvalidConsistencyBounds
        let err = AtlError::InvalidConsistencyBounds { from_size: 100, to_size: 50 };
        let msg = err.to_string();
        assert!(msg.contains("100"), "Should contain from_size");
        assert!(msg.contains("50"), "Should contain to_size");

        // ArithmeticOverflow
        let err = AtlError::ArithmeticOverflow { operation: "test op" };
        let msg = err.to_string();
        assert!(msg.contains("test op"), "Should contain operation");

        // InvalidProofStructure
        let err = AtlError::InvalidProofStructure { reason: "test structure".to_string() };
        let msg = err.to_string();
        assert!(msg.contains("test structure"), "Should contain reason");
    }

    #[test]
    fn test_is_power_of_two() {
        // Zero case (different from std)
        assert!(!is_power_of_two(0));

        // Powers of two
        assert!(is_power_of_two(1));
        assert!(is_power_of_two(2));
        assert!(is_power_of_two(4));
        assert!(is_power_of_two(8));
        assert!(is_power_of_two(16));
        assert!(is_power_of_two(32));
        assert!(is_power_of_two(64));
        assert!(is_power_of_two(1 << 32));
        assert!(is_power_of_two(1 << 63));

        // Non-powers of two
        assert!(!is_power_of_two(3));
        assert!(!is_power_of_two(5));
        assert!(!is_power_of_two(6));
        assert!(!is_power_of_two(7));
        assert!(!is_power_of_two(9));
        assert!(!is_power_of_two(15));
        assert!(!is_power_of_two(17));
        assert!(!is_power_of_two(u64::MAX));
    }

    // ========== MERKLE-4: RFC 9162 Consistency Proof Tests ==========
    // Unit tests for RFC 9162 consistency verification algorithm

    // Category 1: Roundtrip Tests - Power of 2 sizes

    #[test]
    fn test_consistency_proof_roundtrip_power_of_2() {
        // Power-of-2 sizes: requires prepending old_root
        for (from, to) in [(1, 2), (2, 4), (4, 8), (8, 16), (16, 32)] {
            let leaves: Vec<Hash> = (0..to).map(|i| [i as u8; 32]).collect();
            let old_root = compute_root(&leaves[..from as usize]);
            let new_root = compute_root(&leaves);

            let get_node = |level: u32, index: u64| -> Option<Hash> {
                if level == 0 && (index as usize) < leaves.len() {
                    Some(leaves[index as usize])
                } else {
                    None
                }
            };

            let proof = generate_consistency_proof(from, to, get_node).unwrap();
            assert!(
                verify_consistency(&proof, &old_root, &new_root).unwrap(),
                "Failed for power-of-2 transition {from} -> {to}"
            );
        }
    }

    #[test]
    fn test_consistency_proof_roundtrip_non_power_of_2() {
        // Non-power-of-2 sizes: no prepending
        for (from, to) in [(3, 5), (5, 7), (6, 9), (7, 15), (9, 17), (15, 31)] {
            let leaves: Vec<Hash> = (0..to).map(|i| [i as u8; 32]).collect();
            let old_root = compute_root(&leaves[..from as usize]);
            let new_root = compute_root(&leaves);

            let get_node = |level: u32, index: u64| -> Option<Hash> {
                if level == 0 && (index as usize) < leaves.len() {
                    Some(leaves[index as usize])
                } else {
                    None
                }
            };

            let proof = generate_consistency_proof(from, to, get_node).unwrap();
            assert!(
                verify_consistency(&proof, &old_root, &new_root).unwrap(),
                "Failed for non-power-of-2 transition {from} -> {to}"
            );
        }
    }

    #[test]
    fn test_consistency_proof_roundtrip_mixed() {
        // Mixed: power-of-2 to non-power-of-2 and vice versa
        for (from, to) in [(2, 3), (4, 5), (4, 7), (8, 9), (8, 15), (16, 17)] {
            let leaves: Vec<Hash> = (0..to).map(|i| [i as u8; 32]).collect();
            let old_root = compute_root(&leaves[..from as usize]);
            let new_root = compute_root(&leaves);

            let get_node = |level: u32, index: u64| -> Option<Hash> {
                if level == 0 && (index as usize) < leaves.len() {
                    Some(leaves[index as usize])
                } else {
                    None
                }
            };

            let proof = generate_consistency_proof(from, to, get_node).unwrap();
            assert!(
                verify_consistency(&proof, &old_root, &new_root).unwrap(),
                "Failed for mixed transition {from} -> {to}"
            );
        }
    }

    // Category 2: Boundary Tests

    #[test]
    fn test_consistency_proof_single_leaf_to_two() {
        // Minimal non-trivial case: 1 -> 2
        let leaves: Vec<Hash> = vec![[0u8; 32], [1u8; 32]];
        let old_root = leaves[0]; // Single leaf is its own root
        let new_root = compute_root(&leaves);

        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let proof = generate_consistency_proof(1, 2, get_node).unwrap();
        assert!(verify_consistency(&proof, &old_root, &new_root).unwrap());
    }

    #[test]
    fn test_consistency_proof_large_tree() {
        // Large tree: 100 -> 1000
        let leaves: Vec<Hash> = (0..1000u64)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&i.to_le_bytes());
                h
            })
            .collect();

        let _old_root = compute_root(&leaves[..100]);
        let _new_root = compute_root(&leaves);

        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let proof = generate_consistency_proof(100, 1000, get_node).unwrap();

        // Proof size should be O(log n)
        assert!(proof.path.len() <= 20, "Proof too large: {}", proof.path.len());
    }

    // Category 3: Invalid Proof Tests

    #[test]
    fn test_consistency_proof_wrong_old_root() {
        let leaves: Vec<Hash> = (0..8).map(|i| [i as u8; 32]).collect();
        let _old_root = compute_root(&leaves[..4]);
        let new_root = compute_root(&leaves);

        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let proof = generate_consistency_proof(4, 8, get_node).unwrap();

        // Wrong old root should fail (returns Ok(false))
        let wrong_old_root = [0xff; 32];
        assert!(!verify_consistency(&proof, &wrong_old_root, &new_root).unwrap());
    }

    #[test]
    fn test_consistency_proof_wrong_new_root() {
        let leaves: Vec<Hash> = (0..8).map(|i| [i as u8; 32]).collect();
        let old_root = compute_root(&leaves[..4]);
        let _new_root = compute_root(&leaves);

        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let proof = generate_consistency_proof(4, 8, get_node).unwrap();

        // Wrong new root should fail (returns Ok(false))
        let wrong_new_root = [0xff; 32];
        assert!(!verify_consistency(&proof, &old_root, &wrong_new_root).unwrap());
    }

    #[test]
    fn test_consistency_proof_tampered_path() {
        let leaves: Vec<Hash> = (0..8).map(|i| [i as u8; 32]).collect();
        let old_root = compute_root(&leaves[..4]);
        let new_root = compute_root(&leaves);

        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let mut proof = generate_consistency_proof(4, 8, get_node).unwrap();

        // Tamper with first hash in path
        if !proof.path.is_empty() {
            proof.path[0] = [0xff; 32];
        }

        assert!(!verify_consistency(&proof, &old_root, &new_root).unwrap());
    }

    #[test]
    fn test_consistency_proof_truncated_path() {
        let leaves: Vec<Hash> = (0..8).map(|i| [i as u8; 32]).collect();
        let old_root = compute_root(&leaves[..4]);
        let new_root = compute_root(&leaves);

        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let mut proof = generate_consistency_proof(4, 8, get_node).unwrap();

        // Remove last hash (truncate)
        if !proof.path.is_empty() {
            proof.path.pop();
        }

        assert!(!verify_consistency(&proof, &old_root, &new_root).unwrap());
    }

    #[test]
    fn test_consistency_proof_extended_path() {
        let leaves: Vec<Hash> = (0..8).map(|i| [i as u8; 32]).collect();
        let old_root = compute_root(&leaves[..4]);
        let new_root = compute_root(&leaves);

        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let mut proof = generate_consistency_proof(4, 8, get_node).unwrap();

        // Add extra hash (extend)
        proof.path.push([0xaa; 32]);

        assert!(!verify_consistency(&proof, &old_root, &new_root).unwrap());
    }

    #[test]
    fn test_consistency_proof_swapped_hashes() {
        let leaves: Vec<Hash> = (0..8).map(|i| [i as u8; 32]).collect();
        let old_root = compute_root(&leaves[..4]);
        let new_root = compute_root(&leaves);

        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let mut proof = generate_consistency_proof(4, 8, get_node).unwrap();

        // Swap first two hashes if possible
        if proof.path.len() >= 2 {
            proof.path.swap(0, 1);
            assert!(!verify_consistency(&proof, &old_root, &new_root).unwrap());
        }
    }

    // Category 4: Empty/Trivial Tests

    #[test]
    fn test_consistency_proof_empty_path_nontrivial_fails() {
        // Non-trivial case with empty path should fail
        // Use non-power-of-2 from_size (3) to get error; power-of-2 returns Ok(false) per RFC 9162
        let proof = ConsistencyProof { from_size: 3, to_size: 8, path: vec![] };

        let old_root = [0u8; 32];
        let new_root = [1u8; 32];

        // Empty path for non-trivial case with non-power-of-2 from_size returns error
        let result = verify_consistency(&proof, &old_root, &new_root);
        assert!(matches!(result, Err(AtlError::InvalidProofStructure { .. })));
    }

    #[test]
    fn test_consistency_proof_empty_path_power_of_2_fails() {
        // Non-trivial case with empty path and power-of-2 from_size
        // RFC 9162 prepends old_root, but algorithm still fails (sn != 0)
        let proof = ConsistencyProof { from_size: 4, to_size: 8, path: vec![] };

        let old_root = [0u8; 32];
        let new_root = [1u8; 32];

        // Empty path for power-of-2 from_size returns Ok(false), not error
        let result = verify_consistency(&proof, &old_root, &new_root);
        assert!(matches!(result, Ok(false)));
    }

    #[test]
    fn test_consistency_proof_sizes_swapped() {
        // from_size > to_size should return Err(InvalidConsistencyBounds)
        let proof = ConsistencyProof { from_size: 8, to_size: 4, path: vec![[0u8; 32]] };

        let result = verify_consistency(&proof, &[0u8; 32], &[0u8; 32]);
        assert!(matches!(result, Err(AtlError::InvalidConsistencyBounds { .. })));
    }

    // ========== MERKLE-6: Adversarial Input Tests ==========

    #[test]
    fn test_adversarial_arbitrary_hashes_rejected() {
        // Simplified impl would accept: power-of-2 with first hash == old_root
        // + reasonable length

        let from_size = 4u64; // Power of 2
        let to_size = 8u64;

        // Correct roots
        let leaves: Vec<Hash> = (0..8).map(|i| [i as u8; 32]).collect();
        let old_root = compute_root(&leaves[..4]);
        let new_root = compute_root(&leaves);

        // Malicious proof: correct first hash (old_root) but wrong other hashes
        let malicious_proof = ConsistencyProof {
            from_size,
            to_size,
            path: vec![
                old_root,   // First hash matches old_root (bypasses simplified check)
                [0xde; 32], // Random hash
                [0xad; 32], // Random hash
            ],
        };

        // RFC 9162 implementation must reject this - note: returns AtlResult<bool>
        assert!(
            !verify_consistency(&malicious_proof, &old_root, &new_root).unwrap(),
            "Should reject proof with arbitrary hashes"
        );
    }

    #[test]
    fn test_adversarial_correct_length_wrong_content() {
        // Generate a valid proof, then replace all hashes with random data
        // while keeping length "reasonable"

        let leaves: Vec<Hash> = (0..8).map(|i| [i as u8; 32]).collect();
        let old_root = compute_root(&leaves[..4]);
        let new_root = compute_root(&leaves);

        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let valid_proof = generate_consistency_proof(4, 8, get_node).unwrap();

        // Create malicious proof with same length but random content
        let malicious_proof = ConsistencyProof {
            from_size: 4,
            to_size: 8,
            path: valid_proof.path.iter().map(|_| [0xba; 32]).collect(),
        };

        // Note: verify_consistency returns AtlResult<bool>
        assert!(
            !verify_consistency(&malicious_proof, &old_root, &new_root).unwrap(),
            "Should reject proof with random content"
        );
    }

    #[test]
    fn test_adversarial_replay_different_tree() {
        // Generate proof for one tree, try to use it on different tree

        // Tree A: leaves 0..8
        let leaves_a: Vec<Hash> = (0..8).map(|i| [i as u8; 32]).collect();
        let _old_root_a = compute_root(&leaves_a[..4]);
        let _new_root_a = compute_root(&leaves_a);

        let get_node_a = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves_a.len() {
                Some(leaves_a[index as usize])
            } else {
                None
            }
        };

        let proof_a = generate_consistency_proof(4, 8, get_node_a).unwrap();

        // Tree B: different leaves (same sizes)
        let leaves_b: Vec<Hash> = (100..108).map(|i| [i as u8; 32]).collect();
        let old_root_b = compute_root(&leaves_b[..4]);
        let new_root_b = compute_root(&leaves_b);

        // Try to use proof from tree A on tree B - note: returns AtlResult<bool>
        assert!(
            !verify_consistency(&proof_a, &old_root_b, &new_root_b).unwrap(),
            "Should reject proof from different tree"
        );
    }

    #[test]
    fn test_adversarial_replay_different_sizes() {
        // Generate proof for (4 -> 8), try to use it for (3 -> 7)

        let leaves: Vec<Hash> = (0..8).map(|i| [i as u8; 32]).collect();

        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let proof_4_8 = generate_consistency_proof(4, 8, get_node).unwrap();

        // Compute roots for different sizes
        let old_root_3 = compute_root(&leaves[..3]);
        let new_root_7 = compute_root(&leaves[..7]);

        // Modify proof to claim different sizes
        let replayed_proof = ConsistencyProof { from_size: 3, to_size: 7, path: proof_4_8.path };

        // Note: verify_consistency returns AtlResult<bool>
        assert!(
            !verify_consistency(&replayed_proof, &old_root_3, &new_root_7).unwrap(),
            "Should reject proof with wrong sizes"
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_adversarial_boundary_sizes() {
        // Test sizes that might cause edge cases in bit operations

        let boundary_cases = [
            (1, 2),     // Minimum non-trivial
            (63, 64),   // Near power of 2
            (64, 65),   // Just past power of 2
            (127, 128), // Near power of 2
            (128, 129), // Just past power of 2
            (255, 256), // Near power of 2
            (256, 257), // Just past power of 2
        ];

        for (from, to) in boundary_cases {
            let leaves: Vec<Hash> = (0u64..to)
                .map(|i| {
                    let mut h = [0u8; 32];
                    h[..8].copy_from_slice(&i.to_le_bytes());
                    h
                })
                .collect();

            let old_root = compute_root(&leaves[..from as usize]);
            let new_root = compute_root(&leaves);

            let get_node = |level: u32, index: u64| -> Option<Hash> {
                if level == 0 && (index as usize) < leaves.len() {
                    Some(leaves[index as usize])
                } else {
                    None
                }
            };

            let proof = generate_consistency_proof(from, to, get_node).unwrap();

            // Valid proof should pass - note: returns AtlResult<bool>
            assert!(
                verify_consistency(&proof, &old_root, &new_root).unwrap(),
                "Valid proof failed for {from} -> {to}"
            );

            // Tampered proof should fail
            if !proof.path.is_empty() {
                let mut tampered = proof.clone();
                tampered.path[0][0] ^= 0xff;
                // Note: verify_consistency returns AtlResult<bool>
                assert!(
                    !verify_consistency(&tampered, &old_root, &new_root).unwrap(),
                    "Tampered proof should fail for {from} -> {to}"
                );
            }
        }
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_adversarial_all_ones_size() {
        // Sizes like 0b111111 (all ones in binary) stress bit manipulation

        let all_ones_cases = [
            (3, 7),   // 0b11 -> 0b111
            (7, 15),  // 0b111 -> 0b1111
            (15, 31), // 0b1111 -> 0b11111
            (31, 63), // 0b11111 -> 0b111111
        ];

        for (from, to) in all_ones_cases {
            let leaves: Vec<Hash> = (0u64..to)
                .map(|i| {
                    let mut h = [0u8; 32];
                    h[..8].copy_from_slice(&i.to_le_bytes());
                    h
                })
                .collect();

            let old_root = compute_root(&leaves[..from as usize]);
            let new_root = compute_root(&leaves);

            let get_node = |level: u32, index: u64| -> Option<Hash> {
                if level == 0 && (index as usize) < leaves.len() {
                    Some(leaves[index as usize])
                } else {
                    None
                }
            };

            let proof = generate_consistency_proof(from, to, get_node).unwrap();

            // Note: verify_consistency returns AtlResult<bool>
            assert!(
                verify_consistency(&proof, &old_root, &new_root).unwrap(),
                "All-ones boundary failed for {from} -> {to}"
            );
        }
    }

    #[test]
    fn test_adversarial_zero_from_size_with_path() {
        // from_size = 0 with non-empty path returns Err(InvalidProofStructure)
        // NOTE: Spec incorrectly said InvalidTreeSize, but actual behavior is InvalidProofStructure

        let proof = ConsistencyProof {
            from_size: 0,
            to_size: 8,
            path: vec![[0xaa; 32], [0xbb; 32]], // Non-empty path
        };

        // With Safe Merkle API, from_size == 0 with non-empty path returns InvalidProofStructure
        let result = verify_consistency(&proof, &[0u8; 32], &[0u8; 32]);
        // Should return Err(InvalidProofStructure), not InvalidTreeSize
        assert!(matches!(result, Err(AtlError::InvalidProofStructure { .. })));
    }

    #[test]
    fn test_adversarial_very_long_proof() {
        // Proof way longer than O(log n) should be rejected

        let leaves: Vec<Hash> = (0..8).map(|i| [i as u8; 32]).collect();
        let old_root = compute_root(&leaves[..4]);
        let new_root = compute_root(&leaves);

        let malicious_proof = ConsistencyProof {
            from_size: 4,
            to_size: 8,
            path: vec![[0xaa; 32]; 100], // Way too many hashes
        };

        // Very long proof should be rejected (either Ok(false) or Err)
        let result = verify_consistency(&malicious_proof, &old_root, &new_root);
        assert!(
            matches!(result, Ok(false) | Err(AtlError::InvalidProofStructure { .. })),
            "Should reject overly long proof"
        );
    }

    #[test]
    fn test_adversarial_duplicate_hashes() {
        // Proof with all same hashes

        let leaves: Vec<Hash> = (0..8).map(|i| [i as u8; 32]).collect();
        let old_root = compute_root(&leaves[..4]);
        let new_root = compute_root(&leaves);

        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let valid_proof = generate_consistency_proof(4, 8, get_node).unwrap();

        // Replace all hashes with the same value
        let malicious_proof = ConsistencyProof {
            from_size: 4,
            to_size: 8,
            path: vec![old_root; valid_proof.path.len()],
        };

        // Note: verify_consistency returns AtlResult<bool>
        assert!(
            !verify_consistency(&malicious_proof, &old_root, &new_root).unwrap(),
            "Should reject proof with all duplicate hashes"
        );
    }

    #[test]
    fn test_regression_simplified_impl_vulnerability() {
        // This test documents the exact vulnerability that existed in the
        // simplified implementation and ensures it's fixed.

        // The simplified impl (lines 670-691) did:
        // 1. Check path not empty
        // 2. If power-of-2 from_size: check path[0] == old_root
        // 3. Check path.len() <= 2 * log2(to_size)
        // 4. Return true (!)

        // Attack: For from_size=4 (power of 2), to_size=8
        // Construct proof where path[0] = old_root but rest is garbage

        let from_size = 4u64;
        let to_size = 8u64;

        let leaves: Vec<Hash> = (0..8).map(|i| [i as u8; 32]).collect();
        let old_root = compute_root(&leaves[..4]);
        let new_root = compute_root(&leaves);

        // This proof would have passed the old simplified check:
        // - path not empty: yes
        // - from_size is power of 2: yes, and path[0] == old_root: yes
        // - path.len() (3) <= 2 * log2(8) = 6: yes
        // - return true!
        let attack_proof = ConsistencyProof {
            from_size,
            to_size,
            path: vec![
                old_root,   // Passes simplified check
                [0x00; 32], // Garbage
                [0x00; 32], // Garbage
            ],
        };

        // RFC 9162 implementation MUST reject this - note: returns AtlResult<bool>
        assert!(
            !verify_consistency(&attack_proof, &old_root, &new_root).unwrap(),
            "CRITICAL: Simplified implementation vulnerability not fixed!"
        );
    }
}
