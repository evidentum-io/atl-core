//! Conformance tests against frozen, externally-sourced test vectors.
//!
//! Every expected value used here is read from `test_data/vectors/`. None of it is
//! computed by `atl-core`: the Merkle values come from the Certificate Transparency
//! reference vector set and from the RFC 6962 Section 2.1 / 2.1.1 / 2.1.2 algorithm
//! text re-derived by an independent implementation, the JCS values come from
//! RFC 8785 Section 3.2.2, Section 3.2.3 and Appendix B, and the ATL-specific values
//! are hand-derived from the clauses of `atl-protocol-ietf.md` named in the vector
//! files. A test that derived its own expectation from the code under test would
//! confirm that code's bugs forever, so this file never does that: it only reads
//! frozen bytes and compares.
//!
//! Provenance and derivation for each value live in the vector files themselves, so
//! a third-party implementer can check their own code against them without running
//! or trusting `atl-core`.

use atl_core::core::jcs::{canonicalize, canonicalize_and_hash};
use atl_core::core::merkle::{
    compute_genesis_leaf_hash, compute_leaf_hash, compute_root, generate_consistency_proof,
    generate_inclusion_proof, verify_consistency, verify_inclusion, ConsistencyProof, Hash,
    InclusionProof,
};
use atl_core::core::receipt::SuperProof;
use atl_core::core::verify::super_tree::{verify_consistency_to_origin, verify_super_inclusion};
use serde_json::Value;
use sha2::{Digest, Sha256};

const MERKLE_VECTORS: &str = include_str!("../test_data/vectors/merkle/trees.json");
const LEAF_VECTORS: &str = include_str!("../test_data/vectors/atl/leaf_composition.json");
const SUPER_VECTORS: &str = include_str!("../test_data/vectors/atl/super_tree.json");
const JCS_VECTORS: &str = include_str!("../test_data/vectors/jcs/cases.json");

/// Deliberately not under `test_data/vectors/`: see the banner in the file itself.
const GENESIS_PIN: &str = include_str!("../test_data/implementation_only/genesis_chain_leaf.json");

// ---------------------------------------------------------------------------
// Vector-file access helpers
//
// These deliberately panic with a descriptive message on malformed input: a
// broken vector file is a broken test, not a runtime condition to handle.
// ---------------------------------------------------------------------------

fn load(src: &str, what: &str) -> Value {
    serde_json::from_str(src).unwrap_or_else(|e| panic!("{what} vectors are not valid JSON: {e}"))
}

fn hash_from_hex(s: &str, what: &str) -> Hash {
    let bytes = hex::decode(s).unwrap_or_else(|e| panic!("{what}: {s:?} is not valid hex: {e}"));
    <Hash>::try_from(bytes.as_slice()).unwrap_or_else(|_| panic!("{what}: {s:?} is not 32 bytes"))
}

fn field<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).unwrap_or_else(|| panic!("vector entry is missing field {key:?}: {v}"))
}

fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    field(v, key).as_str().unwrap_or_else(|| panic!("field {key:?} is not a string: {v}"))
}

fn u64_field(v: &Value, key: &str) -> u64 {
    field(v, key).as_u64().unwrap_or_else(|| panic!("field {key:?} is not a u64: {v}"))
}

fn array_field<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    field(v, key).as_array().unwrap_or_else(|| panic!("field {key:?} is not an array: {v}"))
}

fn hash_list(v: &Value, key: &str, what: &str) -> Vec<Hash> {
    array_field(v, key)
        .iter()
        .map(|h| {
            hash_from_hex(
                h.as_str().unwrap_or_else(|| panic!("{what}: path element is not a string")),
                what,
            )
        })
        .collect()
}

/// Leaf hashes of the eight Certificate Transparency reference records, in order.
fn ct_leaf_hashes() -> Vec<Hash> {
    let doc = load(MERKLE_VECTORS, "merkle");
    array_field(&doc, "records")
        .iter()
        .map(|r| hash_from_hex(str_field(r, "leaf_hash"), "record leaf_hash"))
        .collect()
}

/// Storage callback over a fixed leaf-hash slice, exposing level 0 only.
///
/// Returning `None` above level 0 forces the proof generators down their
/// recursive path instead of the stored-intermediate-node shortcut, so both
/// code paths are exercised against the frozen vectors.
fn leaf_only_storage(leaves: &[Hash]) -> impl Fn(u32, u64) -> Option<Hash> + '_ {
    move |level, index| {
        if level == 0 {
            usize::try_from(index).ok().and_then(|i| leaves.get(i)).copied()
        } else {
            None
        }
    }
}

fn flip_first_byte(mut h: Hash) -> Hash {
    h[0] ^= 0x01;
    h
}

// ---------------------------------------------------------------------------
// RFC 6962 Merkle tree geometry
// ---------------------------------------------------------------------------

#[test]
fn rfc6962_record_leaf_hashes_match_frozen_values() {
    let doc = load(MERKLE_VECTORS, "merkle");
    for record in array_field(&doc, "records") {
        let data = hex::decode(str_field(record, "data_hex")).expect("record data_hex is hex");
        let mut hasher = Sha256::new();
        hasher.update([0x00]);
        hasher.update(&data);
        let computed: Hash = hasher.finalize().into();
        assert_eq!(
            hex::encode(computed),
            str_field(record, "leaf_hash"),
            "SHA256(0x00 || d) for record {} does not match the frozen leaf hash",
            u64_field(record, "index")
        );
    }
}

#[test]
fn rfc6962_roots_match_frozen_values() {
    let doc = load(MERKLE_VECTORS, "merkle");
    let leaves = ct_leaf_hashes();

    for entry in array_field(&doc, "roots") {
        let size = usize::try_from(u64_field(entry, "tree_size")).expect("tree_size fits usize");
        let expected = str_field(entry, "root");
        let actual = hex::encode(compute_root(&leaves[..size]));
        assert_eq!(
            actual,
            expected,
            "root for tree_size {size} diverges from the frozen vector ({})",
            str_field(entry, "origin")
        );
    }
}

#[test]
fn rfc6962_inclusion_proofs_are_generated_as_frozen() {
    let doc = load(MERKLE_VECTORS, "merkle");
    let leaves = ct_leaf_hashes();

    for entry in array_field(&doc, "inclusion_proofs") {
        let tree_size = u64_field(entry, "tree_size");
        let leaf_index = u64_field(entry, "leaf_index");
        let size = usize::try_from(tree_size).expect("tree_size fits usize");
        let expected = hash_list(entry, "path", "inclusion path");

        let proof =
            generate_inclusion_proof(leaf_index, tree_size, leaf_only_storage(&leaves[..size]))
                .expect("proof generation succeeds for an in-range leaf");

        assert_eq!(
            proof.path, expected,
            "generated inclusion path for leaf {leaf_index} of tree size {tree_size} \
             diverges from the frozen vector"
        );
    }
}

#[test]
fn rfc6962_inclusion_proofs_verify_against_frozen_roots() {
    let doc = load(MERKLE_VECTORS, "merkle");

    for entry in array_field(&doc, "inclusion_proofs") {
        let proof = InclusionProof {
            leaf_index: u64_field(entry, "leaf_index"),
            tree_size: u64_field(entry, "tree_size"),
            path: hash_list(entry, "path", "inclusion path"),
        };
        let leaf = hash_from_hex(str_field(entry, "leaf_hash"), "inclusion leaf_hash");
        let root = hash_from_hex(str_field(entry, "root"), "inclusion root");

        assert!(
            verify_inclusion(&leaf, &proof, &root).expect("frozen proof is structurally valid"),
            "frozen inclusion proof for leaf {} of tree size {} failed verification",
            proof.leaf_index,
            proof.tree_size
        );
    }
}

#[test]
fn rfc6962_inclusion_proofs_reject_tampering() {
    let doc = load(MERKLE_VECTORS, "merkle");

    for entry in array_field(&doc, "inclusion_proofs") {
        let leaf_index = u64_field(entry, "leaf_index");
        let tree_size = u64_field(entry, "tree_size");
        let path = hash_list(entry, "path", "inclusion path");
        let leaf = hash_from_hex(str_field(entry, "leaf_hash"), "inclusion leaf_hash");
        let root = hash_from_hex(str_field(entry, "root"), "inclusion root");
        let proof = InclusionProof { leaf_index, tree_size, path: path.clone() };

        assert!(
            !verify_inclusion(&flip_first_byte(leaf), &proof, &root).expect("structure unchanged"),
            "a modified leaf still verified for leaf {leaf_index} of tree size {tree_size}"
        );
        assert!(
            !verify_inclusion(&leaf, &proof, &flip_first_byte(root)).expect("structure unchanged"),
            "a modified root still verified for leaf {leaf_index} of tree size {tree_size}"
        );

        if !path.is_empty() {
            let mut tampered = path;
            tampered[0] = flip_first_byte(tampered[0]);
            let proof = InclusionProof { leaf_index, tree_size, path: tampered };
            assert!(
                !verify_inclusion(&leaf, &proof, &root).expect("structure unchanged"),
                "a modified path still verified for leaf {leaf_index} of tree size {tree_size}"
            );
        }
    }
}

#[test]
fn rfc6962_consistency_proofs_are_generated_as_frozen() {
    let doc = load(MERKLE_VECTORS, "merkle");
    let leaves = ct_leaf_hashes();

    for entry in array_field(&doc, "consistency_proofs") {
        let from_size = u64_field(entry, "from_size");
        let to_size = u64_field(entry, "to_size");
        let size = usize::try_from(to_size).expect("to_size fits usize");
        let expected = hash_list(entry, "path", "consistency path");

        let proof =
            generate_consistency_proof(from_size, to_size, leaf_only_storage(&leaves[..size]))
                .expect("proof generation succeeds for valid bounds");

        assert_eq!(
            proof.path, expected,
            "generated consistency path from {from_size} to {to_size} diverges from the \
             frozen vector"
        );
    }
}

#[test]
fn rfc6962_consistency_proofs_verify_against_frozen_roots() {
    let doc = load(MERKLE_VECTORS, "merkle");

    for entry in array_field(&doc, "consistency_proofs") {
        let proof = ConsistencyProof {
            from_size: u64_field(entry, "from_size"),
            to_size: u64_field(entry, "to_size"),
            path: hash_list(entry, "path", "consistency path"),
        };
        let from_root = hash_from_hex(str_field(entry, "from_root"), "consistency from_root");
        let to_root = hash_from_hex(str_field(entry, "to_root"), "consistency to_root");

        assert!(
            verify_consistency(&proof, &from_root, &to_root)
                .expect("frozen proof is structurally valid"),
            "frozen consistency proof from {} to {} failed verification",
            proof.from_size,
            proof.to_size
        );
    }
}

#[test]
fn rfc6962_consistency_proofs_reject_tampering() {
    let doc = load(MERKLE_VECTORS, "merkle");

    for entry in array_field(&doc, "consistency_proofs") {
        let from_size = u64_field(entry, "from_size");
        let to_size = u64_field(entry, "to_size");
        let path = hash_list(entry, "path", "consistency path");
        let from_root = hash_from_hex(str_field(entry, "from_root"), "consistency from_root");
        let to_root = hash_from_hex(str_field(entry, "to_root"), "consistency to_root");
        let proof = ConsistencyProof { from_size, to_size, path: path.clone() };

        assert!(
            !verify_consistency(&proof, &flip_first_byte(from_root), &to_root)
                .expect("structure unchanged"),
            "a modified old root still verified for {from_size} -> {to_size}"
        );
        assert!(
            !verify_consistency(&proof, &from_root, &flip_first_byte(to_root))
                .expect("structure unchanged"),
            "a modified new root still verified for {from_size} -> {to_size}"
        );

        if !path.is_empty() {
            let mut tampered = path;
            tampered[0] = flip_first_byte(tampered[0]);
            let proof = ConsistencyProof { from_size, to_size, path: tampered };
            assert!(
                !verify_consistency(&proof, &from_root, &to_root).expect("structure unchanged"),
                "a modified path still verified for {from_size} -> {to_size}"
            );
        }
    }
}

/// RFC 6962 Section 2.1.3 states its 7-leaf worked example symbolically, using the
/// node labels of the diagram. Those statements are the only proof structure the RFC
/// document itself pins down, so they are asserted here literally.
#[test]
fn rfc6962_section_2_1_3_symbolic_example() {
    let doc = load(MERKLE_VECTORS, "merkle");
    let nodes = field(&doc, "rfc6962_section_2_1_3").get("nodes").expect("nodes present");
    let label = |name: &str| -> Hash {
        let node = nodes.get(name).unwrap_or_else(|| panic!("node {name} is missing"));
        hash_from_hex(str_field(node, "hash"), "labelled node")
    };

    let leaves = ct_leaf_hashes();
    let seven = &leaves[..7];

    // "The audit path for d0 is [b, h, l]." and the three sibling statements.
    for (index, expected) in [
        (0u64, vec!["b", "h", "l"]),
        (3, vec!["c", "g", "l"]),
        (4, vec!["f", "j", "k"]),
        (6, vec!["i", "k"]),
    ] {
        let proof = generate_inclusion_proof(index, 7, leaf_only_storage(seven))
            .expect("in-range leaf of the 7-leaf tree");
        let expected: Vec<Hash> = expected.iter().map(|n| label(n)).collect();
        assert_eq!(
            proof.path, expected,
            "audit path for d{index} does not match the RFC 6962 Section 2.1.3 statement"
        );
    }

    // "PROOF(3, D[7]) = [c, d, g, l]", "PROOF(4, D[7]) = [l]", "PROOF(6, D[7]) = [i, j, k]".
    for (from_size, expected) in
        [(3u64, vec!["c", "d", "g", "l"]), (4, vec!["l"]), (6, vec!["i", "j", "k"])]
    {
        let proof = generate_consistency_proof(from_size, 7, leaf_only_storage(seven))
            .expect("valid consistency bounds");
        let expected: Vec<Hash> = expected.iter().map(|n| label(n)).collect();
        assert_eq!(
            proof.path, expected,
            "PROOF({from_size}, D[7]) does not match the RFC 6962 Section 2.1.3 statement"
        );
    }

    // The diagram's internal nodes must be exactly the subtree roots it claims.
    assert_eq!(compute_root(&leaves[0..2]), label("g"), "node g is MTH(D[0:2])");
    assert_eq!(compute_root(&leaves[2..4]), label("h"), "node h is MTH(D[2:4])");
    assert_eq!(compute_root(&leaves[4..6]), label("i"), "node i is MTH(D[4:6])");
    assert_eq!(compute_root(&leaves[6..7]), label("j"), "node j is MTH(D[6:7])");
    assert_eq!(compute_root(&leaves[0..4]), label("k"), "node k is MTH(D[0:4])");
    assert_eq!(compute_root(&leaves[4..7]), label("l"), "node l is MTH(D[4:7])");
    assert_eq!(compute_root(seven), label("hash"), "the root is MTH(D[0:7])");
}

// ---------------------------------------------------------------------------
// ATL leaf construction
// ---------------------------------------------------------------------------

#[test]
fn atl_leaf_composition_matches_frozen_values() {
    let doc = load(LEAF_VECTORS, "ATL leaf");

    for case in array_field(&doc, "cases") {
        let name = str_field(case, "name");

        if let Some(payload) = case.get("payload_utf8").and_then(Value::as_str) {
            let digest: Hash = Sha256::digest(payload.as_bytes()).into();
            assert_eq!(
                hex::encode(digest),
                str_field(case, "payload_hash"),
                "{name}: SHA256 of the payload does not match the frozen payload_hash"
            );
        }

        if let Some(metadata) = case.get("metadata") {
            assert_eq!(
                canonicalize(metadata),
                str_field(case, "metadata_canonical_jcs"),
                "{name}: JCS canonical form diverges from the frozen vector"
            );
            assert_eq!(
                hex::encode(canonicalize_and_hash(metadata)),
                str_field(case, "metadata_hash"),
                "{name}: metadata_hash diverges from the frozen vector"
            );
        }

        let payload_hash = hash_from_hex(str_field(case, "payload_hash"), "payload_hash");
        let metadata_hash = hash_from_hex(str_field(case, "metadata_hash"), "metadata_hash");
        assert_eq!(
            hex::encode(compute_leaf_hash(&payload_hash, &metadata_hash)),
            str_field(case, "leaf_hash"),
            "{name}: leaf_hash diverges from the frozen vector"
        );
    }
}

/// The leaf formula binds `payload_hash` and `metadata_hash` in a fixed order, so
/// swapping them must change the leaf. Without this the asymmetric boundary vector
/// would not actually pin the argument order down.
#[test]
fn atl_leaf_composition_is_order_sensitive() {
    let doc = load(LEAF_VECTORS, "ATL leaf");
    let case = array_field(&doc, "cases")
        .iter()
        .find(|c| str_field(c, "name") == "boundary_asymmetric")
        .expect("boundary_asymmetric vector is present");

    let payload_hash = hash_from_hex(str_field(case, "payload_hash"), "payload_hash");
    let metadata_hash = hash_from_hex(str_field(case, "metadata_hash"), "metadata_hash");

    assert_ne!(
        compute_leaf_hash(&payload_hash, &metadata_hash),
        compute_leaf_hash(&metadata_hash, &payload_hash),
        "leaf hash is insensitive to the order of payload_hash and metadata_hash"
    );
}

/// Regression pin, **not** a conformance check.
///
/// `compute_genesis_leaf_hash` and its `"ATL-CHAIN-v1"` domain have no first source:
/// the construction appears nowhere in the protocol specification. An independent
/// SHA-256 confirms the arithmetic of these values, but nothing confirms that the
/// construction is the contract, so they cannot ground a claim of external
/// conformance and are kept outside `test_data/vectors/` for that reason. What this
/// test buys is only that the public function does not change by accident.
#[test]
fn implementation_only_genesis_chain_leaf_arithmetic_is_pinned() {
    let doc = load(GENESIS_PIN, "genesis chain leaf pin");

    for case in array_field(&doc, "cases") {
        let prev_root = hash_from_hex(str_field(case, "prev_root_hash"), "prev_root_hash");
        let prev_size = u64_field(case, "prev_tree_size");
        assert_eq!(
            hex::encode(compute_genesis_leaf_hash(&prev_root, prev_size)),
            str_field(case, "genesis_leaf_hash"),
            "genesis chain leaf for prev_tree_size {prev_size} changed; this is a pin on \
             atl-core's own arithmetic, so a mismatch means the function changed, not that \
             some specification was violated"
        );
    }
}

// ---------------------------------------------------------------------------
// ATL Super-Tree
// ---------------------------------------------------------------------------

fn super_proof_from(entry: &Value) -> SuperProof {
    let hashes = |key: &str| -> Vec<String> {
        array_field(entry, key)
            .iter()
            .map(|h| format!("sha256:{}", h.as_str().expect("path element is a string")))
            .collect()
    };
    SuperProof {
        genesis_super_root: format!("sha256:{}", str_field(entry, "genesis_super_root")),
        data_tree_index: u64_field(entry, "data_tree_index"),
        super_tree_size: u64_field(entry, "super_tree_size"),
        super_root: format!("sha256:{}", str_field(entry, "super_root")),
        inclusion: hashes("inclusion"),
        consistency_to_origin: hashes("consistency_to_origin"),
    }
}

#[test]
fn atl_super_tree_roots_match_frozen_values() {
    let doc = load(SUPER_VECTORS, "Super-Tree");
    let leaves: Vec<Hash> = array_field(&doc, "super_leaves")
        .iter()
        .map(|l| hash_from_hex(str_field(l, "data_tree_root"), "data_tree_root"))
        .collect();

    for entry in array_field(&doc, "super_roots") {
        let size = usize::try_from(u64_field(entry, "super_tree_size")).expect("fits usize");
        assert_eq!(
            hex::encode(compute_root(&leaves[..size])),
            str_field(entry, "super_root"),
            "Super Root for super_tree_size {size} diverges from the frozen vector"
        );
    }

    // "genesis_super_root: The root hash of Super-Tree at size 1 (first Data Tree's
    // root)" -- a Data Tree root is used directly as a Super-Tree leaf hash, never
    // re-hashed as SHA256(0x00 || root_hash).
    assert_eq!(
        hex::encode(leaves[0]),
        str_field(&doc, "genesis_super_root"),
        "genesis_super_root is not the first Data Tree root"
    );
    assert_eq!(
        hex::encode(compute_root(&leaves[..1])),
        str_field(&doc, "genesis_super_root"),
        "the size-1 Super Root is not the first Data Tree root"
    );
}

#[test]
fn atl_super_tree_proofs_verify_against_frozen_values() {
    let doc = load(SUPER_VECTORS, "Super-Tree");

    for entry in array_field(&doc, "super_proofs") {
        let proof = super_proof_from(entry);
        let data_tree_root = hash_from_hex(str_field(entry, "data_tree_root"), "data_tree_root");

        assert!(
            verify_super_inclusion(&data_tree_root, &proof)
                .expect("frozen super proof is structurally valid"),
            "frozen Super-Tree inclusion failed for index {} of super_tree_size {}",
            proof.data_tree_index,
            proof.super_tree_size
        );
        assert!(
            verify_consistency_to_origin(&proof)
                .expect("frozen consistency_to_origin is structurally valid"),
            "frozen consistency_to_origin failed for super_tree_size {}",
            proof.super_tree_size
        );
    }
}

#[test]
fn atl_super_tree_proofs_reject_tampering() {
    let doc = load(SUPER_VECTORS, "Super-Tree");

    for entry in array_field(&doc, "super_proofs") {
        let proof = super_proof_from(entry);
        let data_tree_root = hash_from_hex(str_field(entry, "data_tree_root"), "data_tree_root");

        assert!(
            !verify_super_inclusion(&flip_first_byte(data_tree_root), &proof)
                .expect("structure unchanged"),
            "a modified Data Tree root still verified for index {} of super_tree_size {}",
            proof.data_tree_index,
            proof.super_tree_size
        );

        let mut forged = proof.clone();
        forged.genesis_super_root = format!(
            "sha256:{}",
            hex::encode(flip_first_byte(hash_from_hex(
                str_field(entry, "genesis_super_root"),
                "genesis_super_root",
            )))
        );
        assert!(
            !verify_consistency_to_origin(&forged).expect("structure unchanged"),
            "a forged genesis_super_root still verified for super_tree_size {}",
            proof.super_tree_size
        );
    }
}

// ---------------------------------------------------------------------------
// RFC 8785 JSON Canonicalization Scheme
// ---------------------------------------------------------------------------

/// Check one JCS case against its frozen RFC value and its conformance marker.
///
/// A `known_divergence` case is checked twice, and the second check is the point.
/// Asserting only that the output differs from the RFC value would accept *any*
/// wrong answer, so a fresh bug in the canonicalizer could replace the documented
/// one unnoticed. Pinning `atl_core_actual` as well makes the case fail on both
/// events that matter: a repair (the output becomes the RFC value, so the marker
/// must go) and a regression (the output becomes something the file does not
/// describe).
fn assert_conformance(name: &str, case: &Value, actual: &str, what: &str) {
    let expected = str_field(case, "expected");

    match str_field(case, "conformance") {
        "pass" => assert_eq!(actual, expected, "{name}: {what}"),
        "known_divergence" => {
            assert_ne!(
                actual, expected,
                "{name}: marked `known_divergence`, but atl-core now matches the RFC. \
                 Remove the marker, its `atl_core_actual` pin, and the entry in \
                 `known_divergences` from the vector file."
            );
            assert_eq!(
                actual,
                str_field(case, "atl_core_actual"),
                "{name}: atl-core diverges from the RFC in a way the vector file does not \
                 describe. The documented divergence was replaced by a different one, which \
                 is a new bug, not the known one."
            );
        }
        other => panic!("{name}: unknown conformance marker {other:?}"),
    }
}

#[test]
fn rfc8785_canonicalization_cases() {
    let doc = load(JCS_VECTORS, "JCS");

    for case in array_field(&doc, "canonicalization_cases") {
        let name = str_field(case, "name");
        let input: Value = serde_json::from_str(str_field(case, "input_json_text"))
            .unwrap_or_else(|e| panic!("{name}: input_json_text is not valid JSON: {e}"));

        assert_conformance(
            name,
            case,
            &canonicalize(&input),
            "canonical form diverges from the RFC 8785 value",
        );
    }
}

#[test]
fn rfc8785_number_serialization_cases() {
    let doc = load(JCS_VECTORS, "JCS");

    for case in array_field(&doc, "number_serialization_cases") {
        let bits_hex = str_field(case, "ieee754_hex");
        let bits = u64::from_str_radix(bits_hex, 16)
            .unwrap_or_else(|e| panic!("{bits_hex}: not 64-bit hex: {e}"));
        let number = serde_json::Number::from_f64(f64::from_bits(bits))
            .unwrap_or_else(|| panic!("{bits_hex}: RFC 8785 excludes NaN and Infinity"));

        assert_conformance(
            bits_hex,
            case,
            &canonicalize(&Value::Number(number)),
            "number serialization diverges from RFC 8785 Appendix B",
        );
    }
}

/// Every `known_divergence` marker must name a divergence that the vector file
/// actually documents, so the file always explains why a value is not met.
#[test]
fn rfc8785_divergence_markers_are_documented() {
    let doc = load(JCS_VECTORS, "JCS");
    let documented = field(&doc, "known_divergences");

    let mut seen = 0;
    for group in ["canonicalization_cases", "number_serialization_cases"] {
        for case in array_field(&doc, group) {
            if str_field(case, "conformance") != "known_divergence" {
                continue;
            }
            let name = case
                .get("name")
                .or_else(|| case.get("ieee754_hex"))
                .and_then(Value::as_str)
                .unwrap_or("<unnamed>");

            // Without a pin the case would assert only "not the RFC value", which any
            // wrong answer satisfies.
            let pinned = str_field(case, "atl_core_actual");
            assert_ne!(
                pinned,
                str_field(case, "expected"),
                "{name}: the `atl_core_actual` pin equals the RFC value, so the case is not \
                 a divergence at all"
            );

            for key in array_field(case, "divergence") {
                let key = key.as_str().expect("divergence key is a string");
                assert!(
                    documented.get(key).is_some(),
                    "{name}: divergence {key:?} is referenced but not described in \
                     `known_divergences`"
                );
                seen += 1;
            }
        }
    }
    assert!(seen > 0, "divergence markers vanished without the vector file being updated");
}

// ---------------------------------------------------------------------------
// Guards on the vector files themselves
// ---------------------------------------------------------------------------

/// Guard against the failure mode these vectors were written to remove: entries
/// whose expected value is a placeholder such as `"root": "computed"`, or a prose
/// `path_description` instead of an actual path. Such an entry asserts nothing.
#[test]
fn vector_files_contain_no_placeholders() {
    const BANNED_VALUES: [&str; 3] = ["computed", "TODO", "generated"];
    const BANNED_KEYS: [&str; 2] = ["path_description", "proof_description"];

    fn walk(value: &Value, path: &str, file: &str) {
        match value {
            Value::String(s) => assert!(
                !BANNED_VALUES.contains(&s.as_str()),
                "{file}: {path} is the placeholder {s:?} instead of a frozen value"
            ),
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    walk(item, &format!("{path}[{i}]"), file);
                }
            }
            Value::Object(map) => {
                for (key, item) in map {
                    assert!(
                        !BANNED_KEYS.contains(&key.as_str()),
                        "{file}: {path}.{key} describes a proof in prose instead of freezing it"
                    );
                    walk(item, &format!("{path}.{key}"), file);
                }
            }
            _ => {}
        }
    }

    for (file, src) in [
        ("merkle/trees.json", MERKLE_VECTORS),
        ("atl/leaf_composition.json", LEAF_VECTORS),
        ("atl/super_tree.json", SUPER_VECTORS),
        ("jcs/cases.json", JCS_VECTORS),
        ("implementation_only/genesis_chain_leaf.json", GENESIS_PIN),
    ] {
        walk(&load(src, file), "$", file);
    }
}

/// Nothing under `test_data/vectors/` may be grounded in `atl-core` itself.
///
/// This is the rule the whole vector set rests on, so it is asserted rather than
/// merely documented. A value derived from this implementation's own doc comments
/// or output cannot ground a conformance claim -- matching it would only mean the
/// other implementation copied ours. Such values belong in
/// `test_data/implementation_only/`, which is outside this directory and says so on
/// its first line.
#[test]
fn vectors_directory_is_free_of_self_grounded_values() {
    const EXTERNALLY_GROUNDED: [&str; 6] = [
        "rfc6962-published",
        "rfc6962-symbolic",
        "rfc6962-derived",
        "rfc8785-published",
        "rfc8785-derived",
        "atl-spec-derived",
    ];

    fn walk(value: &Value, path: &str, file: &str) {
        match value {
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    walk(item, &format!("{path}[{i}]"), file);
                }
            }
            Value::Object(map) => {
                if let Some(origin) = map.get("origin").and_then(Value::as_str) {
                    assert!(
                        EXTERNALLY_GROUNDED.contains(&origin),
                        "{file}: {path} has origin {origin:?}, which is not grounded outside \
                         atl-core. Move it to test_data/implementation_only/ or give it a \
                         specification clause it can be derived from."
                    );
                }
                for (key, item) in map {
                    walk(item, &format!("{path}.{key}"), file);
                }
            }
            _ => {}
        }
    }

    for (file, src) in [
        ("merkle/trees.json", MERKLE_VECTORS),
        ("atl/leaf_composition.json", LEAF_VECTORS),
        ("atl/super_tree.json", SUPER_VECTORS),
        ("jcs/cases.json", JCS_VECTORS),
    ] {
        walk(&load(src, file), "$", file);
    }
}

/// Every frozen value must say where it came from, otherwise the file cannot be
/// audited by reading and the vectors are worth no more than the code they test.
#[test]
fn every_vector_records_its_origin() {
    let merkle = load(MERKLE_VECTORS, "merkle");
    let leaf = load(LEAF_VECTORS, "ATL leaf");
    let super_tree = load(SUPER_VECTORS, "Super-Tree");
    let jcs = load(JCS_VECTORS, "JCS");

    let check = |file: &str, doc: &Value, keys: &[&str]| {
        for key in keys {
            let entries = array_field(doc, key);
            assert!(!entries.is_empty(), "{file}: section {key} is empty");
            for (i, entry) in entries.iter().enumerate() {
                let origin = str_field(entry, "origin");
                assert!(!origin.is_empty(), "{file}: {key}[{i}] has an empty origin");
            }
        }
    };

    check("merkle", &merkle, &["records", "roots", "inclusion_proofs", "consistency_proofs"]);
    check("ATL leaf", &leaf, &["cases"]);
    check("genesis pin", &load(GENESIS_PIN, "genesis chain leaf pin"), &["cases"]);
    check("Super-Tree", &super_tree, &["super_leaves", "super_roots", "super_proofs"]);
    check("JCS", &jcs, &["canonicalization_cases", "number_serialization_cases"]);
}
