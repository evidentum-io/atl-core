//! Property-based tests for atl-core using proptest
//!
//! These tests verify invariants that must hold for all inputs.

use atl_core::core::jcs::{canonicalize, canonicalize_and_hash};
use atl_core::core::merkle::{
    compute_leaf_hash, compute_root, generate_consistency_proof, generate_inclusion_proof,
    verify_consistency, verify_inclusion, ConsistencyProof, Hash,
};
use proptest::prelude::*;

// ========== Property Tests ==========

#[test]
fn prop_leaf_hash_is_deterministic() {
    proptest!(|(payload: [u8; 32], metadata: [u8; 32])| {
        let hash1 = compute_leaf_hash(&payload, &metadata);
        let hash2 = compute_leaf_hash(&payload, &metadata);
        prop_assert_eq!(hash1, hash2);
    });
}

#[test]
fn prop_root_is_deterministic() {
    proptest!(|(leaves: Vec<[u8; 32]>)| {
        if leaves.is_empty() {
            return Ok(());
        }
        let root1 = compute_root(&leaves);
        let root2 = compute_root(&leaves);
        prop_assert_eq!(root1, root2);
    });
}

#[test]
fn prop_single_leaf_equals_root() {
    proptest!(|(leaf: [u8; 32])| {
        let root = compute_root(&[leaf]);
        prop_assert_eq!(root, leaf);
    });
}

#[test]
fn prop_valid_proof_always_verifies() {
    proptest!(|(leaves: Vec<[u8; 32]>)| {
        if leaves.is_empty() {
            return Ok(());
        }

        let tree_size = leaves.len() as u64;
        let leaf_index = 0u64;
        let root = compute_root(&leaves);

        #[allow(clippy::cast_possible_truncation)]
        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let proof = generate_inclusion_proof(leaf_index, tree_size, get_node)?;
        prop_assert!(verify_inclusion(&leaves[0], &proof, &root).unwrap());
    });
}

#[test]
fn prop_proof_size_is_logarithmic() {
    proptest!(|(leaves: Vec<[u8; 32]>)| {
        if leaves.is_empty() {
            return Ok(());
        }

        let tree_size = leaves.len() as u64;
        let leaf_index = 0u64;

        #[allow(clippy::cast_possible_truncation)]
        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let proof = generate_inclusion_proof(leaf_index, tree_size, get_node)?;

        #[allow(clippy::cast_possible_truncation)]
        let max_proof_size = if tree_size <= 1 {
            0
        } else {
            (64 - tree_size.leading_zeros()) as usize
        };

        prop_assert!(
            proof.path.len() <= max_proof_size,
            "Proof size {} exceeds max {}",
            proof.path.len(),
            max_proof_size
        );
    });
}

#[test]
fn prop_jcs_is_idempotent() {
    proptest!(|(json_str: String)| {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&format!("{{\"key\":\"{json_str}\"}}")) {
            let once = canonicalize(&json);
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&once) {
                let twice = canonicalize(&parsed);
                prop_assert_eq!(once, twice);
            }
        }
    });
}

#[test]
fn prop_jcs_hash_is_deterministic() {
    proptest!(|(value: i64)| {
        let json = serde_json::json!({"value": value});
        let hash1 = canonicalize_and_hash(&json);
        let hash2 = canonicalize_and_hash(&json);
        prop_assert_eq!(hash1, hash2);
    });
}

#[test]
fn prop_jcs_no_whitespace() {
    proptest!(|(value: i64)| {
        let json = serde_json::json!({"value": value});
        let canonical = canonicalize(&json);
        prop_assert!(!canonical.contains(' '));
        prop_assert!(!canonical.contains('\n'));
        prop_assert!(!canonical.contains('\t'));
    });
}

#[test]
fn prop_hash_output_is_32_bytes() {
    proptest!(|(payload: [u8; 32], metadata: [u8; 32])| {
        let hash = compute_leaf_hash(&payload, &metadata);
        prop_assert_eq!(hash.len(), 32);
    });
}

#[test]
fn prop_root_output_is_32_bytes() {
    proptest!(|(leaves: Vec<[u8; 32]>)| {
        if leaves.is_empty() {
            return Ok(());
        }
        let root = compute_root(&leaves);
        prop_assert_eq!(root.len(), 32);
    });
}

#[test]
fn prop_empty_tree_has_deterministic_root() {
    use sha2::{Digest, Sha256};

    let root1 = compute_root(&[]);
    let root2 = compute_root(&[]);
    let expected: Hash = Sha256::digest([]).into();

    assert_eq!(root1, root2);
    assert_eq!(root1, expected);
}

// ========== Consistency Proof Property Tests ==========

#[test]
fn prop_consistency_proof_roundtrip() {
    proptest!(ProptestConfig::with_cases(10000), |(
        from_size in 1u64..100,
        additional in 1u64..100,
    )| {
        let to_size = from_size + additional;

        let leaves: Vec<Hash> = (0..to_size)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&i.to_le_bytes());
                h
            })
            .collect();

        #[allow(clippy::cast_possible_truncation)]
        let old_root = compute_root(&leaves[..from_size as usize]);
        let new_root = compute_root(&leaves);

        #[allow(clippy::cast_possible_truncation)]
        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let proof = generate_consistency_proof(from_size, to_size, get_node)?;
        // Note: verify_consistency returns AtlResult<bool>
        prop_assert!(
            verify_consistency(&proof, &old_root, &new_root).unwrap(),
            "Roundtrip failed for {} -> {}",
            from_size, to_size
        );
    });
}

#[test]
fn prop_consistency_proof_wrong_old_root_detected() {
    proptest!(ProptestConfig::with_cases(5000), |(
        from_size in 1u64..50,
        additional in 1u64..50,
        wrong_byte: u8,
    )| {
        let to_size = from_size + additional;

        let leaves: Vec<Hash> = (0..to_size)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&i.to_le_bytes());
                h
            })
            .collect();

        #[allow(clippy::cast_possible_truncation)]
        let old_root = compute_root(&leaves[..from_size as usize]);
        let new_root = compute_root(&leaves);

        // Create wrong old root
        let mut wrong_old_root = old_root;
        wrong_old_root[0] = wrong_old_root[0].wrapping_add(wrong_byte.saturating_add(1));

        #[allow(clippy::cast_possible_truncation)]
        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let proof = generate_consistency_proof(from_size, to_size, get_node)?;

        // Must fail with wrong old root - note: returns AtlResult<bool>
        prop_assert!(
            !verify_consistency(&proof, &wrong_old_root, &new_root).unwrap(),
            "Should reject wrong old root for {} -> {}",
            from_size, to_size
        );
    });
}

#[test]
fn prop_consistency_proof_wrong_new_root_detected() {
    proptest!(ProptestConfig::with_cases(5000), |(
        from_size in 1u64..50,
        additional in 1u64..50,
        wrong_byte: u8,
    )| {
        let to_size = from_size + additional;

        let leaves: Vec<Hash> = (0..to_size)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&i.to_le_bytes());
                h
            })
            .collect();

        #[allow(clippy::cast_possible_truncation)]
        let old_root = compute_root(&leaves[..from_size as usize]);
        let new_root = compute_root(&leaves);

        // Create wrong new root
        let mut wrong_new_root = new_root;
        wrong_new_root[0] = wrong_new_root[0].wrapping_add(wrong_byte.saturating_add(1));

        #[allow(clippy::cast_possible_truncation)]
        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let proof = generate_consistency_proof(from_size, to_size, get_node)?;

        // Must fail with wrong new root - note: returns AtlResult<bool>
        prop_assert!(
            !verify_consistency(&proof, &old_root, &wrong_new_root).unwrap(),
            "Should reject wrong new root for {} -> {}",
            from_size, to_size
        );
    });
}

#[test]
fn prop_consistency_proof_size_logarithmic() {
    proptest!(ProptestConfig::with_cases(5000), |(
        from_size in 1u64..1000,
        additional in 1u64..1000,
    )| {
        let to_size = from_size + additional;

        let leaves: Vec<Hash> = (0..to_size)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&i.to_le_bytes());
                h
            })
            .collect();

        #[allow(clippy::cast_possible_truncation)]
        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let proof = generate_consistency_proof(from_size, to_size, get_node)?;

        // Proof size should be O(log n)
        // Upper bound: 2 * log2(to_size) + 1
        #[allow(clippy::cast_possible_truncation)]
        let max_size = if to_size <= 1 {
            1
        } else {
            ((64 - to_size.leading_zeros()) as usize) * 2 + 1
        };

        prop_assert!(
            proof.path.len() <= max_size,
            "Proof size {} exceeds max {} for {} -> {}",
            proof.path.len(), max_size, from_size, to_size
        );
    });
}

#[test]
fn prop_consistency_proof_tamper_detected() {
    proptest!(ProptestConfig::with_cases(5000), |(
        from_size in 2u64..50,
        additional in 1u64..50,
        tamper_idx: usize,
        tamper_byte: u8,
    )| {
        let to_size = from_size + additional;

        let leaves: Vec<Hash> = (0..to_size)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&i.to_le_bytes());
                h
            })
            .collect();

        #[allow(clippy::cast_possible_truncation)]
        let old_root = compute_root(&leaves[..from_size as usize]);
        let new_root = compute_root(&leaves);

        #[allow(clippy::cast_possible_truncation)]
        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let mut proof = generate_consistency_proof(from_size, to_size, get_node)?;

        // Skip if proof is empty (can't tamper)
        if proof.path.is_empty() {
            return Ok(());
        }

        // Tamper with a hash
        let idx = tamper_idx % proof.path.len();
        proof.path[idx][0] = proof.path[idx][0].wrapping_add(tamper_byte.saturating_add(1));

        // Note: verify_consistency returns AtlResult<bool>
        prop_assert!(
            !verify_consistency(&proof, &old_root, &new_root).unwrap(),
            "Tampered proof should fail for {} -> {}",
            from_size, to_size
        );
    });
}

#[test]
fn prop_consistency_same_size_same_root() {
    proptest!(ProptestConfig::with_cases(5000), |(
        size in 1u64..100,
    )| {
        let leaves: Vec<Hash> = (0..size)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&i.to_le_bytes());
                h
            })
            .collect();

        let root = compute_root(&leaves);

        let proof = ConsistencyProof {
            from_size: size,
            to_size: size,
            path: vec![],
        };

        // Note: verify_consistency returns AtlResult<bool>
        prop_assert!(
            verify_consistency(&proof, &root, &root).unwrap(),
            "Same size/root should pass for size {}",
            size
        );
    });
}

#[test]
fn prop_consistency_same_size_different_root_fails() {
    proptest!(ProptestConfig::with_cases(5000), |(
        size in 1u64..100,
        diff_byte: u8,
    )| {
        let root1 = [0u8; 32];
        let mut root2 = root1;
        root2[0] = diff_byte.saturating_add(1);

        let proof = ConsistencyProof {
            from_size: size,
            to_size: size,
            path: vec![],
        };

        // Note: verify_consistency returns AtlResult<bool>
        prop_assert!(
            !verify_consistency(&proof, &root1, &root2).unwrap(),
            "Same size/different root should fail for size {}",
            size
        );
    });
}

// ========== Timestamp parsing: total on every `&str` ==========
//
// `parse_iso8601_to_nanos` is public and is fed `bitcoin_block_time` and an
// anchor's `timestamp` straight out of a receipt -- unvalidated `String`s
// from a document this crate does not control. It must therefore answer for
// every possible input, and "answer" excludes aborting the process.
//
// It did not. `split_at(len - 6)` indexed a `&str` at a byte position
// computed from its length, and `str` slicing panics when that position is
// not a UTF-8 character boundary: a `bitcoin_block_time` of "💥abc" killed
// `atl-cli` with SIGABRT instead of returning a verdict.
//
// The fix was structural -- the parser indexes byte slices, where a bad
// index is a `None` and character boundaries do not exist -- so the test for
// it is stated as a property over arbitrary input rather than as a list of
// the shapes that happened to break it. A list only ever covers what someone
// thought of.

/// **The property: no `&str` whatsoever makes this function panic.**
///
/// `\PC*` generates arbitrary Unicode strings, so multi-byte characters land
/// at arbitrary byte positions -- including the positions the parser computes
/// from lengths.
#[test]
fn prop_timestamp_parsing_never_panics() {
    proptest!(|(input in "\\PC*")| {
        let _ = atl_core::core::verify::parse_iso8601_to_nanos(&input);
    });
}

/// The same property where it actually bites: a *valid* timestamp with one
/// arbitrary character inserted at an arbitrary position. Random strings
/// rarely reach the parser's later stages; these reach every one of them,
/// with a multi-byte character sitting exactly where an index is computed.
#[test]
fn prop_a_character_inserted_anywhere_in_a_valid_timestamp_never_panics() {
    proptest!(|(ch in any::<char>(), at in 0usize..26)| {
        for valid in [
            "2026-01-19T07:01:20+00:00",
            "2026-01-19T07:01:20Z",
            "2026-01-19T07:01:20.123456789Z",
        ] {
            let mut mutated = String::from(valid);
            // Every byte of these is ASCII, so any index within them is a
            // character boundary and the insert itself cannot panic.
            mutated.insert(at.min(valid.len()), ch);
            let _ = atl_core::core::verify::parse_iso8601_to_nanos(&mutated);
        }
    });
}

/// Truncation, not insertion: every prefix and every suffix of a valid
/// timestamp, so the length-derived indices are exercised against every
/// possible length rather than only the ones a generator happens to pick.
#[test]
fn prop_every_prefix_and_suffix_of_a_valid_timestamp_never_panics() {
    for valid in ["2026-01-19T07:01:20+00:00", "2026-01-19T07:01:20.000000001Z"] {
        for cut in 0..=valid.len() {
            let (head, tail) = valid.split_at(cut);
            assert!(
                atl_core::core::verify::parse_iso8601_to_nanos(head).is_none()
                    || cut == valid.len()
            );
            let _ = atl_core::core::verify::parse_iso8601_to_nanos(tail);
        }
    }
}

/// Regression corpus. The property tests above are the real guarantee; these
/// are the specific shapes worth naming, so a failure says which one broke.
///
/// A truncated UTF-8 byte sequence is deliberately absent: it cannot reach a
/// `&str` at all, because the type guarantees valid UTF-8. What *can* reach
/// the parser is a whole multi-byte character at a byte position the parser
/// computes, which is what the lengths below are chosen to produce.
#[test]
fn deliberately_awkward_timestamps_return_none_without_panicking() {
    let cases = [
        // The exact input that aborted the process.
        "💥abc",
        // A multi-byte character straddling the offset split (len - 6).
        "2026-01-19T07:01:2💥+00:00",
        "2026-01-19T07:01:20+00:0💥",
        "2026-01-19T07:01:20💥0:00",
        // Lengths either side of the fixed widths the parser once assumed.
        "💥",
        "💥💥",
        "💥💥💥💥💥",
        "1234567890123456789",
        "12345678901234567890",
        "123456789012345678901",
        "💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥",
        // Empty and whitespace.
        "",
        " ",
        "\t\n",
        // Right shape, wrong bytes.
        "2026-01-19T07:01:20+ラ:00",
        "2026-01-19T07:01:20.💥Z",
        "2026-01-19Tラ7:01:20Z",
        "ラ026-01-19T07:01:20Z",
        // Controls and a zero-width marker, which are valid UTF-8 and can
        // arrive in a JSON string.
        "\u{0}2026-01-19T07:01:20Z",
        "\u{feff}2026-01-19T07:01:20Z",
        // Digits that would overflow a naive accumulator.
        "99999999-01-19T07:01:20Z",
        "2026-01-19T07:01:20.99999999999999999999Z",
    ];

    for case in cases {
        assert_eq!(
            atl_core::core::verify::parse_iso8601_to_nanos(case),
            None,
            "{case:?} must be refused, not accepted -- and above all not panic"
        );
    }
}
