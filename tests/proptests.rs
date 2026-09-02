//! Property-based tests for atl-core using proptest
//!
//! These tests verify invariants that must hold for all inputs.

use atl_core::core::jcs::{canonicalize, canonicalize_and_hash, check_unique_property_names};
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
            let once = canonicalize(&json).expect("a string-valued object is canonicalizable");
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&once) {
                let twice = canonicalize(&parsed).expect("a canonical form re-parses");
                prop_assert_eq!(once, twice);
            }
        }
    });
}

/// A canonicalized double must parse back to the *same* double.
///
/// This is the joint property of the two halves of RFC 8785 number handling,
/// and it is the one that decides whether `metadata_hash` is reproducible.
/// Rendering is this crate's (ECMA-262 Section 7.1.12.1, via `ryu-js`); parsing
/// belongs to `serde_json`, and only holds because the dependency is taken with
/// `float_roundtrip`. Without that feature roughly 30% of arbitrary doubles come
/// back one ULP off and this test fails -- so it also guards the feature against
/// being dropped from `Cargo.toml` as a apparently-harmless tidy-up.
#[test]
fn prop_jcs_number_survives_a_json_round_trip() {
    proptest!(|(bits: u64)| {
        let value = f64::from_bits(bits);
        if !value.is_finite() {
            return Ok(());
        }
        let Some(number) = serde_json::Number::from_f64(value) else {
            return Ok(());
        };

        let canonical = canonicalize(&serde_json::Value::Number(number))
            .map_err(|e| TestCaseError::fail(format!("finite double refused: {e}")))?;
        let reparsed: serde_json::Value = serde_json::from_str(&canonical)
            .map_err(|e| TestCaseError::fail(format!("{canonical} is not JSON: {e}")))?;
        let back = reparsed.as_f64().ok_or_else(|| TestCaseError::fail("not a number"))?;

        // Bitwise, not `==`: `0.0 == -0.0` is true, and the canonical form of
        // both is "0", which is what ECMA-262 Section 7.1.12.1 requires.
        prop_assert_eq!(back.to_bits(), value.to_bits(), "{} did not survive", canonical);
    });
}

/// Canonicalizing a document, re-reading it, and canonicalizing again must give
/// the same bytes -- for floats too, not just for the strings the older
/// idempotence property covers. Two verifiers exchange receipts as text, so a
/// canonical form that does not survive its own re-parse would give them two
/// different `metadata_hash` values for one receipt.
#[test]
fn prop_jcs_is_a_fixed_point_for_numbers() {
    proptest!(|(bits: u64, key: String)| {
        let value = f64::from_bits(bits);
        if !value.is_finite() {
            return Ok(());
        }
        let Some(number) = serde_json::Number::from_f64(value) else {
            return Ok(());
        };

        let document = serde_json::json!({ key: serde_json::Value::Number(number) });
        let once = canonicalize(&document)
            .map_err(|e| TestCaseError::fail(format!("finite double refused: {e}")))?;
        let reparsed: serde_json::Value = serde_json::from_str(&once)
            .map_err(|e| TestCaseError::fail(format!("{once} is not JSON: {e}")))?;
        prop_assert_eq!(&once, &canonicalize(&reparsed).expect("a canonical form re-parses"));
        prop_assert_eq!(
            canonicalize_and_hash(&document).expect("canonicalizable"),
            canonicalize_and_hash(&reparsed).expect("canonicalizable")
        );
    });
}

/// **Whatever this crate accepts, it must denote what went in.**
///
/// The number properties above cover doubles specifically. This one is stated
/// over arbitrary `Value` documents and over the *acceptance decision itself*:
/// if `canonicalize` returned a string, that string must parse back to a value
/// denoting the same JSON. A canonicalizer that quietly rewrote a value it
/// could not represent -- which is exactly what emitting an out-of-range
/// integer's digits, or `null` for a non-finite double, used to do -- fails
/// here, because the reparse no longer denotes what went in.
///
/// Note "denote", not "equal": an integer that is an exact double but is not
/// written as that double's ECMA-262 spelling is deliberately *normalised*
/// (2^62 comes out as `4611686018427388000`), which is what canonicalization
/// is for. The comparison below is therefore over the double each number
/// denotes, and normalisation passes it while any loss of value would not.
///
/// Equality is over the JSON *values*, not over `serde_json::Value` variants.
/// `Value` draws a distinction JSON does not: `Number::from_f64(3.496830563546663e15)`
/// and the integer `3496830563546663` are `!=` to each other, while RFC 8785 and
/// ECMA-262 have one number type and render both as `3496830563546663`. Holding
/// the canonicalizer to `Value`'s finer distinction would demand it emit a
/// fractional part that RFC 8785 §3.2.2.3 forbids, so numbers are compared by
/// the double they denote.
///
/// The generator deliberately reaches past what `canonicalize` accepts:
/// integers spanning the whole `i64`/`u64` range, so runs include values that
/// are neither exact doubles nor any double's canonical spelling. Those must
/// come back as errors, and an error is not a counterexample -- the property is
/// conditional on success. What would be a counterexample is a success whose
/// output says something else.
#[test]
fn prop_a_successful_canonicalization_never_alters_the_value() {
    /// Structural equality with numbers compared as the doubles they denote.
    fn denotes_the_same_json(a: &serde_json::Value, b: &serde_json::Value) -> bool {
        match (a, b) {
            (serde_json::Value::Number(x), serde_json::Value::Number(y)) => {
                match (x.as_f64(), y.as_f64()) {
                    // Bitwise, so a one-ULP drift is caught -- but with the one
                    // exception RFC 8785 itself mandates: ECMA-262 Section
                    // 7.1.12.1 step 1 renders -0 as "0", so the sign of zero
                    // provably cannot survive canonicalization and demanding it
                    // would demand a non-conformant output.
                    (Some(x), Some(y)) => {
                        let zero = |f: f64| if f == 0.0 { 0.0_f64 } else { f };
                        zero(x).to_bits() == zero(y).to_bits()
                    }
                    _ => x == y,
                }
            }
            (serde_json::Value::Array(x), serde_json::Value::Array(y)) => {
                x.len() == y.len() && x.iter().zip(y).all(|(x, y)| denotes_the_same_json(x, y))
            }
            (serde_json::Value::Object(x), serde_json::Value::Object(y)) => {
                x.len() == y.len()
                    && x.iter().all(|(k, x)| y.get(k).is_some_and(|y| denotes_the_same_json(x, y)))
            }
            _ => a == b,
        }
    }

    fn leaf() -> impl Strategy<Value = serde_json::Value> {
        prop_oneof![
            Just(serde_json::Value::Null),
            any::<bool>().prop_map(serde_json::Value::Bool),
            any::<i64>().prop_map(|i| serde_json::json!(i)),
            any::<u64>().prop_map(|u| serde_json::json!(u)),
            any::<u64>().prop_map(|bits| {
                let f = f64::from_bits(bits);
                serde_json::Number::from_f64(f)
                    .map_or(serde_json::Value::Null, serde_json::Value::Number)
            }),
            "\\PC*".prop_map(serde_json::Value::String),
        ]
    }

    let document = leaf().prop_recursive(4, 32, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(serde_json::Value::Array),
            prop::collection::hash_map("\\PC*", inner, 0..6)
                .prop_map(|m| serde_json::Value::Object(m.into_iter().collect())),
        ]
    });

    // Signed zero is rare enough in a `u64` generator to be luck rather than
    // coverage, and it is the one value whose sign the RFC deliberately drops.
    assert_eq!(
        canonicalize(&serde_json::Value::Number(
            serde_json::Number::from_f64(-0.0).expect("finite")
        ))
        .expect("canonicalizable"),
        "0"
    );

    proptest!(|(value in document)| {
        let Ok(canonical) = canonicalize(&value) else {
            // Refused, which is the other half of the contract: nothing was
            // emitted, so nothing can be wrong about it.
            return Ok(());
        };

        let reparsed: serde_json::Value = serde_json::from_str(&canonical)
            .map_err(|e| TestCaseError::fail(format!("{canonical} is not JSON: {e}")))?;
        prop_assert!(
            denotes_the_same_json(&reparsed, &value),
            "canonical form {} is a different value than {}",
            canonical,
            value
        );

        // And the canonical form is a fixed point, so two verifiers exchanging
        // it as text agree on the hash.
        prop_assert_eq!(
            &canonical,
            &canonicalize(&reparsed).expect("a canonical form re-canonicalizes")
        );
    });
}

/// A duplicate property name must be refused wherever it sits, and never
/// silently collapsed. The generator builds a document, then re-emits one of
/// its objects with a repeated member -- something `serde_json::Value` cannot
/// represent, so the text has to be assembled directly.
#[test]
fn prop_duplicate_property_names_are_always_refused() {
    proptest!(|(key in "\\PC{0,8}", depth in 0usize..5, first: i64, second: i64)| {
        let escaped = serde_json::to_string(&key).expect("a string serializes");
        let mut json = format!("{{{escaped}:{first},{escaped}:{second}}}");
        let mut pointer = String::new();
        for level in 0..depth {
            json = format!("{{\"n{level}\":{json}}}");
            pointer = format!("/n{level}{pointer}");
        }

        let err = check_unique_property_names(&json)
            .expect_err("a repeated property name must be refused");
        match err {
            atl_core::AtlError::JcsInputConstraint { path, .. } => {
                prop_assert_eq!(path, pointer);
            }
            other => return Err(TestCaseError::fail(format!("wrong error: {other}"))),
        }
    });
}

/// The generator is bounded by `Number.MAX_SAFE_INTEGER` on purpose: outside
/// that range `canonicalize` refuses, and this property is about determinism
/// of the values it accepts, not about where it draws the line (which
/// `prop_a_successful_canonicalization_never_alters_the_value` and the unit
/// tests in `src/core/jcs.rs` cover).
#[test]
fn prop_jcs_hash_is_deterministic() {
    proptest!(|(value in -9_007_199_254_740_991_i64..=9_007_199_254_740_991_i64)| {
        let json = serde_json::json!({"value": value});
        let hash1 = canonicalize_and_hash(&json).expect("i64 metadata is canonicalizable");
        let hash2 = canonicalize_and_hash(&json).expect("i64 metadata is canonicalizable");
        prop_assert_eq!(hash1, hash2);
    });
}

#[test]
fn prop_jcs_no_whitespace() {
    proptest!(|(value in -9_007_199_254_740_991_i64..=9_007_199_254_740_991_i64)| {
        let json = serde_json::json!({"value": value});
        let canonical = canonicalize(&json).expect("i64 metadata is canonicalizable");
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
