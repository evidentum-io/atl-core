//! `serde_json/arbitrary_precision` must not change a single canonical byte.
//!
//! # Why this file exists
//!
//! Cargo unifies features across the entire dependency graph. Any crate
//! anywhere in a consumer's tree can enable `serde_json/arbitrary_precision`,
//! and it is then enabled for `atl-core` too — without this crate's consent and
//! usually without anyone noticing. That configuration changes `serde_json` in
//! two ways this crate is directly exposed to:
//!
//! * `Deserializer::deserialize_any` delivers a non-integer number as a **map**
//!   keyed by the private token `$serde_json::private::Number`. `serde_json`'s
//!   own `Deserialize for Value` knows that token; nothing else does. A
//!   hand-written visitor builds an object where a number belongs, so `1.5`
//!   becomes `{"$serde_json::private::Number":"1.5"}` — every `metadata_hash`
//!   changes, and a document containing that literal object collides with one
//!   containing the number. This crate therefore has no hand-written
//!   `Deserialize` for `Value`; one was written and removed.
//! * `Number::as_f64` re-parses the stored decimal text instead of returning a
//!   stored double. The whole of `jcs::format_number` stands on that method.
//!
//! # How it proves anything
//!
//! Every expectation below is a **literal constant** — a canonical string or a
//! hex digest — not a comparison against a second run. Running the suite with
//! and without `--features arbitrary-precision-audit` therefore proves the two
//! configurations agree byte for byte, rather than proving each is merely
//! self-consistent.

use atl_core::core::jcs::{canonicalize, canonicalize_and_hash, check_unique_property_names};
use atl_core::Receipt;
use serde_json::Value;

/// Canonical forms that must hold in both configurations.
///
/// Chosen to cross the token boundary in both directions: integers (which stay
/// on the `visit_u64`/`visit_i64` path even under `arbitrary_precision`) and
/// non-integers (which do not).
const CASES: &[(&str, &str)] = &[
    // Fractions: the shape that becomes a token map under arbitrary_precision.
    (r#"{"d":1.5}"#, r#"{"d":1.5}"#),
    (r#"{"d":333333333.33333329}"#, r#"{"d":333333333.3333333}"#),
    (r#"{"d":1e30}"#, r#"{"d":1e+30}"#),
    (r#"{"d":1e-7}"#, r#"{"d":1e-7}"#),
    (r#"{"d":5e-324}"#, r#"{"d":5e-324}"#),
    (r#"{"d":-0.0}"#, r#"{"d":0}"#),
    (r#"{"d":2e-3}"#, r#"{"d":0.002}"#),
    // Integers, including the ones that must normalise.
    (r#"{"i":42}"#, r#"{"i":42}"#),
    (r#"{"i":-9007199254740991}"#, r#"{"i":-9007199254740991}"#),
    (r#"{"i":9007199254740993}"#, r#"{"i":9007199254740992}"#),
    (r#"{"i":4611686018427387904}"#, r#"{"i":4611686018427388000}"#),
    (r#"{"i":295147905179352825856}"#, r#"{"i":295147905179352830000}"#),
    (r#"{"i":18446744073709551615}"#, r#"{"i":18446744073709552000}"#),
    // Mixed, nested, and with the key ordering rule in play.
    (
        r#"{"z":[1,2.5,{"b":3.25,"a":-1}],"a":{"n":null,"t":true}}"#,
        r#"{"a":{"n":null,"t":true},"z":[1,2.5,{"a":-1,"b":3.25}]}"#,
    ),
];

/// `metadata_hash` for the mixed document above, as a literal.
///
/// This is the value the protocol actually carries, so pinning the canonical
/// string alone would not be enough — it is the digest two verifiers must
/// agree on. Computed independently as SHA-256 of
/// `{"a":{"n":null,"t":true},"z":[1,2.5,{"a":-1,"b":3.25}]}`, the canonical
/// form asserted separately above, not by running this crate.
const MIXED_METADATA_HASH: &str =
    "6a813dbd3fc62e382a8332ad608eb6d09f6420f2df69f3559bc1ac9fb6e0760d";

#[test]
fn canonical_forms_are_identical_under_arbitrary_precision() {
    for (input, expected) in CASES {
        let value: Value =
            serde_json::from_str(input).unwrap_or_else(|e| panic!("{input}: not valid JSON: {e}"));
        let canonical = canonicalize(&value).unwrap_or_else(|e| panic!("{input}: {e}"));
        assert_eq!(&canonical, expected, "{input}");

        // And the canonical form is still a fixed point in this configuration.
        let reparsed: Value = serde_json::from_str(&canonical)
            .unwrap_or_else(|e| panic!("{canonical}: not valid JSON: {e}"));
        assert_eq!(
            canonicalize(&reparsed).unwrap_or_else(|e| panic!("{canonical}: {e}")),
            canonical,
            "{input}: not a fixed point"
        );
    }
}

#[test]
fn metadata_hash_is_identical_under_arbitrary_precision() {
    let (input, _) = CASES[CASES.len() - 1];
    let value: Value = serde_json::from_str(input).expect("valid JSON");
    assert_eq!(hex::encode(canonicalize_and_hash(&value).expect("canonical")), MIXED_METADATA_HASH);
}

/// The method the whole number path stands on. Under `arbitrary_precision` it
/// re-parses stored text, so its answers are pinned rather than assumed.
#[test]
fn number_as_f64_behaves_as_format_number_requires() {
    for (text, expected) in [
        ("1.5", Some(1.5_f64)),
        ("42", Some(42.0)),
        ("-0.0", Some(-0.0)),
        ("9007199254740993", Some(9_007_199_254_740_992.0)),
        ("295147905179352825856", Some(295_147_905_179_352_830_000.0)),
    ] {
        let value: Value = serde_json::from_str(text).expect("valid JSON");
        let actual = value.as_number().expect("a number").as_f64();
        match (actual, expected) {
            (Some(a), Some(e)) => assert_eq!(a.to_bits(), e.to_bits(), "as_f64({text})"),
            (a, e) => assert_eq!(a.is_none(), e.is_none(), "as_f64({text})"),
        }
    }
}

/// The raw-text duplicate scan walks numbers too, so it must not be confused by
/// the token map — and above all must not report a false duplicate.
#[test]
fn duplicate_detection_is_unaffected_by_the_number_representation() {
    for accepted in
        [r#"{"a":1.5,"b":2.5}"#, r#"{"a":{"n":1.5},"b":{"n":2.5}}"#, r#"[1.5,2.5,{"x":3.5}]"#]
    {
        assert!(check_unique_property_names(accepted).is_ok(), "{accepted} falsely refused");
    }

    for refused in [r#"{"a":1.5,"a":2.5}"#, r#"{"m":{"n":1.5,"n":2.5}}"#] {
        assert!(check_unique_property_names(refused).is_err(), "{refused} wrongly accepted");
    }
}

/// End to end: a receipt whose metadata holds both integer and fractional
/// numbers must produce the same `metadata_hash` in either configuration.
#[test]
fn receipt_metadata_hashing_is_identical_under_arbitrary_precision() {
    let json = format!(
        r#"{{"spec_version":"2.0.0","entry":{{"id":"550e8400-e29b-41d4-a716-446655440000",
        "payload_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "metadata_hash":"sha256:{MIXED_METADATA_HASH}",
        "metadata":{}}},"proof":{{"tree_size":1,
        "root_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "inclusion_path":[],"leaf_index":0,"checkpoint":{{
        "origin":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "tree_size":1,
        "root_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "timestamp":1704067200000000000,"signature":"base64:AAAA",
        "key_id":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}}}}}}"#,
        CASES[CASES.len() - 1].0
    );

    let receipt = Receipt::from_json(&json).expect("valid receipt");
    assert!(receipt.source_text_was_checked());
    assert_eq!(
        hex::encode(canonicalize_and_hash(&receipt.entry().metadata).expect("canonical")),
        MIXED_METADATA_HASH,
        "metadata rehashes differently after a round trip through Receipt"
    );
}
