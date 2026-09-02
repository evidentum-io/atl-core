//! RFC 8785 JSON Canonicalization Scheme
//!
//! Canonical JSON serialization, and the input constraints that make it mean
//! anything.
//!
//! This module implements RFC 8785 (JSON Canonicalization Scheme) to ensure
//! deterministic JSON serialization. This is critical for computing reproducible
//! hashes of metadata JSON objects across different systems and implementations.
//!
//! # Key Features
//!
//! - Object keys sorted by UTF-16 code units (not UTF-8 bytes), Section 3.2.3
//! - No whitespace between tokens, Section 3.2.1
//! - Minimal string escaping (only `\`, `"`, and control chars U+0000-U+001F),
//!   Section 3.2.2.2
//! - Numbers rendered by the ECMA-262 Section 7.1.12.1 algorithm, Section 3.2.2.3
//! - Non-ASCII Unicode characters output as UTF-8 (not escaped), Section 3.2.2.2
//!
//! # Section 3.1 is a precondition, and it is checked
//!
//! RFC 8785 Section 3.1 does not describe an output format; it constrains the
//! *input*, with three MUST requirements on "data to be canonicalized":
//!
//! > JSON objects MUST NOT exhibit duplicate property names
//!
//! > JSON string data MUST be expressible as Unicode
//!
//! > JSON number data MUST be expressible as IEEE 754 double-precision values
//!
//! and Section 3.2.2.3 adds that `NaN` and `Infinity` "MUST cause a
//! compliant implementation to terminate with an appropriate error".
//!
//! These constrain the *producer*, not the serializer, and they are not all
//! actionable in the same way. Where the RFC defines what the algorithm does
//! with offending input, this module does that; where it defines nothing, this
//! module refuses, because emitting bytes that a conformant reader would not
//! agree with -- and hashing them into a `metadata_hash` as *the* canonical
//! form -- is a split verdict on one receipt.
//!
//! Concretely: **numbers are normalized, never refused** (Appendix B notes (1)
//! and (2) say so outright, and Table 1 normalizes 2^68); **duplicate property
//! names are refused**, because neither RFC 8785 nor RFC 8259 Section 4 says
//! which occurrence wins, so two conformant readers can compute two different
//! hashes and both be right. [`canonicalize`] and [`canonicalize_and_hash`] are
//! fallible for the one case Section 3.2.2.3 does mandate an error -- `NaN` and
//! `Infinity` -- and the refusal names the [RFC 6901] JSON Pointer of the
//! offending node. See [`format_number`] for the full argument.
//!
//! The three constraints are enforced in three different places, because they
//! become visible at three different moments:
//!
//! | Constraint | Where it is caught | How |
//! |---|---|---|
//! | duplicate property names | [`check_unique_property_names`] | on the raw JSON *text*, the only place the duplicate still exists |
//! | strings expressible as Unicode | `serde_json`, at parse time | lone surrogates are rejected in both `\uXXXX` escapes and raw bytes; a `&str` cannot carry one |
//! | numbers expressible as IEEE 754 double | *not enforced, by design* | a number is **normalized** to its double's ECMA-262 spelling, never refused -- see [`format_number`] and Appendix B notes (1) and (2) |
//!
//! Duplicate names *cannot* be caught in [`canonicalize`]: by the time a
//! [`Value`] exists the parser has already discarded all but one of them
//! (`serde_json` keeps the last). The constraint is a property of the **byte
//! stream**, so the only place it can be enforced is on text, which is what
//! [`check_unique_property_names`] does and what
//! [`Receipt::from_json`](crate::core::receipt::Receipt::from_json) and
//! [`Receipt::from_slice`](crate::core::receipt::Receipt::from_slice) run.
//!
//! A `Receipt` produced any other way -- `serde_json::from_str`, `from_reader`,
//! `from_value` -- therefore carries no evidence that its bytes were ever
//! examined, and
//! [`ReceiptVerifier::verify`](crate::core::verify::ReceiptVerifier::verify)
//! declines to confirm it. That gate, not detection, is what makes the
//! guarantee hold on paths this crate cannot intercept.
//!
//! An earlier revision instead replaced `serde_json`'s own `Deserialize` impl
//! for `Value` on the `metadata` field with a hand-written visitor that
//! rejected duplicates during deserialization. It was removed: under
//! `serde_json/arbitrary_precision` -- which any crate in a consumer's
//! dependency graph can switch on, and Cargo then unifies onto this one --
//! `deserialize_any` delivers a non-integer number as a map keyed by the
//! private token `$serde_json::private::Number`. A hand-written visitor builds
//! an *object* there, so `1.5` becomes
//! `{"$serde_json::private::Number":"1.5"}`: every metadata hash silently
//! changes, and a document containing that literal object collides with one
//! containing the number. Buying earlier diagnostics with a dependency on
//! undocumented internals, at the risk of corrupting the one thing this crate
//! exists to reproduce exactly, is not a trade worth making.
//!
//! [RFC 6901]: https://www.rfc-editor.org/rfc/rfc6901
//!
//! # Numbers are only half ours
//!
//! RFC 8785 Section 3.2.2.3 builds on IEEE 754 double precision, so a JSON
//! number literal is protocol-visible twice: once when it is *parsed* into a
//! double and once when that double is *rendered* back. This module owns the
//! second half only. The first half belongs to the JSON parser that produced
//! the [`Value`], and it is not a free choice: `serde_json`'s default number
//! parser is a best-effort f64 fast path that misses the correctly rounded
//! double by one ULP for a large fraction of inputs, so this crate depends on
//! `serde_json` with its `float_roundtrip` feature enabled.
//!
//! Cargo unifies features, so any build that links `atl-core` gets the
//! correctly rounded parser. **A third-party implementation must make the same
//! choice**: two verifiers that read the same receipt bytes into different
//! doubles compute different `metadata_hash` values, and neither the RFC nor
//! this module can repair that after the fact.
//!
//! # Example
//!
//! ```rust
//! use atl_core::core::jcs::canonicalize;
//! use serde_json::json;
//!
//! let value = json!({"b": 2, "a": 1});
//! let canonical = canonicalize(&value)?;
//! assert_eq!(canonical, r#"{"a":1,"b":2}"#);
//! # Ok::<(), atl_core::AtlError>(())
//! ```

use std::collections::HashSet;
use std::fmt::Write as _;

use serde::de::{DeserializeSeed, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::{AtlError, AtlResult};

// ========== Input constraints (RFC 8785 Section 3.1) ==========

/// Build the error for an RFC 8785 Section 3.1 violation at `path`.
fn constraint_violation(path: &PathBuilder, reason: impl Into<String>) -> AtlError {
    AtlError::JcsInputConstraint { path: path.pointer().to_owned(), reason: reason.into() }
}

/// Accumulates the [RFC 6901] JSON Pointer of the node being visited.
///
/// Diagnostics without a location are close to useless on the nested metadata
/// this crate actually sees: "some number in here is too large" does not tell
/// an operator which field of which claim to fix.
///
/// [RFC 6901]: https://www.rfc-editor.org/rfc/rfc6901
struct PathBuilder(String);

impl PathBuilder {
    const fn new() -> Self {
        Self(String::new())
    }

    /// Descend into an object member. Returns the mark to pass to [`Self::leave`].
    fn enter_key(&mut self, key: &str) -> usize {
        let mark = self.0.len();
        self.0.push('/');
        // RFC 6901 Section 3: `~` is `~0` and `/` is `~1`, so a pointer stays
        // unambiguous for keys that contain either.
        for ch in key.chars() {
            match ch {
                '~' => self.0.push_str("~0"),
                '/' => self.0.push_str("~1"),
                _ => self.0.push(ch),
            }
        }
        mark
    }

    /// Descend into an array element. Returns the mark to pass to [`Self::leave`].
    fn enter_index(&mut self, index: usize) -> usize {
        let mark = self.0.len();
        // Cannot fail: writing to a `String` is infallible.
        let _ = write!(self.0, "/{index}");
        mark
    }

    /// Ascend back to the position recorded by an `enter_*` call.
    fn leave(&mut self, mark: usize) {
        self.0.truncate(mark);
    }

    /// The pointer to the current node; empty for the document root.
    fn pointer(&self) -> &str {
        &self.0
    }
}

/// State threaded through the duplicate-property-name scan.
///
/// The violation is carried here rather than inside the `serde` error because
/// `serde::de::Error` can only be constructed from a message: the structured
/// path would have to be re-parsed out of a string to be usable.
struct Scan {
    path: PathBuilder,
    violation: Option<AtlError>,
}

/// Visits every node of a JSON document, discarding it, and fails on the first
/// object that repeats a property name.
struct UniquePropertyNames<'a>(&'a mut Scan);

impl<'de> DeserializeSeed<'de> for UniquePropertyNames<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for UniquePropertyNames<'_> {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_i128<E>(self, _: i128) -> Result<(), E> {
        Ok(())
    }
    fn visit_u128<E>(self, _: u128) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let scan = self.0;
        let mut index = 0usize;
        loop {
            let mark = scan.path.enter_index(index);
            let element = seq.next_element_seed(UniquePropertyNames(scan))?;
            scan.path.leave(mark);
            if element.is_none() {
                return Ok(());
            }
            index += 1;
        }
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let scan = self.0;
        let mut seen: HashSet<String> = HashSet::new();

        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                let reason = format!(
                    "RFC 8785 Section 3.1: \"JSON objects MUST NOT exhibit duplicate \
                     property names\"; the property {key:?} appears more than once"
                );
                scan.violation = Some(constraint_violation(&scan.path, reason.clone()));
                return Err(A::Error::custom(reason));
            }

            let mark = scan.path.enter_key(&key);
            let outcome = map.next_value_seed(UniquePropertyNames(scan));
            scan.path.leave(mark);
            outcome?;
        }

        Ok(())
    }
}

/// Reject JSON text whose objects repeat a property name.
///
/// # This is the only place the constraint is decidable
///
/// `Receipt` derives `Deserialize` publicly, so `serde_json::from_str`,
/// `from_reader` and `from_value` all go around any constructor -- and
/// `from_value` is handed a `Value` whose duplicate an earlier parse already
/// discarded, so no amount of inspection downstream could recover it. Detection
/// therefore lives here, on text, and everything it cannot reach is handled by
/// provenance instead: see
/// [`SourceTextCheck`](crate::core::receipt::SourceTextCheck).
///
/// # Why this takes text and not a [`Value`]
///
/// By the time a `Value` exists the duplicate is gone: `serde_json` keeps the
/// last occurrence and silently discards the rest, so `{"x":1,"x":2}` and
/// `{"x":2}` are indistinguishable afterwards. RFC 8785 Section 3.1 forbids
/// the first document outright, and RFC 8259 Section 4 says the behaviour of
/// an implementation given repeated names "is unpredictable" -- last-wins is
/// `serde_json`'s choice, not a rule other parsers share. Two verifiers can
/// therefore hash two different objects out of one byte sequence. The only
/// place that is still visible is the text.
///
/// # Scope: the whole document, not just `metadata`
///
/// Only `entry.metadata` is JCS-canonicalized, so Section 3.1 formally binds
/// only that subtree. This function is nevertheless applied by
/// [`Receipt::from_json`](crate::core::receipt::Receipt::from_json) to the
/// entire receipt, for two reasons:
///
/// 1. **The hazard is not confined to `metadata`.** A receipt carrying
///    `"metadata_hash"` twice, or two `"root_hash"` values, is a document two
///    conformant readers can disagree about — one verifier checks the proof
///    against the first value, another against the second, and they publish
///    opposite verdicts over identical bytes. That is the same split-verdict
///    failure Section 3.1 exists to prevent, and there is no reading of ATL
///    v2.0 Section 4.2 under which such a receipt is well-formed.
/// 2. **Narrowing the scope would cost a second parser.** Checking only the
///    `metadata` subtree means locating it in the raw text before parsing,
///    i.e. writing an ad-hoc JSON scanner whose idea of where `metadata`
///    starts could itself disagree with `serde_json`'s. Rejecting at the
///    document level needs no such thing.
///
/// The trade-off is that this is *stricter* than RFC 8785 requires. It refuses
/// receipts that a JCS-only reading would accept, and it is deliberate: a
/// duplicate anywhere in an evidence document is a defect, not a style.
///
/// # Errors
///
/// * [`AtlError::JcsInputConstraint`] if any object repeats a property name.
///   `path` is the [RFC 6901] JSON Pointer of the *object* that repeats it
///   (empty for the document root).
/// * [`AtlError::Json`] if `json` is not well-formed JSON at all.
///
/// Trailing content after the first JSON value is *not* diagnosed here; that
/// is left to whichever typed parse follows, which reports it in its own
/// vocabulary.
///
/// [RFC 6901]: https://www.rfc-editor.org/rfc/rfc6901
///
/// # Example
///
/// ```rust
/// use atl_core::core::jcs::check_unique_property_names;
///
/// assert!(check_unique_property_names(r#"{"a":1,"b":{"c":2}}"#).is_ok());
/// assert!(check_unique_property_names(r#"{"a":1,"a":2}"#).is_err());
/// // Nested, and the error names where:
/// let err = check_unique_property_names(r#"{"m":{"x":1,"x":2}}"#).unwrap_err();
/// assert!(err.to_string().contains("/m"));
/// ```
pub fn check_unique_property_names(json: &str) -> AtlResult<()> {
    let mut scan = Scan { path: PathBuilder::new(), violation: None };
    let mut deserializer = serde_json::Deserializer::from_str(json);

    match UniquePropertyNames(&mut scan).deserialize(&mut deserializer) {
        Ok(()) => Ok(()),
        Err(e) => Err(scan.violation.unwrap_or(AtlError::Json(e))),
    }
}

// ========== Canonicalization ==========

/// Canonicalize a JSON value according to RFC 8785.
///
/// # Arguments
///
/// * `value` - A JSON value that satisfies the RFC 8785 Section 3.1 input
///   constraints
///
/// # Returns
///
/// Canonical UTF-8 string representation.
///
/// # Errors
///
/// Returns [`AtlError::JcsInputConstraint`], naming the [RFC 6901] JSON
/// Pointer of the offending node, for `NaN` or an infinity — the one case
/// RFC 8785 Section 3.2.2.3 says "MUST cause a compliant implementation to
/// terminate with an appropriate error". These are unreachable through
/// [`Value`] (`serde_json::Number` cannot hold one, and `serde_json` rejects
/// an out-of-range literal at parse time); the check is written anyway,
/// because a guarantee resting on a neighbouring crate's invariant should be
/// observable here rather than assumed.
///
/// **No number is refused for magnitude or precision.** A number is normalized
/// to the ECMA-262 Section 7.1.12.1 spelling of the double it denotes, so
/// `9007199254740993` canonicalizes to `9007199254740992` and 2^68 to
/// `295147905179352830000` — which is what RFC 8785 Appendix B Table 1 itself
/// requires. [`format_number`] records four rules written here that wrongly
/// refused numbers, so that none of them is reintroduced.
///
/// **Duplicate property names are not and cannot be diagnosed here**: a
/// `Value` no longer has any. Call [`check_unique_property_names`] on the JSON
/// text before parsing it.
///
/// [RFC 6901]: https://www.rfc-editor.org/rfc/rfc6901
///
/// # Example
///
/// ```rust
/// use atl_core::core::jcs::canonicalize;
/// use serde_json::json;
///
/// let value = json!({"zebra": 1, "apple": 2});
/// assert_eq!(canonicalize(&value)?, r#"{"apple":2,"zebra":1}"#);
///
/// // 2^53 + 1 denotes the double 2^53, and is normalized to it -- not refused.
/// let beyond_precision = serde_json::from_str::<serde_json::Value>("9007199254740993")?;
/// assert_eq!(canonicalize(&beyond_precision)?, "9007199254740992");
/// # Ok::<(), atl_core::AtlError>(())
/// ```
pub fn canonicalize(value: &Value) -> AtlResult<String> {
    let mut output = String::new();
    let mut path = PathBuilder::new();
    canonicalize_impl(value, &mut path, &mut output)?;
    Ok(output)
}

/// Canonicalize JSON and compute SHA256 hash.
///
/// Convenience function combining canonicalization with hashing.
/// This is useful for computing content identifiers or integrity checks.
///
/// # Arguments
///
/// * `value` - JSON value to canonicalize and hash
///
/// # Returns
///
/// 32-byte SHA256 hash of the canonical form.
///
/// # Errors
///
/// Whatever [`canonicalize`] returns. A hash is never computed over an input
/// that has no canonical form: there is no byte string to hash, and inventing
/// one would produce a `metadata_hash` no other implementation can reproduce.
///
/// # Example
///
/// ```rust
/// use atl_core::core::jcs::canonicalize_and_hash;
/// use serde_json::json;
///
/// let value = json!({"key": "value"});
/// assert_eq!(canonicalize_and_hash(&value)?, canonicalize_and_hash(&value)?);
/// # Ok::<(), atl_core::AtlError>(())
/// ```
pub fn canonicalize_and_hash(value: &Value) -> AtlResult<[u8; 32]> {
    let canonical = canonicalize(value)?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(hasher.finalize().into())
}

/// Internal implementation that builds the canonical string.
fn canonicalize_impl(value: &Value, path: &mut PathBuilder, output: &mut String) -> AtlResult<()> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(b) => output.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => format_number(n, path, output)?,
        Value::String(s) => escape_string(s, output),
        Value::Array(arr) => {
            output.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    output.push(',');
                }
                let mark = path.enter_index(i);
                canonicalize_impl(item, path, output)?;
                path.leave(mark);
            }
            output.push(']');
        }
        Value::Object(obj) => {
            output.push('{');

            // Sort keys by UTF-16 code units as per RFC 8785
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort_by(|a, b| compare_utf16(a, b));

            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    output.push(',');
                }
                escape_string(key, output);
                output.push(':');
                if let Some(val) = obj.get(*key) {
                    let mark = path.enter_key(key);
                    canonicalize_impl(val, path, output)?;
                    path.leave(mark);
                }
            }
            output.push('}');
        }
    }

    Ok(())
}

/// Compare two strings by UTF-16 code units (RFC 8785 requirement).
///
/// This is different from standard UTF-8 byte comparison. We need to compare
/// the UTF-16 code unit sequences.
fn compare_utf16(a: &str, b: &str) -> std::cmp::Ordering {
    let a_utf16: Vec<u16> = a.encode_utf16().collect();
    let b_utf16: Vec<u16> = b.encode_utf16().collect();
    a_utf16.cmp(&b_utf16)
}

/// Format a JSON number according to RFC 8785 Section 3.2.2.3.
///
/// **Numbers are never refused for magnitude or precision.** Every number is
/// converted to the double it denotes and rendered by [`format_float`]; the
/// only refusal is the `NaN`/`Infinity` one Section 3.2.2.3 mandates, and no
/// JSON text can reach it (`serde_json` rejects an out-of-range literal at
/// parse time, and `Number` cannot hold a non-finite double).
///
/// So `9007199254740993` canonicalizes to `9007199254740992`, and
/// `295147905179352825856` (2^68) to `295147905179352830000`.
///
/// # Section 3.1 does not say what it looks like it says
///
/// "JSON number data MUST be expressible as IEEE 754 double-precision values"
/// reads like an instruction to this function. It is not: Section 3.1 is
/// addressed to whoever *creates* the input ("Data to be canonically
/// serialized is usually created by..."), and RFC 8785 Appendix B settles the
/// question for the algorithm in two notes:
///
/// > (1) For maximum compliance with the ECMAScript "JSON" object, values that
/// > are to be interpreted as true integers SHOULD be in the range
/// > -9007199254740991 to 9007199254740991. However, **how numbers are used in
/// > applications does not affect the JCS algorithm.**
/// >
/// > (2) Although a set of specific integers like 2**68 could be regarded as
/// > having extended precision, **the JCS/ECMAScript number serialization
/// > algorithm does not take this into consideration.**
///
/// The RFC then does exactly that in its own Table 1, where the row
/// `4430000000000000` -- the double 2^68, exactly `295147905179352825856` --
/// is required to serialize as `295147905179352830000`. The specification
/// normalizes a large integer; it does not reject one. Both of those rows are
/// frozen in `test_data/vectors/jcs/cases.json`.
///
/// # Four rules that were written here and are all wrong
///
/// Recorded so none of them is reintroduced. The first three narrowed the
/// accepted set; the fourth is the idea that any of them belonged here.
///
/// 1. **"Reject past `Number.MAX_SAFE_INTEGER`."** The canonical form of an
///    ordinary double is often an integer literal above 2^53 -- the double
///    `9.011805220822756e15` canonicalizes to `9011805220822756` -- so a
///    magnitude rule refuses this module's own output.
/// 2. **"Reject an integer whose digits are not its double's ECMA-262
///    spelling."** This refuses 2^62 and 2^60, which are exact doubles: a
///    claimed inability where the ability plainly exists, so a receipt holding
///    a byte count of that size came back unverified here and valid from a
///    JavaScript verifier.
/// 3. **"Reject an integer that is not exactly representable."** This refuses
///    `4611686018427388000`, which is *not* an exact double yet is precisely
///    the spelling required for 2^62 -- again refusing our own output.
/// 4. **"Reject numbers at all."** The three above are variations on one
///    mistake: reading a constraint on the data's *producer* as a duty of the
///    *serializer*. Section 3.2.2.3 names exactly one condition under which a
///    compliant implementation must terminate with an error, and it is
///    `NaN`/`Infinity`. There is no other.
///
/// # Why duplicate property names still are refused, and numbers are not
///
/// The asymmetry is not inconsistency; it is the difference between a rule the
/// RFC completes and one it does not.
///
/// For numbers the specification says what the algorithm *does*: serialize the
/// double. Every conformant implementation reaches the same bytes for
/// `9007199254740993`, so normalizing is interoperable and refusing is merely
/// unhelpful.
///
/// For duplicate property names the specification defines no resolution at
/// all, and RFC 8259 Section 4 explicitly leaves the behaviour unpredictable.
/// One conformant reader may keep the first value and another the last, and
/// both are right -- so the same bytes yield two different `metadata_hash`
/// values and two honest, opposite verdicts. Refusal is the only correct answer
/// where the specification does not supply a single one. See
/// [`check_unique_property_names`], and
/// [`SourceTextCheck`](crate::core::receipt::SourceTextCheck) for the paths
/// where even that is impossible.
fn format_number(n: &serde_json::Number, path: &PathBuilder, output: &mut String) -> AtlResult<()> {
    let Some(as_double) = n.as_f64() else {
        // Reachable only when a dependent enables `serde_json/arbitrary_precision`,
        // which lets a `Number` hold a literal whose text cannot be read back as
        // a double at all. There is no double to serialize, so there is nothing
        // to render -- distinct from a value that merely loses precision, which
        // is normalized like any other.
        return Err(constraint_violation(
            path,
            format!("the number {n} cannot be read as an IEEE 754 double-precision value"),
        ));
    };

    // Integer-to-double conversion in `as_f64` is a Rust `as` cast, which
    // rounds to nearest with ties to even -- the same correctly rounded result
    // as parsing the literal, for negative values too.
    format_float(as_double, path, output)
}

/// Format a double exactly as ECMA-262 Section 7.1.12.1 `Number::toString`.
///
/// RFC 8785 Section 3.2.2.3 requires that algorithm verbatim, "including the
/// Note 2 enhancement", and deliberately does not restate it. Two of its rules
/// are not shared by Rust's `f64` Display, and both are protocol-visible
/// because every byte of the canonical form goes into `metadata_hash`:
///
/// * **Exponential form.** ECMA-262 switches to `<mantissa>e<sign><exponent>`
///   once the decimal exponent reaches 21 or drops to -7, and writes the `+`
///   for a positive exponent: `1e+21`, `1.7976931348623157e+308`, `5e-324`.
///   Rust's Display is always positional, so it spells those out in full: 22,
///   309 and 326 characters respectively.
/// * **Tie to even.** Where two shortest round-tripping decimals are exactly
///   equidistant from the double, ECMA-262 Note 2 takes the even one. Rust
///   takes the larger. RFC 8785 Appendix B note (4) calls this row out by
///   name: `0x43143ff3c1cb0959` is exactly `1424953923781206.25` and
///   canonicalizes to `1424953923781206.2`, not `...06.3`.
///
/// So this delegates to `ryu-js`, whose documented contract *is* the ECMAScript
/// algorithm, rather than to a std formatter that only promises to round-trip.
/// The output is always valid JSON number syntax: never a leading `+`, never a
/// capital `E`, never a trailing `.`.
fn format_float(f: f64, path: &PathBuilder, output: &mut String) -> AtlResult<()> {
    // Unreachable through `serde_json::Value`: `Number` cannot hold a
    // non-finite double. RFC 8785 Section 3.2.2.3 nevertheless requires a
    // conformant implementation to terminate with an error here, so the
    // refusal is written down and tested rather than left resting on another
    // crate's invariant. The previous code emitted `null` at this point --
    // a valid-looking canonical form for a value that has none.
    if !f.is_finite() {
        return Err(constraint_violation(
            path,
            "RFC 8785 Section 3.2.2.3: NaN and Infinity MUST cause a compliant \
             implementation to terminate with an error",
        ));
    }

    let mut buffer = ryu_js::Buffer::new();
    output.push_str(buffer.format_finite(f));
    Ok(())
}

/// Escape a JSON string according to RFC 8785.
///
/// Rules:
/// - Escape `\` as `\\`
/// - Escape `"` as `\"`
/// - Escape control characters U+0000-U+001F as `\uXXXX`
/// - Do NOT escape non-ASCII Unicode characters (output as UTF-8)
///
/// RFC 8785 Section 3.1's "JSON string data MUST be expressible as Unicode" is
/// not checked here and does not need to be: the argument is a `&str`, which
/// is valid UTF-8 by construction, and UTF-8 has no encoding for an unpaired
/// surrogate. The constraint is enforced one layer earlier, by the parser --
/// `serde_json` rejects a lone surrogate both as a `\uXXXX` escape ("lone
/// leading surrogate in hex escape") and as raw CESU-8 bytes ("invalid unicode
/// code point"). `tests/rfc_vectors.rs` pins that behaviour so the guarantee is
/// observable rather than assumed.
fn escape_string(s: &str, output: &mut String) {
    output.push('"');

    for ch in s.chars() {
        match ch {
            '"' => output.push_str(r#"\""#),
            '\\' => output.push_str(r"\\"),
            '\u{0008}' => output.push_str(r"\b"),
            '\u{000C}' => output.push_str(r"\f"),
            '\n' => output.push_str(r"\n"),
            '\r' => output.push_str(r"\r"),
            '\t' => output.push_str(r"\t"),
            // Control characters U+0000-U+001F (except those handled above)
            '\u{0000}'..='\u{001F}' => {
                // Cannot fail: writing to a `String` is infallible.
                let _ = write!(output, r"\u{:04x}", ch as u32);
            }
            // All other characters (including non-ASCII) output as-is
            _ => output.push(ch),
        }
    }

    output.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Canonicalize an input the test asserts is canonicalizable.
    ///
    /// The fallible signature is the point of this module, so the tests that
    /// are *about* output shape unwrap it here rather than repeating `.expect`
    /// on every line; the tests that are about refusal call `canonicalize`
    /// directly and assert on the error.
    fn jcs(value: &Value) -> String {
        canonicalize(value).expect("input satisfies RFC 8785 Section 3.1")
    }

    fn jcs_hash(value: &Value) -> [u8; 32] {
        canonicalize_and_hash(value).expect("input satisfies RFC 8785 Section 3.1")
    }

    #[test]
    fn test_null() {
        assert_eq!(jcs(&json!(null)), "null");
    }

    #[test]
    fn test_bool() {
        assert_eq!(jcs(&json!(true)), "true");
        assert_eq!(jcs(&json!(false)), "false");
    }

    #[test]
    fn test_integers() {
        assert_eq!(jcs(&json!(0)), "0");
        assert_eq!(jcs(&json!(42)), "42");
        assert_eq!(jcs(&json!(-42)), "-42");
        assert_eq!(jcs(&json!(1000)), "1000");
    }

    #[test]
    fn test_floats() {
        assert_eq!(jcs(&json!(1.0)), "1");
        assert_eq!(jcs(&json!(1.5)), "1.5");
        assert_eq!(jcs(&json!(0.0)), "0");
        assert_eq!(jcs(&json!(-0.0)), "0");
        assert_eq!(jcs(&json!(1.23)), "1.23");
    }

    #[test]
    fn test_string_basic() {
        assert_eq!(jcs(&json!("hello")), r#""hello""#);
        assert_eq!(jcs(&json!("")), r#""""#);
    }

    #[test]
    fn test_string_escaping() {
        assert_eq!(jcs(&json!("a\"b")), r#""a\"b""#);
        assert_eq!(jcs(&json!("a\\b")), r#""a\\b""#);
        assert_eq!(jcs(&json!("a\nb")), r#""a\nb""#);
        assert_eq!(jcs(&json!("a\rb")), r#""a\rb""#);
        assert_eq!(jcs(&json!("a\tb")), r#""a\tb""#);
    }

    #[test]
    fn test_control_characters() {
        assert_eq!(jcs(&json!("\u{0000}")), r#""\u0000""#);
        assert_eq!(jcs(&json!("\u{0001}")), r#""\u0001""#);
        assert_eq!(jcs(&json!("\u{001F}")), r#""\u001f""#);
    }

    #[test]
    fn test_unicode_not_escaped() {
        // Non-ASCII Unicode should NOT be escaped
        assert_eq!(jcs(&json!("café")), r#""café""#);
        assert_eq!(jcs(&json!("日本語")), r#""日本語""#);
        assert_eq!(jcs(&json!("emoji😀")), r#""emoji😀""#);
    }

    #[test]
    fn test_empty_array() {
        assert_eq!(jcs(&json!([])), "[]");
    }

    #[test]
    fn test_array() {
        assert_eq!(jcs(&json!([1, 2, 3])), "[1,2,3]");
        assert_eq!(jcs(&json!(["a", "b", "c"])), r#"["a","b","c"]"#);
    }

    #[test]
    fn test_nested_array() {
        assert_eq!(jcs(&json!([[1, 2], [3, 4]])), "[[1,2],[3,4]]");
    }

    #[test]
    fn test_empty_object() {
        assert_eq!(jcs(&json!({})), "{}");
    }

    #[test]
    fn test_object_key_ordering() {
        let input = json!({"zebra": 1, "apple": 2});
        assert_eq!(jcs(&input), r#"{"apple":2,"zebra":1}"#);
    }

    #[test]
    fn test_object_multiple_keys() {
        let input = json!({"b": 2, "a": 1, "c": 3});
        assert_eq!(jcs(&input), r#"{"a":1,"b":2,"c":3}"#);
    }

    #[test]
    fn test_nested_object() {
        let input = json!({"b": {"d": 1, "c": 2}, "a": 3});
        assert_eq!(jcs(&input), r#"{"a":3,"b":{"c":2,"d":1}}"#);
    }

    #[test]
    fn test_complex_structure() {
        let input = json!({
            "z": [1, 2, 3],
            "a": {
                "nested": true,
                "array": [{"b": 2}, {"a": 1}]
            },
            "m": null
        });
        let canonical = jcs(&input);
        assert_eq!(
            canonical,
            r#"{"a":{"array":[{"b":2},{"a":1}],"nested":true},"m":null,"z":[1,2,3]}"#
        );
    }

    #[test]
    fn test_utf16_sort_order() {
        // Test UTF-16 code unit ordering
        // These characters have different sort orders in UTF-8 vs UTF-16
        let input = json!({
            "é": 1,      // U+00E9 (single code unit)
            "e": 2,      // U+0065 (single code unit)
            "ē": 3,      // U+0113 (single code unit)
        });
        let canonical = jcs(&input);

        // In UTF-16, these sort as: e (U+0065) < é (U+00E9) < ē (U+0113)
        assert_eq!(canonical, r#"{"e":2,"é":1,"ē":3}"#);
    }

    #[test]
    fn test_utf16_sort_order_complex() {
        // More complex UTF-16 sorting test
        let input = json!({
            "\u{1F600}": "emoji",  // U+1F600 (surrogate pair in UTF-16)
            "z": "letter",
            "a": "first",
        });
        let canonical = jcs(&input);

        // In UTF-16, basic ASCII comes before surrogate pairs
        // So order is: a < z < emoji
        assert!(canonical.starts_with(r#"{"a":"first""#));
    }

    #[test]
    fn test_no_whitespace() {
        let input = json!({"key": "value", "number": 42});
        let canonical = jcs(&input);
        assert!(!canonical.contains(' '));
        assert!(!canonical.contains('\n'));
        assert!(!canonical.contains('\t'));
    }

    #[test]
    fn test_hash_determinism() {
        let input = json!({"key": "value"});
        let hash1 = jcs_hash(&input);
        let hash2 = jcs_hash(&input);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_different_values() {
        let input1 = json!({"key": "value1"});
        let input2 = json!({"key": "value2"});
        let hash1 = jcs_hash(&input1);
        let hash2 = jcs_hash(&input2);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_key_order_independence() {
        // Same data, different key order in source
        let input1 = json!({"a": 1, "b": 2});
        let input2 = json!({"b": 2, "a": 1});
        let hash1 = jcs_hash(&input1);
        let hash2 = jcs_hash(&input2);
        // After canonicalization, hashes should be identical
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_rfc8785_examples() {
        // The number list from the RFC 8785 Section 3.2.2 worked example. Rust's
        // own literal parser is correctly rounded, so these literals denote the
        // doubles the RFC means; the same example read from JSON *text* is a
        // frozen vector in `test_data/vectors/jcs/cases.json`, which is where the
        // parser's behaviour is pinned.
        #[allow(clippy::excessive_precision)]
        let input = json!({"numbers": [333_333_333.333_333_29, 1e+30, 4.5, 6, 2e-3, 0.000_002]});

        assert_eq!(jcs(&input), r#"{"numbers":[333333333.3333333,1e+30,4.5,6,0.002,0.000002]}"#);
    }

    #[test]
    fn test_exponential_notation_thresholds() {
        // ECMA-262 Section 7.1.12.1 stays positional while the decimal exponent
        // is in -6..=21 and switches to exponential outside it, writing the sign
        // of the exponent in both directions.
        assert_eq!(jcs(&json!(1e20)), "100000000000000000000");
        assert_eq!(jcs(&json!(1e21)), "1e+21");
        assert_eq!(jcs(&json!(1e30)), "1e+30");
        assert_eq!(jcs(&json!(f64::MAX)), "1.7976931348623157e+308");

        assert_eq!(jcs(&json!(1e-6)), "0.000001");
        assert_eq!(jcs(&json!(1e-7)), "1e-7");
        assert_eq!(jcs(&json!(1e-30)), "1e-30");
        assert_eq!(jcs(&json!(5e-324)), "5e-324");

        // Not near either threshold: still positional, no exponent.
        assert_eq!(jcs(&json!(1.23e10)), "12300000000");
    }

    #[test]
    fn test_shortest_digit_tie_breaks_to_even() {
        // RFC 8785 Appendix B note (4): exactly 1424953923781206.25, equidistant
        // between two shortest representations. ECMA-262 Note 2 takes the even
        // digit; Rust's `f64` Display takes the larger one.
        let exact_tie = f64::from_bits(0x4314_3ff3_c1cb_0959);
        assert_eq!(exact_tie.to_string(), "1424953923781206.3");
        assert_eq!(jcs(&json!(exact_tie)), "1424953923781206.2");
    }

    #[test]
    fn test_canonical_numbers_are_valid_json() {
        // ECMA-262 spells exponents `e+21`, which JSON accepts, but its
        // `Infinity` and `NaN` spellings are not JSON at all -- and cannot arise
        // here, because `serde_json::Number` cannot hold them.
        for value in [1e21, 1e-7, f64::MAX, f64::MIN_POSITIVE, -0.0, 0.0, -1.5] {
            let canonical = jcs(&json!(value));
            let reparsed: Value = serde_json::from_str(&canonical).expect("valid JSON number");
            assert_eq!(
                reparsed.as_f64().expect("a number").to_bits(),
                if value == 0.0 { 0.0_f64 } else { value }.to_bits(),
                "{canonical} did not survive a JSON round trip"
            );
        }
    }

    #[test]
    fn test_mixed_types_in_array() {
        let input = json!([null, true, false, 42, "string", [], {}]);
        let canonical = jcs(&input);
        assert_eq!(canonical, r#"[null,true,false,42,"string",[],{}]"#);
    }

    #[test]
    fn test_deeply_nested() {
        let input = json!({
            "level1": {
                "level2": {
                    "level3": {
                        "value": 42
                    }
                }
            }
        });
        let canonical = jcs(&input);
        assert_eq!(canonical, r#"{"level1":{"level2":{"level3":{"value":42}}}}"#);
    }

    #[test]
    fn test_array_with_objects() {
        let input = json!([
            {"b": 2, "a": 1},
            {"d": 4, "c": 3}
        ]);
        let canonical = jcs(&input);
        assert_eq!(canonical, r#"[{"a":1,"b":2},{"c":3,"d":4}]"#);
    }

    #[test]
    fn test_string_with_quotes_and_backslashes() {
        let input = json!(r#"He said "Hi!" and used \\ backslashes"#);
        let canonical = jcs(&input);
        assert_eq!(canonical, r#""He said \"Hi!\" and used \\\\ backslashes""#);
    }

    #[test]
    fn test_all_control_characters() {
        // Test all control characters from U+0000 to U+001F
        for code in 0x00..=0x1F {
            let ch = char::from_u32(code).unwrap();
            let input = json!(format!("test{}end", ch));
            let canonical = jcs(&input);

            // Verify it contains escaped form (except special cases)
            match ch {
                '\u{0008}' => assert!(canonical.contains(r"\b")),
                '\u{0009}' => assert!(canonical.contains(r"\t")),
                '\u{000A}' => assert!(canonical.contains(r"\n")),
                '\u{000C}' => assert!(canonical.contains(r"\f")),
                '\u{000D}' => assert!(canonical.contains(r"\r")),
                _ => assert!(canonical.contains(r"\u00")),
            }
        }
    }

    #[test]
    fn test_canonicalize_is_deterministic() {
        let input = json!({
            "random": [1, 2, 3, 4, 5],
            "nested": {"z": 26, "a": 1, "m": 13}
        });

        let result1 = jcs(&input);
        let result2 = jcs(&input);
        let result3 = jcs(&input);

        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
    }

    #[test]
    fn test_empty_string_in_object() {
        let input = json!({"": "empty key", "a": "normal key"});
        let canonical = jcs(&input);
        assert_eq!(canonical, r#"{"":"empty key","a":"normal key"}"#);
    }

    // ========== RFC 8785 Section 3.1 input constraints ==========

    /// Pull the pointer and reason out of the one error variant this module
    /// raises, failing loudly on any other.
    fn constraint(err: AtlError) -> (String, String) {
        match err {
            AtlError::JcsInputConstraint { path, reason } => (path, reason),
            other => panic!("expected a Section 3.1 refusal, got {other:?}"),
        }
    }

    /// **Numbers are normalized, never refused.** RFC 8785 Appendix B note (2)
    /// says the algorithm "does not take into consideration" that an integer
    /// like 2^68 could be regarded as having extended precision, and Table 1
    /// then requires that very double to serialize as `295147905179352830000`.
    /// Refusing here would diverge from the RFC's own published table.
    #[test]
    fn test_integers_beyond_double_precision_are_normalised_not_refused() {
        for (written, canonical) in [
            // 2^53 + 1: the smallest integer no double holds. Denotes 2^53.
            ("9007199254740993", "9007199254740992"),
            // 2^68 exactly -- RFC 8785 Appendix B Table 1, row 4430000000000000.
            ("295147905179352825856", "295147905179352830000"),
            ("18446744073709551615", "18446744073709552000"),
            ("1756812345678901234", "1756812345678901200"),
            ("-9223372036854775808", "-9223372036854776000"),
        ] {
            let value: Value = serde_json::from_str(written).expect("valid JSON");
            assert_eq!(canonicalize(&value).expect(written), canonical, "{written}");
        }
    }

    /// The whole safe-integer range is emitted verbatim, so ordinary metadata
    /// is byte-identical to what a naive implementation produces.
    #[test]
    fn test_every_safe_integer_is_emitted_verbatim() {
        for i in [0_i64, 1, -1, 42, -42, 1000, 9_007_199_254_740_991, -9_007_199_254_740_991] {
            assert_eq!(jcs(&json!(i)), i.to_string());
        }
    }

    /// Normalization reaches a fixed point in one step, for every shape of
    /// integer input: exact doubles written non-canonically, the spellings
    /// those produce, and integers no double holds.
    #[test]
    fn test_integer_normalisation_is_a_fixed_point() {
        for literal in [
            "9007199254740993",
            "295147905179352825856",
            "4611686018427387904", // 2^62, exact
            "4611686018427388000", // its canonical spelling, not itself exact
            "1152921504606846976", // 2^60, exact
            "9011805220822756",
            "9007199254740992",
            "1000000000000000000",
            "18446744073709551615",
        ] {
            let once =
                canonicalize(&serde_json::from_str::<Value>(literal).unwrap()).expect(literal);
            let reparsed: Value = serde_json::from_str(&once).expect("canonical form is JSON");
            assert_eq!(jcs(&reparsed), once, "{literal} is not a fixed point");
        }
    }

    /// An exact double written with digits that are not its ECMA-262 spelling
    /// is normalized like any other number. Refusing these was one of four
    /// wrong rules recorded on `format_number`; it made this crate report
    /// `untrusted` for receipts a JavaScript verifier reports valid.
    #[test]
    fn test_exact_doubles_are_normalised() {
        for (written, canonical) in [
            (4_611_686_018_427_387_904_i64, "4611686018427388000"), // 2^62
            (1_152_921_504_606_846_976, "1152921504606847000"),     // 2^60
            (-4_611_686_018_427_387_904, "-4611686018427388000"),
        ] {
            assert_eq!(jcs(&json!(written)), canonical, "{written}");
        }
    }

    /// The pointer machinery is tested directly rather than through
    /// `canonicalize`, because after numbers stopped being refused there is no
    /// longer a *reachable* refusal inside `canonicalize_impl` to carry a
    /// pointer out of: `NaN`/`Infinity` cannot occur in a `Value`, and the
    /// `as_f64() == None` arm needs `serde_json/arbitrary_precision`, which a
    /// dependent can turn on by feature unification but this crate cannot
    /// reach on its own. The plumbing is kept for that case and for the
    /// refusals that do fire (duplicate names, both layers), so it is pinned
    /// here instead of being left implied by a test that no longer exercises it.
    #[test]
    fn test_json_pointers_follow_rfc_6901() {
        let mut path = PathBuilder::new();
        assert_eq!(path.pointer(), "", "the document root is the empty pointer");

        let outer = path.enter_key("a");
        let middle = path.enter_key("b/c");
        assert_eq!(path.pointer(), "/a/b~1c", "RFC 6901 Section 3: `/` is `~1`");

        let inner = path.enter_index(2);
        assert_eq!(path.pointer(), "/a/b~1c/2");

        path.leave(inner);
        path.leave(middle);
        let tilde = path.enter_key("a~b");
        assert_eq!(path.pointer(), "/a/a~0b", "RFC 6901 Section 3: `~` is `~0`");

        path.leave(tilde);
        path.leave(outer);
        assert_eq!(path.pointer(), "", "every descent is undone by its mark");
    }

    /// The one refusal RFC 8785 Section 3.2.2.3 mandates, reached the only way
    /// it can be: a `Value` cannot carry a non-finite double, and neither can
    /// any JSON text (`serde_json` rejects an out-of-range literal at parse
    /// time). The guarantee is written down rather than left resting on those
    /// two invariants.
    #[test]
    fn test_non_finite_refusal_carries_the_pointer_it_was_given() {
        let mut path = PathBuilder::new();
        let mark = path.enter_key("claims");
        let inner = path.enter_index(3);

        let mut output = String::new();
        let (pointer, reason) = constraint(format_float(f64::NAN, &path, &mut output).unwrap_err());
        assert_eq!(pointer, "/claims/3");
        assert!(reason.contains("3.2.2.3"), "{reason}");
        assert!(output.is_empty());

        path.leave(inner);
        path.leave(mark);
    }

    #[test]
    fn test_canonicalize_and_hash_agree_on_what_they_accept() {
        // Normalized, not refused -- and the hash is over the normalized bytes.
        let value: Value = serde_json::from_str(r#"{"n":9007199254740993}"#).unwrap();
        assert_eq!(canonicalize(&value).unwrap(), r#"{"n":9007199254740992}"#);

        let mut hasher = Sha256::new();
        hasher.update(r#"{"n":9007199254740992}"#.as_bytes());
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(canonicalize_and_hash(&value).unwrap(), expected);
    }

    // ========== Duplicate property names ==========

    /// The reason [`check_unique_property_names`] takes text: after parsing,
    /// the duplicate is simply gone, and no check on a `Value` could ever see it.
    #[test]
    fn test_duplicates_are_already_invisible_in_a_parsed_value() {
        let collapsed: Value = serde_json::from_str(r#"{"x":1,"x":2}"#).unwrap();
        assert_eq!(collapsed, json!({"x": 2}));
        assert_eq!(jcs(&collapsed), r#"{"x":2}"#);
    }

    #[test]
    fn test_unique_property_names_accepts_well_formed_documents() {
        for ok in [
            r#"{}"#,
            r#"{"a":1,"b":2}"#,
            r#"{"a":{"a":1},"b":[{"a":1},{"a":2}]}"#,
            r#"[1,"two",null,true,{"k":[]}]"#,
            r#"null"#,
            r#"9007199254740993"#,
        ] {
            assert!(check_unique_property_names(ok).is_ok(), "{ok} should be accepted");
        }
    }

    #[test]
    fn test_duplicate_property_name_at_the_root_is_refused() {
        let (path, reason) =
            constraint(check_unique_property_names(r#"{"x":1,"x":2}"#).unwrap_err());
        assert_eq!(path, "");
        assert!(reason.contains("duplicate"), "{reason}");
        assert!(reason.contains("\"x\""), "{reason}");
    }

    #[test]
    fn test_duplicate_property_name_is_located_however_deep() {
        let json = r#"{"entry":{"metadata":{"claims":[{"v":1},{"v":1,"v":2}]}}}"#;
        let (path, _) = constraint(check_unique_property_names(json).unwrap_err());
        assert_eq!(path, "/entry/metadata/claims/1");
    }

    #[test]
    fn test_duplicate_detection_reports_malformed_json_as_a_json_error() {
        let err = check_unique_property_names("{not json").unwrap_err();
        assert!(matches!(err, AtlError::Json(_)), "got {err:?}");
    }

    /// RFC 8785 Section 3.1: "JSON string data MUST be expressible as Unicode."
    ///
    /// This one is enforced by the parser, not by this module, so the guarantee
    /// is pinned here instead of assumed. An unpaired surrogate has no UTF-8
    /// encoding, so it cannot survive into a `&str` in the first place; what
    /// has to be refused is the two ways it can be *written*.
    #[test]
    fn test_lone_surrogates_never_reach_canonicalization() {
        for escaped in [r#""\ud800""#, r#""\udc00""#, r#""\ud800x""#, r#"{"k":"\udfff"}"#] {
            assert!(
                serde_json::from_str::<Value>(escaped).is_err(),
                "{escaped}: a lone surrogate escape must be refused at parse time"
            );
        }

        // The same code point written as raw CESU-8 bytes (ED A0 80).
        let raw: &[u8] = &[b'"', 0xED, 0xA0, 0x80, b'"'];
        assert!(serde_json::from_slice::<Value>(raw).is_err());

        // A well-formed surrogate *pair* is an ordinary character and passes.
        let paired: Value = serde_json::from_str(r#""😀""#).unwrap();
        assert_eq!(jcs(&paired), "\"\u{1F600}\"");
    }
}
