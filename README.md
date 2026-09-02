# atl-core

Pure cryptographic library for ATL Protocol v2.0.

## Documentation

Full documentation is available at:

**https://atl-protocol.org/implementations/atl-core**

## JSON canonicalization is RFC 8785 (read this before writing another verifier)

`metadata_hash` is `SHA-256(JCS(metadata))`, so every byte of the canonical
form is protocol-visible — and so is the *parse* that produced the values
being canonicalized. Both halves are requirements, and only one of them lives
in this crate:

- **Rendering.** RFC 8785 §3.2.2.3 requires the ECMA-262 §7.1.12.1
  number-to-string algorithm verbatim, "including the Note 2 enhancement".
  Rust's `f64` Display is *not* that algorithm — it never switches to
  exponential notation (`1e+21` becomes 22 digits) and it breaks shortest-digit
  ties away from zero rather than to even. This crate takes the formatter from
  `ryu-js`, whose documented contract is the ECMAScript algorithm.
- **Parsing.** RFC 8785 §3.1 requires number data to be expressible as IEEE 754
  doubles, which makes "which double does this literal denote" part of the
  hash. `serde_json`'s default number parser is a best-effort fast path that
  misses the correctly rounded double by one ULP for a large share of inputs —
  including RFC 8785's own example, `333333333.33333329`. This crate therefore
  depends on `serde_json` with **`float_roundtrip`**, and Cargo's feature
  unification carries that to every build linking `atl-core`.

- **Input constraints.** RFC 8785 §3.1 states three MUSTs on the data *being*
  canonicalized. They bind the data's *producer*, not the serializer, and this
  crate treats them accordingly.

  **Numbers are normalised, never refused.** Appendix B notes (1) and (2) say
  the algorithm ignores how numbers are used, and Table 1 requires the double
  2^68 to serialize as `295147905179352830000` rather than be rejected. So
  `9007199254740993` canonicalizes to `9007199254740992`. The one refusal
  §3.2.2.3 mandates is `NaN`/`Infinity`, which no JSON text can produce.

  **Duplicate property names are refused**, because neither RFC 8785 nor
  RFC 8259 §4 says which occurrence wins — two conformant readers can compute
  two different hashes from identical bytes and both be right, and refusal is
  the only correct answer where the specification supplies no single one.
  `Receipt::from_json` and `Receipt::from_slice` scan the raw text and refuse.

  **That constraint is a property of a byte stream**, so no API taking a parsed
  structure can check it — `serde_json::from_str::<Receipt>` collapses the
  duplicate before this crate sees it, and `from_value` is handed a value where
  it is already gone. Such a receipt is *declined*, not rejected: it carries no
  record that its bytes were examined, and the verifier reports "not evaluated"
  rather than "invalid". Nothing was compared, so nothing was disproved. A
  producer that assembles receipts itself uses `ReceiptBuilder` and states that
  provenance at `.build(...)`. There is no way to pass another receipt's marker
  through: the only public reader answers a `bool`, every `Receipt` field is
  private behind a shared-reference accessor, and no public method takes a
  `Receipt` and returns a `Receipt` — so a receipt cannot be edited, or rebuilt
  by method, into holding content its marker never covered.

**Any independent implementation must do the same on both sides.** Two
verifiers that read the same receipt bytes into different doubles compute
different `metadata_hash` values, different leaf hashes and different roots,
and nothing downstream can repair it. In Rust, `str::parse::<f64>` is already
correctly rounded; in Python and in any ECMAScript runtime, the built-in parser
is. It is the JSON library's fast path that is not.

Up to and including 0.27.0 this crate met neither half of the serialization
requirement, so a receipt whose metadata contains a floating-point number
outside roughly 1e-6..1e21, an exact shortest-digit tie, or a
17-significant-digit literal got a `metadata_hash` no conformant verifier
reproduces. That is fixed rather than grandfathered; see CHANGELOG.md for why
no receipt is affected.

## Upgrading to 0.26

`PathStatus` gained a variant, `Indeterminate`, and the meaning of the
existing ones narrowed. **A `match` with a wildcard arm keeps compiling and
silently changes behaviour**, so this needs an explicit audit rather than a
rebuild. `TerminalAnchor::Assumed` also gained a field, and
`Rfc3161AnchorFacts` gained two.

`Rfc3161AnchorFacts::cms_signature_valid` and `imprint_matches_root` are also
gone, replaced by the three-valued `cms_signature: CmsSignature` and
`message_imprint: MessageImprint`. Those *do* fail to compile, on purpose.

One rule governs the whole change, in both directions: **a refutation means
something was checked and is false, and an inability means nothing at all.**
Do not let an inability suppress a refutation either — aggregate every fact
before forming a verdict rather than returning at the first non-`Verified`
one, or an unevaluatable imprint will quietly conceal a refuted signature.

The short version: a refutation now means *something was checked and is
false*, and nothing else. `PathStatus::Incomplete`,
`PathStatus::Indeterminate`, `CmsSignature::Indeterminate` and
`MessageImprint::Indeterminate` all describe this verifier's own limits — a
missing certificate, or cryptography this crate does not implement — and must
never be reported as refuted evidence. Route them explicitly and fail closed.

See [CHANGELOG.md](CHANGELOG.md) for the full before/after table and the
reasoning.

## License

Apache-2.0
