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

## Verifying anchors: read the facts, not a boolean

`ReceiptVerifier::verify` answers "is this receipt acceptable" and collapses
each anchor to `is_valid: bool`. That boolean cannot tell you whether an anchor
was **checked and found false** or **not checked at all** — a missing trust
root, an unimplemented algorithm, a Bitcoin block nobody fetched. Those call
for opposite reactions, and a verifier that reports the second as the first is
publishing an accusation it cannot support.

Use `verify_receipt_anchors` when you need to say *why*:

```rust,ignore
use atl_core::{verify_receipt_anchors, Receipt, VerifyOptions};

let receipt = Receipt::from_json(&json)?;

for anchor in verify_receipt_anchors(&receipt, &VerifyOptions::default()) {
    if anchor.is_refuted() {
        // A fact about THIS ANCHOR was checked and is false. Report it: an
        // anchor is something anybody who relayed the receipt could have
        // appended, so a refuted one is evidence that somebody interfered.
        // It is NOT evidence against the receipt — see below.
        for finding in anchor.refutations() {
            eprintln!("{}: {finding}", anchor.anchor_type());
        }
    } else if anchor.is_indeterminate() {
        // Nothing was refuted; this check could not be finished. Do NOT
        // present it as a broken anchor either.
        for finding in anchor.inabilities() {
            eprintln!("{}: {finding}", anchor.anchor_type());
        }
    }
}

// The receipt's own verdict is a separate question, and no anchor finding
// takes part in it: `ReceiptVerifier::verify`, read through
// `VerificationResult::receipt_errors()`.
```

The three predicates partition, every finding is a `VerificationError` that
answers `is_refutation()` for itself, and the full RFC 3161 / OpenTimestamps
fact sets ride along in `AnchorFacts::evidence()` so nothing has to be
recomputed. **Any refutation outranks every inability**: `is_refuted()` is a
question about the whole finding set, never about the first one met.

## What `is_valid` means

`VerificationResult::is_valid` is acceptance, and since 0.29 it means what it
says. ATL v2.0 §5.5 — "At least one anchor MUST be verified to establish trust
in the receipt" — is enforced literally:

- **enough verified anchors** — `max(1, min_valid_anchors)` of them; §5.5's
  floor is one and a caller may raise it but never lower it. The log operator's
  own checkpoint signature is not an anchor: §5.4 calls it "an integrity check,
  not a trust establishment" and §1.2 derives trust "exclusively from external,
  independent anchors". A shortfall is reported once, as
  `NoTrustAnchor { required, verified }`, and is an *inability* — not enough was
  proved, nothing was disproved;
- **nothing may be wrong with the receipt itself** — its inclusion proof, its
  Super-Tree proofs, `metadata_hash`, the provenance of its bytes. "The receipt
  itself" is exact: see below;
- **a receipt with no anchors is not accepted** — and not refuted either. It is
  `is_indeterminate()` with `NoTrustAnchor`: nothing about it was shown false,
  it was simply never attested to by anything outside the log. §5.6's own table
  calls that tier "internal consistency only".

### An anchor that fails verification is reported, and vetoes nothing

§5.5 sets a *threshold* — at least one verified anchor — and says nothing about
the others. That is not a detail to paper over, because **a receipt does not
authenticate its own anchors**: the leaf hash is `SHA256(0x00 || payload_hash
|| metadata_hash)` and the checkpoint blob is 98 bytes of origin, tree size,
timestamp and root hash. The `anchors` array is in neither. Anybody who relays
a receipt can append an anchor to it, with no key at all.

If an appended anchor that *fails* verification could veto acceptance, one
malformed token would destroy the verification of a receipt carrying a flawless
independent anchor — a denial of verification available to every relay, for
free. An anchor nobody could verify reports on itself and on nothing else; it
cannot undo an existence in time that another anchor established.

So an anchor that fails verification changes **no status this crate reports
about the receipt** — not `is_valid`, and not `is_indeterminate` either.
Scoping only `is_valid` would have left the same defect one storey up: a
stranger could not make a receipt invalid, but could still flip it from *trust
could not be established* to *this evidence is disproved*, which is an
accusation manufactured for free against a document nothing had disproved.

**The guarantee is one-sided, and only the one side holds.** An anchor that
*passes* verification raises the verified count and can carry a receipt over
the threshold — at `min_valid_anchors: 2`, a receipt with one verified anchor
reports `NoTrustAnchor { required: 2, verified: 1 }` and a second verified
anchor clears it. That is not a gap: it is what anchors are for, and a verifier
in which anchors changed nothing would be worthless. The asymmetry mirrors the
capability. Appending rubbish costs nothing; producing an anchor that verifies
needs a timestamp token over *this* receipt's root, chaining to a trust root
*you* supplied.

A receipt whose only anchor is refuted is therefore reported as **unattested**,
not as refuted. Its own facts are untouched; what was found false is an
attachment anybody could have added. And that is the only answer a stranger
cannot steer.

**It is never hidden.** The finding stays in `VerificationResult::errors`,
wrapped in `VerificationError::AnchorFinding { index, anchor_type, finding }`,
still answering `is_refutation()` as a refutation *of the anchor*. An appended
anchor is evidence that somebody interfered with the receipt, and a consumer
that drops it because it did not change the verdict is concealing the very
thing it reveals.

`VerificationError::is_about_the_receipt()` draws the line, and
`VerificationResult` gives both sides of it directly:

| what you want | what to read |
|---|---|
| decide anything | `receipt_errors()` — the errors every status is computed from |
| show the tampering | `anchor_findings()` — never empty-handed, never load-bearing |
| show everything | `errors()` — both, in the order found |

Nothing derived from the full `errors()` list is safe to branch on: an anchor
anybody could have appended adds to it, and where in the `anchors` array it sits
decides where its finding lands.

Because a `bitcoin_ots` anchor is never verified without a block header, a
receipt whose only anchor is a Bitcoin one is never accepted by this crate
alone. That is not a limitation to route around: it is the honest report of
what an offline verifier established.

Two things this crate cannot answer, by design — it performs no I/O:

- a `bitcoin_ots` anchor is never `is_verified()`, because the block header
  whose Merkle root would confirm the OTS proof was never obtained
  (`BitcoinBlockNotObtained`), and neither was the block time ATL v2.0 §5.5.2
  step 5 asks about;
- revocation is never checked (`Revocation::NotChecked`).

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
