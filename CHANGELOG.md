# Changelog

All notable changes to `atl-core` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.29.0]

### An anchor's outcome is three-valued, and callers can finally see it

`ReceiptVerifier::verify` reports each anchor as an `AnchorVerificationResult`
whose load-bearing field is a single `is_valid: bool`. That boolean cannot say
whether an anchor was **checked and found false** or **not checked at all**,
and those call for opposite reactions: one is evidence that somebody attached a
forged anchor, the other is a gap in the verifier. (Neither is evidence against
the *receipt* — see the entry below on why an unauthenticated anchor decides
nothing about it.) This is the same distinction `PathStatus`,
`MessageImprint` and `CmsSignature` already draw one level down — and the
distinction the receipt level threw away.

A caller needing it has had exactly one option: set
`VerifyOptions { skip_anchors: true }` and re-implement §5.5 itself. That is
not duplicated cryptography — `verify_rfc3161_token` and
`verify_ots_anchor_impl` were always public — it is duplicated **protocol
orchestration**: pinning the anchor to the receipt's own root, deciding which
facts refute and which merely fail to confirm, and reducing them to an outcome.
Two implementations of a mandatory rule drift, and every defect fixed on one
side stays open on the other. `atl-cli` is that caller, and this release exists
so it can stop.

**`verify_receipt_anchors(&receipt, &options) -> Vec<AnchorFacts>`** is that
orchestration published as facts, one entry per anchor in receipt order, with
no verdict formed. `AnchorFacts` answers three questions that partition:

* `is_verified()` — no findings at all;
* `is_refuted()` — something checkable was checked and is false;
* `is_indeterminate()` — nothing was refuted and a check could not be finished.

**No fourth vocabulary was introduced for this.** Every check that did not come
out verified is a `VerificationError`, and `VerificationError::is_refutation()`
— which 0.28 added for the receipt level — is what splits them. The eleven new
variants carry the fact enums themselves rather than flattening them into
prose, so `Rfc3161MessageImprint(Indeterminate)` classifies as an inability and
`Rfc3161MessageImprint(Mismatch)` as a refutation with nothing for a consumer
to re-derive. `is_refutation` is now an exhaustive match rather than a negated
`matches!`: a wildcard would silently classify the next variant somebody adds,
and both possible silent answers are wrong.

**Any refutation outranks every inability**, and the rule is enforced by
construction: every finding is gathered before any is weighed. The `atl-cli`
implementation of the same rule once returned on the first non-verified fact it
met, so an `Indeterminate` imprint beside a `Refuted` CMS signature came out as
"nothing was refuted". The test that pins this here uses a real OTS proof whose
height the receipt contradicts: both kinds of finding are present at once, and
the outcome must be `refuted`.

### `ReceiptVerifier::verify` no longer contradicts its own facts

Three defects, all in the receipt-level aggregate, all of the same kind: the
verdict asserted more than the checks behind it supported.

**1. A `bitcoin_ots` anchor was reported as verified without ever seeing a
block.** ATL v2.0 §5.5.2 step 4 is "verify the OTS proof chain from
`anchor.target_hash` **to the Bitcoin block**". This crate performs no I/O, so
it decodes the proof, walks its Merkle path and compares the height the proof
carries against the receipt's claim — and stops there. Nothing compares the
computed Merkle root against a block header, because no block header is ever
obtained. Such an anchor nonetheless came back `is_valid: true`, so a
Receipt-Full verified offline on the strength of a proof nothing had checked
against Bitcoin.

**2. A refuted anchor was not reported at all.** A refutation reached
`result.errors` only when `min_valid_anchors` was set, which it is not by
default. So `is_valid: true` could sit on the same result as
`anchor_results[0].is_valid == false` — and did, in this crate's own
integration suite, where `assert!(result.is_valid)` stood two lines above
`assert!(!anchor_result.is_valid)` and nobody read them together. A receipt
carrying a token somebody had appended to it verified silently.

**3. The log operator's own signature counted as a trust anchor.** §5.4 calls
the checkpoint signature "an integrity check, not a trust establishment", §1.2
derives trust "exclusively from external, independent anchors", and §5.6's
table rates a receipt with no anchors as "internal consistency only". Rule 4
of `compute_validity` nevertheless accepted a verified signature in place of a
verified anchor — which is to say it accepted the one party a transparency log
exists so that nobody has to believe.

Measured against `atl-cli/test_data`, three receipts changed verdict, all of
them in that suite's `invalid/` directory:

| fixture | 0.28 | 0.29 |
|---|---|---|
| `bitcoin_time_contradicts_block.atl` | `valid` | not valid, **indeterminate**, `NoTrustAnchor` |
| `hostile_block_time.atl` | `valid` | not valid, **indeterminate**, `NoTrustAnchor` |
| `hostile_anchor_timestamp.atl` | `valid` | not valid, **refuted**, `AnchorPayloadUndecodable` |

None of the three had a single verified anchor, and the third had a *refuted*
one. No other receipt in that corpus changed verdict.

**The rule now.** `is_valid` is: the §5.5 threshold is met (at least one
verified anchor) **and** nothing is wrong with the receipt itself — its
inclusion proof, its Super-Tree proofs, `metadata_hash`, the provenance of its
bytes. Anchor findings are reported but take no part in that conjunct;
`VerificationError::is_about_the_receipt()` draws the line.

**Why an anchor finding may not veto the verdict.** A receipt does not
authenticate its own anchors. The leaf hash is `SHA256(0x00 || payload_hash ||
metadata_hash)` and the checkpoint blob is 98 bytes of origin, tree size,
timestamp and root hash; the `anchors` array appears in neither, so nothing
signs it and nothing hashes it. **Anybody who relays a receipt can append an
anchor to it, with no key.** A first draft of this release let any refuted
anchor refute the receipt, which would have handed every relay a denial of
verification: append one malformed token and a receipt holding a flawless
independent anchor stops verifying. §5.5 sets a threshold and has no term for
the remaining anchors, and an unauthenticated anchor reports on itself and on
nothing else — it cannot undo an existence in time that another anchor
established.

**One report of an unmet threshold, produced independently of the anchor
array.** The quorum
check (`min_valid_anchors`) used to run only inside the anchor block, which a
receipt with no anchors never entered. So an unanchored receipt reported
`NoTrustAnchor`, and appending a single rubbish anchor moved it into the block
and produced an `AnchorFailed` aggregate instead — classified as a refutation,
and suppressing `NoTrustAnchor` on the way past. A stranger could therefore
change both the receipt's status *and its set of receipt-level errors*, which is
the same defect a third time, in the one place two rounds of guards had not
looked.

`AnchorFailed` is removed. `NoTrustAnchor` becomes
`NoTrustAnchor { required, verified }` and is the only report of an unmet
threshold — for a receipt with no anchors, one whose anchors were all
unresolved, one whose anchors were all refuted, one verified with
`skip_anchors`, and a caller-raised quorum alike. `min_valid_anchors` raises the
threshold (`required = max(1, min_valid_anchors)`, Section 5.5's floor being
one); it does not create a second kind of failure, so it no longer gets a second
error. It is pushed whenever `verified < required`, with no guard on what else
is in the list and no dependence on what the `anchors` array holds, because a
guard on either is the same fragility one step removed.

`verify` still returns early on five receipt-level refutations — an unsupported
`spec_version`, a leaf hash that could not be reconstructed, an unparsable
`proof.root_hash`, and the two checkpoint-versus-proof mismatches — and so does
not reach the threshold check on those paths. That changes no status, and it is
measured rather than assumed: every one of those paths, with and without
anchors, reports exactly what it would report with `NoTrustAnchor` appended.
The receipt has no parsed root and therefore no verified anchor either way, and
adding a non-refutation to a non-empty error list moves neither `is_valid` nor
`is_indeterminate`.

**No status moves, not just `is_valid`.** The first draft of this fix scoped
only the acceptance conjunct and left `VerificationResult::is_indeterminate`
consulting every error. Since `AnchorFinding::is_refutation()` delegates to what
it wraps — correct for the anchor, wrong for the receipt — a stranger could
still flip a receipt from *trust could not be established* to *this evidence is
disproved* by appending one malformed token. That is the same defect one storey
up: not an invalidation, but an accusation manufactured for free against a
document nothing had disproved. `is_indeterminate` now consults
`receipt_errors()` only.

**The guarantee is one-sided, and is stated that way: an anchor that *fails*
verification changes no status of the receipt.** The unqualified form —
"appending an anchor changes no status" — is false, and asserting it would be
this same defect once more, in the wording of the guarantee rather than in the
code. An anchor that *passes* verification raises the verified count and can
carry a receipt over the threshold: at `min_valid_anchors: 2`, a receipt with
one verified anchor reports `NoTrustAnchor { required: 2, verified: 1 }` and a
second verified anchor clears it. Anchors would be pointless otherwise. The
asymmetry mirrors the capability — appending rubbish costs nothing, while
producing an anchor that verifies needs a timestamp token over this receipt's
own root chaining to a caller-supplied trust root — and the test suite guards
both directions, so "the invariant holds" cannot be confused with "anchors do
not matter".

A receipt whose only anchor is refuted is therefore *unattested*, not refuted.
Every anchor refutation this crate can produce is reachable by appending — a
wrong `target`, a `target_hash` naming another root, an undecodable payload, a
genuine token minted for other data, a Bitcoin anchor whose stated height its
own proof contradicts — so the observation never distinguishes "the receipt was
altered" from "somebody appended rubbish", and no verdict may rest on a
distinction the evidence does not support. Nothing is lost: an attacker who
alters a receipt so that genuine anchors stop matching must change
`proof.root_hash`, which the checkpoint comparison and the inclusion proof catch
at receipt level.

**And it is never hidden.** A refuted anchor is pushed onto `result.errors`
wrapped in `VerificationError::AnchorFinding { index, anchor_type, finding }`,
machine-readable and carrying its provenance, still answering `is_refutation()`
as a refutation *of the anchor*. `VerificationResult::anchor_findings()` lists
them so that "does not decide the verdict" cannot quietly become "is not shown
to anybody". Inabilities are not pushed: an unfinished check is not a finding,
and the full fact set is a `verify_receipt_anchors` call away.

**A receipt with no anchors is `is_indeterminate`, never refuted.** §5.5's MUST
cannot be met by zero anchors, so it is not accepted; but nothing about such a
receipt was shown false — what is absent is external attestation, and absence
of evidence *for* is not evidence *against*. It reports as `NoTrustAnchor`,
which `is_refutation()` already classified as an inability.

`helpers::legacy_anchor_result` is gone. The projection onto
`AnchorVerificationResult` remains as `anchor_result_from_facts`, and it has no
carve-out left to justify: `is_valid` is exactly `AnchorFacts::is_verified`.

### Compatibility

Breaking for anyone matching exhaustively on `VerificationError` — eleven
variants are added, five of them gated on `rfc3161-verify`. A `_ => …` arm
absorbs them, but reading the new variants is the point of the release.

**`is_valid` is stricter, through every entry point.** `verify_receipt_anchor_only`,
`verify_receipt_with_key`, `verify_receipt_json_*` and the rest all funnel into
`ReceiptVerifier::verify`, so none of them can disagree with it and all of them
change together. A receipt that was accepted and now is not falls into one of
three cases: its only trust was a `bitcoin_ots` anchor; its only trust was the
checkpoint signature (including every `skip_anchors: true` call made with a
key); or it carries no anchors at all. In every case the acceptance was
unsupported by what had been checked. Callers that need the previous
permissiveness should read `AnchorFacts` and apply their own threshold, which
is what the facts API is for.

`VerificationError::is_refutation` is no longer `const`: `AnchorFinding`
delegates to the boxed error it wraps, which a constant context cannot
dereference.

`AnchorVerificationResult::error` — documented since 0.5 as never load-bearing
— changes wording in three places: a malformed `anchor.target_hash` now says
`Invalid hash in field 'anchor.target_hash'`; an anchor type whose feature is
compiled out says `… is not compiled into this build: enable the '<feature>'
feature`; and the wrong-`target` and `target_hash`-mismatch messages carry the
anchor type's wire name.

One further behavioural change reaches an anchor's `is_valid`: a `bitcoin_ots`
anchor whose selected attestation has an empty Merkle path is now refuted
(`AnchorPayloadUndecodable`) rather than accepted. No real `OpenTimestamps`
Bitcoin attestation has one; the previous code simply never looked.

### Added

- `verify_receipt_anchors`, re-exported from the crate root and `prelude`.
- `AnchorFacts` — `anchor_type`, `claimed_timestamp`, `established_timestamp`,
  `evidence`, `findings`, `refutations`, `inabilities`, `is_verified`,
  `is_refuted`, `is_indeterminate`. Fields are private: the relationship
  between the findings and the three predicates is the type's whole contract.
- `AnchorEvidence` — `None`, `Rfc3161(Box<Rfc3161AnchorFacts>)` and
  `BitcoinOts(Box<BitcoinOtsAnchorFacts>)`, each behind its own feature.
  `#[non_exhaustive]`.
- `BitcoinOtsAnchorFacts` (`bitcoin-ots`) — `attested_block_heights`,
  `receipt_block_height`, `receipt_block_time`, `attestation`,
  `computed_block_merkle_root`. There is deliberately no field for the block's
  own Merkle root, time or hash: no header is ever obtained, and a
  permanently-empty field invites a reader to treat its emptiness as a value.
- `VerificationError::AnchorFinding { index, anchor_type, finding }`, which
  records that an error is about an anchor rather than about the receipt, and
  `VerificationError::is_about_the_receipt`, which is what every status of a
  `VerificationResult` is computed over. Not a severity ranking: an anchor
  finding is still a refutation and still reported.
- `VerificationResult::receipt_errors()` and
  `VerificationResult::anchor_findings()` — the two halves of that line, so a
  consumer building its own verdict classifies from the errors that cannot be
  steered by whoever last handled the receipt, and still has the findings to
  display.
- `VerificationError::AnchorTargetInvalid`, `AnchorTargetHashMismatch`,
  `AnchorPayloadUndecodable`, `BitcoinHeightContradictsProof` (refutations);
  `AnchorTypeUnsupported`, `BitcoinBlockNotObtained` (inabilities).
- `VerificationError::Rfc3161MessageImprint`, `Rfc3161CmsSignature`,
  `Rfc3161TimestampingEku`, `Rfc3161CertificatePath`,
  `Rfc3161TerminalNotTrusted` (`rfc3161-verify`), each carrying the fact that
  decides its own `is_refutation()`. `Rfc3161CertificatePath` carries
  `chain_valid_at_gen_time` alongside the `PathStatus`, because that flag is
  `false` whenever no complete path was built and is a contradiction — and
  therefore a refutation — only when the path did complete.

### Changed

- `ReceiptVerifier::verify`'s anchor step is now the same fact gathering
  `verify_receipt_anchors` publishes, so ATL §5.5 has one implementation inside
  this crate rather than two, and the verdict cannot disagree with the facts a
  caller reads directly.
- **Breaking:** `compute_validity` Rule 4 requires at least one *verified*
  anchor. A verified checkpoint signature no longer substitutes.
- **Breaking:** an anchor's refutations reach `VerificationResult::errors`,
  wrapped in `AnchorFinding`. They are fully machine-readable and must be
  displayed; an anchor that fails verification changes no status of the
  receipt.
- **Breaking:** `VerificationResult::is_indeterminate` consults only errors for
  which `is_about_the_receipt()` holds. A receipt whose only anchor is refuted
  is now indeterminate where 0.28 and the first draft of 0.29 called it
  refuted.
- **Breaking:** `VerificationError::NoTrustAnchor` is now
  `NoTrustAnchor { required, verified }`, and `VerificationError::AnchorFailed`
  is removed — the two reported the same fact and only one of them was
  forgeable. `NoTrustAnchor` is pushed whenever fewer than
  `max(1, min_valid_anchors)` anchors verified, with no guard on the anchor
  array or on what else is already in the error list, so it now also appears
  beside a receipt-level refutation where the old guard suppressed it — except
  on the five paths where `verify` returns before reaching the check, which
  changes no status (see above).
- **Breaking:** `VerificationError::is_refutation` is no longer `const`.
- **Breaking:** `AnchorVerificationResult::is_valid` is exactly
  `AnchorFacts::is_verified`; a `bitcoin_ots` anchor is therefore never
  `is_valid` from this crate.
- `VerificationError::is_refutation` is an exhaustive match; the payload
  decides for the variants that carry a fact.

## [0.28.0]

### RFC 8785 §3.1 is a set of MUSTs on the *input*, and they are now checked

The previous entry closed conformance of JCS *serialization*. It left the other
half open: §3.1 states three MUST requirements on "data to be canonicalized",
§3.2.2.3 adds a fourth, and this crate checked none of them.

> JSON objects MUST NOT exhibit duplicate property names
>
> JSON string data MUST be expressible as Unicode
>
> JSON number data MUST be expressible as IEEE 754 double-precision values
>
> — RFC 8785 §3.1

> \[NaN and Infinity\] MUST cause a compliant implementation to terminate with
> an appropriate error
>
> — RFC 8785 §3.2.2.3

**The root cause was the signature.** `canonicalize(&Value) -> String` is
infallible: it physically cannot refuse, so on input that has no canonical form
it had to return *something*, and what it returned was presented as the
canonical form and hashed into `metadata_hash`. Two concrete cases:

* `9007199254740993` (2^53 + 1) came out verbatim. It denotes the double 2^53,
  which every conformant implementation renders as `9007199254740992`.
* A non-finite double emitted the four bytes `null` — a valid-looking canonical
  form for a value the RFC says must abort.

`canonicalize` and `canonicalize_and_hash` now return `AtlResult<_>`, and the
error names the RFC 6901 JSON Pointer of the offending node, because "some
number in here is too large" is not actionable on nested metadata.

**Numbers are normalised, never refused.** Every number is converted to the
double it denotes and rendered by the ECMA-262 §7.1.12.1 algorithm. So
`9007199254740993` canonicalizes to `9007199254740992`, `4611686018427387904`
(2^62) to `4611686018427388000`, and 2^68 written out as
`295147905179352825856` to `295147905179352830000`. The only refusal RFC 8785
mandates for a serializer is §3.2.2.3's `NaN`/`Infinity`, and no JSON text can
reach it.

§3.1's "JSON number data MUST be expressible as IEEE 754 double-precision
values" reads like an instruction to the canonicalizer. It is not — it is
addressed to whoever *creates* the data ("Data to be canonically serialized is
usually created by…"), and Appendix B settles it for the algorithm:

> (1) …values that are to be interpreted as true integers SHOULD be in the range
> -9007199254740991 to 9007199254740991. However, **how numbers are used in
> applications does not affect the JCS algorithm.**
>
> (2) Although a set of specific integers like 2\*\*68 could be regarded as
> having extended precision, **the JCS/ECMAScript number serialization algorithm
> does not take this into consideration.**

RFC 8785's own Table 1 then requires the double `4430000000000000` — exactly
2^68 — to serialize as `295147905179352830000`. **The specification normalizes
a large integer by its own published table; it does not reject one.**

Four rules were written here before this one, all wrong, all recorded on
`format_number` so none is reintroduced: reject past `Number.MAX_SAFE_INTEGER`
(refuses the canonicalizer's own output, since the canonical form of an ordinary
double is often an integer literal above 2^53); reject an integer whose digits
are not its double's spelling (refuses 2^60 and 2^62, which are exact doubles —
a claimed inability where the ability plainly exists, so a receipt holding a
byte count of that size would come back `untrusted` here and `valid` from a
JavaScript verifier); reject an integer that is not exactly representable
(refuses `4611686018427388000`, the required spelling of 2^62 — our own output
again); and, underneath all three, the idea that numbers should be refused at
all.

**Duplicate property names are refused on the raw text, and everything text
cannot reach is gated by provenance.** `serde_json` keeps the last occurrence,
so `{"metadata":{"x":1,"x":2}}` was accepted and hashed as `{"x":2}`, while
RFC 8259 §4 makes the choice of survivor unpredictable across parsers — two
verifiers can hash two different objects out of one byte sequence and both be
right. Refusal is the only correct answer where the specification supplies no
single one, which is exactly why numbers are normalised and this is not.

`check_unique_property_names` scans JSON text and is run by `Receipt::from_json`
and the new `Receipt::from_slice` before the typed parse. It covers the entire
receipt, not just the canonicalized subtree, although §3.1 formally binds only
that: a receipt stating `metadata_hash` or `root_hash` twice is a document two
conformant readers can reach opposite verdicts on, which is the same
split-verdict failure §3.1 exists to prevent.

**The rest cannot be detected at all.** `Receipt` derives `Deserialize`
publicly, so `serde_json::from_str`, `from_reader` and `from_value` all go
around any constructor — and `from_value` is handed a `Value` whose duplicate an
earlier parse already discarded. **The §3.1 constraint is a property of a byte
stream; no API that accepts a parsed structure can check it.**

An intermediate revision tried to close the `serde` paths by replacing
`serde_json`'s `Deserialize` impl for `Value` on the `metadata` field with a
hand-written visitor. That was withdrawn. Under
`serde_json/arbitrary_precision` — which any crate in a consumer's dependency
graph can enable, and Cargo then unifies onto this one — `deserialize_any`
delivers a non-integer number as a map keyed by the private token
`$serde_json::private::Number`. A hand-written visitor builds an *object* where
a number belongs, so `1.5` becomes `{"$serde_json::private::Number":"1.5"}`:
every `metadata_hash` silently changes, and a document containing that literal
object collides with one containing the number. Buying earlier diagnostics with
a dependency on undocumented internals, at the risk of corrupting the one thing
this crate exists to reproduce exactly, is not a trade worth making. The new
`arbitrary-precision-audit` dev feature exists so this can never regress
unnoticed.

So the answer on those paths is provenance. `Receipt` carries a private
`SourceTextCheck`, `#[serde(skip)]`:

* no `serde` path can set it — `from_str`, `from_reader`, `from_slice`,
  `from_value` all produce *unchecked*;
* `Receipt::from_json` and `Receipt::from_slice` set it, because they perform
  the check; `ReceiptBuilder::build` demands it as an argument;
* `ReceiptVerifier::verify` **will not confirm** a receipt that lacks it,
  reporting `VerificationError::SourceTextNotChecked` — an inability, not a
  refutation. Every other check still runs and is still reported; only the
  verdict is gated.

The field is **private** and the marker is **never handed back out**. Two
earlier revisions were wrong about this, in the same way each time:

* while the field was public, `SourceTextCheck` being `Copy` made
  `bad.source_text_check = good.source_text_check` a complete bypass;
* making the field private but leaving `source_text_check() -> SourceTextCheck`
  only changed the syntax — passing `trusted.source_text_check()` into the
  constructor did the same thing, and that is the shape a pipeline "preserving
  provenance" while rebuilding a receipt would naturally take. The concern is
  not an attacker, who calls the hatch regardless; it is careful-looking code
  leaking the gate by accident.

So the public reader is `Receipt::source_text_was_checked() -> bool`. The
checked state has exactly one public producer,
`SourceTextCheck::assume_duplicate_property_names_already_rejected()`, and
`tests/lib_exports_tests.rs` pins both signatures with coerced function
pointers — reintroducing a by-value getter, or relaxing
`ReceiptBuilder::build`'s parameter to `bool`, is a build failure rather than a
red test.

The escape hatch for a holder who did check the bytes — a log operator
assembling a receipt at issuance, where no untrusted JSON text ever existed — is
`SourceTextCheck::assume_duplicate_property_names_already_rejected()`, passed to
`ReceiptBuilder::build`. The name is deliberately unwieldy and there is no
shorter alias.

**`Receipt` is now read-only, and that is what makes the marker mean
anything.** A marker attesting to "the bytes this value was parsed from" is
worth nothing if the value can afterwards come to hold different content, and
it could — `Receipt`'s data fields were public, so no getter and no hatch were
needed at all:

```rust
let mut carried = checked.clone();
carried.entry   = unchecked.entry;     // every crypto field consistent,
carried.proof   = unchecked.proof;     // metadata_hash agrees,
carried.anchors = unchecked.anchors;   // nothing left to catch
// is_valid: true
```

Nothing in that is detectable: the swapped-in fields are internally consistent
with each other, so `metadata_hash` matches and the proofs check out. The
release note "verify will not confirm a receipt whose bytes were never checked"
was simply false.

**Every field of `Receipt` is now private**, readable only through
shared-reference accessors — `entry()`, `proof()`, `anchors()`,
`super_proof()`, `spec_version()`, `upgrade_url()`. No `&mut` accessor, no
setter. `tests/lib_exports_tests.rs` pins all six return types, so handing a
field out by value — or exposing `&mut` — is a build failure.

**And privacy alone was not enough.** Five builder methods on `Receipt`
reproduced by method exactly the assignment that had just been closed:

```rust
let carried = checked
    .with_super_proof_option(unchecked.super_proof().cloned())
    .with_anchors(unchecked.anchors().to_vec());
// carried.source_text_was_checked() == true
```

The Super-Tree proof and the anchors came off an unchecked receipt while the
marker stayed behind from the checked one — and anchors are the subject of
verification, not decoration. The general rule, applied rather than patched
case by case: **no public method may take a `Receipt` and return a `Receipt`**,
because such a method is a setter whatever it is called.

Construction therefore moved to a new type, `ReceiptBuilder`, which **cannot be
obtained from a `Receipt`** — no `From`, no `into_builder`, no `Deref` — and
which settles provenance last, at `build(SourceTextCheck)`, once every part is
already in place. Call order cannot affect safety: no arrangement of the
builder's setters yields a `Receipt` without a fresh provenance decision at the
end. `Receipt::new` and the five `with_*` methods are gone from the public API.

Because "no method with this shape exists" is a statement about absence, no
signature pin can make it. `tests/lib_exports_tests.rs` therefore **parses**
`src/core/receipt.rs` with `syn` (a new dev-dependency) and fails on any method
of `Receipt` that takes a receiver and returns a `Receipt` — in inherent impls
and trait impls alike, whatever the formatting.

That guard took three attempts, and the first two overclaimed in exactly the way
the rest of this release is about.

**A line-by-line text scan** missed any signature `rustfmt` had split across
lines — the `pub fn` line then carries neither the receiver nor the return type
— and examined only the first `impl Receipt` block, so a method handed out
through `impl SomeTrait for Receipt` was invisible. Verified against the retired
implementation: it passed both bypasses and caught only the single-line form.

**The first `syn` version** walked only top-level `impl` items, and its comment
asserted that free functions were not a hole "because they cannot touch private
fields from another module". They are not in another module:

```rust
// in core::receipt itself, where the private fields are visible
pub fn rebuild(mut r: Receipt, entry: ReceiptEntry) -> Receipt { r.entry = entry; r }
```

`lib.rs` declares `pub mod core` and `core/mod.rs` declares `pub mod receipt`,
so `atl_core::core::receipt::rebuild(…)` is callable by any consumer. It also
missed `impl super::Receipt` inside a nested `mod` — an inherent method is
reached through the type, not the module path, so even a *private* nested module
exposes it — and a return type behind `type Rebuilt = Receipt;`, because the
return check was lexical. All three were confirmed reachable by compiling calls
to them from an external test crate.

**The current guard** walks the file recursively, resolves `type` aliases
transitively, and checks methods, free functions, and functions returning a
`ReceiptBuilder`. What it does *not* examine is listed in the test with no
safety claim attached: only this file; macro-generated items; module visibility
chains (a `pub fn` in a private `mod` is reported anyway, deliberately); and
`#[cfg(test)]` items, which are skipped because they are not compiled into the
library a consumer links — the one exclusion justified by reachability rather
than by cost.

`Clone` is deliberately kept: a clone carries the marker together with the
content it covers, consistently. The danger was mutation afterwards, and that
is what is gone.

The nested structures (`ReceiptEntry`, `ReceiptProof`, `SuperProof`, …) keep
public fields, on purpose: they must be assemblable to build a receipt, and
a `&ReceiptEntry` cannot be written through, so it costs nothing.

**Unicode was already enforced, by the parser, and is now observable.**
`serde_json` refuses a lone surrogate both as a `\uXXXX` escape and as raw
CESU-8 bytes, and `&str` cannot carry one. That was an unstated dependency on
another crate's behaviour; it is now pinned by vectors and tests.

### In verification, an inability is *untrusted*, not *invalid*

A receipt this crate could not evaluate has not been shown to be wrong.
Reporting that as a hash mismatch publishes "this evidence is disproved" on the
strength of a computation that never ran. This is the same distinction
`PathStatus::Indeterminate` already draws for RFC 3161 chains.

* `VerificationError::SourceTextNotChecked` — the receipt's bytes were never
  examined for duplicate property names, which is unknowable once JSON has been
  parsed. Not knowing is not evidence.
* `VerificationError::MetadataNotCanonicalizable { path, reason }`, distinct
  from `MetadataHashMismatch`; `path` is receipt-relative. It has no reachable
  trigger in a default build now that numbers are normalised, and is kept
  because `serde_json/arbitrary_precision` makes `Number::as_f64` return `None`,
  and because deleting it would force `reconstruct_leaf_hash` to fold "could not
  compute" back into "hash mismatch".
* `VerificationError::is_refutation()` says whether an error is evidence
  *against* the receipt. Four variants are not: the two above,
  `UnsupportedVersion` (rules this build has never read) and `NoTrustAnchor`
  (absence of trust material disproves nothing).
* `VerificationResult::is_indeterminate()` distinguishes "refuted" from "not
  evaluated" — `is_valid == false` alone never did.

`verify_inclusion_only` returned a bare `bool`, and answering `false` for
metadata it could not canonicalize was a claim about a proof it never
evaluated. It now returns `AtlResult<bool>`.

### Compatibility

Breaking, at the source level, for every caller of `canonicalize`,
`canonicalize_and_hash` and `verify_inclusion_only`: add `?` or handle the
error.

**`Receipt` is read-only; struct-literal construction, field assignment and the
`with_*` methods no longer compile.** All fields are private and construction
moved to `ReceiptBuilder`. A downstream that built receipts with `Receipt { … }`
or `Receipt::new(...).with_*(...)` moves to
`ReceiptBuilder::new(spec_version, entry, proof)` plus `super_proof` /
`anchors` / `upgrade_url`, finishing with `.build(source_text_check)`; one that
*read* fields
moves to the accessors, which cover every read (`atl-cli`'s production code was
walked field by field to confirm this — `entry.{id,metadata,metadata_hash,
payload_hash}`, `proof.{root_hash,tree_size,leaf_index,inclusion_path,
checkpoint.*}`, `super_proof`, `anchors`, `spec_version` are all expressible).

One thing is deliberately *not* expressible: appending an anchor to an existing
receipt. `atl-cli` does that only inside `#[cfg(test)]`, and it must now build a
new receipt instead — an anchor is evidence about a root, and bolting one onto a
value whose provenance was already settled is the mutation this type refuses.

The compile errors are the point: they force an explicit answer about where the
bytes came from, and the safe answer (`SourceTextCheck::default()`) is what you
get by not thinking.

**Normalisation changes hashes.** Any integer outside ±(2^53 − 1) whose digits
are not the ECMA-262 spelling of the double it denotes is now emitted as that
spelling, where 0.27.0 emitted the digits verbatim. Metadata holding 2^62
canonicalizes to `4611686018427388000` where 0.27.0 gave
`4611686018427387904`; a nanosecond Unix timestamp such as `1756812345678901234`
becomes `1756812345678901200`. Those `metadata_hash` values differ and such
receipts no longer verify. This is the same class of repair as the
number-rendering fix below and is not grandfathered, for the same reason: the
old bytes were the non-conformant ones — RFC 8785 Appendix B Table 1 requires
exactly this normalisation. Unlike that fix, **no corpus survey was run for this
case** — the earlier survey covered floating-point values, not integer
magnitudes, and a nanosecond timestamp in metadata is a plausible shape — so the
blast radius is stated as a rule, not as a count. Integers within ±(2^53 − 1),
which is all ordinary metadata, are byte-identical to before.

`Receipt::from_json` gains a refusal path (`AtlError::JcsInputConstraint`) for
documents with duplicate property names. Malformed JSON still reports as
`AtlError::InvalidReceipt`, unchanged. Plain `serde` deserialization still
*accepts* such a document — the duplicate is already gone by then — but the
resulting receipt is never confirmed.

**One gap remains on the raw-`serde` path, and it cannot affect a verdict.**
`serde` ignores unknown fields and does not track them, so a repeated *unknown*
name — `{"junk":1,"junk":2}` — is accepted by
`serde_json::from_str::<Receipt>`. `Receipt::from_json` refuses it, because the
text scan does not care whether a name is typed. Closing it on the `serde` path
means `#[serde(deny_unknown_fields)]`, which is a forward-compatibility decision
about ATL v2.0 §4.2 and not a canonicalization one, so it is recorded in a test
rather than taken unilaterally. Such a receipt carries unchecked provenance
either way, so it can never be confirmed.

### Known limitation

None for numbers. This crate now emits, for every JSON number, exactly what a
conformant JCS implementation emits. The divergence described in an earlier
draft of this entry is gone, because the refusal that caused it is gone.

What remains is the §3.1 duplicate-name constraint on receipts that never
passed through this crate as text. `serde_json::from_value` cannot check it and
neither can anything downstream of it, which is why such receipts are declined
rather than confirmed. A holder who vouches for the bytes with
`SourceTextCheck::assume_duplicate_property_names_already_rejected()` is making
an assertion this crate cannot verify, and the resulting verdict is worth
exactly what that assertion is worth. That is the remaining surface, and it is
irreducible: an in-memory receipt assembled from data structures has no byte
stream for anyone to check.

### Added

- `atl_core::core::jcs::check_unique_property_names`, re-exported from the crate
  root, `core` and `prelude`.
- `SourceTextCheck`, the reader `Receipt::source_text_was_checked() -> bool`,
  and `ReceiptBuilder::build`, which takes it: provenance for the one §3.1
  constraint that cannot be checked after parsing.
- `Receipt::entry()`, `proof()`, `anchors()`, `upgrade_url()` — shared-reference
  accessors replacing the public fields. With `spec_version()` and
  `super_proof()` these cover every read.
- `ReceiptBuilder`, the only way to assemble a `Receipt` from parts. It cannot
  be obtained from a `Receipt`, and `build` takes the `SourceTextCheck` last.
- `Receipt::from_slice`, the byte-oriented counterpart of `from_json`, so a
  caller holding bytes has a checked path that is not `serde_json::from_slice`.
- `AtlError::JcsInputConstraint { path, reason }`, classified as a format error.
- `VerificationError::MetadataNotCanonicalizable`,
  `VerificationError::SourceTextNotChecked`,
  `VerificationError::is_refutation`, `VerificationResult::is_indeterminate`.
- `syn` as a **dev-dependency** (`default-features = false`, features `full`,
  `parsing`, `visit`), used only by the surface guard in
  `tests/lib_exports_tests.rs`. It does not appear in the dependency graph of
  anything that links `atl-core`, and `syn` v2 was already being built for this
  crate as a proc-macro dependency of `der_derive`.
- `arbitrary-precision-audit`, an audit-only feature enabling
  `serde_json/arbitrary_precision`, plus `tests/arbitrary_precision_audit.rs`,
  whose canonical forms and `metadata_hash` values are **literal constants** —
  so running the suite with and without the feature proves the two
  configurations agree byte for byte rather than each being self-consistent.
- `test_data/vectors/jcs/cases.json` gains `input_constraint_cases`: seventeen
  frozen cases covering each §3.1 constraint. Nine pin number *normalisation*,
  including 2^68 as integer text against Appendix B Table 1, and the safe-integer
  range as the case where normalisation changes nothing. Two route whole
  receipts around the constructor — one through
  `serde_json::from_str::<Receipt>`, one through `from_value` — so a regression
  cannot return by the path it came from. New provenance origin
  `rfc8785-input-constraint`; no `expected` value elsewhere in the file was
  touched.
- `tests/proptests.rs` gains
  `prop_a_successful_canonicalization_never_alters_the_value` (the output must
  parse back to a value denoting the same JSON and be a fixed point — "denoting",
  because numbers are normalised) and
  `prop_duplicate_property_names_are_always_refused`.
  `prop_jcs_number_survives_a_json_round_trip` is unchanged.

### Changed

- **Breaking:** `canonicalize` and `canonicalize_and_hash` return
  `AtlResult<_>`.
- **Breaking:** `verify_inclusion_only` returns `AtlResult<bool>`.
- **Breaking:** every `Receipt` field is private and `Receipt::new` plus the
  five `with_*` methods are removed. Struct-literal construction, field
  assignment and the `with_*` chain no longer compile; use `ReceiptBuilder`
  (ending in `.build(source_text_check)`) to construct, and the accessors to
  read.
- `Receipt::from_json` and `Receipt::from_slice` reject duplicate property names
  anywhere in the document. Plain `serde` deserialization still accepts such a
  document — nothing can detect it there — but the receipt is never confirmed.

### JSON canonicalization now actually is RFC 8785

ATL v2.0 §2.3 requires JSON to be canonicalized "according to the JSON
Canonicalization Scheme (JCS) [RFC8785]" before being hashed, §3.1 defines
`MetadataHash` as the SHA-256 of the JCS-canonicalized metadata, and §5.1
steps 2-4 have the verifier recompute it the same way. The requirement has been in
the specification from the start; the implementation did not meet it. This is
therefore a **repair of the implementation, not a change to the protocol** —
`spec_version` stays `2.0.0`, because no receipt's meaning, structure or
required processing changes. What changes is that receipts carrying certain
numbers now get the hash the specification always called for.

Three independent defects, of which only two were in this crate's own code.

**1. Exponential notation was never emitted.** RFC 8785 §3.2.2.3 requires
ECMA-262 §7.1.12.1 verbatim. That algorithm switches to exponential form once
the decimal exponent reaches 21 or drops to -7, and writes the sign:
`1e+21`, `5e-324`, `1.7976931348623157e+308`. `format_float()` delegated to
Rust's `f64` Display, which is always positional, so `1e+21` came out as a
22-character digit string and `5e-324` as 325 characters. The function did
contain an exponential branch, but Rust's Display never produces an `e`, so
the branch was unreachable — and it stripped the `+` from the exponent, so had
it ever fired it would have emitted `1e30` where the RFC requires `1e+30`.
Its doc comment stated "No `+` sign in exponent" as a rule, which is the
opposite of what RFC 8785 says. Branch and comment are both gone.

**2. Shortest-digit ties broke the wrong way.** Where two shortest
round-tripping decimals are exactly equidistant from the double, ECMA-262
"Note 2" takes the even one and Rust's Display takes the larger. RFC 8785
Appendix B note (4) calls out this exact row: `0x43143ff3c1cb0959` is exactly
`1424953923781206.25`, and canonicalizes to `1424953923781206.2`, not `...06.3`.

Both are fixed by taking the number formatter from `ryu-js`, whose documented
contract *is* the ECMAScript algorithm, instead of from a std formatter that
only promises to round-trip. (When this was written, integers that `serde_json`
holds as `i64`/`u64` were still emitted verbatim, on the reasoning that §3.1
puts values beyond double precision outside JCS input. That reasoning was
wrong — §3.1 binds the producer, not the serializer — and integers now go
through the same ECMA-262 rendering as every other number; see the section
above.)

**3. A JSON number could parse to the wrong double — before canonicalization
ran at all.** `serde_json`'s default number parser is a best-effort f64 fast
path. It lands one ULP away from the correctly rounded value for roughly 30%
of arbitrary doubles, including RFC 8785's own worked example:
`333333333.33333329` parsed to `0x41b3de4355555554`, where Rust's
`str::parse::<f64>`, CPython and ECMAScript all give `0x41b3de4355555555`.

This one was the serious one. The other two need an extreme magnitude or an
exact tie; this one needs an ordinary 17-significant-digit decimal, and it
breaks agreement between two verifiers reading *the same bytes*. It was also
not in this crate's code — but the dependency and its configuration are part
of what this crate ships, so it was this crate's defect regardless. The fix is
to take `serde_json` with its `float_roundtrip` feature, which selects the
correctly rounded parser. Cargo unifies features, so every build that links
`atl-core` gets it.

`tests/proptests.rs` now states the joint guarantee as a property over
arbitrary bit patterns — a canonicalized double must parse back to the same
double, and canonicalizing a document, re-reading it and canonicalizing again
must give identical bytes and identical hashes. Dropping `float_roundtrip`
from `Cargo.toml` fails that test rather than silently changing hashes.

### Compatibility

**Deliberately a hard change: an affected receipt issued before this release
no longer verifies.** No compatibility mode is offered, because the evidence
says none is needed. A survey of the production corpus found 116 entries with
metadata and **zero** containing a floating-point number. The 39-receipt
zatona.bio corpus was re-canonicalized here under both the old and the new
code: **byte-identical canonical forms and identical `metadata_hash` values for
all 39** — every metadata value in it is a string. Nothing already issued
changes; a compatibility mode would only preserve non-conformant hashes that
no receipt has.

### A note for other implementations

`metadata_hash` depends on the JSON *parser* as much as on the canonicalizer.
An implementation whose number parser is not correctly rounded computes a
different hash for the same receipt bytes, and no amount of correctness in the
canonicalizer repairs that. In Rust that means `serde_json` with
`float_roundtrip`; `str::parse::<f64>` is already correctly rounded.

### Added

- `ryu-js` dependency (zero transitive dependencies, MSRV 1.71, Apache-2.0 OR
  BSL-1.0): the ECMA-262 §7.1.12.1 number-to-string algorithm RFC 8785 §3.2.2.3
  mandates.

### Changed

- `serde_json` is now taken with the `float_roundtrip` feature, and its minimum
  version is 1.0.151 — the version this was verified against.
- All 11 cases in `test_data/vectors/jcs/cases.json` that were marked
  `known_divergence` are now `pass`; the markers, their `atl_core_actual`
  regression pins and the `known_divergences` descriptions are removed. Not one
  `expected` value was touched.

## [0.27.0]

### The defects this release fixes

Two places where the crate asserted more than it had checked, or disagreed
with itself about what it accepts.

**1. `bitcoin_block_height` was never compared with the proof.** ATL v2.0
§5.5.2 lists five steps for a Bitcoin OpenTimestamps anchor, and step 5 reads:

> Verify that `bitcoin_block_height` and `bitcoin_block_time` match the proof.

`verify_anchor` destructured `ReceiptAnchor::BitcoinOts` with `..` and threw
both fields away. A receipt could state block 900000 while carrying an OTS
proof that attests to 932897, and the anchor came out valid — the receipt's
own assertion about its own evidence, never examined.

The height half is pure computation: an OpenTimestamps Bitcoin attestation
encodes the height in its own bytes. It is now compared, and a disagreement
makes the anchor invalid with an error naming both numbers.

The **time** half is deliberately still not attempted here, and that is not
an oversight. The block time appears in no proof; it exists only in the block
header, and obtaining one is I/O this crate does not do. A caller that does
fetch headers completes that half. Reporting a comparison that never ran
would be worse than not running it.

**2. The parser could not read the reference server's own output.**
`parse_iso8601_to_nanos` required exactly 20 characters ending in `Z`, while
`atl-server` writes anchor timestamps with `to_rfc3339()`, which renders UTC
as `+00:00`. 37 of the 38 anchor timestamps in the production corpus were
rejected, and every `claimed_timestamp` derived from one came out `None`.
§4.2 types these fields as `<ISO8601>` and constrains them no further, so a
verifier accepting only one spelling of an instant was the thing that was
wrong.

**3. The parser aborted the process on non-ASCII input.** Introduced by the
rewrite above and caught before release. `split_at(len - 6)` indexed a `&str`
at a byte position derived from its length, and `str` slicing panics when
that position is not a UTF-8 character boundary. `bitcoin_block_time` and an
anchor's `timestamp` are unvalidated `String`s deserialized straight from a
receipt, so a `bitcoin_block_time` of `"\u{1F4A5}abc"` killed `atl-cli` with
SIGABRT.

A verifier must answer "refuted" or "could not check"; dying on a signal
answers nothing, and a receipt is adversarial input by definition. The parser
now indexes **byte slices only** — where an out-of-range index is a `None`
and character boundaries do not exist — which removes the class rather than
guarding the one instance. The guarantee is stated as a property test over
arbitrary strings, not as a list of the shapes that happened to break it.

**4. `spec_version` was gated by three different rules.**
`Receipt::from_json` and the verifier's step 0 each inlined `!= "2.0.0"`,
while `atl-cli` accepted any `2.x`. A `2.0.1` receipt therefore got past the
caller's door and was then reported as a *defective receipt* rather than as a
revision the build does not implement — "could not check" published as
"checked and false". There is now one predicate,
[`is_supported_spec_version`], and every gate asks it.

**5. The height check compared against an invented criterion.** The first
version of the step 5 check took `attestations.iter().map(|a|
a.block_height).min()`. No such rule exists: §5.5.2 says "match the proof",
and the word *attestation* does not occur in the specification at all. A
proof may carry several Bitcoin attestations, and under `min()` a receipt
naming a height genuinely present in its own proof — just not the lowest —
was declared refuted by a criterion nobody set. The claim now holds if it
matches **any** attestation.

### Added

- **`ots::attestation_for_claimed_height`** and
  **`ots::attested_block_heights`**. The single definition of "the receipt's
  height matches its proof", so a consumer such as `atl-cli` asks rather than
  reimplements — two independent copies of a rule are two rules. The second
  returns the whole attested set, which is the evidence a refusal has to
  publish.

- **`is_supported_spec_version(&str) -> bool`**, exported from the crate root
  and the prelude. The single answer to "does this build implement that
  receipt revision", for this crate and for its consumers.

  The match is **exact**. §4.2 defines `spec_version` as "REQUIRED: Protocol
  version. Currently `"2.0.0"`" and stops: it states no compatibility
  contract, no rule that a verifier must accept later revisions of the same
  major version, and no rule about unrecognised fields. With nothing written
  down to rely on, accepting `2.0.1` would mean asserting a verification
  carried out under rules this build has never seen. Widening it is a
  specification change first.

### Changed

**`parse_iso8601_to_nanos` accepts RFC 3339, not one spelling of it.** A
numeric `±hh:mm` offset is accepted and *applied*; `T` and `Z` are accepted
in either case; fractional seconds are parsed to full nanosecond resolution.

Three refusals are deliberate, and each would otherwise put a wrong value
into a caller's hands:

- **More than nine fractional digits**, unless every digit past the ninth is
  `0`. Nanoseconds are the finest resolution the return type expresses, and
  truncating below it would return the value of a *different* instant — which
  a caller comparing instants then reports as a match.
- **No offset at all.** An instant with no zone is not an instant, and
  assuming UTC would invent information.
- **A second field of `60`.** RFC 3339 permits it for leap seconds; this
  function does not model them, and an approximate instant is worse than
  none.

A `None` return has always meant "this build could not read the string",
never "the string is wrong", and callers must keep classifying it as an
inability.

**The function is total on `&str`: no input panics.** It is public and is fed
receipt fields, so this is part of its contract, not an implementation
detail. `days_since_unix_epoch` was hardened the same way — `get` and
`checked_sub` in place of indexing and unsigned subtraction whose bounds were
enforced in a different function.

### Breaking changes

**`verify_bitcoin_ots_anchor_impl` takes a fourth argument**,
`claimed_block_height: u64` — the receipt's own `bitcoin_block_height`, for
step 5 to check the proof against. Both the feature-enabled and the
feature-disabled form changed, so a downstream call site fails to compile
rather than silently keeping the unchecked behaviour. Pass
`anchor.bitcoin_block_height`; there is no value that means "skip this
check", by design.

Anchors verified through `verify_anchor` / `ReceiptVerifier::verify` need no
change: the field is threaded automatically. A receipt whose stated height
contradicts its proof now comes out `is_valid: false` where it previously
came out `true`, which is the point of the release.

### Notes

- A verifier that already ignored anchors (`VerifyOptions { skip_anchors:
  true }`) is unaffected by the first change.
- The parser fix makes `claimed_timestamp` populated where it was previously
  `None` on production data. It feeds only `claimed_*` fields — a value that
  was never established does not become established by becoming readable.

## [0.26.0]

### The defect this release fixes

RFC 3161 certificate-path construction conflated **"checked and false"** with
**"could not check"**, and reported both as `PathStatus::Invalid` — a
refutation. A consumer reading that status told its user their evidence had
been *disproved*.

The clearest way to trigger it: a self-signed root whose self-signature uses
SHA-1, an algorithm this crate deliberately does not implement. Such roots are
not exotic — 31 of the 156 roots in macOS's system trust store sign themselves
with SHA-1, DigiCert Assured ID Root CA among them. The signature check failed
to *run*, the certificate was therefore not recognised as self-issued, the only
same-named candidate was eliminated, and the fallback declared "every candidate
failed its signature" → `Invalid`. Nothing had been disproved. The same thing
happened whether such a root arrived from a caller-supplied trust store or was
simply present inside the token.

### Breaking changes

**`PathStatus` has a new variant, `Indeterminate`.** This will *not* fail to
compile in a downstream crate whose `match` on `PathStatus` uses a wildcard
arm, and that is exactly why it is called out here: the semantics changed
underneath such code. Audit every place you read `PathStatus`:

| was | is now |
|---|---|
| `Invalid` for an unsupported signature/key/curve algorithm | `Indeterminate` |
| `Invalid` for exceeding the path-exploration depth limit | `Indeterminate` |
| `Invalid` when every same-named candidate was pruned by the cycle guard | `Incomplete` |
| `Invalid` for a CMS signature using an unimplemented algorithm | `cms_signature: Indeterminate` |
| `Invalid` for a `messageImprint` using an unimplemented hash algorithm | `message_imprint: Indeterminate` |
| `Invalid` when the first SID-matching certificate was an impostor | `Verified`, if the genuine signer is also present |
| `Refuted` when every SID-matching candidate failed | `cms_signature: Indeterminate` |
| signer facts / EKU / chain reported for an unverified candidate | `None` / `NotChecked` / `Indeterminate` |
| `Invalid` for an internal DER re-encoding failure | `Indeterminate` |
| `Invalid` when one refuted alternative coexisted with an unexplored one | `Incomplete` / `Indeterminate` |
| `Complete` for a self-issued terminal whose self-signature is unverifiable | `Indeterminate` |
| `Invalid` when the token was rejected before a signer certificate was chosen | `Incomplete` (the refutation is in the CMS facts) |

`Invalid` now means one thing only: **something was checked and is false**, and
no viable unexplored alternative remains. `Incomplete` and `Indeterminate` are
statements about *this verifier's* limits and must never be presented as
refuted evidence. If your code maps anything but `Complete` to a failure
verdict, it is reintroducing the bug this release fixes.

Every consumer must route `Indeterminate` explicitly and **fail closed**: it is
never a success, and never a refutation.

**`TerminalAnchor::Assumed` gained a field**, `self_signature: SelfSignature`
(`Verified` | `Unverifiable`). This *does* fail to compile for a struct-pattern
match that names the fields exhaustively; add `..` or bind the new field. The
variant's documentation previously claimed the certificate "correctly signs
itself" — that was never true for `Unverifiable`, and is now stated accurately.
A self-issued certificate whose self-signature is checked and *fails* is no
longer reported as `Assumed` at all: equal Distinguished Names plus a
demonstrably wrong self-signature is not a terminus.

**`Rfc3161AnchorFacts::cms_signature_valid: bool` is replaced by
`cms_signature: CmsSignature`** (`Verified` | `Refuted` | `Indeterminate`).
This *does* fail to compile wherever the field was read, which is deliberate:
the boolean had the same defect as `PathStatus::Invalid`. A signature this
crate cannot evaluate — `algorithms` implements neither P-521 nor RSA-PSS, so
this is a token a real TSA can mint today — came back `false` and was
published as *a broken signature*. An ESS signing-certificate binding whose
hash algorithm is unimplemented was likewise reported as a binding *mismatch*
(new `CmsVerifyError::EssBindingUnverifiable`). Map `Refuted` to whatever you
mapped `false` to; map `Indeterminate` to fail-closed-but-not-refuted.

**`Rfc3161AnchorFacts::imprint_matches_root: bool` is replaced by
`message_imprint: MessageImprint`** (`Verified` | `Mismatch` | `Malformed` |
`Indeterminate`), for the same reason. A `messageImprint` naming a hash
algorithm this crate does not implement was never *compared* with the
expected root, yet came back `false` and was published as a mismatch. ATL
mandates a *minimum* of algorithm support, not a prohibition on the rest, so
an unrecognised algorithm is this verifier's limitation and not the token's
defect — hence `Indeterminate` rather than a refutation. `Mismatch` and
`Malformed` are both refutations but are kept apart: a hash length that
contradicts the algorithm it names could never be compared at all, so
reporting it as "does not match the expected root" would explain a proven
defect with a cause that is not true of it.

**`Rfc3161AnchorFacts` gained two public fields**, `timestamping_eku:
TimestampingEku` and `chain_diagnostic: Option<String>`. Struct-literal
construction of this type breaks; reading it does not. `timestamping_eku_ok`
is unchanged and still equals `timestamping_eku.is_ok()`.

**`AnchorVerificationResult::timestamp` is now `Some` only when
`is_valid`**, and the anchor's asserted time moved to the new
`claimed_timestamp` field. This compiles unchanged for existing readers and
changes what they see, which is normally the dangerous kind of change — it is
acceptable here only because it fails *safe*: a reader loses a value it
should never have trusted rather than gaining a false one. A timestamp anchor
exists to answer "when did this exist", so handing that number over
unqualified for an anchor that did not verify was the most misleading thing
this type could do. The claim is not discarded, only renamed so it cannot be
mistaken for a verified fact.

**`TimestampingEku` has a `NotChecked` variant**, and consumers must route it
as an inability rather than a failure — `timestamping_eku_ok` is `false` for
it, so any consumer branching on that boolean alone will refute on a fact
nobody examined. Branch on `timestamping_eku` instead. It is used where the token
was rejected before a signer certificate was settled on, which previously
reported `Absent` — a fact about a certificate nobody had looked at.

### Added

- `PathStatus::Indeterminate`, `CmsSignature`, `MessageImprint`,
  `SelfSignature`, `TimestampingEku` (all re-exported from the crate root and
  the prelude).
- `Rfc3161AnchorFacts::chain_diagnostic` — prose explaining what stopped path
  construction, including the reasons alternative paths were refuted. Kept even
  when the reported status is not a refutation, so a consumer can say *why* a
  path was not reached without having to overclaim that it was disproved.
- RFC 5280 §4.1.1.2 enforcement: `Certificate.signatureAlgorithm` and
  `tbsCertificate.signature` must be the same algorithm identifier. This was
  not checked at all before; a mismatch is now a refutation.
- Candidate-issuer **ordering** by `AuthorityKeyIdentifier` →
  `SubjectKeyIdentifier` and by issuer/serial, where the certificates carry
  that data. This is part of the defence against a certificate planted in the
  CMS certificate set (RFC 5652 §5.1): candidates the identifier points at
  are tried first, so a planted certificate cannot displace the real issuer
  by position. **No candidate is ever excluded** — RFC 5280 §4.2.1.1 does not
  require applications to match key identifiers when validating a path, and
  the signature, not the identifier, settles who the issuer was.

### Changed

- **"Every candidate failed" is no longer a refutation, and an unestablished
  signer publishes no signer facts.** The same unauthenticated certificate
  set that lets an attacker *add* a certificate lets them *delete* one, so a
  token whose genuine signer certificate was removed — leaving only a
  same-SID impostor — would have been reported as disproved evidence when its
  signature was never checked against anything. That is the same over-claim
  as the absent-certificate case, which was already `Indeterminate`; two
  spellings of "we do not have the certificate" must not give opposite
  verdicts. Both are now `Indeterminate`, with the diagnostic recording what
  was tried.

  What can still be refuted is everything checkable from `SignerInfo` and the
  encapsulated content — `content-type`, `message-digest`, signed-attribute
  cardinality, the presence of an ESS binding, CMS Algorithm Protection.
  Those are certificate-independent, so a failure is a property of the token
  whichever certificate a caller might try; they now run once up front
  (`cms_verify::verify_signed_attributes`), so a tampered `message-digest` is
  still caught as forgery rather than softened into "cannot tell".

  Correspondingly, when no signer is established `signer` is `None`,
  `timestamping_eku` is `NotChecked`, `path_status` is `Indeterminate` and
  `terminal_anchor` is `None`. `SignerFacts` documents the identity of the
  certificate that *produced the CMS signature*; filling it from an
  unverified candidate put a falsehood in the type itself, and a deterministic
  choice among unverified candidates is still an arbitrary one.
- **The CMS signer is chosen by verification, not by position.** A
  `SignedData` certificate set is not covered by the signature, and
  `SignerInfo.sid` (issuer+serial or `SubjectKeyIdentifier`) is not unique
  across an attacker-supplied set. Taking the first match let anyone add a
  certificate bearing the real signer's issuer and serial but a different
  key: the impostor was selected, failed verification, and a wholly valid
  token was published as refuted evidence while the genuine signer sat
  unexamined in the same set — a way for a stranger to discredit somebody
  else's sound token. Every SID-matching candidate is now tried, and any
  one verifying in full makes the token `Verified`. When none verifies the
  result is `Indeterminate`, never `Refuted` — see the entry above on why
  "every candidate failed" cannot establish anything about the signature.
- An ESS signing-certificate binding whose hash algorithm is not implemented
  now reports the new `CmsVerifyError::EssBindingUnverifiable` instead of
  `EssBindingMismatch` — the same "could not check" reported as "checked and
  wrong", one layer down.
- Certificate-to-certificate edges now yield three answers instead of two:
  verified, refuted, or undeterminable. Only "unsupported signature algorithm",
  "unsupported public-key algorithm" and "unsupported curve" are
  undeterminable; malformed keys, malformed signature bits, key-family
  mismatches and failed verifications are refutations.
- Alternative paths are aggregated as **independent facts** rather than ranked.
  The previous ranking put `Invalid` above `Incomplete`, which meant a single
  planted same-named certificate with a bad signature could declare an entire
  chain refuted while a genuine unexplored alternative sat beside it. The rule
  now: *if a viable unexplored alternative exists, the outcome may not claim
  the chain is refuted.*
- The trust-anchor match is evaluated **before** a non-leaf anchor's own
  validity period, `BasicConstraints`, `KeyUsage` and `ExtendedKeyUsage`.
  RFC 5280 §6.1 treats a trust anchor as an externally supplied trusted input
  to path validation, not as a link of the path being validated. Without this,
  an expired long-lived root a verifier had explicitly designated would
  silently stop working, as would a cross-signed "root" whose own issuer is
  absent from the token. Every edge *below* the anchor is still verified in
  full.

  **The signer certificate is excluded from that exemption.** Its validity at
  `genTime`, its critical extensions and its `KeyUsage` are checked before any
  trust matching, even when the caller pinned it. Pinning the leaf is still
  permitted — it is simply not a way to switch off the checks. A timestamp's
  entire claim is temporal, so reporting `Complete` and
  `chain_valid_at_gen_time = true` for a signer that had already expired at
  `genTime` would publish a fact nobody verified.
- **`AuthorityKeyIdentifier` orders issuer candidates; it never removes
  them.** An earlier draft of this release used it as a filter, which
  RFC 5280 §4.2.1.1 does not support — applications are not required to match
  key identifiers when validating a path — and which produced a false
  `Incomplete` for a legitimate issuer that omits or disagrees on its
  `SubjectKeyIdentifier`. It would also have hollowed out the aggregation rule
  below: "an unexplored alternative forbids claiming refutation" is only sound
  if the alternatives are actually walked. Every DN match is now walked, with
  AKI-named candidates tried first; the signature settles who the issuer was.
- `check_timestamping_eku` now reports *which* RFC 3161 §2.3 condition failed
  (absent / malformed / not critical / not exclusive) instead of a single
  `false`.
- `BasicConstraints` is now actually decoded on the signer certificate. It was
  in the processed-critical-extension whitelist — a promise to evaluate it —
  but was never read there. A malformed or duplicated extension is refuted; a
  signer asserting `cA = true` is **not** rejected, deliberately: RFC 3161
  constrains the signer through the exclusive critical `id-kp-timeStamping`
  EKU, not through `BasicConstraints`.
- A `TSTInfo.genTime` that cannot be represented now yields `Indeterminate`
  rather than `Incomplete`: no certificate was ever checked against it.

### Unchanged, deliberately

Malformed or duplicated `BasicConstraints` / `KeyUsage` / CA-`ExtendedKeyUsage`
extensions, and unrecognised critical extensions, remain refutations. These are
not gaps in the material supplied — they are contents that are wrong, and
RFC 5280 §4.2 requires rejecting the last of them outright.

[0.26.0]: https://github.com/evidentum-io/atl-core/releases/tag/v0.26.0
