# Changelog

All notable changes to `atl-core` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
