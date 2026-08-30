# Changelog

All notable changes to `atl-core` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
