# atl-core

Pure cryptographic library for ATL Protocol v2.0.

## Documentation

Full documentation is available at:

**https://atl-protocol.org/implementations/atl-core**

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
