//! Integration tests for lib.rs exports and constants

use atl_core::*;

// ========== Version Constants Tests ==========

#[test]
fn test_version_constant() {
    assert!(!VERSION.is_empty());
    assert!(VERSION.contains('.'));
}

#[test]
fn test_protocol_version_constant() {
    assert_eq!(PROTOCOL_VERSION, "2.0.0");
}

#[test]
fn test_receipt_version_constant() {
    assert_eq!(RECEIPT_VERSION, "2.0.0");
}

// ========== Merkle Exports Tests ==========

#[test]
fn test_merkle_constants_accessible() {
    assert_eq!(LEAF_PREFIX, 0x00);
    assert_eq!(NODE_PREFIX, 0x01);
    assert_eq!(GENESIS_DOMAIN, b"ATL-CHAIN-v1");
}

#[test]
fn test_merkle_functions_accessible() {
    let hash = [0u8; 32];
    let leaf = compute_leaf_hash(&hash, &hash);
    assert_eq!(leaf.len(), 32);

    let root = compute_root(&[leaf]);
    assert_eq!(root, leaf);

    let children = hash_children(&hash, &hash);
    assert_eq!(children.len(), 32);
}

#[test]
fn test_merkle_proof_accessible() {
    // Verify inclusion proof functions are accessible
    let hash = [0u8; 32];
    let proof = InclusionProof { leaf_index: 0, tree_size: 1, path: vec![] };
    assert!(verify_inclusion(&hash, &proof, &hash).is_ok());
}

#[test]
fn test_genesis_leaf_hash() {
    let root = [5u8; 32];
    let size = 10;
    let hash = compute_genesis_leaf_hash(&root, size);
    assert_eq!(hash.len(), 32);

    // Should be deterministic
    let hash2 = compute_genesis_leaf_hash(&root, size);
    assert_eq!(hash, hash2);
}

// ========== Checkpoint Exports Tests ==========

#[test]
fn test_checkpoint_constants() {
    assert_eq!(CHECKPOINT_MAGIC, b"ATL-Protocol-v1-CP");
    assert_eq!(CHECKPOINT_BLOB_SIZE, 98);
}

#[test]
fn test_checkpoint_id_functions() {
    use uuid::Uuid;

    let key_bytes = [42u8; 32];
    let key_id = compute_key_id(&key_bytes);
    assert_eq!(key_id.len(), 32);

    let uuid = Uuid::nil();
    let origin_id = compute_origin_id(&uuid);
    assert_eq!(origin_id.len(), 32);
}

// ========== Receipt Exports Tests ==========

#[test]
fn test_receipt_spec_version() {
    assert_eq!(RECEIPT_SPEC_VERSION, "2.0.0");
}

#[test]
fn test_anchor_target_constants() {
    assert_eq!(ANCHOR_TARGET_DATA_TREE_ROOT, "data_tree_root");
    assert_eq!(ANCHOR_TARGET_SUPER_ROOT, "super_root");
}

#[test]
fn test_receipt_tier_names() {
    assert_eq!(ReceiptTier::Lite.name(), "Receipt-Lite");
    assert_eq!(ReceiptTier::Full.name(), "Receipt-Full");
}

// ========== Verification Exports Tests ==========

#[test]
fn test_signature_mode_default() {
    let mode = SignatureMode::default();
    assert_eq!(mode, SignatureMode::Optional);
}

#[test]
fn test_signature_status_default() {
    let status = SignatureStatus::default();
    assert_eq!(status, SignatureStatus::Skipped);
}

#[test]
fn test_verify_options_default() {
    let options = VerifyOptions::default();
    assert_eq!(options.signature_mode, SignatureMode::Optional);
    assert!(!options.skip_anchors);
    assert!(!options.skip_consistency);
    assert_eq!(options.min_valid_anchors, 0);
}

// ========== JCS Export Tests ==========

#[test]
fn test_jcs_canonicalize() {
    let json = serde_json::json!({"b": 2, "a": 1});
    let canonical = canonicalize(&json).expect("input satisfies RFC 8785 Section 3.1");
    assert_eq!(canonical, r#"{"a":1,"b":2}"#);
}

#[test]
fn test_jcs_hash() {
    let json = serde_json::json!({"test": "data"});
    let hash = canonicalize_and_hash(&json).expect("metadata satisfies RFC 8785 Section 3.1");
    assert_eq!(hash.len(), 32);

    // Should be deterministic
    let hash2 = canonicalize_and_hash(&json).expect("metadata satisfies RFC 8785 Section 3.1");
    assert_eq!(hash, hash2);
}

// ========== Type Accessibility Tests ==========

#[test]
fn test_all_main_types_accessible() {
    // Merkle types
    let _: Hash = [0u8; 32];
    let _ = Leaf { payload_hash: [0u8; 32], metadata_hash: [1u8; 32] };
    let _ = TreeHead { tree_size: 1, root_hash: [0u8; 32] };
    let _ = InclusionProof { leaf_index: 0, tree_size: 1, path: vec![] };
    let _ = ConsistencyProof { from_size: 1, to_size: 2, path: vec![] };

    // Receipt types
    let _ = ReceiptTier::Full;

    // Verify types
    let _ = SignatureMode::Optional;
    let _ = SignatureStatus::Skipped;
}

#[test]
fn test_super_verification_result_accessible() {
    let result = SuperVerificationResult::valid([0u8; 32], [1u8; 32]);
    assert!(result.inclusion_valid);
    assert!(result.consistency_valid);
    assert_eq!(result.genesis_super_root, [0u8; 32]);
    assert_eq!(result.super_root, [1u8; 32]);
}

#[test]
fn test_anchor_verification_context_accessible() {
    let ctx = AnchorVerificationContext::new([0u8; 32], [1u8; 32]);
    assert!(ctx.expected_hash_for_target("data_tree_root").is_some());
    assert!(ctx.expected_hash_for_target("super_root").is_some());
}

// ========== Deprecated Functions Still Work ==========

#[allow(deprecated)]
#[test]
fn test_deprecated_exports_accessible() {
    // Just verify they compile and are accessible
    let _ = verify_receipt;
    let _ = verify_receipt_json;
}

// ========== Cross-Receipt Types ==========

#[test]
fn test_cross_receipt_result_methods() {
    let result = CrossReceiptVerificationResult {
        same_log_instance: true,
        history_consistent: true,
        genesis_super_root: [0u8; 32],
        receipt_a_index: 1,
        receipt_b_index: 2,
        receipt_a_super_tree_size: 5,
        receipt_b_super_tree_size: 10,
        errors: vec![],
    };

    assert!(result.is_valid());
    assert!(result.same_log_instance);
    assert!(result.history_consistent);
}

#[test]
fn test_cross_receipt_ordering() {
    use std::cmp::Ordering;

    let result = CrossReceiptVerificationResult {
        same_log_instance: true,
        history_consistent: true,
        genesis_super_root: [0u8; 32],
        receipt_a_index: 5,
        receipt_b_index: 10,
        receipt_a_super_tree_size: 10,
        receipt_b_super_tree_size: 15,
        errors: vec![],
    };

    let ordering = result.ordering();
    assert_eq!(ordering, Ordering::Less);
}

// ========== Feature-gated Tests ==========

#[cfg(feature = "bitcoin-ots")]
#[test]
fn test_ots_module_accessible() {
    use atl_core::ots::*;
    // Just verify the module and types are accessible when feature is enabled
    let _ = BITCOIN_TAG;
    let _ = PENDING_TAG;
}

#[cfg(feature = "rfc3161-verify")]
#[test]
fn test_rfc3161_types_accessible() {
    // Verify types are accessible when feature is enabled
    let _: Option<Rfc3161VerifyResult> = None;
    let _: Option<ParsedTimestampToken> = None;
}

// ========== Prelude Tests ==========

#[test]
fn test_prelude_exports() {
    use atl_core::prelude::*;

    // Verify main types are accessible via prelude
    let _ = ReceiptTier::Lite;
    let _ = SignatureMode::Optional;

    // Verify functions accessible
    let hash = canonicalize_and_hash(&serde_json::json!({}))
        .expect("metadata satisfies RFC 8785 Section 3.1");
    assert_eq!(hash.len(), 32);

    // Verify more types
    let _ = SuperProof {
        genesis_super_root: String::new(),
        data_tree_index: 0,
        super_tree_size: 1,
        super_root: String::new(),
        inclusion: vec![],
        consistency_to_origin: vec![],
    };

    let _ = AnchorVerificationContext::new([0u8; 32], [1u8; 32]);
}

#[test]
fn test_prelude_verification_functions() {
    use atl_core::prelude::*;

    // Verify verification functions are accessible
    let _ = verify_super_inclusion;
    let _ = verify_consistency_to_origin;
    let _ = verify_cross_receipts;
    let _ = verify_receipt_anchor_only;
}

// ========== Error Types ==========

#[test]
fn test_error_types_accessible() {
    let _: AtlError = AtlError::InvalidHash("test".to_string());
    let _: AtlResult<()> = Ok(());
}

#[test]
fn test_verification_error_types() {
    let error = VerificationError::SignatureFailed;
    let s = format!("{error}");
    assert!(!s.is_empty());
}

// ===========================================================================
// Compile-time pins on the provenance API
// ===========================================================================
//
// These are `const` items, not `#[test]` functions: they are checked when this
// file compiles, so a regression is a build failure rather than a red test.
// They live in an integration test on purpose — that makes this an *external*
// crate, so what they pin is the surface a consumer actually sees, not what is
// reachable from inside `atl-core`.
//
// Why a signature pin and not `trybuild`: the regression being guarded is
// exactly "the marker is handed out by value again", and a coerced function
// pointer catches that at zero dependency cost. `trybuild` could additionally
// assert that a *named* expression fails to compile, but it cannot assert the
// absence of an API either — it can only enumerate candidate expressions, the
// same as this does — and it pulls in a dependency tree (glob, toml, termcolor,
// serde_derive) into a crate that is deliberately thin and is audited by
// `cargo-deny`. The added coverage does not pay for that.

/// **The marker must never leave a `Receipt` by value.**
///
/// While `source_text_check()` returned `SourceTextCheck`, the private field
/// bought nothing: the type is `Copy` and `Receipt::new` accepts it, so
/// `Receipt::new(spec, bad_entry, bad_proof, trusted.source_text_check())`
/// carried a certification onto content it never covered — no escape hatch
/// named, and the shape a "preserve the provenance" pipeline would naturally
/// take. Changing this return type back to `SourceTextCheck` fails to compile
/// here.
const _: fn(&Receipt) -> bool = Receipt::source_text_was_checked;

/// **Construction goes through a separate type, and provenance is settled last.**
///
/// `ReceiptBuilder::build` must consume a `ReceiptBuilder` — never a `Receipt`
/// — and must keep demanding a `SourceTextCheck`. A method taking a `Receipt`
/// and returning a `Receipt` is a setter whatever it is called: five of them
/// (`with_anchors`, `with_super_proof`, `with_super_proof_option`,
/// `with_upgrade_url`, `with_upgrade_url_option`) once reproduced by method the
/// field assignment that privacy had just closed. If the parameter became a
/// `bool`, any caller could spell the checked state with the literal `true`.
const _: fn(ReceiptBuilder, SourceTextCheck) -> Receipt = ReceiptBuilder::build;
const _: fn(String, ReceiptEntry, ReceiptProof) -> ReceiptBuilder = ReceiptBuilder::new;

/// And the hatch stays the only public producer of a checked marker.
const _: fn() -> SourceTextCheck =
    SourceTextCheck::assume_duplicate_property_names_already_rejected;

/// **Every `Receipt` accessor must return a shared reference or a copy — never
/// an owned field and never `&mut`.**
///
/// This is what makes the provenance marker inseparable from the content it was
/// taken over. While the data fields were public, the marker could be carried
/// onto foreign content without touching `SourceTextCheck` at all:
///
/// ```text
/// let mut carried = checked.clone();
/// carried.entry   = unchecked.entry;     // every crypto field consistent,
/// carried.proof   = unchecked.proof;     // metadata_hash agrees,
/// carried.anchors = unchecked.anchors;   // nothing to catch
/// // is_valid: true
/// ```
///
/// Returning an owned `ReceiptEntry`, or exposing `&mut`, reopens exactly that.
/// Each line below fails to compile if the corresponding signature changes.
const _: fn(&Receipt) -> &ReceiptEntry = Receipt::entry;
const _: fn(&Receipt) -> &ReceiptProof = Receipt::proof;
const _: fn(&Receipt) -> &[ReceiptAnchor] = Receipt::anchors;
const _: fn(&Receipt) -> Option<&SuperProof> = Receipt::super_proof;
const _: fn(&Receipt) -> &str = Receipt::spec_version;
const _: fn(&Receipt) -> Option<&str> = Receipt::upgrade_url;

/// A receipt cannot be edited after it exists; a changed one is a *new* one,
/// and building it demands a provenance answer. Checked here through the
/// public API only, since this is an external crate.
#[test]
fn test_a_rebuilt_receipt_states_its_own_provenance() {
    let json = sample_receipt_json();
    let checked = Receipt::from_json(&json).expect("valid receipt");
    assert!(checked.source_text_was_checked());

    // Everything a consumer can read is a shared borrow, and the only route to a
    // different receipt is `ReceiptBuilder`, which cannot be made from a
    // `Receipt` and settles provenance at `build`.
    let rebuilt = ReceiptBuilder::new(
        checked.spec_version().to_string(),
        checked.entry().clone(),
        checked.proof().clone(),
    )
    .anchors(checked.anchors().to_vec())
    .super_proof_option(checked.super_proof().cloned())
    .build(SourceTextCheck::default());

    assert!(!rebuilt.source_text_was_checked());
    assert_eq!(rebuilt.entry().payload_hash, checked.entry().payload_hash);
}

/// **Nothing in `src/core/receipt.rs` may turn a `Receipt` into a `Receipt`.**
///
/// That is the rule `ReceiptBuilder` exists to enforce. It is a statement about
/// *absence*, which no signature pin can make, so this parses the file with
/// `syn` and fails on anything matching the shape.
///
/// # What it checks
///
/// Walking every item in the file, **recursively through inline `mod` blocks**:
///
/// * **Methods.** In any `impl` whose self type is `Receipt` — inherent or
///   trait, written as `Receipt`, `super::Receipt`, `crate::…::Receipt`, or
///   through a type alias — a method that takes a receiver in any form
///   (`self`, `mut self`, `&self`, `&mut self`) and whose return type mentions
///   `Receipt`, `Self`, or a `Receipt` alias.
/// * **Free functions.** A function taking a `Receipt` parameter and returning
///   a `Receipt`. This is the same setter without a receiver, and it is *not*
///   hypothetical: written in `core::receipt` itself it sits inside the module
///   where the private fields are visible, and `lib.rs` declares `pub mod core`
///   while `core/mod.rs` declares `pub mod receipt`, so
///   `atl_core::core::receipt::rebuild(…)` is callable by any consumer. An
///   earlier revision of this guard asserted such functions were safe because
///   they "cannot touch private fields from another module". They are not in
///   another module.
/// * **Escapes to the builder.** A function taking a `Receipt` and returning a
///   `ReceiptBuilder`, which would reopen the path from a receipt back to a
///   mutable form.
/// * **Type aliases.** `type Rebuilt = Receipt;` is resolved transitively, so
///   `-> Rebuilt` is caught. Without this the return check was purely lexical.
///
/// # What it does not check
///
/// Named exactly, and **no claim of safety is attached to any of them** — the
/// previous version of this comment drew exactly that unproven inference and
/// was wrong:
///
/// * **Only this file.** An `impl Receipt` or a free function in another module
///   of this crate is not seen. Such code in another module cannot write the
///   private fields directly, but it can call anything this file exposes, so
///   this is a gap in coverage rather than a proof of safety.
/// * **Macro-generated items.** `syn` parses source as written. A method
///   produced by expansion is invisible here, `Clone::clone` included.
/// * **Module visibility is not tracked.** A `pub fn` inside a private `mod` is
///   not reachable by a consumer, yet is still reported. That is deliberate:
///   a crate-internal carry is still a carry, and this guard should not have to
///   reason about visibility chains to be trusted.
/// * **`#[cfg(test)]` items are skipped**, because they are not compiled into
///   the library a consumer links. This is the one exclusion justified by
///   reachability rather than by cost, and it is why `test_support::tamper` —
///   which is exactly a rebuild helper — does not trip the guard.
/// * Trait *objects*, generic parameters bounded to `Receipt`, and any future
///   syntactic form nobody has thought of.
///
/// The guard is not complete and cannot be. What it is, is honest about which
/// shapes it covers.
#[test]
fn test_nothing_turns_a_receipt_into_a_receipt() {
    use std::collections::BTreeSet;

    /// Methods that take a receiver and return `Self` legitimately.
    ///
    /// `(trait, method)`, each needing a reason, because a wrong entry here is
    /// a hole in the invariant.
    ///
    /// * `Clone::clone` — takes `&self` and returns an identical value, copying
    ///   the provenance marker together with the content that marker covers, so
    ///   it cannot separate them. In practice it is derived and never appears
    ///   in the parsed source; the entry stays so a hand-written
    ///   `impl Clone for Receipt` need not be argued about again.
    const ALLOWED: &[(&str, &str)] = &[("Clone", "clone")];

    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/core/receipt.rs");
    let source = std::fs::read_to_string(path).expect("receipt.rs is readable");
    let file = syn::parse_file(&source).expect("receipt.rs parses as Rust");

    /// `#[cfg(test)]`, in the plain form this crate uses.
    ///
    /// A compound predicate such as `#[cfg(all(test, feature = "x"))]` is not
    /// recognised, which fails *safe*: the item would be walked and possibly
    /// reported, never silently skipped.
    fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|a| {
            if !a.path().is_ident("cfg") {
                return false;
            }
            let mut found = false;
            let _ = a.parse_nested_meta(|meta| {
                if meta.path.is_ident("test") {
                    found = true;
                }
                Ok(())
            });
            found
        })
    }

    fn last_segment(path: &syn::Path) -> Option<String> {
        path.segments.last().map(|s| s.ident.to_string())
    }

    /// Every identifier appearing anywhere in a type.
    fn idents_in(ty: &syn::Type) -> BTreeSet<String> {
        use syn::visit::Visit;

        #[derive(Default)]
        struct Collect(BTreeSet<String>);
        impl<'ast> Visit<'ast> for Collect {
            fn visit_ident(&mut self, ident: &'ast syn::Ident) {
                self.0.insert(ident.to_string());
            }
        }

        let mut c = Collect::default();
        c.visit_type(ty);
        c.0
    }

    /// Collect `type X = Receipt;` transitively, descending into modules.
    fn collect_aliases(items: &[syn::Item], names: &mut BTreeSet<String>) -> bool {
        let mut grew = false;
        for item in items {
            match item {
                syn::Item::Type(alias) => {
                    if let syn::Type::Path(p) = &*alias.ty {
                        if let Some(target) = last_segment(&p.path) {
                            if names.contains(&target) && names.insert(alias.ident.to_string()) {
                                grew = true;
                            }
                        }
                    }
                }
                syn::Item::Mod(m) => {
                    if let Some((_, inner)) = &m.content {
                        grew |= collect_aliases(inner, names);
                    }
                }
                _ => {}
            }
        }
        grew
    }

    let mut receipt_names: BTreeSet<String> = BTreeSet::new();
    receipt_names.insert("Receipt".to_string());
    while collect_aliases(&file.items, &mut receipt_names) {}

    struct Ctx<'a> {
        names: &'a BTreeSet<String>,
        allowed: &'a [(&'a str, &'a str)],
        findings: Vec<String>,
        impls_seen: usize,
        free_fns_seen: usize,
    }

    fn mentions(ty: &syn::Type, names: &BTreeSet<String>, allow_self: bool) -> bool {
        idents_in(ty).iter().any(|i| names.contains(i) || (allow_self && i == "Self"))
    }

    fn returns_builder(output: &syn::ReturnType, names: &BTreeSet<String>) -> bool {
        match output {
            syn::ReturnType::Default => false,
            syn::ReturnType::Type(_, ty) => {
                let _ = names;
                idents_in(ty).contains("ReceiptBuilder")
            }
        }
    }

    fn takes_receipt(sig: &syn::Signature, names: &BTreeSet<String>) -> bool {
        sig.inputs.iter().any(|arg| match arg {
            syn::FnArg::Typed(t) => mentions(&t.ty, names, false),
            syn::FnArg::Receiver(_) => false,
        })
    }

    fn returns_receipt(
        output: &syn::ReturnType,
        names: &BTreeSet<String>,
        allow_self: bool,
    ) -> bool {
        match output {
            syn::ReturnType::Default => false,
            syn::ReturnType::Type(_, ty) => mentions(ty, names, allow_self),
        }
    }

    fn walk(items: &[syn::Item], module: &str, ctx: &mut Ctx<'_>) {
        for item in items {
            match item {
                syn::Item::Mod(m) if !is_cfg_test(&m.attrs) => {
                    if let Some((_, inner)) = &m.content {
                        let nested = if module.is_empty() {
                            m.ident.to_string()
                        } else {
                            format!("{module}::{}", m.ident)
                        };
                        walk(inner, &nested, ctx);
                    }
                }

                // A free function taking a receipt and handing one back.
                syn::Item::Fn(f) if !is_cfg_test(&f.attrs) => {
                    ctx.free_fns_seen += 1;
                    if !takes_receipt(&f.sig, ctx.names) {
                        continue;
                    }
                    if returns_receipt(&f.sig.output, ctx.names, false) {
                        ctx.findings.push(format!(
                            "free function `{}`{} takes a Receipt and returns a Receipt",
                            f.sig.ident,
                            location(module)
                        ));
                    } else if returns_builder(&f.sig.output, ctx.names) {
                        ctx.findings.push(format!(
                            "free function `{}`{} turns a Receipt into a ReceiptBuilder",
                            f.sig.ident,
                            location(module)
                        ));
                    }
                }

                syn::Item::Impl(block) if !is_cfg_test(&block.attrs) => {
                    let self_is_receipt = match &*block.self_ty {
                        syn::Type::Path(p) if p.qself.is_none() => {
                            last_segment(&p.path).is_some_and(|n| ctx.names.contains(&n))
                        }
                        _ => false,
                    };
                    if !self_is_receipt {
                        continue;
                    }
                    ctx.impls_seen += 1;

                    let trait_name =
                        block.trait_.as_ref().and_then(|(_, path, _)| last_segment(path));

                    for impl_item in &block.items {
                        let syn::ImplItem::Fn(method) = impl_item else { continue };
                        if is_cfg_test(&method.attrs) {
                            continue;
                        }
                        // Inherent methods are reachable only if `pub`; trait
                        // methods carry no visibility of their own and are as
                        // reachable as the trait, so all are examined.
                        if trait_name.is_none() && !matches!(method.vis, syn::Visibility::Public(_))
                        {
                            continue;
                        }
                        if method.sig.receiver().is_none() {
                            continue;
                        }
                        if !returns_receipt(&method.sig.output, ctx.names, true) {
                            continue;
                        }

                        let name = method.sig.ident.to_string();
                        if let Some(t) = &trait_name {
                            if ctx.allowed.contains(&(t.as_str(), name.as_str())) {
                                continue;
                            }
                        }
                        let where_ = trait_name.as_ref().map_or_else(
                            || "impl Receipt".to_string(),
                            |t| format!("impl {t} for Receipt"),
                        );
                        ctx.findings.push(format!(
                            "`{name}` in `{where_}`{} takes a receiver and returns a Receipt",
                            location(module)
                        ));
                    }
                }
                _ => {}
            }
        }
    }

    fn location(module: &str) -> String {
        if module.is_empty() {
            String::new()
        } else {
            format!(" (in `mod {module}`)")
        }
    }

    let mut ctx = Ctx {
        names: &receipt_names,
        allowed: ALLOWED,
        findings: Vec::new(),
        impls_seen: 0,
        free_fns_seen: 0,
    };
    walk(&file.items, "", &mut ctx);

    assert!(
        ctx.findings.is_empty(),
        "these carry a provenance marker onto content it never covered, which is a \
         setter however it is named. Construction belongs on ReceiptBuilder, which \
         cannot be made from a Receipt. If one of these is genuinely safe, add it to \
         ALLOWED with a reason:\n  - {}",
        ctx.findings.join("\n  - ")
    );

    // The walk must actually have looked at something; a guard that silently
    // matches nothing is worse than none.
    assert!(ctx.impls_seen > 0, "found no `impl Receipt` -- the guard is inspecting nothing");
    assert!(
        ctx.free_fns_seen > 0,
        "found no free functions -- the recursive walk is not reaching them"
    );
    assert!(
        !receipt_names.is_empty(),
        "alias resolution produced nothing, not even `Receipt` itself"
    );
}

/// `Default` must stay *unchecked*, since it is what every `serde` path yields.
#[test]
fn test_default_provenance_is_unchecked() {
    assert!(!SourceTextCheck::default().is_checked());
    assert!(SourceTextCheck::assume_duplicate_property_names_already_rejected().is_checked());
}

/// The public reader answers a `bool`, and the two ways a consumer can obtain a
/// confirmable receipt both go through this crate's own text parsing.
#[test]
fn test_provenance_is_readable_only_as_a_bool() {
    let json = sample_receipt_json();

    let parsed = Receipt::from_json(&json).expect("valid receipt");
    let checked: bool = parsed.source_text_was_checked();
    assert!(checked);

    let sliced = Receipt::from_slice(json.as_bytes()).expect("valid receipt");
    assert!(sliced.source_text_was_checked());

    // Every `serde` path is unchecked, read through the same `bool`.
    let via_serde: Receipt = serde_json::from_str(&json).expect("valid receipt");
    let unchecked: bool = via_serde.source_text_was_checked();
    assert!(!unchecked);
}

fn sample_receipt_json() -> String {
    r#"{"spec_version":"2.0.0","entry":{"id":"550e8400-e29b-41d4-a716-446655440000",
    "payload_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "metadata_hash":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "metadata":{}},"proof":{"tree_size":1,
    "root_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "inclusion_path":[],"leaf_index":0,"checkpoint":{
    "origin":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "tree_size":1,
    "root_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "timestamp":1704067200000000000,"signature":"base64:AAAA",
    "key_id":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}}}"#
        .to_string()
}
