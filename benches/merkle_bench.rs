//! Merkle tree and cryptographic operation benchmarks
//!
//! Performance targets:
//! - `sha256_hash`: < 1 microsec (32-byte input)
//! - `leaf_hash`: < 1 microsec (single leaf)
//! - `inclusion_verify`: < 10 microsec (log(n) hashes)
//! - `checkpoint_verify`: < 200 microsec (Ed25519 verify)
//! - `jcs_canonicalize`: < 100 microsec (typical metadata)
//! - `receipt_verify`: < 500 microsec (full verification)

#![allow(missing_docs)]

use atl_core::core::checkpoint::{Checkpoint, CheckpointVerifier, compute_key_id};
use atl_core::core::jcs::{canonicalize, canonicalize_and_hash};
use atl_core::core::merkle::{
    Hash, compute_leaf_hash, compute_root, generate_inclusion_proof, verify_inclusion,
};
use atl_core::core::receipt::{Receipt, format_hash, format_signature};
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

// ========== Helper Functions ==========

fn setup_test_keypair() -> (SigningKey, [u8; 32]) {
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let verifying_key_bytes = signing_key.verifying_key().to_bytes();
    (signing_key, verifying_key_bytes)
}

fn create_test_checkpoint(signing_key: &SigningKey) -> Checkpoint {
    let origin = [1u8; 32];
    let tree_size = 1000u64;
    let timestamp = 1_704_067_200_000_000_000u64;
    let root_hash = [2u8; 32];

    let mut blob = [0u8; 98];
    blob[0..18].copy_from_slice(b"ATL-Protocol-v1-CP");
    blob[18..50].copy_from_slice(&origin);
    blob[50..58].copy_from_slice(&tree_size.to_le_bytes());
    blob[58..66].copy_from_slice(&timestamp.to_le_bytes());
    blob[66..98].copy_from_slice(&root_hash);

    let signature = signing_key.sign(&blob);
    let key_id = compute_key_id(&signing_key.verifying_key().to_bytes());

    Checkpoint::new(origin, tree_size, timestamp, root_hash, signature.to_bytes(), key_id)
}

// ========== Benchmarks ==========

fn bench_sha256_hash(c: &mut Criterion) {
    use sha2::{Digest, Sha256};

    let input = [0xabu8; 32];

    c.bench_function("sha256_hash_32bytes", |b| {
        b.iter(|| {
            let _hash: [u8; 32] = Sha256::digest(black_box(&input)).into();
        });
    });
}

fn bench_compute_leaf_hash(c: &mut Criterion) {
    let payload_hash = [0xaau8; 32];
    let metadata_hash = [0xbbu8; 32];

    c.bench_function("compute_leaf_hash", |b| {
        b.iter(|| compute_leaf_hash(black_box(&payload_hash), black_box(&metadata_hash)));
    });
}

fn bench_compute_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("compute_root");

    for size in &[1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1000] {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let leaves: Vec<Hash> = (0..*size).map(|i| [(i % 256) as u8; 32]).collect();

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| compute_root(black_box(&leaves)));
        });
    }

    group.finish();
}

fn bench_verify_inclusion(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_inclusion");

    for tree_size in &[10, 100, 1000, 10000] {
        #[allow(clippy::cast_possible_truncation)]
        let leaves: Vec<Hash> = (0..*tree_size).map(|i| [(i % 256) as u8; 32]).collect();
        let root = compute_root(&leaves);

        #[allow(clippy::cast_possible_truncation)]
        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let leaf_index = tree_size / 2;
        let proof = generate_inclusion_proof(leaf_index, *tree_size, get_node).unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(tree_size), tree_size, |b, _| {
            b.iter(|| {
                verify_inclusion(
                    black_box(&leaves[leaf_index as usize]),
                    black_box(&proof),
                    black_box(&root),
                )
            });
        });
    }

    group.finish();
}

fn bench_generate_inclusion_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("generate_inclusion_proof");

    for tree_size in &[10, 100, 1000, 10000] {
        #[allow(clippy::cast_possible_truncation)]
        let leaves: Vec<Hash> = (0..*tree_size).map(|i| [(i % 256) as u8; 32]).collect();

        #[allow(clippy::cast_possible_truncation)]
        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let leaf_index = tree_size / 2;

        group.bench_with_input(BenchmarkId::from_parameter(tree_size), tree_size, |b, _| {
            b.iter(|| {
                generate_inclusion_proof(black_box(leaf_index), black_box(*tree_size), get_node)
            });
        });
    }

    group.finish();
}

fn bench_jcs_canonicalize(c: &mut Criterion) {
    let mut group = c.benchmark_group("jcs_canonicalize");

    // Simple metadata
    let simple = json!({"filename": "document.pdf"});

    group.bench_function("simple", |b| {
        b.iter(|| canonicalize(black_box(&simple)));
    });

    // Typical metadata
    let typical = json!({
        "filename": "important_contract.pdf",
        "size": 1_024_567,
        "mime_type": "application/pdf",
        "created": "2026-01-15T10:30:00Z",
        "tags": ["contract", "important", "signed"]
    });

    group.bench_function("typical", |b| {
        b.iter(|| canonicalize(black_box(&typical)));
    });

    // Complex nested metadata
    let complex = json!({
        "filename": "report.pdf",
        "size": 5_242_880,
        "metadata": {
            "author": "John Doe",
            "department": "Engineering",
            "version": "1.2.3",
            "tags": ["report", "quarterly", "2026"],
            "properties": {
                "pages": 150,
                "language": "en",
                "format": "A4"
            }
        },
        "history": [
            {"action": "created", "timestamp": "2026-01-01T00:00:00Z"},
            {"action": "modified", "timestamp": "2026-01-15T10:30:00Z"}
        ]
    });

    group.bench_function("complex", |b| {
        b.iter(|| canonicalize(black_box(&complex)));
    });

    group.finish();
}

fn bench_jcs_canonicalize_and_hash(c: &mut Criterion) {
    let metadata = json!({
        "filename": "document.pdf",
        "size": 1_024_567,
        "created": "2026-01-15T10:30:00Z"
    });

    c.bench_function("jcs_canonicalize_and_hash", |b| {
        b.iter(|| canonicalize_and_hash(black_box(&metadata)));
    });
}

fn bench_checkpoint_verify(c: &mut Criterion) {
    let (signing_key, verifying_key_bytes) = setup_test_keypair();
    let checkpoint = create_test_checkpoint(&signing_key);
    let verifier = CheckpointVerifier::from_bytes(&verifying_key_bytes).unwrap();

    c.bench_function("checkpoint_verify", |b| {
        b.iter(|| {
            checkpoint.verify(black_box(&verifier)).unwrap();
        });
    });
}

fn bench_checkpoint_to_bytes(c: &mut Criterion) {
    let (signing_key, _) = setup_test_keypair();
    let checkpoint = create_test_checkpoint(&signing_key);

    c.bench_function("checkpoint_to_bytes", |b| {
        b.iter(|| checkpoint.to_bytes());
    });
}

fn bench_checkpoint_from_bytes(c: &mut Criterion) {
    let (signing_key, _) = setup_test_keypair();
    let checkpoint = create_test_checkpoint(&signing_key);
    let blob = checkpoint.to_bytes();

    c.bench_function("checkpoint_from_bytes", |b| {
        b.iter(|| Checkpoint::from_bytes(black_box(&blob)));
    });
}

fn bench_receipt_parsing(c: &mut Criterion) {
    let receipt_json = r#"{
        "spec_version": "1.0.0",
        "entry": {
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "payload_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "metadata": {
                "filename": "document.pdf",
                "size": 1024567,
                "created": "2026-01-15T10:30:00Z"
            }
        },
        "proof": {
            "tree_size": 100,
            "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "inclusion_path": [
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            ],
            "leaf_index": 42,
            "checkpoint": {
                "origin": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "tree_size": 100,
                "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "timestamp": 1704067200000000000,
                "signature": "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "key_id": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            }
        }
    }"#;

    c.bench_function("receipt_from_json", |b| {
        b.iter(|| Receipt::from_json(black_box(receipt_json)));
    });

    let receipt = Receipt::from_json(receipt_json).unwrap();

    c.bench_function("receipt_to_json", |b| {
        b.iter(|| receipt.to_json());
    });
}

fn bench_hash_formatting(c: &mut Criterion) {
    let hash = [0xabu8; 32];

    c.bench_function("format_hash", |b| {
        b.iter(|| format_hash(black_box(&hash)));
    });

    let signature = [0xcdu8; 64];

    c.bench_function("format_signature", |b| {
        b.iter(|| format_signature(black_box(&signature)));
    });
}

criterion_group!(
    benches,
    bench_sha256_hash,
    bench_compute_leaf_hash,
    bench_compute_root,
    bench_verify_inclusion,
    bench_generate_inclusion_proof,
    bench_jcs_canonicalize,
    bench_jcs_canonicalize_and_hash,
    bench_checkpoint_verify,
    bench_checkpoint_to_bytes,
    bench_checkpoint_from_bytes,
    bench_receipt_parsing,
    bench_hash_formatting,
);

criterion_main!(benches);
