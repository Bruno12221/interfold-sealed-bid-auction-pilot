//! Auction Secure Process guest. Source only until built/proved with the pinned OpenVM toolchain.
//! It relies on the application contract's input verifier for sparse plaintext/range validity.
//! It NEVER reads plaintext bids, encryption randomness, or a decryption key.
openvm::init!();
use e3_compute_provider::SecureProcess;
use e3_openvm_types::{ComputeJournal, GuestHeader};
use interfold_auction_bfv_slots::{fhe_processor, keccak, policy, MAX_BIDDERS};
use sha2::Digest;

fn main() {
    let header = GuestHeader::decode(&openvm::io::read_vec()).expect("invalid guest header");
    let count = header.indices.len();
    assert!(
        (1..=MAX_BIDDERS).contains(&count),
        "empty or oversized auction"
    );
    assert_eq!(
        header.published.len(),
        count,
        "every admitted bid needs bound metadata"
    );
    assert!(
        header
            .indices
            .iter()
            .enumerate()
            .all(|(i, v)| *v == i as u64),
        "nonconsecutive slots"
    );
    assert_eq!(header.domain.chain_id, 11155111, "wrong chain");
    // Exact keccak256(encode_bfv_params(SECURE_THRESHOLD_8192)), checked by native fixture tests.
    let secure_hash = [
        0x1b, 0x26, 0x20, 0xf6, 0xa5, 0x91, 0x9d, 0x5e, 0xe1, 0x9a, 0x51, 0xf3, 0x40, 0x26, 0x36,
        0x98, 0x16, 0xf4, 0x79, 0xef, 0xd0, 0x40, 0x4b, 0x56, 0x58, 0x5a, 0xd3, 0x7d, 0x31, 0xc5,
        0x23, 0x17,
    ];
    assert_eq!(keccak(&header.params), secure_hash, "wrong BFV preset");
    let mut process =
        SecureProcess::new(&header.params, header.indices, header.published, policy())
            .expect("invalid round");
    for _ in 0..count {
        process
            .absorb(&openvm::io::read_vec())
            .expect("invalid admitted ciphertext");
    }
    let (result, _) = process
        .select()
        .expect("invalid selection")
        .finish(fhe_processor, |_| Ok(openvm::io::read_vec()))
        .expect("invalid aggregate");
    let journal = ComputeJournal::new(&header.domain, &result)
        .expect("invalid journal")
        .abi_bytes();
    let digest = openvm_sha2::Sha256::digest(&journal);
    for (i, word) in digest.chunks_exact(4).enumerate() {
        openvm::io::reveal_u32(u32::from_le_bytes(word.try_into().unwrap()), i);
    }
}
