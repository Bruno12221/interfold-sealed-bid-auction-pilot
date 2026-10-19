//! Prove only public serialization/commitment linkage; the composed Noir proof
//! independently proves valid private encryption and the bounded sparse bid.
openvm::init!();
use sha2::Digest;

fn main() {
    let statement = openvm::io::read_vec();
    let ciphertext = openvm::io::read_vec();
    interfold_auction_bfv_slots::input_binding::validate(&statement, &ciphertext)
        .expect("input bytes do not match the public encryption statement");
    let digest = openvm_sha2::Sha256::digest(&statement);
    for (i, word) in digest.chunks_exact(4).enumerate() {
        openvm::io::reveal_u32(u32::from_le_bytes(word.try_into().unwrap()), i);
    }
}
