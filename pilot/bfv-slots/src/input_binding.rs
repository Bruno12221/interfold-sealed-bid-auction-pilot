//! Public half of the composed input proof: bind exact ciphertext bytes to the SAFE
//! commitments used by the private Noir encryption circuit. No bid or randomness is read.
use crate::{Result, keccak, params};
use e3_bfv_client::client::compute_ct_commitment_with_params;

pub const STATEMENT_BYTES: usize = 13 * 32;
pub const SECURE_PARAMS_HASH: [u8; 32] = [
    0x1b, 0x26, 0x20, 0xf6, 0xa5, 0x91, 0x9d, 0x5e, 0xe1, 0x9a, 0x51, 0xf3, 0x40,
    0x26, 0x36, 0x98, 0x16, 0xf4, 0x79, 0xef, 0xd0, 0x40, 0x4b, 0x56, 0x58, 0x5a,
    0xd3, 0x7d, 0x31, 0xc5, 0x23, 0x17,
];

/// `statement` is exactly `abi.encode(IAuctionInputVerifier.Statement)` in struct order.
/// Its SHA-256 digest is the public output of the byte-binding OpenVM guest. The
/// final adapter also reconstructs all 26 high/low u128 Noir public inputs from it.
pub fn validate(statement: &[u8], ciphertext: &[u8]) -> Result<()> {
    if statement.len() != STATEMENT_BYTES {
        return Err("input statement must contain exactly thirteen ABI words".into());
    }
    let word = |i: usize| -> [u8; 32] { statement[i * 32..(i + 1) * 32].try_into().unwrap() };
    let integer = |i: usize, expected: u64| -> bool {
        let value = word(i);
        value[..24] == [0; 24] && value[24..] == expected.to_be_bytes()
    };
    if !integer(0, 11_155_111) || word(7) != SECURE_PARAMS_HASH || !integer(10, 100) {
        return Err("wrong chain, secure BFV parameters, or auction range".into());
    }
    for i in [1, 2, 3, 9] {
        let value = word(i);
        if value[..12] != [0; 12] || value[12..] == [0; 20] {
            return Err("statement address must be a nonzero canonical ABI address".into());
        }
    }
    let slot = word(8);
    if slot[..31] != [0; 31] || slot[31] >= 32 {
        return Err("statement slot exceeds auction hard limit".into());
    }
    if ciphertext.is_empty() || ciphertext.len() > 1_000_000 {
        return Err("invalid serialized ciphertext size".into());
    }
    if keccak(ciphertext) != word(11) {
        return Err("ciphertext bytes do not match the admitted hash".into());
    }
    // The companion Noir proof already anchors its pk0/pk1 polynomials to word(6),
    // the DKG committee's SAFE key commitment. Public-key serialization is not an
    // admitted object and adds no relation to the ciphertext byte link here.
    let commitment = compute_ct_commitment_with_params(ciphertext, &params())
        .map_err(|_| "invalid secure-8192 ciphertext serialization")?;
    if commitment != word(12) {
        return Err("serialized ciphertext does not match the encryption proof SAFE commitment".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DEGREE, MODULI, PLAINTEXT_MODULUS, encrypt_bid, fixed};
    use fhe::bfv::{PublicKey, SecretKey};
    use fhe_traits::Serialize;
    use std::sync::OnceLock;
    struct Fixture { statement: Vec<u8>, ct: Vec<u8> }
    fn fixture() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let params = params();
            let secret = SecretKey::random(&params, &mut rand::rng());
            let key = PublicKey::new(&secret, &mut rand::rng()).to_bytes();
            let key_commitment = e3_bfv_client::client::compute_pk_commitment(key.clone(), DEGREE, PLAINTEXT_MODULUS, MODULI.to_vec()).unwrap();
            let bid = encrypt_bid(&key, key_commitment, 31, 100, 100).unwrap();
            let mut words = [[0u8; 32]; 13];
            words[0][24..].copy_from_slice(&11_155_111u64.to_be_bytes());
            for i in [1, 2, 3, 9] { words[i][12..].fill(i as u8); }
            words[4] = [0xff; 32]; // Keep full-width context and address-prefixed E3 ID.
            words[5] = [0xfd; 32];
            words[6] = key_commitment;
            words[7] = SECURE_PARAMS_HASH;
            words[8][31] = 31;
            words[10][31] = 100;
            words[11] = fixed(&bid.ciphertext_hash).unwrap();
            words[12] = fixed(&bid.commitment).unwrap();
            Fixture { statement: words.concat(), ct: crate::bytes(&bid.ciphertext).unwrap() }
        })
    }
    #[test]
    fn binds_actual_secure_ciphertext_and_full_width_statement() {
        let f = fixture();
        validate(&f.statement, &f.ct).unwrap();
        assert_eq!(f.statement.len(), 416);
        assert_eq!(f.statement[5 * 32], 0xfd);
    }
    #[test]
    fn rejects_hash_and_safe_commitment_substitution() {
        let f = fixture();
        for index in [11, 12] {
            let mut statement = f.statement.clone();
            statement[index * 32 + 31] ^= 1;
            assert!(validate(&statement, &f.ct).is_err());
        }
        let mut ct = f.ct.clone(); ct[100] ^= 1;
        assert!(validate(&f.statement, &ct).is_err());
    }
    #[test]
    fn rejects_noncanonical_abi_and_wrong_preset() {
        let f = fixture();
        for (offset, value) in [(0, 1), (32, 1), (7 * 32, 1), (8 * 32 + 31, 32), (10 * 32 + 31, 101)] {
            let mut statement = f.statement.clone(); statement[offset] = value;
            assert!(validate(&statement, &f.ct).is_err());
        }
        assert!(validate(&f.statement[..415], &f.ct).is_err());
    }
}
