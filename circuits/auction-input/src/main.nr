// SPDX-License-Identifier: LGPL-3.0-only

// Compose BOTH secure8192 encryption legs and the private auction constraints
// in one circuit. No k1 commitment or private inner proof is a public output.
//
// This proof must be paired with a verified serialized-byte-to-SAFE proof.
// The companion public proof binds ciphertextHash and ciphertextCommitment to
// the actual serialized ciphertext. This private circuit binds the key's SAFE
// commitment to the encryption key coefficients.
// Both proofs MUST be verified against the identical 26 public limbs below.

use auction_slot::assert_auction_slot;
use interfold::configs::secure::threshold::{
    L, N, USER_DATA_ENCRYPTION_BIT_CT, USER_DATA_ENCRYPTION_BIT_E0,
    USER_DATA_ENCRYPTION_BIT_E1, USER_DATA_ENCRYPTION_BIT_K,
    USER_DATA_ENCRYPTION_BIT_PK, USER_DATA_ENCRYPTION_BIT_U,
    USER_DATA_ENCRYPTION_CT0_BIT_R, USER_DATA_ENCRYPTION_CT0_CONFIGS,
    USER_DATA_ENCRYPTION_CT1_BIT_R, USER_DATA_ENCRYPTION_CT1_CONFIGS,
};
use interfold::core::threshold::user_data_encryption_ct0::UserDataEncryptionCt0;
use interfold::core::threshold::user_data_encryption_ct1::UserDataEncryptionCt1;
use interfold::math::commitments::{compute_commitment, DS_CIPHERTEXT, DS_PK_AGGREGATION};
use interfold::math::polynomial::Polynomial;

global TWO_POW_128: Field = 340282366920938463463374607431768211456;
global FIELD_MODULUS_HIGH: u128 = 64323764613183177041862057485226039389;
global FIELD_MODULUS_LOW: u128 = 53438638232309528389504892708671455233;

// All words are encoded high128, low128, in IAuctionInputVerifier.Statement
// ABI order. u128 input types constrain BOTH limbs; no 256-bit value is reduced
// modulo the Noir field. SAFE values additionally have canonical field checks.
fn canonical_safe(high: u128, low: u128) -> Field {
    assert(
        (high < FIELD_MODULUS_HIGH)
            | ((high == FIELD_MODULUS_HIGH) & (low < FIELD_MODULUS_LOW)),
        "SAFE commitment must be canonical",
    );
    (high as Field) * TWO_POW_128 + low as Field
}

fn assert_address(high: u128, low: u128) {
    assert(high <= 4294967295, "address exceeds 160 bits");
    assert((high != 0) | (low != 0), "zero address");
}

fn main(
    statement: pub [u128; 26],
    bid: u16,
    pk0is: [Polynomial<N>; L],
    pk1is: [Polynomial<N>; L],
    ct0is: [Polynomial<N>; L],
    ct1is: [Polynomial<N>; L],
    u: Polynomial<N>,
    e0: Polynomial<N>,
    e1: Polynomial<N>,
    k1: Polynomial<N>,
    r: [Polynomial<N>; L],
    r_ct1: [Polynomial<N>; L],
) {
    // chainId, program, Interfold, auction, bidder.
    assert(statement[0] == 0);
    assert(statement[1] == 11155111, "only Sepolia is supported");
    assert_address(statement[2], statement[3]);
    assert_address(statement[4], statement[5]);
    assert_address(statement[6], statement[7]);
    assert_address(statement[18], statement[19]);

    // Secure8192 parameters, independent of the upstream default preset.
    assert(statement[14] == 36087131745293411406921770754992649880);
    assert(statement[15] == 30512409512294138972111128587156136727);
    assert(statement[16] == 0);
    assert(statement[17] < 32, "slot exceeds auction hard limit");
    assert(statement[20] == 0);
    assert(statement[21] == 100, "unsupported bid range");
    let expected_pk = canonical_safe(statement[12], statement[13]);
    let expected_ct = canonical_safe(statement[24], statement[25]);

    assert_auction_slot(k1.coefficients, statement[17] as u32, bid);

    let ct0: UserDataEncryptionCt0<N, L, USER_DATA_ENCRYPTION_BIT_PK, USER_DATA_ENCRYPTION_BIT_CT, USER_DATA_ENCRYPTION_BIT_U, USER_DATA_ENCRYPTION_BIT_E0, USER_DATA_ENCRYPTION_BIT_K, USER_DATA_ENCRYPTION_CT0_BIT_R> =
        UserDataEncryptionCt0::new(USER_DATA_ENCRYPTION_CT0_CONFIGS, pk0is, ct0is, u, e0, k1, r);
    let ct1: UserDataEncryptionCt1<N, L, USER_DATA_ENCRYPTION_BIT_PK, USER_DATA_ENCRYPTION_BIT_CT, USER_DATA_ENCRYPTION_BIT_U, USER_DATA_ENCRYPTION_BIT_E1, USER_DATA_ENCRYPTION_CT1_BIT_R> =
        UserDataEncryptionCt1::new(USER_DATA_ENCRYPTION_CT1_CONFIGS, pk1is, ct1is, u, e1, r_ct1);
    let (pk0_commitment, ct0_commitment, _private_k1_commitment, u0_commitment) = ct0.execute();
    let (pk1_commitment, ct1_commitment, u1_commitment) = ct1.execute();
    assert(u0_commitment == u1_commitment, "encryption legs must share randomness");

    let actual_pk = compute_commitment(
        [pk0_commitment, pk1_commitment].as_vector(), DS_PK_AGGREGATION,
    );
    let actual_ct = compute_commitment(
        [ct0_commitment, ct1_commitment].as_vector(), DS_CIPHERTEXT,
    );
    assert(actual_pk == expected_pk, "committee key differs");
    assert(actual_ct == expected_ct, "ciphertext differs");
}
