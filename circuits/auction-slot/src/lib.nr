// SPDX-License-Identifier: MIT

// Interfold v0.19.0 secure-8192 P3 uses descending polynomial coefficients.
// Its k1 witness equals (Q mod t) * plaintext mod t, represented in [0,t).
pub global DEGREE: u32 = 8192;
pub global PLAINTEXT_MODULUS: u64 = 17000000;
pub global Q_MOD_T: u64 = 13178113;
pub global MAX_BIDDERS: u32 = 32;
pub global MAX_BID: u16 = 100;

/// Application constraints to compose INSIDE the encryption proof.
/// `bid` is private. Never publish k1 or its deterministic commitment: this
/// auction's 101 possible amounts can be enumerated from such a commitment.
/// This library alone does not establish encryption, byte/hash, key or DA validity.
pub fn assert_auction_slot(k1: [Field; DEGREE], slot: u32, bid: u16) {
    assert(slot < MAX_BIDDERS, "slot exceeds auction hard limit");
    assert(bid <= MAX_BID, "bid exceeds collateral range");
    let scaled = ((Q_MOD_T * bid as u64) % PLAINTEXT_MODULUS) as Field;
    for i in 0..DEGREE {
        let expected = if i == DEGREE - 1 - slot { scaled } else { 0 };
        assert(k1[i] == expected, "k1 must contain only the assigned bid slot");
    }
}

fn fixture(slot: u32, bid: u16) -> [Field; DEGREE] {
    let mut k1 = [0; DEGREE];
    k1[DEGREE - 1 - slot] = ((Q_MOD_T * bid as u64) % PLAINTEXT_MODULUS) as Field;
    k1
}

#[test]
fn valid_first_and_last_slots() {
    assert_auction_slot(fixture(0, 31), 0, 31);
    assert_auction_slot(fixture(31, 100), 31, 100);
}

#[test]
fn zero_abstention() {
    assert_auction_slot([0; DEGREE], 7, 0);
}

#[test(should_fail)]
fn rejects_out_of_range_bid() {
    assert_auction_slot(fixture(0, 101), 0, 101);
}

#[test(should_fail)]
fn rejects_out_of_range_slot() {
    assert_auction_slot(fixture(32, 31), 32, 31);
}

#[test(should_fail)]
fn rejects_extra_coefficient_above_revealed_prefix() {
    let mut k1 = fixture(1, 77);
    k1[DEGREE - 1 - 8000] = 1;
    assert_auction_slot(k1, 1, 77);
}

#[test(should_fail)]
fn rejects_other_bidder_slot() {
    assert_auction_slot(fixture(0, 42), 1, 42);
}

#[test(should_fail)]
fn rejects_ascending_order() {
    let mut k1 = [0; DEGREE];
    k1[1] = ((Q_MOD_T * 77) % PLAINTEXT_MODULUS) as Field;
    assert_auction_slot(k1, 1, 77);
}

#[test(should_fail)]
fn rejects_unscaled_plaintext() {
    let mut k1 = [0; DEGREE];
    k1[DEGREE - 1 - 1] = 77;
    assert_auction_slot(k1, 1, 77);
}

#[test(should_fail)]
fn rejects_negative_field_alias() {
    let mut k1 = fixture(1, 77);
    k1[DEGREE - 1 - 1] = -1;
    assert_auction_slot(k1, 1, 77);
}
