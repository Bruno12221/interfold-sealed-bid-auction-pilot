use e3_bfv_client::client::compute_pk_commitment;
use fhe::bfv::{Ciphertext, Encoding, PublicKey, SecretKey};
use fhe_traits::{DeserializeParametrized, FheDecoder, FheDecrypter, Serialize};
use interfold_auction_bfv_slots::{
    Anchor, DEGREE, MODULI, Manifest, ManifestInput, OUTPUT_COEFFICIENTS, PLAINTEXT_MODULUS,
    UPSTREAM_COMMIT, bytes, compute, encrypt_bid, envelope, hex, next_root, params, reveal,
};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let params = params();
    let mut rng = rand::rng();
    // The full throwaway key exists only in this process. Never serialize it.
    let secret = SecretKey::random(&params, &mut rng);
    let public = PublicKey::new(&secret, &mut rng).to_bytes();
    let key_commitment =
        compute_pk_commitment(public.clone(), DEGREE, PLAINTEXT_MODULUS, MODULI.to_vec())?;
    let bids = [31, 77, 42];
    let context = [0x11; 32];
    let mut root = context;
    let mut inputs = Vec::new();
    for (slot, bid) in bids.iter().copied().enumerate() {
        let encrypted = encrypt_bid(&public, key_commitment, slot, bid, 100)?;
        let ciphertext = bytes(&encrypted.ciphertext)?;
        // Empty proof fields are a synthetic fixture, deliberately unacceptable for live admission.
        let input = ManifestInput {
            slot,
            bidder: format!("0x{:040x}", slot + 1),
            ciphertext: encrypted.ciphertext,
            envelope: hex(&envelope(
                &interfold_auction_bfv_slots::keccak(&ciphertext),
                &[],
                &[],
            )),
            commitment: encrypted.commitment,
        };
        root = next_root(&root, &input)?;
        inputs.push(input);
    }
    let manifest = Manifest {
        schema_version: 1,
        anchor: Anchor {
            chain_id: "11155111".into(),
            auction: format!("0x{:040x}", 100),
            e3_id: "0".into(),
            context: hex(&context),
            committee_public_key: hex(&key_commitment),
            input_root: hex(&root),
            bid_count: bids.len(),
        },
        public_key: hex(&public),
        inputs,
    };
    // Synthetic anchor is local test data. A network worker must obtain its anchor independently.
    let native = compute(&manifest, &manifest.anchor)?;
    let aggregate = bytes(&native.aggregate_ciphertext)?;
    let plaintext = secret.try_decrypt(&Ciphertext::from_bytes(&aggregate, &params)?)?;
    let coefficients = Vec::<u64>::try_decode(&plaintext, Encoding::poly())?;
    assert_eq!(&coefficients[..bids.len()], &bids);
    assert!(coefficients[bids.len()..].iter().all(|x| *x == 0));
    let public_output: Vec<_> = coefficients[..OUTPUT_COEFFICIENTS]
        .iter()
        .flat_map(|x| x.to_le_bytes())
        .collect();
    assert_eq!(reveal(&public_output, bids.len(), 100)?, bids);
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "scope":"local-real-bfv-single-party-synthetic-test-only",
            "upstreamInterfoldCommit":UPSTREAM_COMMIT,
            "preset":"SECURE_THRESHOLD_8192",
            "degree":DEGREE,
            "plaintextModulus":PLAINTEXT_MODULUS,
            "syntheticBids":bids,
            "ciphertextBytes":manifest.inputs.iter().map(|x|bytes(&x.ciphertext).unwrap().len()).collect::<Vec<_>>(),
            "publicKeyBytes":public.len(),
            "manifest":manifest,
            "nativeOutput":native,
            "plaintextOutput":hex(&public_output),
            "plaintextOutputBytes":public_output.len(),
            "decryptedBidSlots":&coefficients[..bids.len()],
            "unusedCoefficientsZero":true,
            "winningSlot":1,
            "winningBid":77,
            "secondPricePaymentTicks":42,
            "thresholdNetworkUsed":false,
            "zkInputProofsGenerated":false,
            "openvmReceiptGenerated":false
        }))?
    );
    Ok(())
}
