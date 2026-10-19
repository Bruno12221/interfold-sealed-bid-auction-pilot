//! Secure-8192 client and native reference computation for the reveal-after-close pilot.
//!
//! Native checks are not zero-knowledge proofs. In particular, a ciphertext's sparse plaintext
//! cannot be checked by a compute provider without the missing application input-proof verifier.
use e3_bfv_client::client::{compute_ct_commitment_with_params, validate_pk_commitment};
use e3_compute_provider::{
    ComputeError, ComputeInput, FHEInputs, FHEProcessorInput, InputPolicy, PublishedData,
    PublishedInput,
};
use fhe::bfv::{BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, PublicKey};
use fhe_traits::{DeserializeParametrized, FheEncoder, FheEncrypter, Serialize};
use serde::{Deserialize, Serialize as SerdeSerialize};
use std::sync::{Arc, OnceLock};

pub mod input_binding;

mod linear_sum;

pub type Result<T> = std::result::Result<T, String>;
pub const DEGREE: usize = 8192;
pub const PLAINTEXT_MODULUS: u64 = 17_000_000;
pub const OUTPUT_COEFFICIENTS: usize = 50;
pub const MAX_BIDDERS: usize = 32;
pub const MAX_TICK: u64 = 100;
pub const MODULI: [u64; 3] = [0x0800000000db4001, 0x0800000000d54001, 0x0800000000cbc001];
pub const ERROR1_VARIANCE: &str = "17723039943798878305460955570711717478400";
pub const UPSTREAM_COMMIT: &str = "c65722fcab24b3b5ffc7ccaf4544bd1d6ef8826a";

pub fn params() -> Arc<BfvParameters> {
    static PARAMS: OnceLock<Arc<BfvParameters>> = OnceLock::new();
    PARAMS
        .get_or_init(|| {
            BfvParametersBuilder::new()
                .set_degree(DEGREE)
                .set_plaintext_modulus(PLAINTEXT_MODULUS)
                .set_moduli(&MODULI)
                .set_error1_variance_str(ERROR1_VARIANCE)
                .expect("pinned error variance")
                .build_arc()
                .expect("pinned BFV preset")
        })
        .clone()
}
pub fn keccak(bytes: &[u8]) -> [u8; 32] {
    e3_compute_provider::hashing::keccak256(bytes)
}
pub fn hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}
pub fn bytes(value: &str) -> Result<Vec<u8>> {
    let body = value.strip_prefix("0x").ok_or("hex must begin with 0x")?;
    if body.len() % 2 != 0
        || body
            .bytes()
            .any(|x| !x.is_ascii_hexdigit() || x.is_ascii_uppercase())
    {
        return Err("hex must be lowercase and contain complete bytes".into());
    }
    hex::decode(body).map_err(|_| "invalid hex".into())
}
pub fn fixed<const N: usize>(value: &str) -> Result<[u8; N]> {
    bytes(value)?
        .try_into()
        .map_err(|_| format!("expected {N} bytes"))
}
/// Parse a canonical decimal uint256 without truncating Interfold's address-prefixed E3 IDs.
pub fn uint256_word(value: &str) -> Result<[u8; 32]> {
    if value.len() > 78 {
        return Err("uint256 overflow".into());
    }
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|x| x.is_ascii_digit())
    {
        return Err("expected canonical decimal uint256".into());
    }
    let mut out = [0u8; 32];
    for digit in value.bytes() {
        let mut carry = (digit - b'0') as u16;
        for byte in out.iter_mut().rev() {
            let next = *byte as u16 * 10 + carry;
            *byte = next as u8;
            carry = next >> 8;
        }
        if carry != 0 {
            return Err("uint256 overflow".into());
        }
    }
    Ok(out)
}
fn word(value: usize) -> [u8; 32] {
    let mut out = [0; 32];
    out[24..].copy_from_slice(&(value as u64).to_be_bytes());
    out
}
fn read_word(value: &[u8]) -> Result<usize> {
    if value.len() != 32 || value[..24] != [0; 24] {
        return Err("ABI integer too large".into());
    }
    usize::try_from(u64::from_be_bytes(value[24..].try_into().unwrap()))
        .map_err(|_| "ABI integer too large".into())
}
fn padded(bytes: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&word(bytes.len()));
    out.extend_from_slice(bytes);
    out.resize(out.len() + (32 - bytes.len() % 32) % 32, 0);
}

/// EXACT contract envelope: abi.encode(uint8(1), bytes32(ciphertextHash), bytes(inputProof), bytes(availabilityProof)).
pub fn envelope(
    ciphertext_hash: &[u8; 32],
    input_proof: &[u8],
    availability_proof: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&word(1));
    out.extend_from_slice(ciphertext_hash);
    out.extend_from_slice(&word(128));
    out.extend_from_slice(&word(160 + input_proof.len().div_ceil(32) * 32));
    padded(input_proof, &mut out);
    padded(availability_proof, &mut out);
    out
}
pub fn decode_envelope(raw: &[u8]) -> Result<([u8; 32], Vec<u8>, Vec<u8>)> {
    if raw.len() < 192 || raw.len() > 16_384 || raw.len() % 32 != 0 {
        return Err("envelope length is invalid".into());
    }
    if read_word(&raw[..32])? != 1 {
        return Err("unsupported envelope version".into());
    }
    let hash: [u8; 32] = raw[32..64].try_into().unwrap();
    let dynamic = |at: usize| -> Result<Vec<u8>> {
        let offset = read_word(&raw[at..at + 32])?;
        let lenword = raw
            .get(offset..offset.checked_add(32).ok_or("ABI overflow")?)
            .ok_or("ABI offset out of bounds")?;
        let size = read_word(lenword)?;
        let end = offset
            .checked_add(32)
            .and_then(|x| x.checked_add(size))
            .ok_or("ABI overflow")?;
        Ok(raw
            .get(offset + 32..end)
            .ok_or("ABI data out of bounds")?
            .to_vec())
    };
    let proof = dynamic(64)?;
    let availability = dynamic(96)?;
    if envelope(&hash, &proof, &availability) != raw {
        return Err("non-canonical envelope encoding".into());
    }
    Ok((hash, proof, availability))
}

/// The plaintext witness must contain one bounded coefficient at the assigned slot, with every
/// other one of the 8192 coefficients zero. This is a client check, not a substitute for a ZK proof.
pub fn sparse_plaintext(slot: usize, bid: u64, max_tick: u64) -> Result<Vec<u64>> {
    if slot >= MAX_BIDDERS || max_tick > MAX_TICK || bid > max_tick {
        return Err("slot or bid is outside the auction range".into());
    }
    let mut out = vec![0; DEGREE];
    out[slot] = bid;
    Ok(out)
}
pub fn validate_sparse_plaintext(coefficients: &[u64], slot: usize, max_tick: u64) -> Result<()> {
    if coefficients.len() != DEGREE || slot >= MAX_BIDDERS || max_tick > MAX_TICK {
        return Err("invalid sparse witness dimensions".into());
    }
    if coefficients[slot] > max_tick
        || coefficients
            .iter()
            .enumerate()
            .any(|(i, v)| i != slot && *v != 0)
    {
        return Err("witness is not one bounded coefficient at the assigned slot".into());
    }
    Ok(())
}
#[derive(Debug, Clone, SerdeSerialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncryptedBid {
    pub slot: usize,
    pub ciphertext: String,
    pub ciphertext_hash: String,
    pub commitment: String,
    pub committee_public_key: String,
    pub input_proof_generated: bool,
}
pub fn encrypt_bid(
    public_key: &[u8],
    expected_key: [u8; 32],
    slot: usize,
    bid: u64,
    max_tick: u64,
) -> Result<EncryptedBid> {
    validate_pk_commitment(
        public_key,
        expected_key,
        DEGREE,
        PLAINTEXT_MODULUS,
        MODULI.to_vec(),
    )
    .map_err(|e| e.to_string())?;
    let params = params();
    let key = PublicKey::from_bytes(public_key, &params).map_err(|e| e.to_string())?;
    let witness = sparse_plaintext(slot, bid, max_tick)?;
    let plaintext =
        Plaintext::try_encode(&witness, Encoding::poly(), &params).map_err(|e| e.to_string())?;
    let ciphertext = key
        .try_encrypt(&plaintext, &mut rand::rng())
        .map_err(|e| e.to_string())?
        .to_bytes();
    let commitment =
        compute_ct_commitment_with_params(&ciphertext, &params).map_err(|e| e.to_string())?;
    Ok(EncryptedBid {
        slot,
        ciphertext_hash: hex(&keccak(&ciphertext)),
        ciphertext: hex(&ciphertext),
        commitment: hex(&commitment),
        committee_public_key: hex(&expected_key),
        input_proof_generated: false,
    })
}

/// Preserve the upstream encryption witness for the SAME randomized ciphertext.
/// The second return value contains private bid/randomness and must never be public.
/// It is input for a future composed circuit, not a generated or verified proof.
pub fn encrypt_bid_for_proof(
    public_key: &[u8],
    expected_key: [u8; 32],
    slot: usize,
    bid: u64,
    max_tick: u64,
) -> Result<(EncryptedBid, serde_json::Value)> {
    validate_pk_commitment(
        public_key,
        expected_key,
        DEGREE,
        PLAINTEXT_MODULUS,
        MODULI.to_vec(),
    )
    .map_err(|_| "committee public key commitment differs".to_string())?;
    let plaintext = sparse_plaintext(slot, bid, max_tick)?;
    let result = e3_bfv_client::bfv_verifiable_encrypt(
        plaintext,
        public_key.to_vec(),
        DEGREE,
        PLAINTEXT_MODULUS,
        MODULI.to_vec(),
    )
    .map_err(|_| "upstream verifiable encryption failed; private witness suppressed".to_string())?;
    let commitment = compute_ct_commitment_with_params(&result.encrypted_data, &params())
        .map_err(|_| "ciphertext commitment computation failed".to_string())?;
    let public = EncryptedBid {
        slot,
        ciphertext_hash: hex(&keccak(&result.encrypted_data)),
        ciphertext: hex(&result.encrypted_data),
        commitment: hex(&commitment),
        committee_public_key: hex(&expected_key),
        input_proof_generated: false,
    };
    let inputs: serde_json::Value = serde_json::from_str(&result.circuit_inputs)
        .map_err(|_| "invalid upstream witness serialization".to_string())?;
    let private = serde_json::json!({
        "schemaVersion":1,
        "scope":"PRIVATE-encryption-witness-not-a-proof",
        "slot":slot,"bid":bid,"maxTick":max_tick,
        "publicBid":public,"circuitInputs":inputs,
        "inputProofGenerated":false
    });
    Ok((public, private))
}

/// Header values must be independently read from the intended chain, escrow and finalized E3.
/// A self-consistent manifest alone is not an authenticated on-chain input set.
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Anchor {
    pub chain_id: String,
    pub auction: String,
    pub e3_id: String,
    pub context: String,
    pub committee_public_key: String,
    pub input_root: String,
    pub bid_count: usize,
}
#[derive(Debug, Clone, SerdeSerialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestInput {
    pub slot: usize,
    pub bidder: String,
    pub ciphertext: String,
    pub envelope: String,
    pub commitment: String,
}
#[derive(Debug, Clone, SerdeSerialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u8,
    pub anchor: Anchor,
    pub public_key: String,
    pub inputs: Vec<ManifestInput>,
}
/// abi.encode(context, uint256(slot), bidder, envelope, commitment), also the publishInput payload.
pub fn metadata(context: &[u8; 32], input: &ManifestInput) -> Result<Vec<u8>> {
    let bidder = fixed::<20>(&input.bidder)?;
    let raw_envelope = bytes(&input.envelope)?;
    let mut out = Vec::new();
    out.extend_from_slice(context);
    out.extend_from_slice(&word(input.slot));
    out.extend_from_slice(&[0; 12]);
    out.extend_from_slice(&bidder);
    out.extend_from_slice(&word(160));
    out.extend_from_slice(&fixed::<32>(&input.commitment)?);
    padded(&raw_envelope, &mut out);
    Ok(out)
}
fn decode_metadata(raw: &[u8]) -> Result<([u8; 32], ManifestInput)> {
    if raw.len() < 192 || raw[64..76] != [0; 12] || read_word(&raw[96..128])? != 160 {
        return Err("invalid input metadata".into());
    }
    let context = raw[..32].try_into().unwrap();
    let size = read_word(&raw[160..192])?;
    let input = ManifestInput {
        slot: read_word(&raw[32..64])?,
        bidder: hex(&raw[76..96]),
        commitment: hex(&raw[128..160]),
        envelope: hex(raw
            .get(192..192usize.checked_add(size).ok_or("ABI overflow")?)
            .ok_or("truncated metadata")?),
        ciphertext: String::new(),
    };
    if metadata(&context, &input)? != raw {
        return Err("non-canonical input metadata".into());
    }
    Ok((context, input))
}
pub fn leaf_digest(context: &[u8; 32], input: &ManifestInput) -> Result<[u8; 32]> {
    let mut out = Vec::new();
    out.extend_from_slice(context);
    out.extend_from_slice(&word(input.slot));
    out.extend_from_slice(&[0; 12]);
    out.extend_from_slice(&fixed::<20>(&input.bidder)?);
    out.extend_from_slice(&keccak(&bytes(&input.envelope)?));
    out.extend_from_slice(&fixed::<32>(&input.commitment)?);
    Ok(keccak(&out))
}
/// BN254 scalar-field reduction used by the on-chain Poseidon input tree.
pub fn leaf_field(context: &[u8; 32], input: &ManifestInput) -> Result<String> {
    let scalar = e3_compute_provider::policy::leaf_from_digest(&leaf_digest(context, input)?);
    Ok(format!("0x{:0>64}", scalar))
}
pub fn next_root(previous: &[u8; 32], input: &ManifestInput) -> Result<[u8; 32]> {
    leaf_digest(previous, input)
}
fn policy_leaf(input: &PublishedInput<'_>) -> std::result::Result<String, ComputeError> {
    let invalid = |reason: String| ComputeError::LeafCommitment {
        index: input.index,
        reason,
    };
    let (context, record) = decode_metadata(input.metadata).map_err(invalid)?;
    if record.slot != input.index || record.slot >= MAX_BIDDERS {
        return Err(invalid(
            "metadata slot differs from authenticated tree position".into(),
        ));
    }
    let (hash, _, _) =
        decode_envelope(&bytes(&record.envelope).map_err(invalid)?).map_err(invalid)?;
    if hash != input.ciphertext_hash
        || !input.matches_commitment()
        || input.commitment != Some(&fixed::<32>(&record.commitment).map_err(invalid)?)
    {
        return Err(invalid(
            "ciphertext bytes, hash or SAFE commitment differ from admitted input".into(),
        ));
    }
    Ok(e3_compute_provider::policy::leaf_from_digest(
        &leaf_digest(&context, &record).map_err(invalid)?,
    ))
}
pub fn policy() -> InputPolicy {
    InputPolicy {
        leaf: policy_leaf,
        select: e3_compute_provider::policy::all_inputs,
    }
}
pub fn fhe_processor(input: FHEProcessorInput<'_>) -> Vec<u8> {
    linear_sum::sum(input)
}
#[derive(Debug, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeOutput {
    pub schema_version: u8,
    pub scope: &'static str,
    pub anchor: Anchor,
    pub poseidon_input_root: String,
    pub aggregate_ciphertext: String,
    pub aggregate_ciphertext_hash: String,
    pub aggregate_commitment: String,
    pub params_hash: String,
    pub openvm_receipt_generated: bool,
    pub input_proofs_verified: bool,
    pub availability_verified: bool,
}
pub fn program_input(manifest: &Manifest, independent_anchor: &Anchor) -> Result<ComputeInput> {
    if manifest.schema_version != 1 || &manifest.anchor != independent_anchor {
        return Err("manifest does not match the independent chain anchor".into());
    }
    let anchor = &manifest.anchor;
    if anchor.chain_id != "11155111" || uint256_word(&anchor.e3_id).is_err() {
        return Err("expected Sepolia chain ID and decimal uint256 E3 ID".into());
    }
    fixed::<20>(&anchor.auction)?;
    let context = fixed::<32>(&anchor.context)?;
    if manifest.inputs.is_empty()
        || manifest.inputs.len() > MAX_BIDDERS
        || manifest.inputs.len() != anchor.bid_count
    {
        return Err("unexpected input count; an empty auction must cancel".into());
    }
    let params = params();
    let public_key = bytes(&manifest.public_key)?;
    validate_pk_commitment(
        &public_key,
        fixed::<32>(&anchor.committee_public_key)?,
        DEGREE,
        PLAINTEXT_MODULUS,
        MODULI.to_vec(),
    )
    .map_err(|e| e.to_string())?;
    let mut root = context;
    let mut ciphertexts = Vec::new();
    let mut published = Vec::new();
    let mut bidders = std::collections::HashSet::new();
    for (slot, input) in manifest.inputs.iter().enumerate() {
        if input.slot != slot
            || !bidders.insert(fixed::<20>(&input.bidder)?)
            || fixed::<20>(&input.bidder)? == [0; 20]
        {
            return Err("slots must be consecutive and bidders distinct nonzero addresses".into());
        }
        let raw = bytes(&input.ciphertext)?;
        if raw.is_empty() || raw.len() > 400_000 {
            return Err("invalid ciphertext byte length".into());
        }
        let parsed = Ciphertext::from_bytes(&raw, &params).map_err(|e| e.to_string())?;
        if parsed.len() != 2 {
            return Err("expected a two-component ciphertext".into());
        }
        let (hash, _, _) = decode_envelope(&bytes(&input.envelope)?)?;
        if hash != keccak(&raw) {
            return Err(format!("ciphertext hash mismatch at slot {slot}"));
        }
        let commitment = fixed::<32>(&input.commitment)?;
        if compute_ct_commitment_with_params(&raw, &params).map_err(|e| e.to_string())?
            != commitment
        {
            return Err(format!(
                "SAFE ciphertext commitment mismatch at slot {slot}"
            ));
        }
        root = next_root(&root, input)?;
        ciphertexts.push((raw, slot as u64));
        published.push(PublishedData {
            commitment: Some(commitment),
            metadata: metadata(&context, input)?,
        });
    }
    if root != fixed::<32>(&anchor.input_root)? {
        return Err("input transcript differs from anchored rolling root".into());
    }
    let input = ComputeInput {
        fhe_inputs: FHEInputs {
            params: e3_fhe_params::encode_bfv_params(&params),
            ciphertexts,
        },
        published,
    };
    Ok(input)
}
pub fn compute(manifest: &Manifest, independent_anchor: &Anchor) -> Result<NativeOutput> {
    let input = program_input(manifest, independent_anchor)?;
    let (result, aggregate) = input
        .run(fhe_processor, policy())
        .map_err(|e| e.to_string())?;
    Ok(NativeOutput {
        schema_version: 1,
        scope: "native-reference-computation-not-a-protocol-proof",
        anchor: manifest.anchor.clone(),
        poseidon_input_root: hex(&result.merkle_root),
        aggregate_ciphertext: hex(&aggregate),
        aggregate_ciphertext_hash: hex(&result.ciphertext_hash),
        aggregate_commitment: hex(&result.ciphertext_commitment),
        params_hash: hex(&result.params_hash),
        openvm_receipt_generated: false,
        input_proofs_verified: false,
        availability_verified: false,
    })
}
/// Decode the exact public 50-u64 output and apply auction range/unused-slot checks.
pub fn reveal(bytes: &[u8], count: usize, max_tick: u64) -> Result<Vec<u64>> {
    if bytes.len() != OUTPUT_COEFFICIENTS * 8 || count > MAX_BIDDERS || max_tick > MAX_TICK {
        return Err("invalid plaintext output dimensions".into());
    }
    let values: Vec<_> = bytes
        .chunks_exact(8)
        .map(|x| u64::from_le_bytes(x.try_into().unwrap()))
        .collect();
    if values[..count].iter().any(|x| *x > max_tick) || values[count..].iter().any(|x| *x != 0) {
        return Err("out-of-range bid or nonzero unused revealed slot".into());
    }
    Ok(values[..count].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserved_encryption_witness_matches_actual_ciphertext_and_sparse_k1() {
        use fhe::bfv::{Ciphertext, SecretKey};
        use fhe_traits::{FheDecoder, FheDecrypter};
        let parameters = params();
        let secret = SecretKey::random(&parameters, &mut rand::rng());
        let public_key = PublicKey::new(&secret, &mut rand::rng()).to_bytes();
        let key_commitment = e3_bfv_client::compute_pk_commitment(
            public_key.clone(),
            DEGREE,
            PLAINTEXT_MODULUS,
            MODULI.to_vec(),
        )
        .unwrap();
        let (public, private) =
            encrypt_bid_for_proof(&public_key, key_commitment, 31, 100, 100).unwrap();
        assert_eq!(private["publicBid"], serde_json::to_value(&public).unwrap());
        let coefficients = private["circuitInputs"]["k1"]["coefficients"]
            .as_array()
            .unwrap();
        assert_eq!(coefficients.len(), DEGREE);
        let scale = MODULI.iter().fold(1u128, |value, modulus| {
            value * u128::from(*modulus) % u128::from(PLAINTEXT_MODULUS)
        });
        let scaled_bid = scale * 100 % u128::from(PLAINTEXT_MODULUS);
        for (index, value) in coefficients.iter().enumerate() {
            let coefficient = value
                .as_u64()
                .map(u128::from)
                .unwrap_or_else(|| value.as_str().unwrap().parse::<u128>().unwrap());
            assert_eq!(
                coefficient,
                if index == DEGREE - 1 - 31 {
                    scaled_bid
                } else {
                    0
                }
            );
        }
        let ciphertext =
            Ciphertext::from_bytes(&bytes(&public.ciphertext).unwrap(), &parameters).unwrap();
        let decoded = secret.try_decrypt(&ciphertext).unwrap();
        let plaintext = Vec::<u64>::try_decode(&decoded, Encoding::poly()).unwrap();
        assert_eq!(plaintext[31], 100);
        assert!(
            plaintext
                .iter()
                .enumerate()
                .all(|(i, v)| i == 31 || *v == 0)
        );
        let public_json = serde_json::to_value(public).unwrap();
        assert!(public_json.get("bid").is_none() && public_json.get("circuitInputs").is_none());
    }
    fn input(slot: usize) -> ManifestInput {
        ManifestInput {
            slot,
            bidder: format!("0x{:040x}", slot + 1),
            ciphertext: "0x1234".into(),
            envelope: hex(&envelope(&keccak(&[0x12, 0x34]), &[1, 2, 3], &[4, 5])),
            commitment: hex(&[7; 32]),
        }
    }
    #[test]
    fn e3_ids_preserve_the_protocol_address_prefix_and_full_uint256_width() {
        let value = uint256_word(
            "85648664479465694523919106262133007425192511854573175310227519544993083555847",
        )
        .unwrap();
        assert_eq!(
            hex(&value),
            "0xbd5b6d1ada9e0eb248b678469c9cd6a63507e42b000000000000000000000007"
        );
        assert_eq!(
            uint256_word(
                "115792089237316195423570985008687907853269984665640564039457584007913129639935"
            )
            .unwrap(),
            [255; 32]
        );
        assert!(
            uint256_word(
                "115792089237316195423570985008687907853269984665640564039457584007913129639936"
            )
            .is_err()
        );
        assert!(uint256_word("+7").is_err());
        assert!(uint256_word("07").is_err());
        assert!(uint256_word("0x7").is_err());
        assert_eq!(uint256_word("0").unwrap(), [0; 32]);
    }
    #[test]
    fn secure_parameters_have_the_exact_guest_and_contract_hash() {
        let encoded = e3_fhe_params::encode_bfv_params(&params());
        assert_eq!(
            hex(&keccak(&encoded)),
            "0x1b2620f6a5919d5ee19a51f34026369816f479efd0404b56585ad37d31c52317"
        );
    }
    #[test]
    fn bid_100_is_representable_and_all_8191_other_coefficients_are_zero() {
        let coefficients = sparse_plaintext(31, 100, 100).unwrap();
        assert_eq!(coefficients.len(), 8192);
        assert_eq!(coefficients[31], 100);
        validate_sparse_plaintext(&coefficients, 31, 100).unwrap();
    }
    #[test]
    fn oversized_bid_and_invalid_slot_are_rejected() {
        assert!(sparse_plaintext(0, 101, 100).is_err());
        assert!(sparse_plaintext(32, 1, 100).is_err());
        assert!(sparse_plaintext(0, 0, 101).is_err());
    }
    #[test]
    fn cross_slot_injection_and_hidden_tail_coefficient_are_rejected() {
        let mut values = sparse_plaintext(0, 50, 100).unwrap();
        values[1] = 1;
        assert!(validate_sparse_plaintext(&values, 0, 100).is_err());
        values[1] = 0;
        values[8191] = 1;
        assert!(validate_sparse_plaintext(&values, 0, 100).is_err());
    }
    #[test]
    fn short_witness_and_wrong_slot_are_rejected() {
        assert!(validate_sparse_plaintext(&vec![0; 50], 0, 100).is_err());
        assert!(validate_sparse_plaintext(&sparse_plaintext(2, 5, 100).unwrap(), 1, 100).is_err());
    }
    #[test]
    fn envelope_roundtrip_and_empty_fields() {
        for (proof, da) in [(vec![], vec![]), (vec![1; 33], vec![2; 65])] {
            let encoded = envelope(&[9; 32], &proof, &da);
            assert_eq!(decode_envelope(&encoded).unwrap(), ([9; 32], proof, da));
        }
    }
    #[test]
    fn envelope_rejects_nonzero_padding_overlapping_offsets_and_trailing_bytes() {
        let good = envelope(&[9; 32], &[1], &[2]);
        let mut padding = good.clone();
        padding[161] = 1;
        assert!(decode_envelope(&padding).is_err());
        let mut offset = good.clone();
        offset[96..128].copy_from_slice(&word(128));
        assert!(decode_envelope(&offset).is_err());
        let mut trailing = good;
        trailing.extend_from_slice(&[0; 32]);
        assert!(decode_envelope(&trailing).is_err());
    }
    #[test]
    fn envelope_rejects_integer_overflow_and_unknown_version() {
        let mut raw = envelope(&[1; 32], &[], &[]);
        raw[0] = 1;
        assert!(decode_envelope(&raw).is_err());
        raw[0] = 0;
        raw[31] = 2;
        assert!(decode_envelope(&raw).is_err());
        raw[31] = 1;
        raw[64] = 255;
        assert!(decode_envelope(&raw).is_err());
    }
    #[test]
    fn rolling_root_binds_order_bidder_commitment_and_entire_envelope() {
        let context = [8; 32];
        let honest = input(0);
        let expected = next_root(&context, &honest).unwrap();
        let mut changed = honest.clone();
        changed.slot = 1;
        assert_ne!(next_root(&context, &changed).unwrap(), expected);
        changed = honest.clone();
        changed.bidder = format!("0x{:040x}", 99);
        assert_ne!(next_root(&context, &changed).unwrap(), expected);
        changed = honest.clone();
        changed.commitment = hex(&[8; 32]);
        assert_ne!(next_root(&context, &changed).unwrap(), expected);
        changed = honest.clone();
        changed.envelope = hex(&envelope(&keccak(&[0x12, 0x34]), &[1, 2, 4], &[4, 5]));
        assert_ne!(next_root(&context, &changed).unwrap(), expected);
        assert_ne!(next_root(&[9; 32], &honest).unwrap(), expected);
    }
    #[test]
    fn metadata_roundtrip_is_canonical() {
        let original = input(2);
        let encoded = metadata(&[3; 32], &original).unwrap();
        let (context, decoded) = decode_metadata(&encoded).unwrap();
        assert_eq!(context, [3; 32]);
        assert_eq!(metadata(&context, &decoded).unwrap(), encoded);
        let mut tampered = encoded;
        tampered[64] = 1;
        assert!(decode_metadata(&tampered).is_err());
    }
    #[test]
    fn policy_binds_authenticated_position_ciphertext_bytes_and_safe_commitment() {
        let original = input(0);
        let commitment = [7; 32];
        let raw = [0x12, 0x34];
        let encoded = metadata(&[3; 32], &original).unwrap();
        let mut published = PublishedInput {
            index: 0,
            ciphertext: &raw,
            ciphertext_hash: keccak(&raw),
            commitment: Some(&commitment),
            metadata: &encoded,
            recomputed: Some(commitment),
        };
        assert!(policy_leaf(&published).is_ok());
        published.index = 1;
        assert!(policy_leaf(&published).is_err());
        published.index = 0;
        published.ciphertext_hash = [0; 32];
        assert!(policy_leaf(&published).is_err());
        published.ciphertext_hash = keccak(&raw);
        published.recomputed = Some([9; 32]);
        assert!(policy_leaf(&published).is_err());
    }
    #[test]
    fn reveal_uses_exactly_400_little_endian_bytes() {
        let mut raw = vec![0; 400];
        raw[..8].copy_from_slice(&100u64.to_le_bytes());
        raw[8..16].copy_from_slice(&31u64.to_le_bytes());
        assert_eq!(reveal(&raw, 2, 100).unwrap(), vec![100, 31]);
        assert!(reveal(&raw[..399], 2, 100).is_err());
    }
    #[test]
    fn reveal_rejects_out_of_range_bid_and_nonzero_unused_slots() {
        let mut raw = vec![0; 400];
        raw[..8].copy_from_slice(&101u64.to_le_bytes());
        assert!(reveal(&raw, 1, 100).is_err());
        raw[..8].fill(0);
        raw[392] = 1;
        assert!(reveal(&raw, 1, 100).is_err());
    }
    #[test]
    fn public_manifest_rejects_unknown_fields_and_noncanonical_hex() {
        assert!(bytes("0xA0").is_err());
        assert!(bytes("1234").is_err());
        assert!(bytes("0x1").is_err());
        assert!(serde_json::from_str::<Anchor>(r#"{"chainId":"11155111","auction":"0x00","e3Id":"0","context":"0x00","committeePublicKey":"0x00","inputRoot":"0x00","bidCount":1,"secret":"leak"}"#).is_err());
    }
    #[test]
    fn manifest_must_match_independent_anchor_before_any_crypto_runs() {
        let anchor = Anchor {
            chain_id: "11155111".into(),
            auction: hex(&[1; 20]),
            e3_id: "0".into(),
            context: hex(&[2; 32]),
            committee_public_key: hex(&[3; 32]),
            input_root: hex(&[4; 32]),
            bid_count: 1,
        };
        let manifest = Manifest {
            schema_version: 1,
            anchor: anchor.clone(),
            public_key: "0x".into(),
            inputs: vec![input(0)],
        };
        let mut substituted = anchor;
        substituted.context = hex(&[9; 32]);
        assert_eq!(
            compute(&manifest, &substituted).unwrap_err(),
            "manifest does not match the independent chain anchor"
        );
    }
}
