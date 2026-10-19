//! Addition in the serialized power basis, avoiding unnecessary NTT transforms.
//!
//! fhe.rs stores power-basis coefficients on the wire even when the polynomial is tagged NTT.
//! Addition commutes with the forward NTT. Adding these canonical rows and retaining that tag
//! therefore produces exactly the ciphertext bytes of fhe.rs's deserialize/add/serialize path.
//! Multiplication and other operations must continue to use fhe.rs's ordinary representation.
use super::*;
use prost::Message;

// The pinned fhe.rs Rq protobuf is private. This mirrors its four-field schema solely to retag
// output produced by its own PowerBasis serializer, without introducing a second coefficient
// encoder. Source: fhe-math/src/proto/rq.proto at 873dc69c07eae251f88c4b5cacf6c4453e2c365a.
#[derive(Clone, PartialEq, Message)]
struct PolynomialWire {
    #[prost(int32, tag = "1")]
    representation: i32,
    #[prost(uint32, tag = "2")]
    degree: u32,
    #[prost(bytes = "vec", tag = "3")]
    coefficients: Vec<u8>,
    #[prost(bool, tag = "4")]
    allow_variable_time: bool,
}

pub(super) fn sum(input: FHEProcessorInput<'_>) -> Vec<u8> {
    let mut aggregate = Vec::new();
    let mut standard_aggregate: Option<Ciphertext> = None;
    for (bytes, _) in input.ciphertexts {
        let direct = if standard_aggregate.is_none() {
            Ciphertext::power_basis_from_bytes_if_canonical(&bytes, input.params)
                .expect("policy accepted parseable ciphertext")
        } else {
            None
        };
        let Some(components) = direct else {
            // Preserve the exact original decoder/serialization semantics for seeded or
            // noncanonical public encodings. In particular, a sole seeded ciphertext retains
            // its seed. Ordinary pilot inputs take the direct, canonical decoding path.
            let ciphertext = Ciphertext::from_bytes(&bytes, input.params)
                .expect("policy accepted parseable ciphertext");
            assert_eq!(
                ciphertext.level, 0,
                "only level-zero ciphertexts are supported"
            );
            assert_eq!(
                ciphertext.len(),
                2,
                "only two-component linear ciphertexts are supported"
            );
            let current = standard_aggregate.get_or_insert_with(|| {
                if aggregate.is_empty() {
                    Ciphertext::zero(input.params)
                } else {
                    Ciphertext::from_bytes(&serialize_components(&aggregate), input.params)
                        .expect("valid accumulated power-basis ciphertext")
                }
            });
            *current += &ciphertext;
            continue;
        };
        if !aggregate.is_empty() {
            // Both components have the same context established by the parameterized decoder.
            for (left, right) in aggregate.iter_mut().zip(&components) {
                *left += right;
            }
        } else {
            aggregate = components;
        }
    }
    if let Some(aggregate) = standard_aggregate {
        return aggregate.to_bytes();
    }
    if aggregate.is_empty() {
        return Ciphertext::zero(input.params).to_bytes();
    }
    serialize_components(&aggregate)
}

fn serialize_components<T: Serialize>(aggregate: &[T]) -> Vec<u8> {
    let c = aggregate
        .iter()
        .map(|polynomial| {
            let mut encoded = PolynomialWire::decode(polynomial.to_bytes().as_slice())
                .expect("fhe.rs produced a valid polynomial encoding");
            assert_eq!(encoded.representation, 1, "expected power-basis serializer");
            assert!(
                !encoded.allow_variable_time,
                "wire timing flag must be false"
            );
            encoded.representation = 2; // Exact NTT tag used by fhe.rs Ciphertext::to_bytes.
            encoded.encode_to_vec()
        })
        .collect();
    fhe::proto::bfv::Ciphertext {
        c,
        seed: Vec::new(),
        level: 0,
    }
    .encode_to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe::bfv::SecretKey;
    use fhe_traits::{FheDecoder, FheDecrypter};

    fn reference(input: FHEProcessorInput<'_>) -> Vec<u8> {
        let mut aggregate = Ciphertext::zero(input.params);
        for (bytes, _) in input.ciphertexts {
            aggregate += &Ciphertext::from_bytes(&bytes, input.params).unwrap();
        }
        aggregate.to_bytes()
    }

    fn execute(
        processor: fn(FHEProcessorInput<'_>) -> Vec<u8>,
        values: &[(Vec<u8>, u64)],
        parameters: &Arc<BfvParameters>,
    ) -> Vec<u8> {
        processor(FHEProcessorInput {
            ciphertexts: &mut values.iter().cloned(),
            params: parameters,
        })
    }

    #[test]
    fn power_basis_sum_is_byte_identical_to_ntt_reference_for_secure_8192() {
        let parameters = params();
        let mut rng = rand::rng();
        let secret = SecretKey::random(&parameters, &mut rng);
        let public_key = PublicKey::new(&secret, &mut rng);
        let values: Vec<_> = (0..MAX_BIDDERS)
            .map(|slot| {
                let mut coefficients = vec![0u64; DEGREE];
                coefficients[slot] = [0, 1, 31, 42, 77, 99, 100][slot % 7];
                let plaintext =
                    Plaintext::try_encode(&coefficients, Encoding::poly(), &parameters).unwrap();
                (
                    public_key
                        .try_encrypt(&plaintext, &mut rng)
                        .unwrap()
                        .to_bytes(),
                    slot as u64,
                )
            })
            .collect();
        for count in [0, 1, 3, MAX_BIDDERS] {
            let expected = execute(reference, &values[..count], &parameters);
            let actual = execute(sum, &values[..count], &parameters);
            assert!(
                actual == expected,
                "serialized aggregate differs for {count} inputs: {} != {}",
                hex(&keccak(&actual)),
                hex(&keccak(&expected))
            );
            if count > 0 {
                assert_eq!(
                    compute_ct_commitment_with_params(&actual, &parameters).unwrap(),
                    compute_ct_commitment_with_params(&expected, &parameters).unwrap()
                );
                let ciphertext = Ciphertext::from_bytes(&actual, &parameters).unwrap();
                let plaintext = secret.try_decrypt(&ciphertext).unwrap();
                let decoded = Vec::<u64>::try_decode(&plaintext, Encoding::poly()).unwrap();
                for slot in 0..DEGREE {
                    assert_eq!(
                        decoded[slot],
                        if slot < count {
                            [0, 1, 31, 42, 77, 99, 100][slot % 7]
                        } else {
                            0
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn seeded_public_ciphertexts_keep_standard_decoder_semantics() {
        let parameters = params();
        let mut rng = rand::rng();
        let secret = SecretKey::random(&parameters, &mut rng);
        let plaintext = Plaintext::try_encode(&[100u64], Encoding::poly(), &parameters).unwrap();
        let seeded_ciphertext: Ciphertext = secret.try_encrypt(&plaintext, &mut rng).unwrap();
        let seeded = seeded_ciphertext.to_bytes();
        assert!(
            Ciphertext::power_basis_from_bytes_if_canonical(&seeded, &parameters)
                .unwrap()
                .is_none()
        );
        let public_key = PublicKey::new(&secret, &mut rng);
        let canonical = public_key
            .try_encrypt(&plaintext, &mut rng)
            .unwrap()
            .to_bytes();
        for values in [vec![(seeded.clone(), 0)], vec![(canonical, 0), (seeded, 1)]] {
            assert!(
                execute(sum, &values, &parameters) == execute(reference, &values, &parameters),
                "seeded aggregate differs for {} inputs",
                values.len()
            );
        }
    }
}
