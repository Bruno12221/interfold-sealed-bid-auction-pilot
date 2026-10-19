//! Application identity and proof checks without generating an aggregation key or EVM receipt.
use eyre::{bail, ensure, Result};
use openvm_circuit::arch::{instructions::exe::VmExe, ContinuationVmProof};
use openvm_continuations::CommitBytes;
use openvm_sdk::{
    fs::read_object_from_file,
    keygen::{AppProvingKey, AppVerifyingKey},
    prover::{verify_app_proof_with_expected_exe_commit, AppProver},
    DefaultStarkEngine, F, OPENVM_VERSION, SC,
};
use openvm_sdk_config::{SdkVmConfig, SdkVmCpuBuilder};
use openvm_stark_backend::p3_field::PrimeField32;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    sync::Arc,
};

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut bytes = [0; 65536];
    loop {
        let count = file.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        hasher.update(&bytes[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn expected_commit(value: &str) -> Result<CommitBytes> {
    ensure!(
        value.len() == 66
            && value.starts_with("0x")
            && value[2..]
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "Expected a lowercase 32-byte executable commitment"
    );
    let mut bytes = [0; 32];
    hex::decode_to_slice(&value[2..], &mut bytes)?;
    Ok(CommitBytes::try_new(bytes)?)
}

fn journal_scheme(journal: &[u8]) -> Result<&'static str> {
    match journal.len() {
        288 => Ok("compute"),
        416 => Ok("input-binding"),
        _ => bail!("Expected a 288-byte compute journal or a 416-byte input-binding journal"),
    }
}

fn check_journal_values(values: &[u32], journal: &[u8]) -> Result<[u8; 32]> {
    journal_scheme(journal)?;
    let digest: [u8; 32] = Sha256::digest(journal).into();
    ensure!(
        values.len() == digest.len()
            && values
                .iter()
                .zip(digest)
                .all(|(actual, byte)| *actual == u32::from(byte)),
        "Authenticated proof public values do not equal SHA256(journal)"
    );
    Ok(digest)
}

fn identity(app_pk: &Path, executable: &Path) -> Result<serde_json::Value> {
    let key: AppProvingKey<SdkVmConfig> = read_object_from_file(app_pk)?;
    let num_public_values = key.num_public_values();
    ensure!(
        num_public_values == 32,
        "Expected exactly 32 byte-valued public values"
    );
    let exe: VmExe<F> = read_object_from_file(executable)?;
    // Building the SDK requires aggregation parameters even when only its app prover is used.
    // Construct the app prover directly to avoid all recursive setup and pin this exact executable.
    let prover = AppProver::<DefaultStarkEngine, SdkVmCpuBuilder>::new(
        SdkVmCpuBuilder,
        &key.app_vm_pk,
        Arc::new(exe),
    )?;
    let commit = CommitBytes::from(prover.app_exe_commit());
    Ok(serde_json::json!({
        "schemaVersion": 1,
        "scope": "application-executable-identity",
        "openvmVersion": OPENVM_VERSION,
        "applicationExecutableCommitment": commit.to_string(),
        "applicationProvingKeySha256": sha256_file(app_pk)?,
        "executableSha256": sha256_file(executable)?,
        "numPublicValues": num_public_values,
        "evmReceiptGenerated": false
    }))
}

fn verify_app(
    app_vk: &Path,
    proof_path: &Path,
    expected: &str,
    journal_path: &Path,
) -> Result<serde_json::Value> {
    let expected = expected_commit(expected)?;
    let journal = fs::read(journal_path)?;
    let scheme = journal_scheme(&journal)?;
    let key: AppVerifyingKey = read_object_from_file(app_vk)?;
    ensure!(
        key.num_user_pvs == 32,
        "Expected exactly 32 byte-valued public values"
    );
    let proof: ContinuationVmProof<SC> = read_object_from_file(proof_path)?;
    verify_app_proof_with_expected_exe_commit::<DefaultStarkEngine>(
        &key,
        &proof,
        Some(expected.into()),
    )?;
    let public_values: Vec<_> = proof
        .user_public_values
        .public_values
        .iter()
        .map(|value| value.as_canonical_u32())
        .collect();
    let journal_digest = check_journal_values(&public_values, &journal)?;
    Ok(serde_json::json!({
        "schemaVersion": 1,
        "scope": "application-stark-proof-only",
        "openvmVersion": OPENVM_VERSION,
        "applicationProofVerified": true,
        "exactExecutableCommitmentVerified": true,
        "publicJournalDigestMatches": true,
        "applicationExecutableCommitment": expected.to_string(),
        "journalSha256": hex::encode(journal_digest),
        "journalBytes": journal.len(),
        "journalScheme": scheme,
        "applicationProofSha256": sha256_file(proof_path)?,
        "applicationVerifyingKeySha256": sha256_file(app_vk)?,
        "segments": proof.per_segment.len(),
        "evmReceiptGenerated": false
    }))
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let report = match args.as_slice() {
        [command, key, exe] if command == "identity" => identity(Path::new(key), Path::new(exe))?,
        [command, key, proof, expected, journal] if command == "verify-app" => verify_app(Path::new(key), Path::new(proof), expected, Path::new(journal))?,
        _ => bail!("Usage: interfold-auction-openvm-tools identity APP_PK EXE | verify-app APP_VK PROOF EXPECTED_EXECUTABLE_COMMITMENT JOURNAL"),
    };
    serde_json::to_writer_pretty(std::io::stdout().lock(), &report)?;
    std::io::stdout().write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openvm_sdk::fs::write_object_to_file;
    use openvm_stark_backend::p3_field::PrimeCharacteristicRing;

    #[test]
    fn expected_identity_requires_canonical_babybear_commitment() {
        assert!(expected_commit(&format!("0x{}", "00".repeat(32))).is_ok());
        assert!(expected_commit(&format!("0x{}", "ff".repeat(32))).is_err());
        assert!(expected_commit(&format!("0x{}", "AA".repeat(32))).is_err());
        assert!(expected_commit("0x00").is_err());
    }

    #[test]
    fn journal_binding_rejects_wrong_digest_length_and_nonbyte_field_values() {
        let journal = vec![7; 288];
        let values: Vec<u32> = Sha256::digest(&journal)
            .iter()
            .map(|v| u32::from(*v))
            .collect();
        assert!(check_journal_values(&values, &journal).is_ok());
        assert!(check_journal_values(&values, &[7; 287]).is_err());
        assert!(check_journal_values(&values, &[7; 417]).is_err());
        assert!(check_journal_values(&values[..31], &journal).is_err());
        let mut changed_journal = journal.clone();
        changed_journal[287] ^= 1;
        assert!(check_journal_values(&values, &changed_journal).is_err());
        let mut changed_values = values;
        changed_values[0] += 256;
        assert!(check_journal_values(&changed_values, &journal).is_err());
        let input_journal = vec![9; 416];
        let input_values: Vec<u32> = Sha256::digest(&input_journal)
            .iter()
            .map(|v| u32::from(*v))
            .collect();
        assert!(check_journal_values(&input_values, &input_journal).is_ok());
        assert_eq!(journal_scheme(&journal).unwrap(), "compute");
        assert_eq!(journal_scheme(&input_journal).unwrap(), "input-binding");
    }

    // Uses a real application STARK produced by the pinned CLI. The fixture stays outside git.
    // Run with OPENVM_TOOLS_FIXTURE=/absolute/fixture/directory cargo test --release -- --ignored.
    #[test]
    #[ignore = "requires an independently generated real application STARK fixture"]
    fn real_stark_authenticates_executable_journal_and_public_values() -> Result<()> {
        let fixture = std::path::PathBuf::from(std::env::var("OPENVM_TOOLS_FIXTURE")?);
        let key = fixture.join("keys/app.vk");
        let proof_path = fixture.join("fixture.app.proof");
        let journal_path = fixture.join("journal.bin");
        let identity = identity(
            &fixture.join("keys/app.pk"),
            &fixture.join("build/proof-binding-fixture.vmexe"),
        )?;
        let commit = identity["applicationExecutableCommitment"]
            .as_str()
            .expect("identity report must contain a commitment");
        let report = verify_app(&key, &proof_path, commit, &journal_path)?;
        assert_eq!(report["applicationProofVerified"], true);
        assert_eq!(report["exactExecutableCommitmentVerified"], true);
        assert_eq!(report["evmReceiptGenerated"], false);
        assert!(verify_app(
            &key,
            &proof_path,
            &format!("0x{}", "00".repeat(32)),
            &journal_path,
        )
        .is_err());
        assert!(verify_app(
            &key,
            &proof_path,
            commit,
            &fixture.join("wrong-journal.bin"),
        )
        .is_err());

        // Preserve valid serialization and all STARK segments, changing only an authenticated
        // public value. Verification must reject before reporting the journal as valid.
        let mut proof: ContinuationVmProof<SC> = read_object_from_file(&proof_path)?;
        proof.user_public_values.public_values[0] += F::ONE;
        let changed_proof = fixture.join("changed-public-value.app.proof");
        write_object_to_file(&changed_proof, &proof)?;
        let result = verify_app(&key, &changed_proof, commit, &journal_path);
        fs::remove_file(changed_proof)?;
        assert!(result.is_err());
        Ok(())
    }
}
