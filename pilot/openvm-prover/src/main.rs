// SPDX-License-Identifier: LGPL-3.0-only

//! The OpenVM worker. It proves an E3 program's guest, checks the proof against the journal the
//! host expects, and writes a seal. It runs as its own process so a failed proof cannot take the
//! service down, and so one service can choose between a CPU and a CUDA build of it.
//!
//! - `prepare <app.pk> <guest.vmexe> <new-dir>`: the aggregation key and the receipt identity.
//! - `write-config <out.json> <app.pk> <guest.vmexe> <prepared-dir> <setup-dir> <segment-bytes>`:
//!   the configuration every other action reads.
//! - `probe`: succeeds when this build can use a GPU on this machine.
//! - `check <config.json>`: loads every key and the verifier, before a service accepts work.
//! - `execute <config.json> <input> <journal>`: runs the guest without proving and checks that it
//!   reveals the journal's digest. A cheap check of a round, and of the guest against the host.
//! - `prove-app <config.json> <input> <journal> <new-app.proof>`: saves a verified application STARK.
//! - `prove <config.json> <input> <journal> <new-seal>`: proves and verifies a round.
//! - `aggregate-app <config.json> <app.proof> <journal> <new-seal>`: resumes a verified app proof.
//! - `aggregate-stark <config.json> <app.proof> <journal> <new-dir>`: saves recursive aggregation.
//! - `prove-root <config.json> <stark-dir> <journal> <new-dir>`: saves an unwrapped root STARK.
//! - `compress-root <config.json> <root-dir> <journal> <new-seal>`: compresses a saved root STARK.
//! - `verify <config.json> <proof.json> <journal> <new-seal>`: verifies an existing proof.

use eyre::{ensure, Result};
use openvm_circuit::arch::{instructions::exe::VmExe, ContinuationVmProof};
use openvm_continuations::{CommitBytes, RootSC};
use openvm_sdk::{
    config::AggregationSystemParams,
    fs::{
        read_halo2_pk_from_file, read_object_from_file, write_object_to_file,
        EVM_VERIFIER_ARTIFACT_FILENAME,
    },
    halo2_params::CacheHalo2ParamsReader,
    keygen::{AggProvingKey, AppProvingKey, AppVerifyingKey},
    prover::{verify_app_proof_with_expected_exe_commit, Halo2Prover, InternalLayerMetadata},
    types::{AppExecutionCommit, EvmHalo2Verifier, EvmProof, VersionedVmStarkProof},
    DefaultStarkEngine, Sdk, StdIn, F, OPENVM_VERSION, SC,
};
use openvm_sdk_config::SdkVmConfig;
use openvm_stark_backend::{
    codec::{Decode, Encode},
    p3_field::PrimeField32,
    proof::Proof,
    StarkEngine,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufReader, Read, Write},
    path::{Path, PathBuf},
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

const OPENVM_REVISION: &str = "59a69b8b0cbee7011ac978e4cc07707ee3681944";
const MAX_CHECKPOINT_BYTES: usize = 256 * 1024 * 1024;

fn initialize_progress() -> Result<()> {
    // Keep just recursive aggregation boundaries: index/group and start/close durations. No
    // tracing of input values, key contents, or the numerous lower-level proving operations.
    let layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_target(false)
        .with_span_events(
            tracing_subscriber::fmt::format::FmtSpan::NEW
                | tracing_subscriber::fmt::format::FmtSpan::CLOSE,
        )
        .with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
            matches!(
                metadata.name(),
                "agg_layer" | "single_leaf_agg" | "single_internal_agg"
            )
        }));
    tracing_subscriber::registry()
        .with(layer)
        .try_init()
        .map_err(|error| eyre::eyre!("Cannot initialize aggregation progress: {error}"))?;
    Ok(())
}

/// Only artifacts needed for STARK aggregation are read here. In particular, staged STARK/root
/// actions must not deserialize or hash the 10 GB Halo2 key or read KZG parameters.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ArtifactDigests {
    app_pk: String,
    executable: String,
    aggregation_pk: String,
    verifier_artifact: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CheckpointManifest {
    schema_version: u32,
    openvm_version: String,
    openvm_revision: String,
    stage: String,
    app_commit: AppExecutionCommit,
    journal_sha256: String,
    journal_bytes: usize,
    config_artifacts: ArtifactDigests,
    files: BTreeMap<String, String>,
}

fn file_sha256(path: &Path) -> Result<String> {
    let mut file = BufReader::new(fs::File::open(path)?);
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let len = file.read(&mut buffer)?;
        if len == 0 {
            break;
        }
        hash.update(&buffer[..len]);
    }
    Ok(hex::encode(hash.finalize()))
}

fn artifact_digests(config: &Config) -> Result<ArtifactDigests> {
    Ok(ArtifactDigests {
        app_pk: file_sha256(&config.app_pk)?,
        executable: file_sha256(&config.executable)?,
        aggregation_pk: file_sha256(&config.aggregation_pk)?,
        verifier_artifact: file_sha256(&config.verifier_artifact)?,
    })
}

fn checkpoint_files(stage: &str) -> Result<&'static [&'static str]> {
    match stage {
        "aggregate-stark" => Ok(&["aggregate.json", "metadata.bin"]),
        "prove-root" => Ok(&["root.bin"]),
        _ => eyre::bail!("Unsupported checkpoint stage"),
    }
}

fn validate_checkpoint_manifest(
    manifest: &CheckpointManifest,
    config: &Config,
    journal: &[u8],
    stage: &str,
) -> Result<()> {
    ensure!(
        manifest.schema_version == 1,
        "Unsupported checkpoint schema"
    );
    ensure!(
        manifest.openvm_version == format!("v{OPENVM_VERSION}")
            && manifest.openvm_revision == OPENVM_REVISION,
        "The checkpoint OpenVM version or revision differs"
    );
    ensure!(manifest.stage == stage, "The checkpoint stage differs");
    ensure!(
        manifest.app_commit == config.app_commit,
        "The checkpoint application identity differs"
    );
    ensure!(
        manifest.journal_bytes == journal.len()
            && manifest.journal_sha256 == hex::encode(Sha256::digest(journal)),
        "The checkpoint journal differs"
    );
    ensure!(
        manifest.config_artifacts == artifact_digests(config)?,
        "The checkpoint configuration artifacts differ"
    );
    let names: Vec<_> = manifest.files.keys().map(String::as_str).collect();
    ensure!(
        names == checkpoint_files(stage)?,
        "The checkpoint file list differs"
    );
    Ok(())
}

fn read_checkpoint(
    directory: &Path,
    config: &Config,
    journal: &[u8],
    stage: &str,
) -> Result<CheckpointManifest> {
    let manifest: CheckpointManifest =
        serde_json::from_slice(&read_limited(&directory.join("manifest.json"), 64 * 1024)?)?;
    validate_checkpoint_manifest(&manifest, config, journal, stage)?;
    for (name, digest) in &manifest.files {
        ensure!(
            file_sha256(&directory.join(name))? == *digest,
            "The checkpoint file digest differs: {name}"
        );
    }
    Ok(manifest)
}

fn new_durable_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn reserve_checkpoint_directory(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// The new directory is reserved before proving. A manifest published last marks a complete
/// checkpoint; a crash cannot expose a complete manifest with unfinished proof files. No file
/// is replaced, including if another process races this one.
fn write_checkpoint(
    directory: &Path,
    config: &Config,
    journal: &[u8],
    stage: &str,
    artifacts: &ArtifactDigests,
    files: &[(&str, Vec<u8>)],
) -> Result<()> {
    ensure!(
        artifact_digests(config)? == *artifacts,
        "Configuration artifacts changed during proving"
    );
    let expected = checkpoint_files(stage)?;
    ensure!(
        files.iter().map(|(name, _)| *name).collect::<Vec<_>>() == expected,
        "Invalid checkpoint files"
    );
    let mut digests = BTreeMap::new();
    for (name, bytes) in files {
        new_durable_file(&directory.join(name), bytes)?;
        digests.insert(name.to_string(), hex::encode(Sha256::digest(bytes)));
    }
    let final_artifacts = artifact_digests(config)?;
    ensure!(
        final_artifacts == *artifacts,
        "Configuration artifacts changed while saving the checkpoint"
    );
    let manifest = CheckpointManifest {
        schema_version: 1,
        openvm_version: format!("v{OPENVM_VERSION}"),
        openvm_revision: OPENVM_REVISION.to_owned(),
        stage: stage.to_owned(),
        app_commit: config.app_commit.clone(),
        journal_sha256: hex::encode(Sha256::digest(journal)),
        journal_bytes: journal.len(),
        config_artifacts: final_artifacts,
        files: digests,
    };
    let pending = directory.join("manifest.json.partial");
    new_durable_file(&pending, &serde_json::to_vec_pretty(&manifest)?)?;
    // hard_link is atomic and refuses an existing destination, unlike rename on Unix.
    fs::hard_link(&pending, directory.join("manifest.json"))?;
    fs::remove_file(pending)?;
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}

/// The largest single item the guest reads. Matches `e3_openvm_types::MAX_ITEM_BYTES`.
const MAX_ITEM_BYTES: u64 = 512 * 1024 * 1024 - 16;

/// The auction computation journal has nine ABI words; ciphertext input binding has thirteen.
/// Both guests expose exactly their SHA-256 digest as 32 byte-valued public values.
fn journal_scheme(journal: &[u8]) -> Result<&'static str> {
    match journal.len() {
        288 => Ok("compute"),
        416 => Ok("input-binding"),
        _ => eyre::bail!("Expected a 288-byte compute journal or a 416-byte input-binding journal"),
    }
}

fn read_journal(path: &Path) -> Result<Vec<u8>> {
    let journal = read_limited(path, 416)?;
    journal_scheme(&journal)?;
    Ok(journal)
}

/// Authenticate all application segments, executable identity and byte-valued journal digest
/// before accepting a saved proof as input to recursive aggregation.
fn verify_saved_app(
    key: &AppVerifyingKey,
    proof: &ContinuationVmProof<SC>,
    expected_exe: CommitBytes,
    journal: &[u8],
) -> Result<()> {
    journal_scheme(journal)?;
    ensure!(
        key.num_user_pvs == 32,
        "Expected exactly 32 public byte values"
    );
    verify_app_proof_with_expected_exe_commit::<DefaultStarkEngine>(
        key,
        proof,
        Some(expected_exe.into()),
    )?;
    let digest = Sha256::digest(journal);
    let values = &proof.user_public_values.public_values;
    ensure!(
        values.len() == 32
            && values
                .iter()
                .zip(digest)
                .all(|(actual, byte)| { actual.as_canonical_u32() == u32::from(byte) }),
        "Authenticated application public values do not equal SHA256(journal)"
    );
    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Config {
    app_pk: PathBuf,
    executable: PathBuf,
    aggregation_pk: PathBuf,
    halo2_pk: PathBuf,
    halo2_params_dir: PathBuf,
    verifier_artifact: PathBuf,
    verifier_sha256: String,
    app_commit: AppExecutionCommit,
    segment_memory_bytes: usize,
}

fn read_limited(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "The artifact exceeds its size limit");
    Ok(bytes)
}

fn validate(config: &Config) -> Result<()> {
    for path in [
        &config.app_pk,
        &config.executable,
        &config.aggregation_pk,
        &config.halo2_pk,
        &config.verifier_artifact,
    ] {
        ensure!(
            path.is_absolute() && path.is_file(),
            "Each artifact path must name an existing absolute file path: {}",
            path.display()
        );
    }
    ensure!(
        config.halo2_params_dir.is_absolute() && config.halo2_params_dir.is_dir(),
        "The Halo2 parameter path must name an existing absolute directory"
    );
    ensure!(
        config.segment_memory_bytes > 0,
        "Set a nonzero segment memory limit"
    );
    Ok(())
}

fn config(path: &Path) -> Result<Config> {
    let config: Config = serde_json::from_slice(&read_limited(path, 64 * 1024)?)?;
    validate(&config)?;
    Ok(config)
}

fn verifier(config: &Config) -> Result<EvmHalo2Verifier> {
    let bytes = read_limited(&config.verifier_artifact, 256 * 1024)?;
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == config.verifier_sha256,
        "The verifier artifact does not match the configured SHA-256 digest"
    );
    Ok(EvmHalo2Verifier {
        artifact: serde_json::from_slice(&bytes)?,
        halo2_verifier_code: String::new(),
        openvm_verifier_code: String::new(),
        openvm_verifier_interface: String::new(),
    })
}

fn sdk(config: &Config) -> Result<(Sdk, VmExe<F>)> {
    let mut app_pk: AppProvingKey<SdkVmConfig> = read_object_from_file(&config.app_pk)?;
    std::sync::Arc::get_mut(&mut app_pk.app_vm_pk)
        .unwrap()
        .vm_config
        .system
        .config
        .segmentation_max_memory = config.segment_memory_bytes;
    let exe: VmExe<F> = read_object_from_file(&config.executable)?;
    let aggregation_key: AggProvingKey = read_object_from_file(&config.aggregation_pk)?;
    let derived = Sdk::builder()
        .app_pk(app_pk.clone())
        .agg_params(AggregationSystemParams {
            leaf: aggregation_key.prefix.leaf.params.clone(),
            internal: aggregation_key.prefix.internal_for_leaf.params.clone(),
        })
        .build()?;
    ensure!(
        serde_json::to_value(derived.agg_pk())? == serde_json::to_value(&aggregation_key)?,
        "The aggregation key does not match the application VM"
    );
    drop(derived);
    let sdk = Sdk::builder()
        .app_pk(app_pk)
        .agg_pk(aggregation_key)
        .halo2_params_dir(&config.halo2_params_dir)
        .build()?;
    let prover = sdk.prover(exe.clone())?;
    let baseline = prover.generate_baseline();
    let expected = AppExecutionCommit {
        app_exe_commit: baseline.app_exe_commit.into(),
        app_vm_commit: prover.app_vm_commit().into(),
    };
    ensure!(
        expected == config.app_commit,
        "The executable or VM commitment differs from the configured identity"
    );
    Ok((sdk, exe))
}

fn require_journal_values(values: &[F], journal: &[u8]) -> Result<()> {
    let digest = Sha256::digest(journal);
    ensure!(
        values.len() == 32
            && values
                .iter()
                .zip(digest)
                .all(|(actual, byte)| actual.as_canonical_u32() == u32::from(byte)),
        "The authenticated proof values do not equal SHA256(journal)"
    );
    Ok(())
}

fn require_root_public_values(values: &[Vec<F>], config: &Config, journal: &[u8]) -> Result<()> {
    // The pinned RootCircuit exposes RootVerifierPvs at AIR0 and user values at AIR1.
    let identity = values
        .first()
        .ok_or_else(|| eyre::eyre!("Missing root identity values"))?;
    ensure!(identity.len() == 16, "Invalid root identity value count");
    let expected_exe: [F; 8] = config.app_commit.app_exe_commit.into();
    let expected_vm: [F; 8] = config.app_commit.app_vm_commit.into();
    ensure!(
        identity[..8] == expected_exe && identity[8..] == expected_vm,
        "The authenticated root application identity differs"
    );
    require_journal_values(
        values
            .get(1)
            .ok_or_else(|| eyre::eyre!("Missing root journal values"))?,
        journal,
    )
}

fn verify_root(sdk: &Sdk, config: &Config, proof: &Proof<RootSC>, journal: &[u8]) -> Result<()> {
    // Derive the root VK from the pinned app/aggregation key, never from an untrusted checkpoint.
    let root = sdk.root_prover();
    root.create_engine()
        .verify(root.0.get_vk().as_ref(), proof)?;
    require_root_public_values(&proof.public_values, config, journal)
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AppProofSourceDigests {
    config_sha256: String,
    input_sha256: String,
    journal_sha256: String,
    config_artifacts: ArtifactDigests,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AppProofManifest {
    schema_version: u32,
    openvm_version: String,
    openvm_revision: String,
    stage: String,
    proof_format: String,
    app_commit: AppExecutionCommit,
    journal_bytes: usize,
    sources: AppProofSourceDigests,
    proof_sha256: String,
    proof_bytes: u64,
}

struct AppProofOutput {
    proof: PathBuf,
    manifest: PathBuf,
    staging: PathBuf,
}

fn suffixed_path(path: &Path, suffix: &str) -> Result<PathBuf> {
    let mut name = path
        .file_name()
        .ok_or_else(|| eyre::eyre!("Expected an application proof file name"))?
        .to_os_string();
    name.push(suffix);
    Ok(path.with_file_name(name))
}

fn require_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => eyre::bail!(
            "Application proof output already exists: {}",
            path.display()
        ),
    }
}

fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn app_proof_output(path: &Path) -> Result<AppProofOutput> {
    let output = AppProofOutput {
        proof: path.to_path_buf(),
        manifest: suffixed_path(path, ".manifest.json")?,
        staging: suffixed_path(path, ".partial")?,
    };
    for path in [&output.proof, &output.manifest, &output.staging] {
        require_absent(path)?;
    }
    ensure!(
        output_parent(path).is_dir(),
        "Application proof output parent must be an existing directory"
    );
    Ok(output)
}

fn app_proof_sources(
    config: &Config,
    config_path: &Path,
    input_path: &Path,
    journal_path: &Path,
) -> Result<AppProofSourceDigests> {
    let config_bytes = read_limited(config_path, 64 * 1024)?;
    let current: Config = serde_json::from_slice(&config_bytes)?;
    ensure!(
        serde_json::to_value(current)? == serde_json::to_value(config)?,
        "Application proof configuration file changed"
    );
    Ok(AppProofSourceDigests {
        config_sha256: hex::encode(Sha256::digest(config_bytes)),
        input_sha256: file_sha256(input_path)?,
        journal_sha256: file_sha256(journal_path)?,
        config_artifacts: artifact_digests(config)?,
    })
}

fn require_app_proof_sources(
    config: &Config,
    config_path: &Path,
    paths: &[PathBuf],
    expected: &AppProofSourceDigests,
) -> Result<()> {
    ensure!(
        app_proof_sources(config, config_path, &paths[0], &paths[1])? == *expected,
        "Application proof input, journal, configuration, or artifacts changed"
    );
    Ok(())
}

/// Persist exactly the SDK bitcode format read by aggregate-stark. No recursive
/// proof, root proof, Halo2 key, KZG parameters, or Ethereum receipt is produced.
fn prove_app(config: &Config, config_path: &Path, paths: &[PathBuf]) -> Result<()> {
    ensure!(
        paths.len() == 3,
        "Expected input, journal, and a new application proof file"
    );
    // Reject collisions (including dangling symlinks), missing parents and bad
    // framing before parsing proving keys or performing expensive proof work.
    let output = app_proof_output(&paths[2])?;
    let journal = read_journal(&paths[1])?;
    let sources = app_proof_sources(config, config_path, &paths[0], &paths[1])?;
    ensure!(
        sources.journal_sha256 == hex::encode(Sha256::digest(&journal)),
        "Application proof journal changed while being read"
    );
    let input = read_items(fs::File::open(&paths[0])?)?;
    require_app_proof_sources(config, config_path, paths, &sources)?;
    let mut directory = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        directory.mode(0o700);
    }
    // The SDK file writer can replace files, so confine it to a freshly reserved
    // private directory, then publish through create-new hard links instead.
    directory.create(&output.staging)?;
    fs::File::open(output_parent(&output.proof))?.sync_all()?;

    let (sdk, exe) = sdk(config)?;
    let verifying_key = sdk.app_pk().get_app_vk();
    let mut prover = sdk.app_prover(exe)?;
    // sdk() already derived the exact executable AND VM identity from the actual
    // app/aggregation keys. Drop recursive state before application proving.
    drop(sdk);
    eprintln!("OpenVM: proving the application STARK; Halo2 remains unloaded");
    let proof = prover.prove(input)?;
    drop(prover);
    verify_saved_app(
        &verifying_key,
        &proof,
        config.app_commit.app_exe_commit,
        &journal,
    )?;
    require_app_proof_sources(config, config_path, paths, &sources)?;

    let staged_proof = output.staging.join("app.proof");
    write_object_to_file(&staged_proof, &proof)?;
    drop(proof);
    fs::File::open(&staged_proof)?.sync_all()?;
    // Authenticate the bytes read back through the same SDK reader that the
    // existing recursive action uses, before exposing any final proof file.
    let saved: ContinuationVmProof<SC> = read_object_from_file(&staged_proof)?;
    verify_saved_app(
        &verifying_key,
        &saved,
        config.app_commit.app_exe_commit,
        &journal,
    )?;
    drop(saved);
    let proof_sha256 = file_sha256(&staged_proof)?;
    let proof_bytes = fs::metadata(&staged_proof)?.len();
    require_app_proof_sources(config, config_path, paths, &sources)?;
    let manifest = AppProofManifest {
        schema_version: 1,
        openvm_version: format!("v{OPENVM_VERSION}"),
        openvm_revision: OPENVM_REVISION.to_owned(),
        stage: "prove-app".to_owned(),
        proof_format: "openvm-sdk-bitcode-ContinuationVmProof<SC>".to_owned(),
        app_commit: config.app_commit.clone(),
        journal_bytes: journal.len(),
        sources,
        proof_sha256,
        proof_bytes,
    };
    let staged_manifest = output.staging.join("manifest.json");
    new_durable_file(&staged_manifest, &serde_json::to_vec_pretty(&manifest)?)?;
    fs::File::open(&output.staging)?.sync_all()?;
    require_app_proof_sources(config, config_path, paths, &manifest.sources)?;
    fs::hard_link(&staged_proof, &output.proof)?;
    // The manifest is the final publication marker. Any interruption or write
    // error retains the staging directory for diagnosis; no retry overwrites it.
    fs::hard_link(&staged_manifest, &output.manifest)?;
    fs::File::open(output_parent(&output.proof))?.sync_all()?;
    fs::remove_file(staged_proof)?;
    fs::remove_file(staged_manifest)?;
    fs::remove_dir(&output.staging)?;
    fs::File::open(output_parent(&output.proof))?.sync_all()?;
    eprintln!("OpenVM: saved verified application STARK for the exact executable, VM, and journal");
    Ok(())
}

fn aggregate_stark(config: &Config, paths: &[PathBuf]) -> Result<()> {
    ensure!(
        paths.len() == 3,
        "Expected app.proof, journal, and a new checkpoint directory"
    );
    reserve_checkpoint_directory(&paths[2])?;
    let journal = read_journal(&paths[1])?;
    let artifacts = artifact_digests(config)?;
    let (sdk, exe) = sdk(config)?;
    let app_proof: ContinuationVmProof<SC> = read_object_from_file(&paths[0])?;
    verify_saved_app(
        &sdk.app_pk().get_app_vk(),
        &app_proof,
        config.app_commit.app_exe_commit,
        &journal,
    )?;
    eprintln!("OpenVM: verified the saved application proof, executable, and journal");
    let agg = sdk.agg_prover();
    let segments = app_proof.per_segment.len();
    let leaf_nodes = segments.div_ceil(agg.agg_tree_config.num_children_leaf);
    eprintln!("OpenVM: aggregating {segments} application segments in {leaf_nodes} leaf nodes; Halo2 remains unloaded");
    let (stark, metadata) = agg.prove_vm(app_proof)?;
    Sdk::verify_proof(
        sdk.agg_vk().as_ref().clone(),
        sdk.prover(exe)?.generate_baseline(),
        &stark,
    )?;
    require_journal_values(&stark.user_pvs_proof.public_values, &journal)?;
    let versioned = VersionedVmStarkProof::new(stark)?;
    write_checkpoint(
        &paths[2],
        config,
        &journal,
        "aggregate-stark",
        &artifacts,
        &[
            ("aggregate.json", serde_json::to_vec(&versioned)?),
            ("metadata.bin", metadata.encode_to_vec()?),
        ],
    )?;
    eprintln!("OpenVM: saved verified aggregate STARK checkpoint");
    Ok(())
}

fn prove_root(config: &Config, paths: &[PathBuf]) -> Result<()> {
    ensure!(
        paths.len() == 3,
        "Expected aggregate checkpoint directory, journal, and a new directory"
    );
    reserve_checkpoint_directory(&paths[2])?;
    let journal = read_journal(&paths[1])?;
    read_checkpoint(&paths[0], config, &journal, "aggregate-stark")?;
    let artifacts = artifact_digests(config)?;
    let versioned: VersionedVmStarkProof = serde_json::from_slice(&read_limited(
        &paths[0].join("aggregate.json"),
        MAX_CHECKPOINT_BYTES,
    )?)?;
    // Upstream TryFrom intentionally ignores its version field; reject it explicitly here.
    ensure!(
        versioned.version == format!("v{OPENVM_VERSION}"),
        "Unsupported aggregate proof version"
    );
    let stark = versioned.try_into()?;
    let mut metadata = InternalLayerMetadata::decode_from_bytes(&read_limited(
        &paths[0].join("metadata.bin"),
        64,
    )?)?;
    ensure!(
        matches!(
            metadata.proofs_type,
            openvm_continuations::circuit::inner::ProofsType::Vm
        ),
        "Expected VM-only aggregation metadata"
    );
    let (sdk, exe) = sdk(config)?;
    Sdk::verify_proof(
        sdk.agg_vk().as_ref().clone(),
        sdk.prover(exe.clone())?.generate_baseline(),
        &stark,
    )?;
    require_journal_values(&stark.user_pvs_proof.public_values, &journal)?;
    eprintln!("OpenVM: verified the saved aggregate STARK, executable, and journal");
    eprintln!("OpenVM: proving the root STARK; Halo2 remains unloaded");
    let root = sdk
        .evm_prover_without_halo2(exe)?
        .prove_root_from_vm_stark_proof(stark, &mut metadata)?;
    verify_root(&sdk, config, &root, &journal)?;
    write_checkpoint(
        &paths[2],
        config,
        &journal,
        "prove-root",
        &artifacts,
        &[("root.bin", root.encode_to_vec()?)],
    )?;
    eprintln!("OpenVM: saved verified root STARK checkpoint");
    Ok(())
}

fn compress_root(config: &Config, paths: &[PathBuf]) -> Result<()> {
    ensure!(
        paths.len() == 3,
        "Expected root checkpoint directory, journal, and a new seal file"
    );
    ensure!(!paths[2].exists(), "The seal output already exists");
    let journal = read_journal(&paths[1])?;
    read_checkpoint(&paths[0], config, &journal, "prove-root")?;
    let artifacts = artifact_digests(config)?;
    let root = Proof::<RootSC>::decode_from_bytes(&read_limited(
        &paths[0].join("root.bin"),
        MAX_CHECKPOINT_BYTES,
    )?)?;
    {
        let (sdk, _) = sdk(config)?;
        verify_root(&sdk, config, &root, &journal)?;
    } // Drop application/aggregation/root prover state before allocating Halo2 state.
    eprintln!("OpenVM: verified the saved root STARK, executable, and journal");
    eprintln!("OpenVM: loading Halo2 keys and parameters, then generating the EVM proof");
    let halo2 = Halo2Prover::new(
        &CacheHalo2ParamsReader::new(&config.halo2_params_dir),
        read_halo2_pk_from_file(&config.halo2_pk)?,
    );
    let proof = halo2.prove_for_evm(&root)?;
    verify(&proof, config, &journal)?;
    ensure!(
        artifact_digests(config)? == artifacts,
        "Configuration artifacts changed during compression"
    );
    new_durable_file(&paths[2], &seal(&proof))?;
    if let Some(parent) = paths[2].parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::File::open(parent)?.sync_all()?;
    }
    eprintln!("OpenVM: saved verified EVM seal for the exact application and journal");
    Ok(())
}

fn verify(proof: &EvmProof, config: &Config, journal: &[u8]) -> Result<()> {
    ensure!(proof.version == "v2.0", "Unsupported OpenVM proof version");
    journal_scheme(journal)?;
    ensure!(
        proof.app_commit == config.app_commit,
        "The application commitment differs"
    );
    ensure!(
        proof.user_public_values == Sha256::digest(journal).to_vec(),
        "The proof public values do not match the journal"
    );
    ensure!(
        proof.proof_data.accumulator.len() == 384 && proof.proof_data.proof.len() == 1376,
        "The proof data has an invalid length"
    );
    Sdk::verify_evm_halo2_proof(
        &verifier(config)?,
        proof.clone(),
        Some(config.app_commit.clone()),
    )?;
    Ok(())
}

fn word(value: usize) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&(value as u64).to_be_bytes());
    bytes
}

/// Encode a verified receipt as `abi.encode(uint8 version, bytes proofData)`.
///
/// The proof's only public value is the journal digest, which the contract recomputes from chain
/// state and passes to the Halo2 verifier, so the seal does not repeat the journal.
fn seal(proof: &EvmProof) -> Vec<u8> {
    encode_seal(
        &[
            proof.proof_data.accumulator.as_slice(),
            proof.proof_data.proof.as_slice(),
        ]
        .concat(),
    )
}

/// `abi.encode(uint8(1), proofData)` for the 1,760 bytes of Halo2 proof data. No padding is needed:
/// the length is a multiple of 32.
fn encode_seal(proof_data: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(96 + proof_data.len());
    bytes.extend_from_slice(&word(1));
    bytes.extend_from_slice(&word(64));
    bytes.extend_from_slice(&word(proof_data.len()));
    bytes.extend_from_slice(proof_data);
    bytes
}

/// Reads the guest's input items, which the host writes with `e3_openvm_types::write_items`: a
/// little-endian `u32` count, then each item as a little-endian `u64` length and its bytes.
///
/// Each item becomes one entry of the guest's input stream, which the guest reads with
/// `openvm::io::read_vec`. Items are converted as they are read, so the raw file is never held
/// whole.
fn read_items(reader: impl Read) -> Result<StdIn> {
    let mut reader = BufReader::new(reader);
    let mut word = [0; 4];
    reader.read_exact(&mut word)?;
    let count = u32::from_le_bytes(word);
    let mut stdin = StdIn::default();
    for _ in 0..count {
        let mut length = [0; 8];
        reader.read_exact(&mut length)?;
        let length = u64::from_le_bytes(length);
        ensure!(
            length <= MAX_ITEM_BYTES,
            "A guest input item exceeds the guest memory limit"
        );
        let mut item = vec![0; length as usize];
        reader.read_exact(&mut item)?;
        stdin.write_bytes(&item);
    }
    ensure!(
        reader.read(&mut [0; 1])? == 0,
        "Unexpected bytes after the last guest input item"
    );
    Ok(stdin)
}

/// Whether this build can use a GPU here. A CUDA build opens the current device; a CPU build
/// always fails, so a service never mistakes it for a GPU worker.
#[cfg(feature = "cuda")]
fn probe() -> Result<()> {
    let device = openvm_cuda_common::common::set_device()
        .map_err(|error| eyre::eyre!("Cannot open a CUDA device: {error}"))?;
    eprintln!("OpenVM: CUDA device {device} is available");
    Ok(())
}

#[cfg(not(feature = "cuda"))]
fn probe() -> Result<()> {
    eyre::bail!("This worker was built without CUDA")
}

/// Runs the guest over `input` without proving it and checks that it reveals the digest of the
/// journal the host expects.
fn execute(config: &Config, input: &Path, journal: &Path) -> Result<()> {
    let journal = read_journal(journal)?;
    let app_pk: AppProvingKey<SdkVmConfig> = read_object_from_file(&config.app_pk)?;
    let exe: VmExe<F> = read_object_from_file(&config.executable)?;
    let sdk = Sdk::builder()
        .app_pk(app_pk)
        .agg_params(AggregationSystemParams::default())
        .build()?;
    let (public_values, segments) =
        sdk.execute_metered(exe, read_items(fs::File::open(input)?)?)?;
    let instructions: u64 = segments.iter().map(|segment| segment.num_insns).sum();
    eprintln!(
        "OpenVM: executed {instructions} instructions in {} segments",
        segments.len()
    );
    ensure!(
        public_values == Sha256::digest(&journal).to_vec(),
        "The guest revealed a digest that differs from the host's journal"
    );
    eprintln!("OpenVM: the guest revealed the digest of the host's journal");
    Ok(())
}

fn absolute(path: &Path) -> Result<PathBuf> {
    fs::canonicalize(path)
        .map_err(|error| eyre::eyre!("Cannot resolve {}: {error}", path.display()))
}

/// Writes the configuration for the keys `prepare` made and the artifacts that
/// `cargo openvm setup --evm` produced (generated, or prebuilt with `--download`).
fn write_config(paths: &[PathBuf]) -> Result<()> {
    ensure!(
        paths.len() == 6,
        "Expected the output path, app.pk, the executable, the prepared directory, the setup \
         directory, and the segment memory limit"
    );
    let prepared = absolute(&paths[3])?;
    let setup = absolute(&paths[4])?;
    let identity: serde_json::Value =
        serde_json::from_slice(&read_limited(&prepared.join("identity.json"), 64 * 1024)?)?;
    let verifier_artifact = setup
        .join("halo2")
        .join("src")
        .join(format!("v{OPENVM_VERSION}-base"))
        .join(EVM_VERIFIER_ARTIFACT_FILENAME);
    let config = Config {
        app_pk: absolute(&paths[1])?,
        executable: absolute(&paths[2])?,
        aggregation_pk: prepared.join("aggregation.pk"),
        halo2_pk: setup.join("halo2.pk"),
        halo2_params_dir: setup.join("params"),
        verifier_sha256: hex::encode(Sha256::digest(read_limited(
            &verifier_artifact,
            256 * 1024,
        )?)),
        verifier_artifact,
        app_commit: serde_json::from_value(identity["app_commit"].clone())?,
        segment_memory_bytes: paths[5]
            .to_str()
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| eyre::eyre!("The segment memory limit must be a number of bytes"))?,
    };
    validate(&config)?;

    let output = &paths[0];
    let partial = output.with_extension("json.partial");
    fs::write(&partial, serde_json::to_vec_pretty(&config)?)?;
    fs::rename(&partial, output)?;
    Ok(())
}

fn main() -> Result<()> {
    initialize_progress()?;
    let mut args = std::env::args_os().skip(1);
    let action = args.next().ok_or_else(|| {
        eyre::eyre!("Expected prepare, write-config, probe, check, execute, prove-app, prove, aggregate-app, aggregate-stark, prove-root, compress-root, or verify")
    })?;
    if action == "probe" {
        ensure!(args.next().is_none(), "Unexpected arguments");
        return probe();
    }
    if action == "write-config" {
        return write_config(&args.map(PathBuf::from).collect::<Vec<_>>());
    }
    if action == "prepare" {
        let paths: Vec<PathBuf> = args.map(PathBuf::from).collect();
        ensure!(
            paths.len() == 3,
            "Expected app.pk, executable, and a new output directory"
        );
        ensure!(!paths[2].exists(), "The output directory already exists");
        let app_pk: AppProvingKey<SdkVmConfig> = read_object_from_file(&paths[0])?;
        let exe: VmExe<F> = read_object_from_file(&paths[1])?;
        let sdk = Sdk::builder()
            .app_pk(app_pk)
            .agg_params(AggregationSystemParams::default())
            .build()?;
        let prover = sdk.prover(exe)?;
        let baseline = prover.generate_baseline();
        let commit = AppExecutionCommit {
            app_exe_commit: baseline.app_exe_commit.into(),
            app_vm_commit: prover.app_vm_commit().into(),
        };
        fs::create_dir(&paths[2])?;
        write_object_to_file(paths[2].join("aggregation.pk"), sdk.agg_pk())?;
        let identity = serde_json::json!({ "app_commit": commit });
        let file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(paths[2].join("identity.json"))?;
        serde_json::to_writer_pretty(file, &identity)?;
        return Ok(());
    }
    let config_path = PathBuf::from(
        args.next()
            .ok_or_else(|| eyre::eyre!("Expected a config path"))?,
    );
    let config = config(&config_path)?;
    verifier(&config)?;
    if action == "check" {
        ensure!(args.next().is_none(), "Unexpected arguments");
        sdk(&config)?;
        // Load the Halo2 key and both KZG parameter files now. `prove` reads them only after the
        // application proof and aggregation, which can take hours.
        Halo2Prover::new(
            &CacheHalo2ParamsReader::new(&config.halo2_params_dir),
            read_halo2_pk_from_file(&config.halo2_pk)?,
        );
        eprintln!("OpenVM: the keys, parameters, verifier, and identity are consistent");
        return Ok(());
    }
    if action == "execute" {
        let paths: Vec<PathBuf> = args.map(PathBuf::from).collect();
        ensure!(paths.len() == 2, "Expected the input and the journal");
        return execute(&config, &paths[0], &paths[1]);
    }
    if action == "prove-app" {
        let paths: Vec<PathBuf> = args.map(PathBuf::from).collect();
        return prove_app(&config, &config_path, &paths);
    }
    if action == "aggregate-stark" || action == "prove-root" || action == "compress-root" {
        let paths: Vec<PathBuf> = args.map(PathBuf::from).collect();
        return if action == "aggregate-stark" {
            aggregate_stark(&config, &paths)
        } else if action == "prove-root" {
            prove_root(&config, &paths)
        } else {
            compress_root(&config, &paths)
        };
    }
    ensure!(
        action == "prove" || action == "aggregate-app" || action == "verify",
        "Expected prepare, write-config, probe, check, execute, prove, aggregate-app, or verify"
    );
    let paths: Vec<PathBuf> = args.map(PathBuf::from).collect();
    ensure!(
        paths.len() == 3,
        "Expected input or proof, journal, and a new seal output path"
    );
    ensure!(!paths[2].exists(), "The seal output already exists");
    let journal = read_journal(&paths[1])?;
    let proof: EvmProof = if action == "verify" {
        serde_json::from_slice(&read_limited(&paths[0], 256 * 1024)?)?
    } else {
        let (sdk, exe) = sdk(&config)?;
        let app_proof = if action == "aggregate-app" {
            let proof: ContinuationVmProof<SC> = read_object_from_file(&paths[0])?;
            // sdk() independently recomputes this identity from the actual key and executable,
            // and rejects a config with a different executable or VM commitment.
            verify_saved_app(
                &sdk.app_pk().get_app_vk(),
                &proof,
                config.app_commit.app_exe_commit,
                &journal,
            )?;
            eprintln!("OpenVM: verified the saved application proof, executable, and journal");
            proof
        } else {
            let input = read_items(fs::File::open(&paths[0])?)?;
            eprintln!("OpenVM: proving the application");
            sdk.app_prover(exe.clone())?.prove(input)?
        };
        eprintln!("OpenVM: aggregating the application proof");
        let (stark_proof, mut metadata) = sdk.agg_prover().prove_vm(app_proof)?;
        let baseline = sdk.prover(exe.clone())?.generate_baseline();
        Sdk::verify_proof(sdk.agg_vk().as_ref().clone(), baseline, &stark_proof)?;
        let root_proof = sdk
            .evm_prover_without_halo2(exe)?
            .prove_root_from_vm_stark_proof(stark_proof, &mut metadata)?;
        eprintln!("OpenVM: generating the EVM proof");
        let halo2 = Sdk::builder()
            .app_pk(sdk.app_pk().clone())
            .agg_pk(sdk.agg_pk())
            .root_pk(sdk.root_pk())
            .halo2_params_dir(&config.halo2_params_dir)
            .halo2_pk(read_halo2_pk_from_file(&config.halo2_pk)?)
            .build()?;
        halo2.halo2_prover().prove_for_evm(&root_proof)?
    };
    verify(&proof, &config, &journal)?;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&paths[2])?;
    file.write_all(&seal(&proof))?;
    file.sync_all()?;
    eprintln!("OpenVM: verified the proof, the application identity, and the journal digest");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openvm_sdk::prover::AppProver;
    use openvm_sdk_config::SdkVmCpuBuilder;
    use openvm_stark_backend::p3_field::PrimeCharacteristicRing;
    use std::sync::Arc;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let nonce = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "interfold-checkpoint-{}-{}-{nonce}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn config(&self) -> Config {
            for name in ["app.pk", "exe", "aggregation.pk", "verifier.json"] {
                fs::write(self.0.join(name), name.as_bytes()).unwrap();
            }
            Config {
                app_pk: self.0.join("app.pk"),
                executable: self.0.join("exe"),
                aggregation_pk: self.0.join("aggregation.pk"),
                halo2_pk: self.0.join("halo2-never-opened.pk"),
                halo2_params_dir: self.0.join("params-never-opened"),
                verifier_artifact: self.0.join("verifier.json"),
                verifier_sha256: String::new(),
                app_commit: AppExecutionCommit {
                    app_exe_commit: CommitBytes::try_new([0; 32]).unwrap(),
                    app_vm_commit: CommitBytes::try_new([0; 32]).unwrap(),
                },
                segment_memory_bytes: 1024,
            }
        }

        fn checkpoint(&self, config: &Config, journal: &[u8], stage: &str) -> PathBuf {
            let dir = self.0.join(stage);
            fs::create_dir(&dir).unwrap();
            let files = checkpoint_files(stage)
                .unwrap()
                .iter()
                .map(|name| (*name, vec![1, 2, 3]))
                .collect::<Vec<_>>();
            write_checkpoint(
                &dir,
                config,
                journal,
                stage,
                &artifact_digests(config).unwrap(),
                &files,
            )
            .unwrap();
            dir
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The bytes `e3_openvm_types::write_items` writes for the items `[1, 2, 3]` and `[]`. The same
    /// vector is pinned on the writer's side, so a format change on either side fails a test.
    const TWO_ITEMS: [u8; 23] = [
        2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    #[test]
    fn reads_each_item_into_its_own_stream_entry() {
        let mut expected = StdIn::default();
        expected.write_bytes(&[1, 2, 3]);
        expected.write_bytes(&[]);

        let mut stdin = read_items(TWO_ITEMS.as_slice()).unwrap();
        assert_eq!(stdin.read(), expected.read());
        assert_eq!(stdin.read(), expected.read());
        assert!(stdin.read().is_none());
    }

    #[test]
    fn refuses_truncated_and_padded_input() {
        assert!(read_items(&TWO_ITEMS[..TWO_ITEMS.len() - 1]).is_err());
        let mut padded = TWO_ITEMS.to_vec();
        padded.push(0);
        assert!(read_items(padded.as_slice()).is_err());
    }

    #[test]
    fn refuses_an_item_above_the_guest_memory_limit() {
        let mut input = 1u32.to_le_bytes().to_vec();
        input.extend_from_slice(&(MAX_ITEM_BYTES + 1).to_le_bytes());
        assert!(read_items(input.as_slice()).is_err());
    }

    /// The seal is `abi.encode(uint8(1), proofData)`: the layout `OpenVmReceiptVerifier` decodes and
    /// the 1,856 bytes `e3_openvm_host::SEAL_BYTES` expects.
    #[test]
    fn the_seal_is_the_abi_encoding_of_the_version_and_the_proof_data() {
        let proof_data = [0xab; 1760];
        let seal = encode_seal(&proof_data);

        assert_eq!(seal.len(), 1856);
        let mut head = [0u8; 96];
        head[31] = 1;
        head[63] = 0x40;
        head[94..96].copy_from_slice(&[0x06, 0xe0]);
        assert_eq!(&seal[..96], head.as_slice());
        assert_eq!(&seal[96..], proof_data.as_slice());
    }

    #[cfg(not(feature = "cuda"))]
    #[test]
    fn a_cpu_build_never_passes_the_gpu_probe() {
        assert!(probe().is_err());
    }

    #[test]
    fn accepts_only_exact_compute_or_input_binding_journals() {
        assert_eq!(journal_scheme(&[0; 288]).unwrap(), "compute");
        assert_eq!(journal_scheme(&[0; 416]).unwrap(), "input-binding");
        for len in [0, 32, 287, 289, 415, 417] {
            assert!(journal_scheme(&vec![0; len]).is_err());
        }
    }

    #[test]
    fn prove_app_rejects_existing_outputs_before_deserializing_proving_keys() {
        for suffix in ["", ".manifest.json", ".partial"] {
            let scratch = Scratch::new();
            let config = scratch.config();
            let output = scratch.0.join("new.app.proof");
            let collision = suffixed_path(&output, suffix).unwrap();
            fs::write(&collision, b"preserve previous work").unwrap();
            // None of these inputs exists and the proving-key bytes are invalid.
            // Collision rejection must precede all of that expensive work.
            let error = prove_app(
                &config,
                &scratch.0.join("missing-config.json"),
                &[
                    scratch.0.join("missing-input.bin"),
                    scratch.0.join("missing-journal.bin"),
                    output,
                ],
            )
            .unwrap_err();
            assert!(error.to_string().contains("output already exists"));
            assert_eq!(fs::read(collision).unwrap(), b"preserve previous work");
            assert!(!config.halo2_pk.exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn prove_app_rejects_dangling_output_symlinks_without_following_them() {
        let scratch = Scratch::new();
        let config = scratch.config();
        let output = scratch.0.join("new.app.proof");
        let destination = scratch.0.join("must-not-create");
        std::os::unix::fs::symlink(&destination, &output).unwrap();
        let error = prove_app(
            &config,
            &scratch.0.join("missing-config.json"),
            &[
                scratch.0.join("missing-input.bin"),
                scratch.0.join("missing-journal.bin"),
                output.clone(),
            ],
        )
        .unwrap_err();
        assert!(error.to_string().contains("output already exists"));
        assert!(fs::symlink_metadata(output)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!destination.exists());
    }

    #[test]
    fn prove_app_rejects_padded_guest_input_before_keys_or_output_reservation() {
        let scratch = Scratch::new();
        let config = scratch.config();
        let config_path = scratch.0.join("config.json");
        fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        let input = scratch.0.join("input.bin");
        let mut padded = TWO_ITEMS.to_vec();
        padded.push(0);
        fs::write(&input, padded).unwrap();
        let journal = scratch.0.join("journal.bin");
        fs::write(&journal, [7; 288]).unwrap();
        let output = scratch.0.join("new.app.proof");
        let error =
            prove_app(&config, &config_path, &[input, journal, output.clone()]).unwrap_err();
        assert!(error
            .to_string()
            .contains("Unexpected bytes after the last guest input item"));
        for suffix in ["", ".manifest.json", ".partial"] {
            assert!(!suffixed_path(&output, suffix).unwrap().exists());
        }
        assert!(!config.halo2_pk.exists() && !config.halo2_params_dir.exists());
    }

    #[test]
    fn application_proof_snapshots_reject_changed_input_journal_artifacts_and_config() {
        let scratch = Scratch::new();
        let config = scratch.config();
        let config_path = scratch.0.join("config.json");
        let config_bytes = serde_json::to_vec(&config).unwrap();
        fs::write(&config_path, &config_bytes).unwrap();
        let input = scratch.0.join("input.bin");
        fs::write(&input, TWO_ITEMS).unwrap();
        let journal = scratch.0.join("journal.bin");
        fs::write(&journal, [7; 288]).unwrap();
        let paths = [input.clone(), journal.clone(), scratch.0.join("app.proof")];
        let sources = app_proof_sources(&config, &config_path, &input, &journal).unwrap();
        require_app_proof_sources(&config, &config_path, &paths, &sources).unwrap();
        fs::write(&input, b"changed input").unwrap();
        assert!(require_app_proof_sources(&config, &config_path, &paths, &sources).is_err());
        fs::write(&input, TWO_ITEMS).unwrap();
        fs::write(&journal, [8; 288]).unwrap();
        assert!(require_app_proof_sources(&config, &config_path, &paths, &sources).is_err());
        fs::write(&journal, [7; 288]).unwrap();
        fs::write(&config.executable, b"changed executable").unwrap();
        assert!(require_app_proof_sources(&config, &config_path, &paths, &sources).is_err());
        fs::write(&config.executable, b"exe").unwrap();
        let mut changed: serde_json::Value = serde_json::from_slice(&config_bytes).unwrap();
        changed["segment_memory_bytes"] = serde_json::json!(2048);
        fs::write(&config_path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(require_app_proof_sources(&config, &config_path, &paths, &sources).is_err());
        fs::write(&config_path, config_bytes).unwrap();
        require_app_proof_sources(&config, &config_path, &paths, &sources).unwrap();
        assert!(!config.halo2_pk.exists() && !config.halo2_params_dir.exists());
    }

    #[test]
    fn checkpoints_pin_artifacts_without_opening_halo2_and_reject_corruption() {
        let scratch = Scratch::new();
        let config = scratch.config();
        let journal = [7; 288];
        let dir = scratch.checkpoint(&config, &journal, "aggregate-stark");
        assert!(read_checkpoint(&dir, &config, &journal, "aggregate-stark").is_ok());
        // These paths deliberately do not exist; reading a STARK checkpoint must not touch them.
        assert!(!config.halo2_pk.exists() && !config.halo2_params_dir.exists());
        fs::write(dir.join("metadata.bin"), [9, 9, 9]).unwrap();
        assert!(read_checkpoint(&dir, &config, &journal, "aggregate-stark").is_err());
    }

    #[test]
    fn checkpoints_reject_wrong_version_stage_identity_journal_and_config_artifacts() {
        let scratch = Scratch::new();
        let mut config = scratch.config();
        let journal = [7; 416];
        let dir = scratch.checkpoint(&config, &journal, "prove-root");
        let manifest: CheckpointManifest =
            serde_json::from_slice(&fs::read(dir.join("manifest.json")).unwrap()).unwrap();
        assert!(validate_checkpoint_manifest(&manifest, &config, &journal, "prove-root").is_ok());
        assert!(read_checkpoint(&dir, &config, &[8; 416], "prove-root").is_err());
        assert!(read_checkpoint(&dir, &config, &[7; 288], "prove-root").is_err());
        assert!(read_checkpoint(&dir, &config, &journal, "aggregate-stark").is_err());
        config.app_commit.app_exe_commit = CommitBytes::from([F::ONE; 8]);
        assert!(read_checkpoint(&dir, &config, &journal, "prove-root").is_err());
        config.app_commit = manifest.app_commit.clone();
        let mut manifest = manifest;
        manifest.openvm_version = "v9.9".to_owned();
        assert!(validate_checkpoint_manifest(&manifest, &config, &journal, "prove-root").is_err());
        manifest.openvm_version = format!("v{OPENVM_VERSION}");
        manifest.openvm_revision = "wrong-revision".to_owned();
        assert!(validate_checkpoint_manifest(&manifest, &config, &journal, "prove-root").is_err());
        manifest.openvm_revision = OPENVM_REVISION.to_owned();
        manifest
            .files
            .insert("../escape".to_owned(), "ignored".to_owned());
        assert!(validate_checkpoint_manifest(&manifest, &config, &journal, "prove-root").is_err());
        manifest.files.remove("../escape");
        fs::write(&config.executable, b"changed executable").unwrap();
        assert!(validate_checkpoint_manifest(&manifest, &config, &journal, "prove-root").is_err());
    }

    #[test]
    fn checkpoints_never_replace_existing_files_and_require_a_complete_manifest() {
        let scratch = Scratch::new();
        let config = scratch.config();
        let journal = [0; 288];
        let dir = scratch.0.join("prove-root");
        fs::create_dir(&dir).unwrap();
        new_durable_file(&dir.join("root.bin"), b"partial proof").unwrap();
        assert!(read_checkpoint(&dir, &config, &journal, "prove-root").is_err());
        assert!(write_checkpoint(
            &dir,
            &config,
            &journal,
            "prove-root",
            &artifact_digests(&config).unwrap(),
            &[("root.bin", b"replacement".to_vec()),]
        )
        .is_err());
        assert_eq!(fs::read(dir.join("root.bin")).unwrap(), b"partial proof");
        assert!(!dir.join("manifest.json").exists());
    }

    #[test]
    fn root_values_require_exact_identity_and_byte_valued_journal_digest() {
        let scratch = Scratch::new();
        let config = scratch.config();
        let journal = [4; 288];
        let digest = Sha256::digest(journal);
        let mut values = vec![
            vec![F::ZERO; 16],
            digest.iter().map(|b| F::from_u32(u32::from(*b))).collect(),
        ];
        require_root_public_values(&values, &config, &journal).unwrap();
        assert!(require_root_public_values(&values, &config, &[5; 288]).is_err());
        values[0][0] = F::ONE;
        assert!(require_root_public_values(&values, &config, &journal).is_err());
        values[0][0] = F::ZERO;
        values[1][0] += F::from_u32(256);
        assert!(require_root_public_values(&values, &config, &journal).is_err());
        assert!(require_root_public_values(&values[..1], &config, &journal).is_err());
    }

    #[test]
    fn resume_rejects_inner_proof_version_even_with_a_matching_file_digest() {
        let scratch = Scratch::new();
        let config = scratch.config();
        let journal = [3; 288];
        let journal_path = scratch.0.join("journal.bin");
        fs::write(&journal_path, journal).unwrap();
        let source = scratch.0.join("source");
        fs::create_dir(&source).unwrap();
        let wrong_version = VersionedVmStarkProof {
            version: "v99.0".to_owned(),
            proof: vec![],
            user_pvs_proof: vec![],
            deferral_merkle_proofs: None,
        };
        write_checkpoint(
            &source,
            &config,
            &journal,
            "aggregate-stark",
            &artifact_digests(&config).unwrap(),
            &[
                (
                    "aggregate.json",
                    serde_json::to_vec(&wrong_version).unwrap(),
                ),
                ("metadata.bin", vec![]),
            ],
        )
        .unwrap();
        let error =
            prove_root(&config, &[source, journal_path, scratch.0.join("new-root")]).unwrap_err();
        assert!(error
            .to_string()
            .contains("Unsupported aggregate proof version"));
        assert!(!config.halo2_pk.exists());
    }

    #[test]
    #[ignore = "requires an independently generated real application STARK fixture"]
    fn saved_real_app_proof_requires_its_exact_executable_and_journal() -> Result<()> {
        let fixture = PathBuf::from(std::env::var("OPENVM_TOOLS_FIXTURE")?);
        let key: AppProvingKey<SdkVmConfig> = read_object_from_file(fixture.join("keys/app.pk"))?;
        let exe = read_object_from_file(fixture.join("build/proof-binding-fixture.vmexe"))?;
        let prover = AppProver::<DefaultStarkEngine, SdkVmCpuBuilder>::new(
            SdkVmCpuBuilder,
            &key.app_vm_pk,
            Arc::new(exe),
        )?;
        let expected = CommitBytes::from(prover.app_exe_commit());
        let mut proof: ContinuationVmProof<SC> =
            read_object_from_file(fixture.join("fixture.app.proof"))?;
        let journal = fs::read(fixture.join("journal.bin"))?;
        let vk = key.get_app_vk();
        verify_saved_app(&vk, &proof, expected, &journal)?;
        assert!(verify_saved_app(&vk, &proof, CommitBytes::try_new([0; 32])?, &journal,).is_err());
        let wrong_journal = fs::read(fixture.join("wrong-journal.bin"))?;
        assert!(verify_saved_app(&vk, &proof, expected, &wrong_journal).is_err());
        assert!(verify_saved_app(&vk, &proof, expected, &[0; 416]).is_err());
        proof.user_public_values.public_values[0] += F::ONE;
        assert!(verify_saved_app(&vk, &proof, expected, &journal).is_err());
        Ok(())
    }
}
