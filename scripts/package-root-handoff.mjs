import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { copyFile, lstat, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const OPENVM_REVISION = '59a69b8b0cbee7011ac978e4cc07707ee3681944';
const OPENVM_BUCKET = 'https://openvm-public-artifacts-us-east-1.s3.us-east-1.amazonaws.com/v2.0.2';
const KZG_BUCKET = 'https://axiom-crypto.s3.us-east-1.amazonaws.com/challenge_0085';
const WORKER_FILES = ['Cargo.toml', 'Cargo.lock', 'LICENSE.md', 'NOTICE.md', 'README.md', 'fetch-setup.py', 'src/main.rs'];
const COMMIT_FIELDS = ['app_exe_commit', 'app_vm_commit'];
const ARTIFACT_FIELDS = ['app_pk', 'executable', 'aggregation_pk', 'verifier_artifact'];
const CONFIG_FIELDS = [...ARTIFACT_FIELDS, 'halo2_pk', 'halo2_params_dir', 'verifier_sha256', 'app_commit', 'segment_memory_bytes'];
const MANIFEST_FIELDS = ['schema_version', 'openvm_version', 'openvm_revision', 'stage', 'app_commit', 'journal_sha256', 'journal_bytes', 'config_artifacts', 'files'];

function exactFields(value, fields, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) {
    throw new Error(`Unexpected ${label} fields; refusing to copy unknown data`);
  }
}

function digest(value) { return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value); }
function commitment(value) { return typeof value === 'string' && /^0x[0-9a-f]{64}$/.test(value); }
function checkCommit(value) {
  exactFields(value, COMMIT_FIELDS, 'application identity');
  if (!COMMIT_FIELDS.every(field => commitment(value[field]))) throw new Error('Invalid application identity');
}

function sameCommit(left, right) { return COMMIT_FIELDS.every(field => left[field] === right[field]); }

async function fingerprint(path, maxBytes = 64 * 1024 * 1024) {
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink() || info.size > maxBytes) throw new Error(`Not a bounded regular public file: ${path}`);
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return { bytes: info.size, sha256: hash.digest('hex') };
}

async function json(path) {
  await fingerprint(path, 64 * 1024);
  return JSON.parse(await readFile(path, 'utf8'));
}

export function setupArtifactUrls() {
  const prefix = 'halo2/src/v2.0-base/';
  const result = Object.fromEntries(['Halo2Verifier.sol', 'OpenVmHalo2Verifier.sol', 'verifier.bytecode.json', 'interfaces/IOpenVmHalo2Verifier.sol']
    .map(name => [prefix + name, `${OPENVM_BUCKET}/${prefix}${name}`]));
  for (let degree = 10; degree <= 24; degree++) result[`params/kzg_bn254_${degree}.srs`] = `${KZG_BUCKET}/kzg_bn254_${degree}.srs`;
  result['halo2.pk'] = `${OPENVM_BUCKET}/halo2.pk`;
  return result;
}

function setupManifest(source) {
  if (source.schemaVersion !== 1 || source.openvmVersion !== '2.0.2') throw new Error('Wrong setup manifest version');
  const urls = setupArtifactUrls();
  exactFields(source.artifacts, Object.keys(urls), 'setup artifact list');
  return {
    schemaVersion: 1, openvmVersion: '2.0.2',
    checksumProvenance: 'SHA-256 of the locally downloaded public artifacts, not an independently authenticated upstream checksum.',
    artifacts: Object.fromEntries(Object.entries(urls).map(([name, url]) => {
      const value = source.artifacts[name];
      if (value?.url !== url || value.status !== 'complete' || !digest(value.sha256)
        || !Number.isSafeInteger(value.bytes) || value.bytes <= 0 || value.bytes > 11_000_000_000) {
        throw new Error(`Incomplete or unexpected public setup artifact: ${name}`);
      }
      return [name, { url, bytes: value.bytes, sha256: value.sha256 }];
    })),
  };
}

async function validateJob(job, expectedVerifier) {
  if (!/^[a-z][a-z0-9-]{0,31}$/.test(job.name)) throw new Error('Invalid public job name');
  const config = await json(job.config);
  exactFields(config, CONFIG_FIELDS, 'worker configuration');
  checkCommit(config.app_commit);
  if (!Number.isSafeInteger(config.segment_memory_bytes) || config.segment_memory_bytes <= 0) throw new Error('Invalid segment memory bound');
  const manifest = await json(join(job.root, 'manifest.json'));
  exactFields(manifest, MANIFEST_FIELDS, 'root checkpoint manifest');
  checkCommit(manifest.app_commit);
  exactFields(manifest.config_artifacts, ARTIFACT_FIELDS, 'checkpoint artifact digests');
  exactFields(manifest.files, ['root.bin'], 'root checkpoint file list');
  if (manifest.schema_version !== 1 || manifest.openvm_version !== 'v2.0' || manifest.openvm_revision !== OPENVM_REVISION
    || manifest.stage !== 'prove-root' || !sameCommit(manifest.app_commit, config.app_commit)
    || ![288, 416].includes(manifest.journal_bytes) || !digest(manifest.journal_sha256)
    || !digest(manifest.files['root.bin'])) throw new Error('Root checkpoint provenance or identity differs');
  const identity = await json(job.identity);
  exactFields(identity, ['app_commit'], 'prepared identity');
  checkCommit(identity.app_commit);
  if (!sameCommit(identity.app_commit, config.app_commit)) throw new Error('Prepared identity differs');
  const journal = await fingerprint(job.journal, 416);
  if (journal.bytes !== manifest.journal_bytes || journal.sha256 !== manifest.journal_sha256) throw new Error('Checkpoint journal differs');
  const root = await fingerprint(join(job.root, 'root.bin'));
  if (root.sha256 !== manifest.files['root.bin']) throw new Error('Root checkpoint file digest differs');
  for (const field of ARTIFACT_FIELDS) {
    const actual = await fingerprint(config[field]);
    if (!digest(manifest.config_artifacts[field]) || actual.sha256 !== manifest.config_artifacts[field]) {
      throw new Error(`Checkpoint configuration artifact differs: ${field}`);
    }
  }
  if (config.verifier_sha256 !== expectedVerifier || manifest.config_artifacts.verifier_artifact !== expectedVerifier) {
    throw new Error('Verifier differs from the recorded public setup');
  }
  return { job, config, manifest };
}

// The bundle contains a fixed file allowlist. This program never traverses source
// directories, reads raw application inputs, or copies an original absolute config.
export async function packageRootHandoff({ output, jobs, worker, setupDownloadManifest, instructions }) {
  if (!Array.isArray(jobs) || jobs.length === 0 || new Set(jobs.map(job => job.name)).size !== jobs.length) throw new Error('Jobs must have unique names');
  const setup = setupManifest(await json(setupDownloadManifest));
  const checked = [];
  for (const job of jobs) checked.push(await validateJob(job, setup.artifacts['halo2/src/v2.0-base/verifier.bytecode.json'].sha256));
  output = resolve(output);
  await mkdir(output, { mode: 0o700 }); // New directory only; never replace a handoff.
  const files = {};
  async function put(name, content, source = null) {
    const target = join(output, name);
    await mkdir(dirname(target), { recursive: true, mode: 0o700 });
    if (source) {
      await fingerprint(source);
      await copyFile(source, target, 1); // COPYFILE_EXCL, retain exact public artifact bytes.
    } else await writeFile(target, content, { flag: 'wx', mode: 0o600 });
    files[name] = await fingerprint(target);
  }
  for (const name of WORKER_FILES) await put(`worker/${name}`, null, join(worker, name));
  await put('SETUP-SOURCES.json', JSON.stringify(setup, null, 2) + '\n');
  await put('configure.py', CONFIGURE_SCRIPT);
  await put('run-compression.py', RUN_SCRIPT);
  await put('README.md', instructions ? await readFile(instructions) : BUNDLE_README);
  const publicJobs = [];
  for (const { job, config, manifest } of checked) {
    const prefix = `jobs/${job.name}`;
    const copied = { app_pk: 'app.pk', executable: 'guest.vmexe', aggregation_pk: 'aggregation.pk', verifier_artifact: 'verifier.bytecode.json' };
    for (const [field, name] of Object.entries(copied)) {
      await put(`${prefix}/${name}`, null, config[field]);
      if (files[`${prefix}/${name}`].sha256 !== manifest.config_artifacts[field]) throw new Error('Source artifact changed while packaging');
    }
    await put(`${prefix}/journal.bin`, null, job.journal);
    await put(`${prefix}/identity.json`, null, job.identity);
    await put(`${prefix}/root/manifest.json`, null, join(job.root, 'manifest.json'));
    await put(`${prefix}/root/root.bin`, null, join(job.root, 'root.bin'));
    if (files[`${prefix}/root/root.bin`].sha256 !== manifest.files['root.bin']
      || files[`${prefix}/journal.bin`].sha256 !== manifest.journal_sha256) throw new Error('Checkpoint changed while packaging');
    const template = {
      ...Object.fromEntries(Object.entries(copied).map(([field, name]) => [field, `${prefix}/${name}`])),
      halo2_pk: '@SETUP@/halo2.pk', halo2_params_dir: '@SETUP@/params',
      verifier_sha256: config.verifier_sha256, app_commit: config.app_commit, segment_memory_bytes: config.segment_memory_bytes,
    };
    await put(`${prefix}/config.template.json`, JSON.stringify(template, null, 2) + '\n');
    publicJobs.push({ name: job.name, app_commit: config.app_commit, journalBytes: manifest.journal_bytes, journalSha256: manifest.journal_sha256 });
  }
  const bundle = {
    schemaVersion: 1, createdAt: new Date().toISOString(), openvmVersion: '2.0.2', openvmRevision: OPENVM_REVISION,
    interfoldRevision: 'c65722fcab24b3b5ffc7ccaf4544bd1d6ef8826a',
    scope: 'Public-only verified root checkpoints for final Halo2 compression; no wallet, encryption witness, raw application input, or decryption material.',
    validation: 'File hashes and checkpoint metadata checked while packaging. The worker must independently verify each native root STARK and final EVM proof.',
    jobs: publicJobs, files,
  };
  await writeFile(join(output, 'bundle-manifest.json'), JSON.stringify(bundle, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return { output, files: Object.keys(files).length + 1, bytes: Object.values(files).reduce((sum, file) => sum + file.bytes, 0) + (await lstat(join(output, 'bundle-manifest.json'))).size, jobs: publicJobs };
}

const CONFIGURE_SCRIPT = `#!/usr/bin/env python3
"""Verify the complete bundle/setup and write portable absolute worker configs."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def checked_file(root, name, expected):
    path = root / name
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("Not a regular contained artifact: " + name)
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    if path.stat().st_size != expected["bytes"] or value.hexdigest() != expected["sha256"]:
        raise ValueError("Artifact size or SHA-256 differs: " + name)

def verify_bundle():
    manifest = json.loads((ROOT / "bundle-manifest.json").read_text())
    if manifest["schemaVersion"] != 1:
        raise ValueError("Unsupported handoff schema")
    for name, expected in manifest["files"].items():
        checked_file(ROOT, name, expected)
    return manifest

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--setup", type=Path, default=ROOT / "setup")
    parser.add_argument("--bundle-only", action="store_true")
    args = parser.parse_args()
    manifest = verify_bundle()
    if args.bundle_only:
        print("Verified all public handoff file hashes; no proof was executed.")
        return
    setup = args.setup.resolve()
    sources = json.loads((ROOT / "SETUP-SOURCES.json").read_text())
    for name, expected in sources["artifacts"].items():
        checked_file(setup, name, expected)
    configs = ROOT / "config"
    configs.mkdir(exist_ok=True)
    for job in manifest["jobs"]:
        name = job["name"]
        config = json.loads((ROOT / "jobs" / name / "config.template.json").read_text())
        for key in ["app_pk", "executable", "aggregation_pk", "verifier_artifact"]:
            config[key] = str((ROOT / config[key]).resolve())
        config["halo2_pk"] = str(setup / "halo2.pk")
        config["halo2_params_dir"] = str(setup / "params")
        target = configs / (name + ".json")
        with target.open("x") as stream:
            json.dump(config, stream, indent=2)
            stream.write("\\n")
        print("Wrote verified absolute config: " + str(target))

if __name__ == "__main__":
    main()
`;

const RUN_SCRIPT = `#!/usr/bin/env python3
"""Compress one verified public checkpoint and record runtime/resource results."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time
from configure import ROOT, verify_bundle

STOP_GRACE_SECONDS = 5.0

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def save_report(path, report):
    temporary = path.with_name(path.name + "." + str(os.getpid()) + ".tmp")
    with temporary.open("w") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)

def send_owned(child, signum):
    if child is not None and child.poll() is None:
        try:
            child.send_signal(signum)
        except ProcessLookupError:
            pass

def reap_owned(child, interruption, stop=False):
    """Only signal/reap this Popen child; never address unrelated process IDs."""
    forced_at = None
    if stop and interruption["signal"] is None and child.poll() is None:
        forced_at = time.monotonic()
        send_owned(child, signal.SIGTERM)
    term_sent = forced_at is not None or interruption["signal"] == signal.SIGTERM
    kill_sent_at = None
    while child.poll() is None:
        interrupted_at = interruption["monotonic"]
        stopping_at = interrupted_at if interrupted_at is not None else forced_at
        if stopping_at is not None:
            elapsed = time.monotonic() - stopping_at
            if not term_sent and elapsed >= STOP_GRACE_SECONDS:
                send_owned(child, signal.SIGTERM)
                term_sent = True
            kill_after = STOP_GRACE_SECONDS if forced_at is not None else 2 * STOP_GRACE_SECONDS
            if kill_sent_at is None and elapsed >= kill_after:
                send_owned(child, signal.SIGKILL)
                kill_sent_at = time.monotonic()
            if kill_sent_at is not None and time.monotonic() - kill_sent_at > STOP_GRACE_SECONDS:
                raise RuntimeError("Owned child did not become reapable after SIGKILL")
        try:
            child.wait(timeout=0.1)
        except subprocess.TimeoutExpired:
            pass
    return child.wait()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("job", choices=["binding", "compute"])
    parser.add_argument("--threads", type=int, default=4)
    args = parser.parse_args()
    if not 1 <= args.threads <= 256:
        raise ValueError("Invalid thread count")
    manifest = verify_bundle()
    if args.job not in [job["name"] for job in manifest["jobs"]]:
        raise ValueError("The selected job is absent from the verified bundle")
    output = ROOT / "results" / args.job
    output.mkdir(parents=True, exist_ok=False)
    worker = ROOT / "target" / "release" / "interfold-openvm-prover"
    command = [str(worker), "compress-root", str(ROOT / "config" / (args.job + ".json")),
               str(ROOT / "jobs" / args.job / "root"), str(ROOT / "jobs" / args.job / "journal.bin"), str(output / "seal.bin")]
    report = {"schemaVersion": 1, "job": args.job, "startedAt": now(), "command": command, "threads": args.threads,
              "status": "running", "scope": "native-root-verification-and-Halo2-compression-with-final-local-EVM-verification"}
    report_path = output / "timing.json"
    started = time.monotonic()
    exit_code = None
    child = None
    interruption = {"signal": None, "monotonic": None}

    def interrupted(signum, frame):
        if interruption["signal"] is None:
            interruption.update(signal=signum, monotonic=time.monotonic())
            report.update(requestedSignal=signal.Signals(signum).name, interruptedAt=now())
        send_owned(child, signum)

    handlers = {signum: signal.signal(signum, interrupted) for signum in [signal.SIGINT, signal.SIGTERM]}
    try:
        save_report(report_path, report)
        report["workerSha256"] = sha256_file(worker)
        report["workerBytes"] = worker.stat().st_size
        if interruption["signal"] is None:
            with (output / "worker.log").open("x") as log:
                child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                         env={**os.environ, "RAYON_NUM_THREADS": str(args.threads)})
                report["workerPid"] = child.pid
                # A signal arriving during Popen can precede assignment to child.
                if interruption["signal"] is not None:
                    send_owned(child, interruption["signal"])
                save_report(report_path, report)
                exit_code = reap_owned(child, interruption)
    except Exception as error:
        report.update(errorType=type(error).__name__, error=str(error))
    finally:
        if child is not None:
            try:
                exit_code = reap_owned(child, interruption, stop=True)
            except Exception as error:
                report.update(cleanupErrorType=type(error).__name__, cleanupError=str(error))
        seal = output / "seal.bin"
        encoded = None
        try:
            encoded = seal.read_bytes() if seal.is_file() and seal.stat().st_size == 1856 else None
        except OSError as error:
            report.update(errorType=type(error).__name__, error=str(error))
        canonical = encoded is not None and [int.from_bytes(encoded[n:n + 32], "big") for n in [0, 32, 64]] == [1, 64, 1760]
        was_interrupted = interruption["signal"] is not None
        verified = exit_code == 0 and canonical and not was_interrupted and "error" not in report and "cleanupError" not in report
        report.update(finishedAt=now(), elapsedSeconds=time.monotonic() - started, exitCode=exit_code,
                      status="interrupted" if was_interrupted else "complete" if verified else "failed",
                      nativeAndLocalEvmVerified=verified, canonicalSealEncoding=canonical,
                      peakWorkerRssBytes=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * (1 if sys.platform == "darwin" else 1024))
        if verified:
            report.update(sealBytes=len(encoded), sealSha256=hashlib.sha256(encoded).hexdigest())
        try:
            save_report(report_path, report)
        except OSError as error:
            report.update(reportPersistenceError=str(error),
                          status="interrupted" if interruption["signal"] is not None else "failed",
                          nativeAndLocalEvmVerified=False)
            report.pop("sealBytes", None)
            report.pop("sealSha256", None)
            verified = False
        for signum, previous in handlers.items():
            signal.signal(signum, previous)
    print(json.dumps(report, indent=2))
    if interruption["signal"] is not None:
        raise SystemExit(128 + interruption["signal"])
    if not verified:
        raise SystemExit(exit_code if exit_code is not None and exit_code > 0 else 1)

if __name__ == "__main__":
    main()
`;

const BUNDLE_README = `# Public OpenVM root compression handoff

See the repository document docs/ROOT-COMPRESSION-HANDOFF.md for provenance and the full procedure.
Verify with python3 configure.py --bundle-only; fetch setup with python3 worker/fetch-setup.py setup;
then run python3 configure.py. Build with cargo build --locked --release --manifest-path worker/Cargo.toml
--target-dir target, and compress sequentially with python3 run-compression.py binding followed by
python3 run-compression.py compute. No wallet or application input is required.
`;

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
  const output = process.argv[2];
  if (!output || process.argv.length !== 3) throw new Error('Usage: node scripts/package-root-handoff.mjs NEW_OUTPUT_DIRECTORY');
  const jobs = [
    { name: 'binding', config: join(root, '.pilot/receipt-configs/binding.json'), root: join(root, '.pilot/receipt-checkpoints/binding-root-20261017'), identity: join(root, '.pilot/prepared-binding/identity.json'), journal: join(root, '.pilot/input-binding/bundle-v2/statement.bin') },
    { name: 'compute', config: join(root, '.pilot/receipt-configs/compute.json'), root: join(root, '.pilot/receipt-checkpoints/compute-root-20261017'), identity: join(root, '.pilot/prepared-compute/identity.json'), journal: join(root, 'pilot/auction-compute/artifacts/fixture-openvm/journal.bin') },
  ];
  console.log(JSON.stringify(await packageRootHandoff({ output, jobs, worker: join(root, 'pilot/openvm-prover'), setupDownloadManifest: join(root, '.tools/openvm-setup/download-manifest.json'), instructions: join(root, 'docs/ROOT-COMPRESSION-HANDOFF.md') }), null, 2));
}
