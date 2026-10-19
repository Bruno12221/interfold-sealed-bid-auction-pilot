#!/usr/bin/env python3
"""Configure, run, inspect and return one public OpenVM input-binding proof job."""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parent
REVISION = "59a69b8b0cbee7011ac978e4cc07707ee3681944"
STAGES = ["prove-app", "aggregate-stark", "prove-root", "compress-root", "verify-seal"]

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def fingerprint(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Not a regular file: " + str(path))
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"bytes": path.stat().st_size, "sha256": digest.hexdigest()}

def contained(root, name):
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("Unsafe relative artifact path")
    path = root / relative
    if any(parent.is_symlink() for parent in [path, *path.parents] if parent != root.parent):
        raise ValueError("Symlink artifact path: " + str(path))
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("Artifact escapes its directory")
    return path

def checked_file(root, name, expected):
    path = contained(root, name)
    if fingerprint(path) != expected:
        raise ValueError("Artifact size or SHA-256 differs: " + name)
    return path

def read_json(path):
    if fingerprint(path)["bytes"] > 1024 * 1024:
        raise ValueError("Oversized metadata")
    return json.loads(path.read_text())

def save(path, value):
    temporary = path.with_name(path.name + "." + str(os.getpid()) + ".tmp")
    with temporary.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    with open_directory(path.parent) as directory:
        os.fsync(directory)

class open_directory:
    def __init__(self, path): self.path = path
    def __enter__(self):
        self.fd = os.open(self.path, os.O_RDONLY)
        return self.fd
    def __exit__(self, *args): os.close(self.fd)

def verify_bundle():
    manifest = read_json(ROOT / "bundle-manifest.json")
    if manifest.get("schemaVersion") != 1 or manifest.get("scope") != "public-input-binding-proof-job" or manifest.get("openvmRevision") != REVISION:
        raise ValueError("Unsupported input proof bundle")
    for name, expected in manifest["files"].items():
        checked_file(ROOT, name, expected)
    return manifest

def setup_directory(explicit):
    if explicit is not None:
        return explicit.resolve()
    candidates = {ROOT / "setup", ROOT.parent / "halo2-handoff-20261018" / "setup",
                  ROOT.parent / "Ubuntu-USB-compression" / "halo2-handoff-20261018" / "setup",
                  Path.home() / "Ubuntu-USB-compression" / "halo2-handoff-20261018" / "setup"}
    for parent in [ROOT.parent, Path.home()]:
        candidates.update(list(parent.glob("*/halo2-handoff-20261018/setup"))[:100])
    found = sorted({path.resolve() for path in candidates if (path / "halo2.pk").is_file()})
    if len(found) != 1:
        raise ValueError("Supply --setup EXISTING_SETUP; discovery found " + str(len(found)) + " candidates")
    return found[0]

def expected_config(setup):
    config = read_json(ROOT / "job" / "config.template.json")
    for key in ["app_pk", "executable", "aggregation_pk", "verifier_artifact"]:
        config[key] = str(contained(ROOT, config[key]).resolve())
    config["halo2_pk"] = str(setup / "halo2.pk")
    config["halo2_params_dir"] = str(setup / "params")
    return config

def verify_setup(setup):
    sources = read_json(ROOT / "SETUP-SOURCES.json")
    for name, expected in sources["artifacts"].items():
        checked_file(setup, name, {"bytes": expected["bytes"], "sha256": expected["sha256"]})

def configure(args):
    verify_bundle()
    if args.bundle_only:
        print("Verified the public bundle; no proof was executed.")
        return
    setup = setup_directory(args.setup)
    print("Stream-verifying existing setup: " + str(setup), flush=True)
    verify_setup(setup)
    config = expected_config(setup)
    # Absolute configs are machine-local and deliberately never overwritten.
    with (ROOT / "config.json").open("x") as stream:
        json.dump(config, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    print("Configured verified public setup: " + str(setup))

def canonical_seal(path):
    if fingerprint(path)["bytes"] != 1856:
        raise ValueError("Seal must have exactly 1856 bytes")
    encoded = path.read_bytes()
    if [int.from_bytes(encoded[n:n + 32], "big") for n in [0, 32, 64]] != [1, 64, 1760]:
        raise ValueError("Noncanonical seal ABI header")
    return encoded

def alive(pid):
    if not isinstance(pid, int) or pid <= 0: return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError: return False
    except PermissionError: return True

def process_identity(pid):
    """Linux boot/start identity distinguishes a process from a later reused PID."""
    if sys.platform != "linux" or not isinstance(pid, int) or pid <= 0: return None
    try:
        fields = Path("/proc", str(pid), "stat").read_text().rsplit(")", 1)[1].split()
        return {"bootId": Path("/proc/sys/kernel/random/boot_id").read_text().strip(), "startTimeTicks": fields[19]}
    except (OSError, IndexError): return None

def matching_process(pid, identity):
    if not alive(pid): return False
    if identity is None: return None
    actual = process_identity(pid)
    return None if actual is None else actual == identity

def signal_child(child, signum):
    if child is not None and child.poll() is None:
        try: child.send_signal(signum)
        except ProcessLookupError: pass

def rss_bytes(pid):
    # Linux VmHWM is the worker's own lifetime high-water mark, sampled every 250ms.
    try:
        for line in Path("/proc", str(pid), "status").read_text().splitlines():
            if line.startswith("VmHWM:"): return int(line.split()[1]) * 1024
    except (FileNotFoundError, ProcessLookupError): pass
    return 0

def run_child(command, directory, threads, signature, phase, interruption):
    report = {"schemaVersion": 1, "phase": phase, "status": "running", "startedAt": now(), "startedUnix": time.time(),
              "supervisorPid": os.getpid(), "command": command, "threads": threads, "signature": signature,
              "workerPid": None, "peakWorkerRssBytes": 0, "nativeAndLocalEvmVerified": False}
    path = directory / "timing.json"
    started = time.monotonic()
    child = None
    error = None
    code = None
    previous = {}
    def interrupted(signum, frame):
        if interruption["signal"] is None:
            interruption.update(signal=signum, monotonic=time.monotonic())
            report.update(requestedSignal=signal.Signals(signum).name, interruptedAt=now())
        signal_child(child, signum)
    try:
        previous = {n: signal.signal(n, interrupted) for n in [signal.SIGINT, signal.SIGTERM]}
        save(path, report)
        with (directory / "worker.log").open("x") as log:
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                     env={**os.environ, "RAYON_NUM_THREADS": str(threads)})
            report["workerPid"] = child.pid
            report["workerProcessIdentity"] = process_identity(child.pid)
            if interruption["signal"] is not None: signal_child(child, interruption["signal"])
            save(path, report)
            term_sent = False
            while child.poll() is None:
                report["peakWorkerRssBytes"] = max(report["peakWorkerRssBytes"], rss_bytes(child.pid))
                if interruption["signal"] is not None:
                    elapsed = time.monotonic() - interruption["monotonic"]
                    if elapsed >= 5 and not term_sent:
                        signal_child(child, signal.SIGTERM); term_sent = True
                    if elapsed >= 10: signal_child(child, signal.SIGKILL)
                time.sleep(0.25)
            code = child.wait()
    except Exception as caught:
        error = caught
    finally:
        if child is not None and child.poll() is None:
            signal_child(child, signal.SIGTERM)
            try: code = child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                signal_child(child, signal.SIGKILL)
                code = child.wait(timeout=5)
        report.update(finishedAt=now(), elapsedSeconds=time.monotonic() - started, exitCode=code,
                      status="interrupted" if interruption["signal"] is not None else "worker-exited" if code == 0 and error is None else "failed")
        if sys.platform == "darwin":
            report["peakWorkerRssBytes"] = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
            report["rssMeasurement"] = "Darwin cumulative child high-water mark"
        else: report["rssMeasurement"] = "Linux worker VmHWM sampled every 250ms; short-lived peaks may be missed"
        if error is not None: report.update(errorType=type(error).__name__, error=str(error))
        try: save(path, report)
        finally:
            for n, handler in previous.items(): signal.signal(n, handler)
    if interruption["signal"] is not None: raise InterruptedError("Interrupted owned proof worker")
    if error is not None: raise error
    if code != 0: raise RuntimeError("Worker failed with exit code " + str(code))
    return report

def stage_outputs(phase, directory, config, journal_digest):
    artifacts = {name: fingerprint(Path(config[name]))["sha256"] for name in ["app_pk", "executable", "aggregation_pk", "verifier_artifact"]}
    if phase == "prove-app":
        names = ["app.proof", "app.proof.manifest.json"]
        manifest = read_json(directory / "app.proof.manifest.json")
        proof = fingerprint(directory / "app.proof")
        sources = {"config_sha256": fingerprint(ROOT / "config.json")["sha256"],
                   "input_sha256": fingerprint(ROOT / "job" / "input.bin")["sha256"],
                   "journal_sha256": journal_digest, "config_artifacts": artifacts}
        if manifest.get("schema_version") != 1 or manifest.get("openvm_version") != "v2.0" or manifest.get("openvm_revision") != REVISION \
                or manifest.get("stage") != phase or manifest.get("proof_format") != "openvm-sdk-bitcode-ContinuationVmProof<SC>" \
                or manifest.get("app_commit") != config["app_commit"] or manifest.get("journal_bytes") != 416 \
                or manifest.get("sources") != sources or manifest.get("proof_sha256") != proof["sha256"] or manifest.get("proof_bytes") != proof["bytes"]:
            raise ValueError("Application proof source metadata differs")
    elif phase in ["aggregate-stark", "prove-root"]:
        expected = ["aggregate.json", "metadata.bin"] if phase == "aggregate-stark" else ["root.bin"]
        checkpoint = read_json(directory / "checkpoint" / "manifest.json")
        if checkpoint.get("schema_version") != 1 or checkpoint.get("openvm_version") != "v2.0" or checkpoint.get("openvm_revision") != REVISION \
                or checkpoint.get("stage") != phase or checkpoint.get("app_commit") != config["app_commit"] \
                or checkpoint.get("journal_sha256") != journal_digest or checkpoint.get("journal_bytes") != 416 \
                or checkpoint.get("config_artifacts") != artifacts \
                or sorted(checkpoint.get("files", {})) != sorted(expected):
            raise ValueError("Checkpoint metadata differs")
        for name in expected:
            if fingerprint(directory / "checkpoint" / name)["sha256"] != checkpoint["files"][name]:
                raise ValueError("Checkpoint digest differs")
        names = ["checkpoint/manifest.json", *["checkpoint/" + name for name in expected]]
    else:
        name = "seal.bin" if phase == "compress-root" else "checked.seal"
        canonical_seal(directory / name)
        names = [name] + (["proof.json"] if phase == "verify-seal" else [])
    outputs = {str((directory / name).relative_to(ROOT)): fingerprint(directory / name) for name in names}
    if any(row["bytes"] == 0 for row in outputs.values()): raise ValueError("Empty stage output")
    return outputs

def validate_completed(state, signature, config):
    stages = state.get("stages")
    if not isinstance(stages, dict) or set(stages) != set(STAGES[:len(stages)]):
        raise ValueError("Incomplete stage prefix")
    for phase, completed in stages.items():
        if completed.get("status") != "complete": raise ValueError("Invalid completed stage state")
        timing_name = completed.get("timing", "")
        if not re.fullmatch(r"results/attempts/[0-9]{4,}-" + re.escape(phase) + r"/timing.json", timing_name):
            raise ValueError("Invalid completed stage timing path")
        timing_path = contained(ROOT, timing_name)
        directory = timing_path.parent
        primary_name = {"prove-app": "app.proof", "aggregate-stark": "checkpoint", "prove-root": "checkpoint",
                        "compress-root": "seal.bin", "verify-seal": "checked.seal"}[phase]
        expected_primary = str((directory / primary_name).relative_to(ROOT))
        if completed.get("primary") != expected_primary:
            raise ValueError("Completed stage primary differs from its exact contained output")
        contained(ROOT, expected_primary)
        expected_outputs = stage_outputs(phase, directory, config, signature["journal"]["sha256"])
        if completed.get("outputs") != expected_outputs: raise ValueError("Completed stage output fingerprints differ")
        timing = read_json(timing_path)
        if timing.get("phase") != phase or timing.get("status") != "complete" or timing.get("signature") != signature \
                or timing.get("outputs") != expected_outputs:
            raise ValueError("Completed timing provenance differs")

def job_signature(manifest, config_path, worker):
    return {"bundleManifest": fingerprint(ROOT / "bundle-manifest.json"), "worker": fingerprint(worker),
            "config": fingerprint(config_path), "input": manifest["files"]["job/input.bin"],
            "journal": manifest["files"]["job/journal.bin"]}

def run(args):
    if not 1 <= args.threads <= 256: raise ValueError("Invalid thread count")
    manifest = verify_bundle()
    config_path = ROOT / "config.json"
    config = read_json(config_path)
    setup = Path(config["halo2_pk"]).parent
    if config != expected_config(setup): raise ValueError("Config differs from the verified template")
    print("Stream-verifying setup before proof stages", flush=True)
    verify_setup(setup)
    worker = ROOT / "target" / "release" / "interfold-openvm-prover"
    signature = job_signature(manifest, config_path, worker)
    results = ROOT / "results"
    results.mkdir(exist_ok=True)
    with (results / ".run.lock").open("a") as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise ValueError("Another proof runner owns this job") from None
        state_path = results / "state.json"
        if state_path.exists():
            if not args.resume: raise ValueError("Existing results require --resume; artifacts are never overwritten")
            state = read_json(state_path)
            if state.get("signature") != signature: raise ValueError("Resume source/input/journal/config/worker fingerprints differ")
        else:
            if args.resume: raise ValueError("No saved job to resume")
            state = {"schemaVersion": 1, "scope": manifest["scope"], "signature": signature,
                     "startedAt": now(), "status": "running", "stages": {}, "attempts": 0,
                     "nativeAndLocalEvmVerified": False, "liveAuctionProof": False}
        validate_completed(state, signature, config)
        if not isinstance(state.get("attempts"), int) or state["attempts"] < 0: raise ValueError("Invalid attempt counter")
        state.update(status="running", supervisorPid=os.getpid(), resumedAt=now() if args.resume else None,
                     supervisorProcessIdentity=process_identity(os.getpid()), nativeAndLocalEvmVerified=False)
        for key in ["error", "errorType", "finishedAt", "sealSha256"]: state.pop(key, None)
        save(state_path, state)
        interruption = {"signal": None, "monotonic": None}
        def between_stages(signum, frame):
            if interruption["signal"] is None:
                interruption.update(signal=signum, monotonic=time.monotonic())
                raise InterruptedError("Interrupted between owned proof stages")
        handlers = {n: signal.signal(n, between_stages) for n in [signal.SIGINT, signal.SIGTERM]}
        try:
            for phase in STAGES:
                if phase in state["stages"] and phase != "verify-seal": continue
                # A completed final seal is cheaply reverified in a fresh output path.
                while True:
                    state["attempts"] += 1
                    # Reserve durably before mkdir; skip an orphan after hard interruption.
                    save(state_path, state)
                    directory = results / "attempts" / (str(state["attempts"]).zfill(4) + "-" + phase)
                    try:
                        directory.mkdir(parents=True, exist_ok=False)
                        break
                    except FileExistsError:
                        pass
                journal = ROOT / "job" / "journal.bin"
                if phase == "prove-app": source, target = ROOT / "job" / "input.bin", directory / "app.proof"
                elif phase == "aggregate-stark": source, target = ROOT / state["stages"]["prove-app"]["primary"], directory / "checkpoint"
                elif phase == "prove-root": source, target = ROOT / state["stages"]["aggregate-stark"]["primary"], directory / "checkpoint"
                elif phase == "compress-root": source, target = ROOT / state["stages"]["prove-root"]["primary"], directory / "seal.bin"
                else:
                    encoded = canonical_seal(ROOT / state["stages"]["compress-root"]["primary"])
                    proof = {"version": "v2.0", **config["app_commit"], "user_public_values": "0x" + signature["journal"]["sha256"],
                             "proof_data": {"accumulator": "0x" + encoded[96:480].hex(), "proof": "0x" + encoded[480:].hex()}}
                    source, target = directory / "proof.json", directory / "checked.seal"
                    with source.open("x") as stream: json.dump(proof, stream)
                command = [str(worker), "verify" if phase == "verify-seal" else phase, str(config_path), str(source), str(journal), str(target)]
                state.update(currentPhase=phase, currentAttempt=str(directory.relative_to(ROOT)), currentPhaseStartedAt=now())
                save(state_path, state)
                report = run_child(command, directory, args.threads, signature, phase, interruption)
                verify_bundle()
                if fingerprint(worker) != signature["worker"] or fingerprint(config_path) != signature["config"]:
                    raise ValueError("Worker or config changed during proof stage")
                outputs = stage_outputs(phase, directory, config, signature["journal"]["sha256"])
                if phase == "verify-seal" and target.read_bytes() != encoded: raise ValueError("Independent verification changed the seal")
                report.update(status="complete", outputs=outputs, nativeAndLocalEvmVerified=phase in ["compress-root", "verify-seal"])
                save(directory / "timing.json", report)
                state["stages"][phase] = {"status": "complete", "primary": str(target.relative_to(ROOT)),
                                          "outputs": outputs, "timing": str((directory / "timing.json").relative_to(ROOT))}
                if phase in ["aggregate-stark", "prove-root", "compress-root"]:
                    predecessor = STAGES[STAGES.index(phase) - 1]
                    state["stages"][predecessor]["cryptographicallyRevalidatedByNextStage"] = phase
                save(state_path, state)
            state.update(status="complete", finishedAt=now(), currentPhase=None, nativeAndLocalEvmVerified=True,
                         sealSha256=fingerprint(ROOT / state["stages"]["compress-root"]["primary"])["sha256"])
            save(state_path, state)
        except BaseException as error:
            state.update(status="interrupted" if interruption["signal"] is not None else "failed", finishedAt=now(),
                         nativeAndLocalEvmVerified=False, errorType=type(error).__name__, error=str(error))
            save(state_path, state)
            if interruption["signal"] is not None: raise SystemExit(128 + interruption["signal"])
            raise
        finally:
            for n, handler in handlers.items(): signal.signal(n, handler)
    print(json.dumps(state, indent=2))

def status(args):
    state = read_json(ROOT / "results" / "state.json")
    supervisor_alive = matching_process(state.get("supervisorPid"), state.get("supervisorProcessIdentity"))
    result = {"status": state["status"], "phase": state.get("currentPhase"), "completedStages": list(state["stages"]),
              "supervisorPid": state.get("supervisorPid"), "supervisorAlive": supervisor_alive, "eta": None}
    attempt = state.get("currentAttempt")
    if attempt:
        report_path = contained(ROOT, attempt) / "timing.json"
        if report_path.exists():
            report = read_json(report_path)
            worker_alive = matching_process(report.get("workerPid"), report.get("workerProcessIdentity"))
            running_observed = report["status"] == "running" and supervisor_alive is True and worker_alive is True
            result.update(workerPid=report.get("workerPid"), workerAlive=worker_alive,
                          phaseElapsedSeconds=max(0, time.time() - report["startedUnix"]) if running_observed else report.get("elapsedSeconds"),
                          phaseStartedAt=report["startedAt"])
            if state["status"] == "running" and (supervisor_alive is not True or (report["status"] == "running" and worker_alive is not True)):
                result.update(status="stale-or-unconfirmed-running-state", finishTimeUnknown=True,
                              livenessExplanation="A saved running label is not evidence of a current matching process.")
    print(json.dumps(result, indent=2))

def archive(args):
    with (ROOT / "results" / ".run.lock").open("a") as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise ValueError("Proof runner owns this job; cannot archive concurrently") from None
        archive_locked(args)

def archive_locked(args):
    manifest = verify_bundle()
    state = read_json(ROOT / "results" / "state.json")
    if state.get("status") != "complete" or state.get("nativeAndLocalEvmVerified") is not True:
        raise ValueError("A completed independently verified seal is required")
    config_path = ROOT / "config.json"
    config = read_json(config_path)
    signature = job_signature(manifest, config_path, ROOT / "target" / "release" / "interfold-openvm-prover")
    if state.get("signature") != signature or config != expected_config(Path(config["halo2_pk"]).parent):
        raise ValueError("Archive source/config/worker fingerprints differ")
    validate_completed(state, signature, config)
    target = (args.output or ROOT.parent / "interfold-input-proof-results.tar.gz").resolve()
    with target.open("xb") as stream:
        with tarfile.open(fileobj=stream, mode="w:gz") as tar:
            names = ["bundle-manifest.json", "SETUP-SOURCES.json", "config.json", "job/statement.json", "job/journal.bin",
                     "job/identity.json", "results/state.json"]
            for stage in state["stages"].values(): names.extend([stage["timing"], *stage["outputs"]])
            # Include logs for all attempts, including interrupted work, using a bounded fixed depth.
            for filename in ["worker.log", "timing.json"]:
                names.extend(str(path.relative_to(ROOT)) for path in (ROOT / "results" / "attempts").glob("*/" + filename))
            names.extend(name for name in ["build.log", "host-info.txt"] if (ROOT / name).exists())
            for name in sorted(set(names)):
                path = contained(ROOT, name)
                fingerprint(path)
                tar.add(path, arcname=name, recursive=False)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({"path": str(target), **fingerprint(target)}, indent=2))

def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    conf = commands.add_parser("configure"); conf.add_argument("--setup", type=Path); conf.add_argument("--bundle-only", action="store_true")
    runner = commands.add_parser("run"); runner.add_argument("--threads", type=int, default=4); runner.add_argument("--resume", action="store_true")
    commands.add_parser("status")
    archiver = commands.add_parser("archive"); archiver.add_argument("--output", type=Path)
    args = parser.parse_args()
    {"configure": configure, "run": run, "status": status, "archive": archive}[args.action](args)

if __name__ == "__main__":
    main()
