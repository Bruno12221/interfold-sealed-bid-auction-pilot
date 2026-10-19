#!/usr/bin/env python3
"""Stream the exact public OpenVM v2.0.2 setup to disk; never buffer the 10.2 GB key.

Hashes record downloaded artifact identity, not an independent trusted checksum.
No setup key is deserialized and no proof, transaction or deployment is performed.
Interrupted downloads can be resumed with validated HTTP Content-Range responses.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import time
from urllib.request import Request, urlopen

VERSION = "2.0.2"
BUCKET = "https://openvm-public-artifacts-us-east-1.s3.us-east-1.amazonaws.com"
KZG_BUCKET = "https://axiom-crypto.s3.us-east-1.amazonaws.com/challenge_0085"


def artifacts(small_only):
    prefix = "halo2/src/v2.0-base/"
    for name in ["Halo2Verifier.sol", "OpenVmHalo2Verifier.sol", "verifier.bytecode.json", "interfaces/IOpenVmHalo2Verifier.sol"]:
        yield prefix + name, f"{BUCKET}/v{VERSION}/{prefix}{name}"
    if not small_only:
        for degree in range(10, 25):
            name = f"kzg_bn254_{degree}.srs"
            yield "params/" + name, f"{KZG_BUCKET}/{name}"
        yield "halo2.pk", f"{BUCKET}/v{VERSION}/halo2.pk"


def save(path, report):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(path)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch(root, name, url, report, status):
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    with urlopen(Request(url, method="HEAD"), timeout=30) as response:
        size = int(response.headers["Content-Length"])
        etag = response.headers.get("ETag")
    if not 0 < size <= 11_000_000_000:
        raise ValueError("Unexpected public setup artifact size")
    previous = report["artifacts"].get(name)
    if target.exists():
        if not previous or previous.get("status") != "complete" or previous.get("bytes") != size or previous.get("etag") != etag:
            raise ValueError(f"Existing artifact has no matching completed download record: {name}")
        if target.stat().st_size != size or sha256(target) != previous["sha256"]:
            raise ValueError(f"Existing artifact differs from its recorded digest: {name}")
        return
    partial = target.with_name(target.name + ".part")
    offset = partial.stat().st_size if partial.exists() else 0
    if offset > size or (offset and (not previous or previous.get("etag") != etag or previous.get("bytes") != size)):
        raise ValueError(f"Partial artifact identity changed: {name}")
    entry = {"url": url, "bytes": size, "etag": etag, "downloadedBytes": offset, "status": "downloading"}
    report["artifacts"][name] = entry
    save(status, report)
    if offset < size:
        headers = {"Range": f"bytes={offset}-"} if offset else {}
        if etag:
            headers["If-Match"] = etag
        with urlopen(Request(url, headers=headers), timeout=60) as response:
            if offset and (response.status != 206 or response.headers.get("Content-Range") != f"bytes {offset}-{size-1}/{size}"):
                raise ValueError("Server did not honor the exact resume byte range")
            if not offset and response.status != 200:
                raise ValueError("Unexpected artifact download response")
            last = time.monotonic()
            with partial.open("ab" if partial.exists() else "xb") as stream:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    if stream.tell() + len(chunk) > size:
                        raise ValueError("Artifact exceeds its advertised size")
                    stream.write(chunk)
                    if time.monotonic() - last > 5:
                        entry["downloadedBytes"] = stream.tell()
                        save(status, report)
                        last = time.monotonic()
                stream.flush()
                os.fsync(stream.fileno())
    if partial.stat().st_size != size:
        raise ValueError("Artifact download was truncated")
    digest = sha256(partial)
    partial.replace(target)
    entry.update(status="complete", downloadedBytes=size, sha256=digest)
    save(status, report)
    print(json.dumps({"artifact": name, "bytes": size, "sha256": digest}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--small-only", action="store_true", help="fetch verifier artifacts only, without the large key/SRS")
    args = parser.parse_args()
    os.umask(0o077)
    root = args.directory.resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    status = root / "download-manifest.json"
    report = json.loads(status.read_text()) if status.exists() else {"schemaVersion": 1, "openvmVersion": VERSION, "artifacts": {}}
    if report.get("openvmVersion") != VERSION:
        raise ValueError("Setup directory belongs to another OpenVM version")
    with (root / ".download.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Another download already owns this setup directory") from None
        for name, url in artifacts(args.small_only):
            fetch(root, name, url, report, status)


if __name__ == "__main__":
    main()
