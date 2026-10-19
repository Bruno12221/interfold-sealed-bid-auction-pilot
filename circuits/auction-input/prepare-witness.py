#!/usr/bin/env python3
"""Write private Noir inputs without rounding JSON polynomial coefficients.

The destination directory must be new. Nothing containing the private bid,
randomness, or polynomial witnesses is printed to stdout or stderr.
"""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617
PARAMS_HASH = "0x1b2620f6a5919d5ee19a51f34026369816f479efd0404b56585ad37d31c52317"
WORDS = (
    "chainId", "program", "interfold", "auction", "context", "e3Id",
    "committeePublicKey", "paramsHash", "slot", "bidder", "maxTick",
    "ciphertextHash", "ciphertextCommitment",
)
POLYNOMIALS = ("pk0is", "pk1is", "ct0is", "ct1is", "u", "e0", "e1", "k1", "r", "r_ct1")
REPO_DIR = Path(__file__).resolve().parents[2]


def checked_destination(destination):
    pilot = REPO_DIR / ".pilot"
    destination = Path(os.path.abspath(destination))
    if not destination.is_relative_to(pilot) or destination == pilot:
        raise ValueError("private proof destination must be inside this repository's .pilot")
    # Resolve existing ancestors before writing anything. Reject symlink escapes
    # and symlink aliases, even when an alias happens to point back into .pilot.
    if destination.resolve() != destination:
        raise ValueError("private proof path must not traverse symlinks")
    for ancestor in (destination, *destination.parents):
        if ancestor.exists() and ancestor.is_symlink():
            raise ValueError("private proof path must not traverse symlinks")
        if ancestor == REPO_DIR:
            break
    ignored = subprocess.run(
        ["git", "-C", str(REPO_DIR), "check-ignore", "--no-index", str(destination / "Prover.toml")],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if ignored.returncode != 0:
        raise ValueError("private proof destination must be ignored by git")
    return destination


def integer(value):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError("expected an exact integer encoding")
    if isinstance(value, str):
        return int(value, 16 if value.startswith("0x") else 10)
    return value


def checked_statement(statement):
    if not isinstance(statement, dict) or set(statement) != set(WORDS):
        raise ValueError("statement must contain exactly the thirteen Solidity fields")
    values = [integer(statement[name]) for name in WORDS]
    if any(value < 0 or value >= 1 << 256 for value in values):
        raise ValueError("statement word exceeds uint256")
    for i in (1, 2, 3, 9):
        if values[i] == 0 or values[i] >= 1 << 160:
            raise ValueError("statement address is invalid")
    if values[0] != 11155111 or values[7] != int(PARAMS_HASH, 16):
        raise ValueError("unsupported chain or BFV parameters")
    if values[8] >= 32 or values[10] != 100:
        raise ValueError("unsupported auction slot or bid range")
    if values[6] >= FIELD or values[12] >= FIELD:
        raise ValueError("SAFE commitment is not a canonical field element")
    return values


def coefficients(poly):
    if not isinstance(poly, dict) or set(poly) != {"coefficients"}:
        raise ValueError("invalid polynomial structure")
    values = poly["coefficients"]
    if not isinstance(values, list) or len(values) != 8192:
        raise ValueError("polynomial degree differs from secure8192")
    encoded = [integer(value) for value in values]
    if any(value < 0 or value >= FIELD for value in encoded):
        raise ValueError("noncanonical polynomial field encoding")
    return json.dumps([str(value) for value in encoded], separators=(",", ":"))


def prepare(private_path, statement_path, destination):
    destination = checked_destination(destination)
    private_path = Path(private_path).resolve(strict=True)
    statement_path = Path(statement_path).resolve(strict=True)
    if os.name != "posix" or stat.S_IMODE(private_path.stat().st_mode) & 0o077:
        raise ValueError("private encryption witness must have owner-only permissions")
    private = json.loads(private_path.read_text())
    statement = json.loads(statement_path.read_text())
    values = checked_statement(statement)
    if private.get("schemaVersion") != 1 or private.get("inputProofGenerated") is not False:
        raise ValueError("unsupported private encryption witness schema")
    public = private.get("publicBid", {})
    if integer(private["slot"]) != values[8] or integer(private["maxTick"]) != values[10]:
        raise ValueError("private witness differs from statement")
    for name, source in (("committeePublicKey", "committeePublicKey"),
                         ("ciphertextHash", "ciphertextHash"),
                         ("ciphertextCommitment", "commitment")):
        if integer(statement[name]) != integer(public[source]):
            raise ValueError("public encryption artifact differs from statement")
    bid = integer(private["bid"])
    if not 0 <= bid <= 100:
        raise ValueError("private bid is out of range")
    inputs = private["circuitInputs"]
    if set(inputs) != set(POLYNOMIALS):
        raise ValueError("unexpected encryption witness fields")

    limbs = [str(limb) for value in values for limb in (value >> 128, value & ((1 << 128) - 1))]
    lines = ["statement = " + json.dumps(limbs), f'bid = "{bid}"']
    for name in POLYNOMIALS:
        value = inputs[name]
        if name.endswith("is") or name in ("r", "r_ct1"):
            if not isinstance(value, list) or len(value) != 3:
                raise ValueError("CRT limb count differs from secure8192")
            for poly in value:
                lines.extend(("", f"[[{name}]]", "coefficients = " + coefficients(poly)))
        else:
            lines.extend(("", f"[{name}]", "coefficients = " + coefficients(value)))

    destination.mkdir(mode=0o700)
    destination.chmod(0o700)
    os.umask(0o077)
    target = destination / "Prover.toml"
    with target.open("x") as output:
        output.write("\n".join(lines) + "\n")
        output.flush()
        os.fsync(output.fileno())
    target.chmod(0o600)
    (destination / "statement.json").write_text(json.dumps(statement, indent=2) + "\n")
    (destination / "statement.bin").write_bytes(b"".join(value.to_bytes(32, "big") for value in values))
    (destination / "public-inputs.json").write_text(json.dumps(limbs) + "\n")
    return {"prepared": True, "inputProofGenerated": False, "publicInputCount": len(limbs)}


if __name__ == "__main__":
    try:
        if len(sys.argv) != 4:
            raise ValueError("usage: prepare-witness.py PRIVATE_JSON STATEMENT_JSON NEW_PRIVATE_DIRECTORY")
        print(json.dumps(prepare(*sys.argv[1:])))
    except Exception:
        # Upstream witnesses contain private scalars. Do not interpolate parser
        # errors, exceptions, input values, or command arguments into diagnostics.
        print("Private witness preparation failed; sensitive diagnostics suppressed.", file=sys.stderr)
        sys.exit(1)
