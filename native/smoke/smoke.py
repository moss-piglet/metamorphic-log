#!/usr/bin/env python3
"""Round-trip smoke test for the Python (UniFFI) verification bindings.

Drives the generated `metamorphic_log` module against locked KAT vectors
(`native/smoke/vectors.json` + `tests/vectors/hybrid_kat_note.b64`, the same
vectors the native Rust and WASM suites verify) to prove the Python personality
reproduces real verifications byte-for-byte, and rejects tampered / untrusted
input via the typed `VerifyError`.

Verification-only: no secret key material crosses the FFI boundary.

Usage (from the repo root):

    PYTHONPATH=bindings/python \
    DYLD_LIBRARY_PATH=target/debug LD_LIBRARY_PATH=target/debug \
    python3 native/smoke/smoke.py

The CI job wires the library + binding search paths; this script only imports
`metamorphic_log` and asserts behaviour.
"""

import base64
import json
import pathlib
import sys

import metamorphic_log as ml

ROOT = pathlib.Path(__file__).resolve().parents[2]
VECTORS = json.loads((ROOT / "native" / "smoke" / "vectors.json").read_text())


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def _expect_verify_error(what: str, fn) -> None:
    try:
        fn()
    except ml.VerifyError:
        return
    _fail(f"{what}: expected VerifyError, but the call succeeded")


def test_checkpoint() -> None:
    cp = VECTORS["checkpoint"]
    note = base64.b64decode(
        (ROOT / cp["note_b64_path"]).read_text().strip()
    ).decode("utf-8")
    vkeys = [cp["vkey"]]

    head = ml.checkpoint_verify(note, vkeys)
    if head.origin != cp["expected_origin"]:
        _fail(f"origin {head.origin!r} != {cp['expected_origin']!r}")
    if head.size != cp["expected_size"]:
        _fail(f"size {head.size} != {cp['expected_size']}")
    if len(head.root) != 32:
        _fail(f"root is {len(head.root)} bytes, expected 32")

    if ml.verify_signed_note(note, vkeys) < 1:
        _fail("verify_signed_note reported 0 trusted signatures")

    # Tamper: mutate the checkpoint body so strict-AND signature verify fails.
    tampered = note.replace(cp["tamper_from"], cp["tamper_to"], 1)
    _expect_verify_error(
        "tampered checkpoint", lambda: ml.checkpoint_verify(tampered, vkeys)
    )

    # Untrusted: an empty trust set must not verify.
    _expect_verify_error(
        "untrusted checkpoint", lambda: ml.checkpoint_verify(note, [])
    )
    print("ok: checkpoint verify + tamper/untrusted rejection")


def test_commitment() -> None:
    c = VECTORS["commitment"]
    commitment = bytes.fromhex(c["commitment_hex"])
    opening = bytes.fromhex(c["opening_hex"])
    value = c["value_utf8"].encode("utf-8")

    ml.verify_commitment(c["context"], commitment, value, opening)

    _expect_verify_error(
        "tampered commitment value",
        lambda: ml.verify_commitment(c["context"], commitment, b"wrong-value", opening),
    )
    print("ok: commitment open + tamper rejection")


def main() -> None:
    test_checkpoint()
    test_commitment()
    print("python smoke: PASS")


if __name__ == "__main__":
    main()
