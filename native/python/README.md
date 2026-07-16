# metamorphic-log (Python)

Verification-only Python bindings for
[`metamorphic-log`](https://github.com/moss-piglet/metamorphic-log), generated
with [UniFFI](https://mozilla.github.io/uniffi-rs/). The wheel bundles a
compiled Rust `cdylib` and a pure-Python module that loads it via `ctypes`, so a
single wheel per platform works across CPython versions.

No secret key material crosses the FFI boundary: this surface verifies
transparency-log checkpoints, signed notes, and commitments.

```python
import metamorphic_log as ml

head = ml.checkpoint_verify(note, [vkey])   # -> CheckpointHead, raises VerifyError
trusted = ml.verify_signed_note(note, [vkey])
ml.verify_commitment(context, commitment, value, opening)  # raises VerifyError
```

Install:

```sh
pip install metamorphic-log
```
