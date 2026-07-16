// Round-trip smoke test for the Kotlin/JVM (UniFFI) verification bindings.
//
// Drives the generated `uniffi.metamorphic_log` package against locked KAT
// vectors (`native/smoke/vectors.json` + `tests/vectors/hybrid_kat_note.b64`,
// the same vectors the native Rust and WASM suites verify) to prove the Kotlin
// personality reproduces real verifications byte-for-byte, and rejects tampered
// / untrusted input via the typed `VerifyException`.
//
// Verification-only: no secret key material crosses the FFI boundary.
//
// The CI job compiles this against the generated bindings + JNA and loads the
// built desktop JVM shared library. It reads vectors relative to the repo root
// passed as argv[0].

import java.io.File
import java.util.Base64
import org.json.JSONObject
import uniffi.metamorphic_log.CheckpointHead
import uniffi.metamorphic_log.VerifyException
import uniffi.metamorphic_log.checkpointVerify
import uniffi.metamorphic_log.verifyCommitment
import uniffi.metamorphic_log.verifySignedNote

private fun fail(msg: String): Nothing {
    System.err.println("FAIL: $msg")
    kotlin.system.exitProcess(1)
}

private fun expectVerifyError(what: String, body: () -> Unit) {
    try {
        body()
        fail("$what: expected VerifyException, but the call succeeded")
    } catch (_: VerifyException) {
        return
    }
}

private fun hexToBytes(hex: String): ByteArray =
    ByteArray(hex.length / 2) { i ->
        hex.substring(2 * i, 2 * i + 2).toInt(16).toByte()
    }

private fun testCheckpoint(root: File, vectors: JSONObject) {
    val cp = vectors.getJSONObject("checkpoint")
    val noteB64 = File(root, cp.getString("note_b64_path")).readText().trim()
    val note = String(Base64.getDecoder().decode(noteB64), Charsets.UTF_8)
    val vkeys = listOf(cp.getString("vkey"))

    val head: CheckpointHead = checkpointVerify(note, vkeys)
    val expectedOrigin = cp.getString("expected_origin")
    val expectedSize = cp.getLong("expected_size").toULong()
    if (head.origin != expectedOrigin) fail("origin ${head.origin} != $expectedOrigin")
    if (head.size != expectedSize) fail("size ${head.size} != $expectedSize")
    if (head.root.size != 32) fail("root is ${head.root.size} bytes, expected 32")

    if (verifySignedNote(note, vkeys) < 1u) fail("verifySignedNote reported 0 trusted signatures")

    val tampered = note.replaceFirst(cp.getString("tamper_from"), cp.getString("tamper_to"))
    expectVerifyError("tampered checkpoint") { checkpointVerify(tampered, vkeys) }
    expectVerifyError("untrusted checkpoint") { checkpointVerify(note, emptyList()) }
    println("ok: checkpoint verify + tamper/untrusted rejection")
}

private fun testCommitment(vectors: JSONObject) {
    val c = vectors.getJSONObject("commitment")
    val context = c.getString("context")
    val commitment = hexToBytes(c.getString("commitment_hex"))
    val opening = hexToBytes(c.getString("opening_hex"))
    val value = c.getString("value_utf8").toByteArray(Charsets.UTF_8)

    verifyCommitment(context, commitment, value, opening)

    expectVerifyError("tampered commitment value") {
        verifyCommitment(context, commitment, "wrong-value".toByteArray(Charsets.UTF_8), opening)
    }
    println("ok: commitment open + tamper rejection")
}

fun main(args: Array<String>) {
    val root = File(if (args.isNotEmpty()) args[0] else ".")
    val vectors = JSONObject(File(root, "native/smoke/vectors.json").readText())
    testCheckpoint(root, vectors)
    testCommitment(vectors)
    println("kotlin smoke: PASS")
}
