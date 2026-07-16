// Round-trip smoke test for the Swift (UniFFI) verification bindings.
//
// Drives the generated `metamorphic_log` module against locked KAT vectors
// (`native/smoke/vectors.json` + `tests/vectors/hybrid_kat_note.b64`, the same
// vectors the native Rust and WASM suites verify) to prove the Swift
// personality reproduces real verifications byte-for-byte, and rejects tampered
// / untrusted input via the typed `VerifyError`.
//
// Verification-only: no secret key material crosses the FFI boundary.
//
// The CI job compiles this against the generated module and links the built
// dylib. It reads vectors relative to the repo root passed as argv[1].

// NOTE: the smoke is compiled together with the generated `metamorphic_log.swift`
// as a single module, so it does not `import metamorphic_log` — the generated
// symbols are already in scope. A real SwiftPM consumer imports the module by
// name; that path is exercised by the xcframework build, not this gate.
import Foundation

func fail(_ msg: String) -> Never {
    FileHandle.standardError.write(Data("FAIL: \(msg)\n".utf8))
    exit(1)
}

func expectVerifyError(_ what: String, _ body: () throws -> Void) {
    do {
        try body()
        fail("\(what): expected VerifyError, but the call succeeded")
    } catch is VerifyError {
        return
    } catch {
        fail("\(what): expected VerifyError, got \(error)")
    }
}

let root = URL(fileURLWithPath: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ".")

let vectorsData = try! Data(contentsOf: root.appendingPathComponent("native/smoke/vectors.json"))
let vectors = try! JSONSerialization.jsonObject(with: vectorsData) as! [String: Any]

func testCheckpoint() {
    let cp = vectors["checkpoint"] as! [String: Any]
    let noteB64Path = cp["note_b64_path"] as! String
    let noteB64 = try! String(contentsOf: root.appendingPathComponent(noteB64Path), encoding: .utf8)
        .trimmingCharacters(in: .whitespacesAndNewlines)
    let note = String(data: Data(base64Encoded: noteB64)!, encoding: .utf8)!
    let vkeys = [cp["vkey"] as! String]

    let head = try! checkpointVerify(noteText: note, vkeys: vkeys)
    let expectedOrigin = cp["expected_origin"] as! String
    let expectedSize = UInt64(cp["expected_size"] as! Int)
    if head.origin != expectedOrigin { fail("origin \(head.origin) != \(expectedOrigin)") }
    if head.size != expectedSize { fail("size \(head.size) != \(expectedSize)") }
    if head.root.count != 32 { fail("root is \(head.root.count) bytes, expected 32") }

    if (try! verifySignedNote(noteText: note, vkeys: vkeys)) < 1 {
        fail("verifySignedNote reported 0 trusted signatures")
    }

    let tampered = note.replacingOccurrences(
        of: cp["tamper_from"] as! String,
        with: cp["tamper_to"] as! String
    )
    expectVerifyError("tampered checkpoint") {
        _ = try checkpointVerify(noteText: tampered, vkeys: vkeys)
    }
    expectVerifyError("untrusted checkpoint") {
        _ = try checkpointVerify(noteText: note, vkeys: [])
    }
    print("ok: checkpoint verify + tamper/untrusted rejection")
}

func hexToData(_ hex: String) -> Data {
    var data = Data(capacity: hex.count / 2)
    var idx = hex.startIndex
    while idx < hex.endIndex {
        let next = hex.index(idx, offsetBy: 2)
        data.append(UInt8(hex[idx..<next], radix: 16)!)
        idx = next
    }
    return data
}

func testCommitment() {
    let c = vectors["commitment"] as! [String: Any]
    let context = c["context"] as! String
    let commitment = hexToData(c["commitment_hex"] as! String)
    let opening = hexToData(c["opening_hex"] as! String)
    let value = Data((c["value_utf8"] as! String).utf8)

    try! verifyCommitment(context: context, commitment: commitment, value: value, opening: opening)

    expectVerifyError("tampered commitment value") {
        try verifyCommitment(
            context: context, commitment: commitment,
            value: Data("wrong-value".utf8), opening: opening
        )
    }
    print("ok: commitment open + tamper rejection")
}

@main
struct Smoke {
    static func main() {
        testCheckpoint()
        testCommitment()
        print("swift smoke: PASS")
    }
}
