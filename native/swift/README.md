# metamorphic-log-swift (distribution repo scaffold)

The SwiftPM package for the native verification bindings lives in a **separate**
repo, `moss-piglet/metamorphic-log-swift`, so it can be resolved by SwiftPM URL
and tagged independently. This directory holds the template used to seed it.

## One-time repo setup (Mark)

1. Create the public repo `moss-piglet/metamorphic-log-swift` with a `main`
   branch.
2. Seed it:
   - `Package.swift` <- copy from `native/swift/Package.swift.template` (the
     placeholder `url`/`checksum`/version are rewritten by CI on each release).
   - `Sources/MetamorphicLog/` <- the generated `metamorphic_log.swift` (shipped
     as `MetamorphicLog-Sources-<version>.zip` on the metamorphic-log Release).
   - `VERSION`, `README.md`, license files.
3. On the `metamorphic-log` repo, add secret `GH_TOKEN_SWIFT_REPO`: a
   fine-grained PAT scoped to `moss-piglet/metamorphic-log-swift` with
   `contents: write` + `pull requests: write`.

## Release flow (automated once `vars.PUBLISH_SWIFT=true`)

1. Tag `native-v<version>` on `metamorphic-log` -> CI builds + attaches the
   xcframework zip and its checksum to the GitHub Release.
2. CI opens a PR here on branch `release/native-v<version>` updating
   `binaryTarget(url:, checksum:)` and `VERSION`.
3. Review + merge, then tag `native-v<version>` here. SwiftPM consumers pin that
   tag:

   ```swift
   .package(url: "https://github.com/moss-piglet/metamorphic-log-swift.git", from: "0.1.11")
   ```
