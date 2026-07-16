// Gradle multi-project for the Maven-published native verification bindings:
//   :library -> Android AAR   (io.github.moss-piglet:metamorphic-log)
//   :jvm     -> desktop JVM jar (io.github.moss-piglet:metamorphic-log-jvm)
//
// Both wrap the SAME CI-generated UniFFI Kotlin bindings (../../bindings/kotlin,
// gitignored — regenerated per run) and the compiled Rust libraries:
//   - :library bundles Android jniLibs (arm64-v8a / armeabi-v7a / x86_64),
//     built by cargo-ndk in release-native.yml.
//   - :jvm bundles desktop shared libs under JNA resource paths
//     (linux-x86-64 / darwin-aarch64 / darwin-x86-64 / win32-x86-64), built on
//     their native runners.
//
// Publishing to the Central Portal is via the nmcp aggregation plugin and is
// gated in CI (vars.PUBLISH_MAVEN); artifacts are GPG-signed with the in-memory
// signing key supplied through ORG_GRADLE_PROJECT_signingKey/Password.
//
// NOTE: plugin/library versions are scaffolding pins; validate + bump in CI.

plugins {
    id("com.gradleup.nmcp.aggregation") version "1.6.1"
}

// Single source of truth: the crate version, passed in via ML_VERSION.
val mlVersion: String = System.getenv("ML_VERSION") ?: "0.0.0-dev"

allprojects {
    group = "io.github.moss-piglet"
    version = mlVersion
}

nmcpAggregation {
    centralPortal {
        username.set(providers.gradleProperty("centralUsername").orElse(""))
        password.set(providers.gradleProperty("centralPassword").orElse(""))
        // Manual so a gated re-run never auto-releases a half-staged deployment.
        publishingType.set("USER_MANAGED")
    }
}

dependencies {
    nmcpAggregation(project(":library"))
    nmcpAggregation(project(":jvm"))
}
