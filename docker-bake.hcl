// Reproducible builds configuration
// Set SOURCE_DATE_EPOCH to git commit time for consistent timestamps:
//   export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
//   docker buildx bake -f docker-bake.hcl

variable "SOURCE_DATE_EPOCH" {
    default = "0"
}

group "default" {
    targets = ["parent", "enclave"]
}

// Build context is the workspace root so each crate's Dockerfile can
// see the workspace Cargo.toml / Cargo.lock and any shared crates
// (e.g. vault-protocol/) referenced via path dependencies. The repo's
// .dockerignore filters out everything that isn't part of the Rust
// build (Python sources, CFN templates, docs, tool config dirs).

target "parent" {
    context = "."
    dockerfile = "parent/Dockerfile"
    args = {
        TARGETPLATFORM = "aarch64-unknown-linux-gnu"
        SOURCE_DATE_EPOCH = "${SOURCE_DATE_EPOCH}"
    }
    platforms = ["linux/arm64"]
    tags = ["parent-vault:latest"]
    cache-to = ["type=gha,ignore-error=true,mode=max,scope=parent"]
    cache-from = ["type=gha,scope=parent"]
}

target "enclave" {
    context = "."
    dockerfile = "enclave/Dockerfile"
    args = {
        TARGETPLATFORM = "aarch64-unknown-linux-musl"
        SOURCE_DATE_EPOCH = "${SOURCE_DATE_EPOCH}"
    }
    platforms = ["linux/arm64"]
    tags = ["enclave-vault:latest"]
    cache-to = ["type=gha,ignore-error=true,mode=max,scope=enclave"]
    cache-from = ["type=gha,scope=enclave"]
}