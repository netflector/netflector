# syntax=docker/dockerfile:1
# Build netflector as a fully static musl binary and ship it on scratch — nothing else to carry
# or to grow CVEs. Architecture-agnostic: buildx's TARGETARCH/TARGETVARIANT select the musl target,
# and the builder runs on the native build host (BUILDPLATFORM) and cross-compiles, so the arm
# images don't crawl under QEMU. Cross layers link with LLVM's lld (any arch, no per-arch gcc);
# a layer built on its own arch uses rustc's default toolchain, following upstream defaults
# where one exists.

# Pin the shared base image by digest: reproducible builds, no drift under the floating tag. Renovate
# keeps it current. Referenced by both the builder and the valgrind runtime below so they stay in lockstep.
ARG RUST_IMAGE=docker.io/library/rust:slim@sha256:466074ef42a9485c726d71017fa629f1954cd5e09b473dcd00467ddc6afdc753
FROM --platform=$BUILDPLATFORM ${RUST_IMAGE} AS builder
ARG TARGETARCH
ARG TARGETVARIANT
WORKDIR /src

RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) triple=x86_64-unknown-linux-musl ;; \
        arm64) triple=aarch64-unknown-linux-musl ;; \
        arm) \
            case "${TARGETVARIANT}" in \
                v7) triple=armv7-unknown-linux-musleabihf ;; \
                v5) triple=armv5te-unknown-linux-musleabi ;; \
                *)  echo "unsupported arm variant: ${TARGETVARIANT}" >&2; exit 1 ;; \
            esac ;; \
        *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    echo "${triple}" > /triple; \
    rustup target add "${triple}"

# Cross-compiled layers link with LLVM's lld (cross-capable, unlike the host gcc), scoped to musl
# via cfg so the host's build scripts and proc-macros keep the default toolchain. A layer built on
# its own arch (TARGETPLATFORM == BUILDPLATFORM: amd64, and arm64 on an arm64 host) writes no
# config: rustc's default toolchain, per the policy of following upstream defaults where one
# exists. lld installs either way so the layer stays shared across platforms.
RUN apt-get update && apt-get install -y --no-install-recommends lld && rm -rf /var/lib/apt/lists/*
ARG BUILDPLATFORM
ARG TARGETPLATFORM
RUN <<'EOF'
set -eu
if [ "${TARGETPLATFORM}" != "${BUILDPLATFORM}" ]; then
    mkdir -p .cargo
    cat > .cargo/config.toml <<'CFG'
[target.'cfg(target_env = "musl")']
linker = "ld.lld"
rustflags = ["-C", "linker-flavor=ld.lld"]
CFG
fi
EOF

COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/
# The cache mount is keyed per arch: multi-platform builds run the per-arch builder stages in
# parallel, and cargo cannot coordinate concurrent registry unpacks across them (its lock file
# is $CARGO_HOME/.package-cache, outside the mounted path) -- two arches racing to unpack the
# same crate into a shared default-id mount fail with "File exists" whenever the mount is cold
# (in CI it always is: RUN-mount contents are not part of the exported layer cache).
RUN --mount=type=cache,id=cargo-registry-${TARGETARCH}${TARGETVARIANT},target=/usr/local/cargo/registry \
    triple="$(cat /triple)"; \
    cargo build --release --locked --target "${triple}"; \
    install -D "target/${triple}/release/netflector" /out/netflector

# netflector under Valgrind memcheck, for `e2e/run.py --valgrind`. A glibc release binary with debug
# symbols (unstripped): the same -O3/LTO codegen the scratch image ships, just with -g for readable traces
# and dynamic glibc -- Valgrind supports that well, unlike the static musl target. amd64-only (the Valgrind
# e2e job is); built and run on the one rust:slim base so the glibc versions match. run.py SIGTERMs the
# daemon so Valgrind reports leaks at a clean exit; --track-fds catches a leaked socket in the live daemon;
# --error-exitcode=1 fails on any leak, leaked fd, or memcheck error. "reachable" is allowed (the logger and
# other process-lifetime statics live to exit by design).
FROM ${RUST_IMAGE} AS runtime-valgrind
RUN apt-get update \
    && apt-get install -y --no-install-recommends valgrind \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/
# Its own cache id: this stage is amd64-only, but the default id would alias the builder's mount.
RUN --mount=type=cache,id=cargo-registry-valgrind,target=/usr/local/cargo/registry \
    CARGO_PROFILE_RELEASE_DEBUG=true CARGO_PROFILE_RELEASE_STRIP=false \
    cargo build --release --locked \
    && install -D target/release/netflector /usr/local/bin/netflector
ENTRYPOINT ["valgrind", \
    "--leak-check=full", \
    "--show-leak-kinds=all", \
    "--errors-for-leak-kinds=definite,indirect,possible", \
    "--track-fds=yes", \
    "--num-callers=30", \
    "--error-exitcode=1", \
    "/usr/local/bin/netflector"]
CMD ["/etc/netflector/config.toml"]

# Production image: one fully static binary on scratch -- nothing else to ship or grow CVEs. Keep this LAST
# so a bare `docker build .` (no --target, as releases and the non-valgrind e2e use) defaults to it.
FROM scratch AS runtime
COPY --from=builder /out/netflector /usr/local/bin/netflector
ENTRYPOINT ["/usr/local/bin/netflector"]
