# syntax=docker/dockerfile:1
# The builder OS/compiler and runtime are immutable registry digests. Compile
# against bookworm's ABI, compatible with the newer trixie runtime, not host libc.
FROM rust:1.99.1-slim-bookworm@sha256:86234e857a413004348b471d11a4ebe1aa92d2eae2b6b143cac68fd1ac3c48be AS build
ENV RUSTUP_TOOLCHAIN=1.99.1 CARGO_TARGET_DIR=/target
WORKDIR /src
COPY rust-toolchain.toml ./
COPY services/guard-kernel ./services/guard-kernel
COPY packages/contracts ./packages/contracts
COPY policies ./policies
RUN --mount=type=secret,id=proxy_ca,required=true \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/target \
    CARGO_HTTP_CAINFO=/run/secrets/proxy_ca cargo build --locked --release --manifest-path services/guard-kernel/Cargo.toml \
    && install -D -m0555 /target/release/nex-guard-kernel /out/guard-kernel
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:3ee00291cf386ec52a552e6a858d555debd74776eb4bfa53fa3df2cd6677515e
COPY --from=build /out/guard-kernel /guard-kernel
USER 65532:65532
ENTRYPOINT ["/guard-kernel"]
