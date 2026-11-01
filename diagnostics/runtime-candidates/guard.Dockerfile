# Diagnostic only: the final image has not passed Nex OS qualification.
FROM rust@sha256:7e9e2d068a107a2adafd19930011178d14a78326053cd4c3a9f7ad3fd049557d AS build
ENV RUSTUP_TOOLCHAIN=1.99.1 CARGO_TARGET_DIR=/target RUSTFLAGS="-C target-feature=-crt-static"
WORKDIR /src
COPY rust-toolchain.toml ./
COPY services/guard-kernel ./services/guard-kernel
COPY packages/contracts ./packages/contracts
COPY policies ./policies
RUN --mount=type=secret,id=proxy_ca,required=true \
    rustc --version | grep -F 'rustc 1.99.1' \
    && CARGO_HTTP_CAINFO=/run/secrets/proxy_ca cargo build --locked --release \
       --target x86_64-unknown-linux-musl --manifest-path services/guard-kernel/Cargo.toml -j 2 \
    && install -D -m0555 /target/x86_64-unknown-linux-musl/release/nex-guard-kernel /out/guard-kernel \
    && readelf -l /out/guard-kernel | grep -F '/lib/ld-musl-x86_64.so.1' \
    && readelf -d /out/guard-kernel | grep -F 'NEEDED'
FROM alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
COPY --from=build --chmod=0555 /out/guard-kernel /guard-kernel
USER 65532:65532
ENTRYPOINT ["/guard-kernel"]
