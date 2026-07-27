FROM stagex/core-git@sha256:6b3e0055f6aeaa8465f207a871db2c63a939cd7406113e9d769ff3b37239f3d0 AS git
FROM stagex/core-ca-certificates@sha256:d135f1189e9b232eb7316626bf7858534c5540b2fc53dced80a4c9a95f26493e AS ca-certificates

FROM stagex/pallet-rust@sha256:abe9b95c93a5afa271f69fcd5eb18c8cd405fe5df6491a63c9418e3a170573dc AS builder

COPY --from=git . /
COPY --from=ca-certificates . /

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/

ENV SOURCE_DATE_EPOCH=1
ENV CARGO_INCREMENTAL=0
ENV CARGO_TARGET_DIR=/tmp/cargo-target
ENV RUSTFLAGS="-C codegen-units=1 -C target-feature=+crt-static -C link-arg=-Wl,--build-id=none"

RUN cargo fetch --locked --target x86_64-unknown-linux-musl && \
    cargo build --release --locked --offline \
      --package steve \
      --target x86_64-unknown-linux-musl

FROM scratch

COPY --from=builder /tmp/cargo-target/x86_64-unknown-linux-musl/release/steve /usr/bin/steve
EXPOSE 1337
ENTRYPOINT ["/usr/bin/steve"]
