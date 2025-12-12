FROM stagex/pallet-rust@sha256:9c38bf1066dd9ad1b6a6b584974dd798c2bf798985bf82e58024fbe0515592ca AS builder

COPY . /app
WORKDIR /app

ENV RUSTFLAGS="-C target-feature=+crt-static"
ENV CARGO_TARGET_DIR=/tmp/cargo-target
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM scratch

COPY --from=builder /tmp/cargo-target/x86_64-unknown-linux-musl/release/keyfork-testing /usr/bin/keyfork-testing
EXPOSE 1337
ENTRYPOINT ["/usr/bin/keyfork-testing"]
