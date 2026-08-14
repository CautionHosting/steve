# steve-sdk-uniffi

Swift-facing UniFFI facade for `steve-sdk`. Rust owns networking, Nitro
attestation, protocol state, X25519/X-Wing cryptography, session keys, and async
execution.

## Generate and link

UniFFI is pinned to 0.32.0. Generate the Swift source, C header, and module map
from the native static library:

```bash
cargo build --release --locked -p steve-sdk-uniffi
cargo build --release --locked -p steve-sdk-uniffi \
  --features bindgen --bin uniffi-bindgen-swift \
  --target-dir target/steve-sdk-uniffi-tools
mkdir -p target/steve-sdk-uniffi/swift
target/steve-sdk-uniffi-tools/release/uniffi-bindgen-swift \
  --metadata-no-deps \
  --module-name SteveSDKFFI \
  --modulemap-filename SteveSDKFFI.modulemap \
  --swift-sources --headers --modulemap \
  target/release/libsteve_sdk_uniffi.a \
  target/steve-sdk-uniffi/swift
```

Compile `SteveSDK.swift` into the application and link
`libsteve_sdk_uniffi.a` using `SteveSDKFFI.modulemap` and `SteveSDKFFI.h`.
These files are generated under `target/`; none are committed. Packaging for an
iOS application or XCFramework is intentionally outside v1.

## API and defaults

`createPinned` and `createTofu` are synchronous and perform no network I/O. The
first `verifyAttestation`, `rotateSession`, or `send` call lazily establishes a
session. An omitted suite selects X25519. Omitted rotation, establishment, and
request timeouts retain the Rust SDK defaults: 25 minutes, 10 seconds, and 30
seconds respectively. Zero values are literal: a zero rotation interval rotates
before every operation, while zero timeouts expire immediately.

HTTP methods and paths are passed to the native SDK. Header values and bodies
cross the FFI as `Data`; response header entries preserve repeated names and
normalize names to lowercase. Compare header names case-insensitively.
Duplicate request names retain the SDK's last-value-wins behavior. Invalid
methods, names, values, paths, and non-UTF-8 request header values fail through
typed `SteveError` cases. Application HTTP 4xx/5xx values remain responses.
The Rust-only `reqwest::ClientBuilder` injection point and generic text/JSON
helpers are not part of the FFI; Swift uses the byte-oriented request and
response DTOs.

The facade owns one lazy, process-global, multi-thread Tokio runtime. A client
may be used concurrently. Swift task cancellation does not prove that a remote
request stopped; configured deadlines and the SDK's no-retry behavior remain
authoritative.

## TOFU contract

The Swift trust store callback is synchronous, may run on a blocking worker
thread, and must be thread-safe. It must not call or wait on methods of the same
`SteveClient`. The client retains the store for its lifetime; any back-reference
from the store to the client must be weak. `loadOrInsert` must atomically:

- durably insert the observed PCR0/1/2 and return `inserted`; or
- return `existing(profile:)` without replacing the stored value.

Once running, the callback cannot be cancelled. A session-establishment timeout
does not roll back caller-owned storage: insertion may still complete, and a
retry can return `tofuMatched` without a prior successful `tofuEnrolled` result.

The 32-byte key is bound to the normalized origin, application context, and
selected suite. Callback failures fail closed, and their messages are retained
inside `SteveError.PcrTrustStore`. Complete signed PCR maps remain available in
`AttestationInfo`; the callback intentionally receives only PCR0/1/2.

## Security and validation

Normal builds contain only AWS Nitro verification. The non-default
`synthetic-testing` feature exposes conspicuously named fixture-only factories
for the macOS smoke test; it must not be linked into a release application.

```bash
make test-swift
```

This requires macOS Command Line Tools and Docker. It does not require full
Xcode, signing, a paid Apple account, or an iOS project. The gate generates and
compiles the bindings once, then exercises pinned X25519 and Swift-owned TOFU
with XWING-DRAFT10 against signed synthetic evidence. It proves FFI and
encrypted-protocol interoperability, not Nitro hardware or production PCRs.
Its synthetic library, bindings, and executable stay isolated under
`target/steve-sdk-uniffi-smoke`.

There is no Keychain, Secure Enclave, platform KEM provider, or persistent
session-key API in v1. Session key generation and use remain ephemeral inside
Rust.
