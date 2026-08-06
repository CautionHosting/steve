# steve-sdk

Native Rust client for the attestation-bound STEVE E2P v2 protocol.

The client:

- requires expected, nonzero 48-byte Nitro PCR0/1/2 values;
- verifies the AWS Nitro certificate chain, fresh nonce, session transcript, and key binder;
- confirms the session before sending application data;
- uses directional AES-256-GCM keys and replay-resistant sequences;
- rotates sessions after 25 minutes; and
- never automatically retries an application request.

```rust
use steve_sdk::{Client, ExpectedPcrs};

let expected_pcrs = ExpectedPcrs::from([
    (0, std::fs::read("pcr0.bin")?),
    (1, std::fs::read("pcr1.bin")?),
    (2, std::fs::read("pcr2.bin")?),
]);
let client = Client::new("https://secure.example", expected_pcrs).await?;
let response = client.get("/api/secret").send().await?;
```

X25519 is the permanent default. X-Wing deployments must be pinned explicitly:

```rust
use steve_sdk::KeyExchangeSuite;

let client = Client::builder("https://secure.example", expected_pcrs)?
    .expected_key_exchange(KeyExchangeSuite::XWingDraft10)
    .connect()
    .await?;
```

The suite is sent in the session request and checked in the session response,
transcript, and attested binding. A mismatch or X-Wing failure aborts session
establishment; there is no negotiation, metadata preflight, or X25519 fallback.

The default session context is SHA-256 of the normalized STEVE origin. Add
application-specific context when needed:

```rust
let client = Client::builder("https://secure.example", expected_pcrs)?
    .application_context(b"payments-production")
    .connect()
    .await?;
```

Run the protocol/vector and signed synthetic server tests with:

```bash
cargo test -p steve-sdk
```

Synthetic evidence validates client/server interoperability, not Nitro hardware.
Before release, repeat session establishment, a protected request, rotation, and
restart recovery on real Nitro hardware using PCRs from the production EIF.

With an honest suite-pinned client, X-Wing session secrecy does not depend on
expected-deployment identity. Routing to another legitimate X-Wing enclave,
first-load bundle replacement, expected-PCR delivery, and plaintext bypass are
separate controls.
