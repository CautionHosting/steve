# steve-sdk

Native Rust client for the attestation-bound STEVE E2P v2 protocol.

The client:

- pins one or more complete Nitro PCR profiles, or uses caller-persisted TOFU;
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

Each successful `Response` carries non-secret `ProtectedExchange` metadata for
the exact authenticated exchange: session ID, sequence, KEM and PCR trust
result, outer HTTP status, and plaintext, ciphertext, and complete-envelope byte
counts in both directions. `response.exchange()` exposes this receipt without
exposing keys, IV prefixes, nonces, binders, shared secrets, or ciphertext.

`Client::new` and `Client::builder` remain single-profile pinned conveniences.
For an upgrade window, approve multiple complete profiles explicitly:

```rust
use steve_sdk::{Client, PcrPolicy};

let policy = PcrPolicy::pinned([current_release, next_release])?;
let client = Client::new_with_policy("https://secure.example", policy).await?;
```

PCR0, PCR1, and PCR2 are mandatory, nonzero, and 48 bytes. A pinned policy
accepts only when every configured PCR in one profile matches; profiles are
never mixed. Extra PCRs in the attestation are ignored unless included in a
profile.

## Trust on first use

TOFU requires application-owned durable storage. The SDK provides no built-in
store:

```rust
use async_trait::async_trait;
use std::sync::Arc;
use steve_sdk::{
    Client, ExpectedPcrs, PcrPolicy, PcrTrustKey, PcrTrustRecord,
    PcrTrustStore, PcrTrustStoreError,
};

#[derive(Debug)]
struct DurableStore;

#[async_trait]
impl PcrTrustStore for DurableStore {
    async fn load_or_insert(
        &self,
        key: PcrTrustKey,
        observed: ExpectedPcrs,
    ) -> Result<PcrTrustRecord, PcrTrustStoreError> {
        // Atomically insert `observed` if absent; otherwise return the stored value.
        todo!()
    }
}

let policy = PcrPolicy::trust_on_first_use(Arc::new(DurableStore));
let client = Client::new_with_policy("https://secure.example", policy).await?;
```

The default selects exactly PCR0/1/2. Add other signed PCR indices when the
application policy requires them:

```rust
let policy = PcrPolicy::trust_on_first_use_with_additional_pcrs(
    Arc::new(DurableStore),
    [3, 8],
);
```

Enrollment happens only after the Nitro evidence, nonce, suite, transcript,
binder, and session confirmation have been verified. The store operation must
be atomic: return `Inserted` only after persisting exactly the supplied selected
PCRs, or `Existing(stored_pcrs)` without replacing them. Existing records must
contain exactly the selected indices and values; missing, extra, or changed
entries fail before application traffic. The complete signed PCR map remains
available in `AttestationInfo`, whose `pcr_trust` reports `TofuEnrolled`,
`TofuMatched`, or `Pinned`.

TOFU provides continuity, not independently authenticated workload identity on
first use. Deleting its record reopens enrollment. PCR-changing upgrades are
therefore automatic only with a pinned allowlist; a TOFU deployment requires
the application to authorize and replace its durable record out of band. The
SDK never replaces a record or offers an unpinned mode. Its trust key remains
bound to origin, application context, and suite, not the selected PCR indices,
so changing the selection also requires explicit record migration or a distinct
application context. Stores that return extra entries for the default PCR0/1/2
selection now fail closed.

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

The signed fixture verifier is compiled only for Rust tests or with the
non-default `eval-attestation` feature. That feature exists for integration
testing and must not be enabled in release clients.

Synthetic evidence validates client/server interoperability, not Nitro hardware.
Before release, repeat session establishment, a protected request, rotation, and
restart recovery on real Nitro hardware using PCRs from the production EIF.

With an honest suite-pinned client, X-Wing session secrecy does not depend on
expected-deployment identity. Routing to another legitimate X-Wing enclave,
first-load bundle replacement, expected-PCR delivery, and plaintext bypass are
separate controls.
