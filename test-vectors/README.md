# E2P v2 vectors

- `xwing-draft10.json` is the
  [three-vector snapshot](https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem/blob/main/spec/test-vectors.json)
  referenced by `draft-connolly-cfrg-xwing-kem-10`. Its raw SHA-256 is
  recorded in `xwing-draft10.sha256`.
- `e2p-v2.json` covers the complete X25519 handshake from session CBOR through
  transcript, HKDF outputs, binder, and confirmation record.
- `e2p-v2-xwing.json` covers the same protocol surface for `XWING-DRAFT10`,
  using the first draft-10 KAT's decapsulation seed, encapsulation seed, public
  key, ciphertext, and shared secret.
- `pcr-policy-v1.json` covers PCR hex normalization, complete-profile matching,
  additional PCR selection, and exact TOFU-record comparison.

Rust and browser tests consume these shared files directly and fail on drift.
The published `x-wing` 0.1.0 package metadata still says draft-06; the KAT test
is the repository's executable evidence that the exact pinned implementation
matches all three vendored draft-10 vectors.
