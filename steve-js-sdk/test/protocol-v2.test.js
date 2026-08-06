import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import {
  decode as decodeCBOR,
  encode as encodeCBOR
} from 'tee-attestation-js/lib/cbor';

import {
  Direction,
  MAX_ENVELOPE_BYTES,
  MessageType,
  SequenceTracker,
  X25519_KEY_EXCHANGE,
  XWING_KEY_EXCHANGE,
  associatedData,
  buildTranscript,
  decodeEnvelope,
  decodeSessionResponse,
  deriveMaterial,
  encodeBase64Url,
  encodeEnvelope,
  encodeSessionRequest,
  messageNonce,
  open,
  seal,
  sha256,
  validateAttestationResult,
  verifyBinding
} from '../src/protocol-v2.js';

const vectors = JSON.parse(await readFile(
  new URL('../../test-vectors/e2p-v2.json', import.meta.url),
  'utf8'
));
const xwingVectors = JSON.parse(await readFile(
  new URL('../../test-vectors/e2p-v2-xwing.json', import.meta.url),
  'utf8'
));
const bytes = value => Uint8Array.from(Buffer.from(value, 'hex'));
const hex = value => Buffer.from(value).toString('hex');

for (const sharedVectors of [vectors, xwingVectors]) {
  test(`${sharedVectors.key_exchange} shared wire, transcript, HKDF, and confirmation vectors match Rust`, async () => {
    const clientNonce = bytes(sharedVectors.client_nonce);
    const clientKeyMaterial = bytes(sharedVectors.client_key_material);
    const serverKeyMaterial = bytes(sharedVectors.server_key_material);
    const sessionId = bytes(sharedVectors.session_id);
    const contextHash = bytes(sharedVectors.context_hash);

    assert.equal(
      hex(encodeSessionRequest(
        sharedVectors.key_exchange,
        clientNonce,
        clientKeyMaterial,
        contextHash
      )),
      sharedVectors.session_request_cbor
    );
    const response = decodeSessionResponse(
      bytes(sharedVectors.session_response_cbor),
      sharedVectors.key_exchange
    );
    assert.deepEqual(response.session_id, sessionId);
    assert.deepEqual(response.server_key_material, serverKeyMaterial);

    const transcript = buildTranscript(
      sharedVectors.key_exchange,
      clientNonce,
      clientKeyMaterial,
      serverKeyMaterial,
      sessionId,
      contextHash
    );
    assert.equal(hex(transcript), sharedVectors.transcript);
    const transcriptHash = await sha256(transcript);
    assert.equal(hex(transcriptHash), sharedVectors.transcript_hash);

    const sharedSecret = bytes(sharedVectors.shared_secret);
    const material = await deriveMaterial(sharedSecret, transcriptHash);
    assert.deepEqual(
      sharedSecret,
      new Uint8Array(32),
      'raw shared secret must be overwritten'
    );
    assert.equal(hex(material.c2sKey), sharedVectors.c2s_key);
    assert.equal(hex(material.s2cKey), sharedVectors.s2c_key);
    assert.equal(hex(material.c2sIvPrefix), sharedVectors.c2s_iv_prefix);
    assert.equal(hex(material.s2cIvPrefix), sharedVectors.s2c_iv_prefix);
    assert.equal(hex(material.binder), sharedVectors.binder);

    const confirmationCiphertext = await seal(
      material,
      Direction.CLIENT_TO_SERVER,
      MessageType.CONFIRMATION,
      sessionId,
      0n,
      bytes(sharedVectors.confirmation_plaintext)
    );
    assert.equal(
      hex(confirmationCiphertext),
      sharedVectors.confirmation_ciphertext
    );
    assert.equal(
      hex(encodeEnvelope(sessionId, 0n, confirmationCiphertext)),
      sharedVectors.confirmation_record_cbor
    );
  });
}

test('X25519 application nonce and AAD match the shared vector', async () => {
  const material = await deriveMaterial(
    bytes(vectors.shared_secret),
    bytes(vectors.transcript_hash)
  );
  const sequence = BigInt(vectors.sequence);
  assert.equal(hex(messageNonce(material.c2sIvPrefix, sequence)), vectors.c2s_application_iv);
  assert.equal(
    hex(associatedData(MessageType.APPLICATION, Direction.CLIENT_TO_SERVER, bytes(vectors.session_id), sequence)),
    vectors.c2s_application_aad
  );
});

test('envelope is strict and response direction is authenticated', async () => {
  const sessionId = bytes(vectors.session_id);
  const material = await deriveMaterial(bytes(vectors.shared_secret), bytes(vectors.transcript_hash));
  const ciphertext = await seal(
    material,
    Direction.CLIENT_TO_SERVER,
    MessageType.APPLICATION,
    sessionId,
    1n,
    new TextEncoder().encode('hello')
  );
  const envelope = decodeEnvelope(encodeEnvelope(sessionId, 1n, ciphertext));
  assert.equal(envelope.sequenceValue, 1n);
  await assert.rejects(() => open(
    material,
    Direction.SERVER_TO_CLIENT,
    MessageType.APPLICATION,
    sessionId,
    1n,
    envelope.ciphertext
  ));
});

test('envelope encoding fails locally above the server size limit', () => {
  assert.throws(
    () => encodeEnvelope(
      new Uint8Array(16),
      0n,
      new Uint8Array(MAX_ENVELOPE_BYTES)
    ),
    /v2 envelope exceeds size limit/u
  );
});

test('attested binder requires exact transcript values', () => {
  const keyExchange = vectors.key_exchange;
  const sessionId = bytes(vectors.session_id);
  const transcriptHash = bytes(vectors.transcript_hash);
  const binder = bytes(vectors.binder);
  const userData = {
    protocol: 'STEVE-E2P-V2',
    key_exchange: keyExchange,
    session_id: encodeBase64Url(sessionId),
    transcript_hash: encodeBase64Url(transcriptHash),
    binder: encodeBase64Url(binder)
  };
  verifyBinding(userData, keyExchange, sessionId, transcriptHash, binder);
  validateAttestationResult(
    { verified: true, userData },
    keyExchange,
    sessionId,
    transcriptHash,
    binder
  );
  assert.throws(
    () => validateAttestationResult(
      { verified: false, error: 'bad chain' },
      keyExchange,
      sessionId,
      transcriptHash,
      binder
    ),
    /bad chain/u
  );
  const tampered = { ...userData, binder: encodeBase64Url(new Uint8Array(32)) };
  assert.throws(
    () => verifyBinding(tampered, keyExchange, sessionId, transcriptHash, binder),
    /binder mismatch/u
  );
  assert.throws(
    () => verifyBinding(
      { ...userData, key_exchange: XWING_KEY_EXCHANGE },
      keyExchange,
      sessionId,
      transcriptHash,
      binder
    ),
    /protocol binding mismatch/u
  );
});

test('session wire uses generic key material fields and exact suite', () => {
  const clientNonce = new Uint8Array(32).fill(1);
  const clientKeyMaterial = new Uint8Array(32).fill(2);
  const contextHash = new Uint8Array(32).fill(3);
  const request = decodeCBOR(encodeSessionRequest(
    X25519_KEY_EXCHANGE,
    clientNonce,
    clientKeyMaterial,
    contextHash
  ));

  assert.equal(request.key_exchange, X25519_KEY_EXCHANGE);
  assert.deepEqual(request.client_key_material, clientKeyMaterial);
  assert.equal('client_public_key' in request, false);

  const response = decodeSessionResponse(encodeCBOR({
    version: 2,
    key_exchange: X25519_KEY_EXCHANGE,
    session_id: new Uint8Array(16),
    server_key_material: new Uint8Array(32),
    attestation_document: new Uint8Array([1]),
    expires_in_seconds: 30
  }), X25519_KEY_EXCHANGE);
  assert.equal(response.key_exchange, X25519_KEY_EXCHANGE);
  assert.equal('server_public_key' in response, false);

  assert.throws(
    () => decodeSessionResponse(encodeCBOR({
      ...response,
      key_exchange: XWING_KEY_EXCHANGE
    }), X25519_KEY_EXCHANGE),
    /key exchange mismatch/u
  );
});

test('X-Wing transcript binds the suite and exact 1216/1120-byte material', () => {
  const transcript = buildTranscript(
    XWING_KEY_EXCHANGE,
    new Uint8Array(32).fill(1),
    new Uint8Array(1216).fill(2),
    new Uint8Array(1120).fill(3),
    new Uint8Array(16).fill(4),
    new Uint8Array(32).fill(5)
  );
  const prefix = new TextEncoder().encode('STEVE-E2P-V2\0XWING-DRAFT10\0');

  assert.deepEqual(transcript.slice(0, prefix.length), prefix);
  assert.equal(transcript.length, prefix.length + 32 + 1216 + 1120 + 16 + 32);
  assert.throws(() => buildTranscript(
    XWING_KEY_EXCHANGE,
    new Uint8Array(32),
    new Uint8Array(32),
    new Uint8Array(1120),
    new Uint8Array(16),
    new Uint8Array(32)
  ), /invalid client key material/u);
});

test('concurrent sequence allocation is unique and duplicate responses fail', async () => {
  const tracker = new SequenceTracker();
  const sequences = await Promise.all(
    Array.from({ length: 64 }, async () => tracker.allocate())
  );
  assert.equal(new Set(sequences.map(String)).size, 64);
  assert.deepEqual(sequences, Array.from({ length: 64 }, (_, index) => BigInt(index + 1)));
  tracker.accept(1n, 1n);
  assert.throws(() => tracker.accept(1n, 1n), /unexpected v2 response sequence/u);
  assert.throws(() => tracker.accept(2n, 3n), /unexpected v2 response sequence/u);
});

test('sequence allocation cannot advance beyond the server replay window', async () => {
  const tracker = new SequenceTracker();
  const first = await tracker.allocate();
  assert.equal(first, 1n);

  for (let expected = 2n; expected <= 64n; expected += 1n) {
    const sequence = await tracker.allocate();
    assert.equal(sequence, expected);
    tracker.accept(sequence, sequence);
  }

  let settled = false;
  const blocked = tracker.allocate().then(sequence => {
    settled = true;
    return sequence;
  });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(settled, false, 'sequence 65 must wait while sequence 1 is pending');

  tracker.accept(first, first);
  assert.equal(await blocked, 65n);
});

test('closing a tracker rejects allocations waiting on the replay window', async () => {
  const tracker = new SequenceTracker();
  const first = await tracker.allocate();
  for (let expected = 2n; expected <= 64n; expected += 1n) {
    const sequence = await tracker.allocate();
    tracker.accept(sequence, sequence);
  }

  const blocked = tracker.allocate();
  await new Promise(resolve => setImmediate(resolve));
  tracker.close(new Error('session reset'));

  await assert.rejects(blocked, /session reset/u);
  assert.throws(() => tracker.accept(first, first), /session reset/u);
});

test('retiring a spent sequence advances the window without reusing it', async () => {
  const tracker = new SequenceTracker();
  const first = await tracker.allocate();
  for (let expected = 2n; expected <= 64n; expected += 1n) {
    const sequence = await tracker.allocate();
    tracker.accept(sequence, sequence);
  }

  const blocked = tracker.allocate();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(tracker.retire(first), true);
  assert.equal(await blocked, 65n);
  assert.throws(() => tracker.retire(first), /unexpected v2 retired sequence/u);
});

test('retiring after a concurrent close is a safe no-op', async () => {
  const tracker = new SequenceTracker();
  const sequence = await tracker.allocate();
  tracker.close(new Error('session reset'));

  assert.equal(tracker.retire(sequence), false);
  assert.throws(() => tracker.accept(sequence, sequence), /session reset/u);
});
