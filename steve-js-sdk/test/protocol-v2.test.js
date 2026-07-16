import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  Direction,
  MessageType,
  SequenceTracker,
  associatedData,
  buildTranscript,
  decodeEnvelope,
  deriveMaterial,
  encodeBase64Url,
  encodeEnvelope,
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
const bytes = value => Uint8Array.from(Buffer.from(value, 'hex'));
const hex = value => Buffer.from(value).toString('hex');

test('shared transcript and HKDF vector matches Rust', async () => {
  const transcript = buildTranscript(
    bytes(vectors.client_nonce),
    bytes(vectors.client_public_key),
    bytes(vectors.server_public_key),
    bytes(vectors.session_id),
    bytes(vectors.context_hash)
  );
  const transcriptHash = await sha256(transcript);
  assert.equal(hex(transcriptHash), vectors.transcript_hash);

  const material = await deriveMaterial(bytes(vectors.shared_secret), transcriptHash);
  assert.equal(hex(material.c2sKey), vectors.c2s_key);
  assert.equal(hex(material.s2cKey), vectors.s2c_key);
  assert.equal(hex(material.c2sIvPrefix), vectors.c2s_iv_prefix);
  assert.equal(hex(material.s2cIvPrefix), vectors.s2c_iv_prefix);
  assert.equal(hex(material.binder), vectors.binder);

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

test('attested binder requires exact transcript values', () => {
  const sessionId = bytes(vectors.session_id);
  const transcriptHash = bytes(vectors.transcript_hash);
  const binder = bytes(vectors.binder);
  const userData = {
    protocol: 'STEVE-E2P-V2',
    session_id: encodeBase64Url(sessionId),
    transcript_hash: encodeBase64Url(transcriptHash),
    binder: encodeBase64Url(binder)
  };
  verifyBinding(userData, sessionId, transcriptHash, binder);
  validateAttestationResult({ verified: true, userData }, sessionId, transcriptHash, binder);
  assert.throws(
    () => validateAttestationResult({ verified: false, error: 'bad chain' }, sessionId, transcriptHash, binder),
    /bad chain/u
  );
  const tampered = { ...userData, binder: encodeBase64Url(new Uint8Array(32)) };
  assert.throws(() => verifyBinding(tampered, sessionId, transcriptHash, binder), /binder mismatch/u);
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
