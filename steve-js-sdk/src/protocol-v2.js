import { encode as encodeCBOR, decode as decodeCBOR } from 'tee-attestation-js/lib/cbor';

export const VERSION = 2;
export const PROTOCOL_ID = 'STEVE-E2P-V2';
export const SESSION_ENDPOINT = '/e2p/v2/session';
export const CONFIRM_ENDPOINT = '/e2p/v2/confirm';
export const REQUEST_ENDPOINT = '/e2p/v2/request';

const encoder = new TextEncoder();
const MAGIC = encoder.encode('STEVE-E2P-V2\0');
const LABELS = {
  c2sKey: encoder.encode('steve-e2p-v2/c2s-key'),
  s2cKey: encoder.encode('steve-e2p-v2/s2c-key'),
  c2sIv: encoder.encode('steve-e2p-v2/c2s-iv'),
  s2cIv: encoder.encode('steve-e2p-v2/s2c-iv'),
  binder: encoder.encode('steve-e2p-v2/attestation-binder')
};

export const Direction = Object.freeze({ CLIENT_TO_SERVER: 0, SERVER_TO_CLIENT: 1 });
export const MessageType = Object.freeze({ CONFIRMATION: 0, APPLICATION: 1 });

export class SequenceTracker {
  constructor() {
    this.next = 1n;
    this.pending = new Set();
  }

  allocate() {
    const sequence = this.next;
    if (sequence > 0xffffffffffffffffn) throw new Error('session sequence exhausted');
    this.next += 1n;
    this.pending.add(sequence.toString());
    return sequence;
  }

  accept(expected, received) {
    const key = expected.toString();
    if (received !== expected || !this.pending.delete(key)) {
      throw new Error('unexpected v2 response sequence');
    }
  }
}

export function concatBytes(...parts) {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

export function equalBytes(left, right) {
  if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array) || left.length !== right.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

export function buildTranscript(clientNonce, clientKey, serverKey, sessionId, contextHash) {
  requireLength('client nonce', clientNonce, 32);
  requireLength('client public key', clientKey, 32);
  requireLength('server public key', serverKey, 32);
  requireLength('session ID', sessionId, 16);
  requireLength('context hash', contextHash, 32);
  return concatBytes(MAGIC, clientNonce, clientKey, serverKey, sessionId, contextHash);
}

export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

export async function hashOrigin(origin) {
  return sha256(encoder.encode(origin));
}

export async function deriveMaterial(sharedSecret, transcriptHash) {
  requireLength('X25519 shared secret', sharedSecret, 32);
  requireLength('transcript hash', transcriptHash, 32);
  const hkdfKey = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveBits']);
  const derive = async (label, bits) => new Uint8Array(await crypto.subtle.deriveBits({
    name: 'HKDF',
    hash: 'SHA-256',
    salt: transcriptHash,
    info: label
  }, hkdfKey, bits));
  return {
    c2sKey: await derive(LABELS.c2sKey, 256),
    s2cKey: await derive(LABELS.s2cKey, 256),
    c2sIvPrefix: await derive(LABELS.c2sIv, 32),
    s2cIvPrefix: await derive(LABELS.s2cIv, 32),
    binder: await derive(LABELS.binder, 256)
  };
}

export function sequenceBytes(sequence) {
  const value = BigInt(sequence);
  if (value < 0n || value > 0xffffffffffffffffn) {
    throw new Error('sequence is out of range');
  }
  const bytes = new Uint8Array(8);
  const view = new DataView(bytes.buffer);
  view.setBigUint64(0, value, false);
  return bytes;
}

export function parseSequence(bytes) {
  requireLength('sequence', bytes, 8);
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(0, false);
}

export function messageNonce(prefix, sequence) {
  requireLength('IV prefix', prefix, 4);
  return concatBytes(prefix, sequenceBytes(sequence));
}

export function associatedData(messageType, direction, sessionId, sequence) {
  requireLength('session ID', sessionId, 16);
  return concatBytes(
    MAGIC,
    new Uint8Array([messageType, direction]),
    sessionId,
    sequenceBytes(sequence)
  );
}

export async function seal(material, direction, messageType, sessionId, sequence, plaintext) {
  const keyBytes = direction === Direction.CLIENT_TO_SERVER ? material.c2sKey : material.s2cKey;
  const prefix = direction === Direction.CLIENT_TO_SERVER
    ? material.c2sIvPrefix
    : material.s2cIvPrefix;
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const ciphertext = await crypto.subtle.encrypt({
    name: 'AES-GCM',
    iv: messageNonce(prefix, sequence),
    additionalData: associatedData(messageType, direction, sessionId, sequence),
    tagLength: 128
  }, key, plaintext);
  return new Uint8Array(ciphertext);
}

export async function open(material, direction, messageType, sessionId, sequence, ciphertext) {
  const keyBytes = direction === Direction.CLIENT_TO_SERVER ? material.c2sKey : material.s2cKey;
  const prefix = direction === Direction.CLIENT_TO_SERVER
    ? material.c2sIvPrefix
    : material.s2cIvPrefix;
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  const plaintext = await crypto.subtle.decrypt({
    name: 'AES-GCM',
    iv: messageNonce(prefix, sequence),
    additionalData: associatedData(messageType, direction, sessionId, sequence),
    tagLength: 128
  }, key, ciphertext);
  return new Uint8Array(plaintext);
}

export function encodeSessionRequest(clientNonce, clientPublicKey, contextHash) {
  return encodeCBOR({
    version: VERSION,
    client_nonce: clientNonce,
    client_public_key: clientPublicKey,
    context_hash: contextHash
  });
}

export function decodeSessionResponse(bytes) {
  const response = decodeCBOR(bytes);
  if (response.version !== VERSION) throw new Error('unsupported session response version');
  requireLength('session ID', response.session_id, 16);
  requireLength('server public key', response.server_public_key, 32);
  if (!(response.attestation_document instanceof Uint8Array)) {
    throw new Error('invalid attestation document');
  }
  if (!Number.isInteger(response.expires_in_seconds) || response.expires_in_seconds <= 0) {
    throw new Error('invalid pending-session expiry');
  }
  return response;
}

export function encodeEnvelope(sessionId, sequence, ciphertext) {
  requireLength('session ID', sessionId, 16);
  return encodeCBOR({
    version: VERSION,
    session_id: sessionId,
    sequence: sequenceBytes(sequence),
    ciphertext
  });
}

export function decodeEnvelope(bytes) {
  const envelope = decodeCBOR(bytes);
  if (envelope.version !== VERSION) throw new Error('unsupported envelope version');
  requireLength('session ID', envelope.session_id, 16);
  requireLength('sequence', envelope.sequence, 8);
  if (!(envelope.ciphertext instanceof Uint8Array)) throw new Error('invalid envelope ciphertext');
  return { ...envelope, sequenceValue: parseSequence(envelope.sequence) };
}

export function verifyBinding(userData, sessionId, transcriptHash, binder) {
  if (!userData || userData.protocol !== PROTOCOL_ID) {
    throw new Error('attestation protocol binding mismatch');
  }
  const expected = {
    session_id: sessionId,
    transcript_hash: transcriptHash,
    binder
  };
  for (const [field, bytes] of Object.entries(expected)) {
    const actual = decodeBase64Url(userData[field]);
    if (!equalBytes(actual, bytes)) throw new Error(`attestation ${field} mismatch`);
  }
}

export function validateAttestationResult(result, sessionId, transcriptHash, binder) {
  if (!result?.verified) {
    throw new Error(`Nitro attestation verification failed: ${result?.error || 'unknown error'}`);
  }
  verifyBinding(result.userData, sessionId, transcriptHash, binder);
}

export function encodeBase64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

export function decodeBase64Url(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/u.test(value)) {
    throw new Error('invalid base64url value in attestation');
  }
  const padded = value.replaceAll('-', '+').replaceAll('_', '/')
    + '='.repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function requireLength(name, value, length) {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new Error(`invalid ${name}`);
  }
}
