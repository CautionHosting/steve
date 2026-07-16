import { verify } from 'tee-attestation-js/nitro';
import { encode as encodeCBOR, decode as decodeCBOR } from 'tee-attestation-js/lib/cbor';
import {
  CONFIRM_ENDPOINT,
  Direction,
  MessageType,
  REQUEST_ENDPOINT,
  SESSION_ENDPOINT,
  SequenceTracker,
  buildTranscript,
  decodeEnvelope,
  decodeSessionResponse,
  deriveMaterial,
  encodeEnvelope,
  encodeSessionRequest,
  equalBytes,
  hashOrigin,
  open,
  seal,
  sha256,
  validateAttestationResult
} from './protocol-v2.js';

const DEFAULT_BOOTSTRAP_PATHS = ['/', '/enclave-sw.js', '/register.js', '/attestation-widget.js'];
const ROTATION_INTERVAL_MS = 25 * 60 * 1000;

let config = {
  passthroughPaths: DEFAULT_BOOTSTRAP_PATHS,
  excludePrefixes: ['/attestation', '/e2p/'],
  emitEncryptedPayloads: false
};

let state = freshState();

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(clients.claim()));
self.addEventListener('message', event => handleMessage(event));
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin || isPassthrough(url.pathname)) {
    return;
  }
  event.respondWith(handleProtectedRequest(event.request));
});

async function handleMessage(event) {
  const { type } = event.data;
  const port = event.ports[0];
  try {
    switch (type) {
      case 'get-status':
        port?.postMessage(statusMessage());
        break;
      case 'initialize':
        await ensureSession();
        port?.postMessage({ type: 'initialized', success: true });
        break;
      case 'rotate-key':
        await rotateSession();
        port?.postMessage({ type: 'key-rotated', success: true });
        break;
      case 'reset':
        resetState();
        port?.postMessage({ type: 'reset', success: true });
        break;
      case 'configure':
        configure(event.data.config || {});
        port?.postMessage({ type: 'configured', success: true, config });
        break;
      default:
        throw new Error('unknown service-worker command');
    }
  } catch (error) {
    port?.postMessage({ type, success: false, error: publicError(error) });
  }
}

async function handleProtectedRequest(request) {
  let session;
  try {
    session = await currentSession();
    const sequence = session.sequences.allocate();
    const url = new URL(request.url);
    const requestBody = new Uint8Array(await request.arrayBuffer());
    const plaintext = encodeCBOR({
      method: request.method,
      path: url.pathname + url.search,
      headers: Object.fromEntries(request.headers),
      body: requestBody.length === 0 ? null : requestBody
    });
    const ciphertext = await seal(
      session.material,
      Direction.CLIENT_TO_SERVER,
      MessageType.APPLICATION,
      session.id,
      sequence,
      plaintext
    );
    const envelope = encodeEnvelope(session.id, sequence, ciphertext);

    if (config.emitEncryptedPayloads) {
      notifyClients('encrypted-request', { sequence: sequence.toString(), size: envelope.length });
    }

    const response = await protocolFetch(REQUEST_ENDPOINT, envelope);
    if (!response.ok) throw new Error(`v2 request rejected (${response.status})`);
    const responseBytes = new Uint8Array(await response.arrayBuffer());
    const responseEnvelope = decodeEnvelope(responseBytes);
    if (!equalBytes(responseEnvelope.session_id, session.id)) {
      throw new Error('unexpected v2 response envelope');
    }
    session.sequences.accept(sequence, responseEnvelope.sequenceValue);

    const responsePlaintext = await open(
      session.material,
      Direction.SERVER_TO_CLIENT,
      MessageType.APPLICATION,
      session.id,
      sequence,
      responseEnvelope.ciphertext
    );
    const decoded = decodeCBOR(responsePlaintext);
    validateApplicationResponse(decoded);

    if (config.emitEncryptedPayloads) {
      notifyClients('encrypted-response', { sequence: sequence.toString(), size: responseBytes.length });
    }

    const body = decoded.body instanceof Uint8Array
      ? decoded.body
      : decoded.error
        ? new TextEncoder().encode(JSON.stringify({ error: decoded.error }))
        : null;
    return new Response(body, { status: decoded.status, headers: decoded.headers || {} });
  } catch (error) {
    if (!session || state.session === session) resetState(publicError(error));
    notifyClients('error', { message: publicError(error), url: request.url });
    return new Response(JSON.stringify({ error: 'secure channel failed' }), {
      status: 502,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
    });
  }
}

async function currentSession() {
  const session = await ensureSession();
  if (Date.now() - session.createdAt >= ROTATION_INTERVAL_MS) {
    return rotateSession();
  }
  return session;
}

async function ensureSession() {
  if (state.session) return state.session;
  if (!state.sessionPromise) {
    state.sessionPromise = establishSession()
      .then(session => {
        state.session = session;
        state.error = null;
        return session;
      })
      .catch(error => {
        state.error = publicError(error);
        throw error;
      })
      .finally(() => { state.sessionPromise = null; });
  }
  return state.sessionPromise;
}

async function rotateSession() {
  if (state.rotationPromise) return state.rotationPromise;
  notifyClients('status', { stage: 'rotating-session' });
  state.rotationPromise = establishSession()
    .then(session => {
      state.session = session;
      state.error = null;
      notifyClients('key-rotated', { timestamp: session.createdAt });
      return session;
    })
    .finally(() => { state.rotationPromise = null; });
  return state.rotationPromise;
}

async function establishSession() {
  notifyClients('status', { stage: 'creating-session' });
  const clientNonce = crypto.getRandomValues(new Uint8Array(32));
  const clientKeyPair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const clientPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', clientKeyPair.publicKey));
  const contextHash = await hashOrigin(self.location.origin);
  const response = await protocolFetch(
    SESSION_ENDPOINT,
    encodeSessionRequest(clientNonce, clientPublicKey, contextHash)
  );
  if (!response.ok) throw new Error(`session creation rejected (${response.status})`);
  const sessionResponse = decodeSessionResponse(new Uint8Array(await response.arrayBuffer()));
  const transcript = buildTranscript(
    clientNonce,
    clientPublicKey,
    sessionResponse.server_public_key,
    sessionResponse.session_id,
    contextHash
  );
  const transcriptHash = await sha256(transcript);
  const serverPublicKey = await crypto.subtle.importKey(
    'raw',
    sessionResponse.server_public_key,
    { name: 'X25519' },
    false,
    []
  );
  const sharedSecret = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'X25519', public: serverPublicKey },
    clientKeyPair.privateKey,
    256
  ));
  const material = await deriveMaterial(sharedSecret, transcriptHash);

  notifyClients('status', { stage: 'verifying-session-attestation' });
  const attestation = await verify(sessionResponse.attestation_document, { nonce: clientNonce });
  validateAttestationResult(
    attestation,
    sessionResponse.session_id,
    transcriptHash,
    material.binder
  );

  const confirmationCiphertext = await seal(
    material,
    Direction.CLIENT_TO_SERVER,
    MessageType.CONFIRMATION,
    sessionResponse.session_id,
    0n,
    transcriptHash
  );
  const confirmationResponse = await protocolFetch(
    CONFIRM_ENDPOINT,
    encodeEnvelope(sessionResponse.session_id, 0n, confirmationCiphertext)
  );
  if (!confirmationResponse.ok) {
    throw new Error(`session confirmation rejected (${confirmationResponse.status})`);
  }
  const confirmationEnvelope = decodeEnvelope(
    new Uint8Array(await confirmationResponse.arrayBuffer())
  );
  if (confirmationEnvelope.sequenceValue !== 0n
      || !equalBytes(confirmationEnvelope.session_id, sessionResponse.session_id)) {
    throw new Error('unexpected confirmation response');
  }
  const confirmedHash = await open(
    material,
    Direction.SERVER_TO_CLIENT,
    MessageType.CONFIRMATION,
    sessionResponse.session_id,
    0n,
    confirmationEnvelope.ciphertext
  );
  if (!equalBytes(confirmedHash, transcriptHash)) throw new Error('session confirmation mismatch');

  const session = {
    id: sessionResponse.session_id,
    material,
    sequences: new SequenceTracker(),
    createdAt: Date.now(),
    attestation: {
      verified: true,
      pcrs: attestation.pcrs,
      moduleId: attestation.moduleId
    }
  };
  notifyClients('initialized', session.attestation);
  return session;
}

async function protocolFetch(path, body) {
  return fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/cbor' },
    body,
    cache: 'no-store',
    credentials: 'omit',
    redirect: 'error'
  });
}

function validateApplicationResponse(response) {
  if (!response || !Number.isInteger(response.status) || response.status < 200 || response.status > 599) {
    throw new Error('invalid protected application response');
  }
  if (response.headers && (typeof response.headers !== 'object' || Array.isArray(response.headers))) {
    throw new Error('invalid protected application headers');
  }
  if (response.body !== null && response.body !== undefined && !(response.body instanceof Uint8Array)) {
    throw new Error('invalid protected application body');
  }
}

function isPassthrough(path) {
  return config.passthroughPaths.includes(path)
    || config.excludePrefixes.some(prefix => path.startsWith(prefix));
}

function configure(update) {
  const allowed = ['passthroughPaths', 'excludePrefixes', 'emitEncryptedPayloads'];
  for (const key of Object.keys(update)) {
    if (!allowed.includes(key)) throw new Error(`unsupported configuration key: ${key}`);
  }
  if (update.passthroughPaths) validatePathList(update.passthroughPaths);
  if (update.excludePrefixes) validatePathList(update.excludePrefixes);
  config = { ...config, ...update };
}

function validatePathList(values) {
  if (!Array.isArray(values)) throw new Error('passthrough rules must be arrays');
  for (const value of values) {
    if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//')
        || value.includes('?') || value.includes('#')) {
      throw new Error(`invalid bootstrap rule: ${value}`);
    }
  }
}

function statusMessage() {
  return {
    type: 'status',
    initialized: Boolean(state.session),
    error: state.error,
    attestation: state.session?.attestation || null,
    lastKeyRotation: state.session?.createdAt || null,
    protocolVersion: 2
  };
}

function freshState(error = null) {
  return { session: null, sessionPromise: null, rotationPromise: null, error };
}

function resetState(error = null) {
  state = freshState(error);
}

function publicError(error) {
  return error instanceof Error ? error.message : 'secure channel error';
}

async function notifyClients(type, data) {
  const allClients = await self.clients.matchAll({ type: 'window' });
  for (const client of allClients) client.postMessage({ type: `enclave:${type}`, ...data });
}
