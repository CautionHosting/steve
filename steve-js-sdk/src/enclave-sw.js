import { encode as encodeCBOR, decode as decodeCBOR } from 'tee-attestation-js/lib/cbor';
import { ATTESTATION_PROFILE, verifyAttestation } from './attestation-verifier.js';
import {
  CONFIRM_ENDPOINT,
  Direction,
  KEY_DERIVATION,
  KEY_ESTABLISHMENT_SUITE,
  MessageType,
  PROTOCOL_ID,
  REQUEST_ENDPOINT,
  RECORD_PROTECTION,
  SESSION_ENDPOINT,
  SequenceTracker,
  VERSION,
  buildTranscript,
  decodeEnvelope,
  decodeSessionResponse,
  deriveMaterial,
  encodeBase64Url,
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
const PROTOCOL_EXCLUDE_PREFIXES = ['/e2p/'];
const DEFAULT_REQUEST_TIMEOUT_MS = 30 * 1000;
const MIN_REQUEST_TIMEOUT_MS = 1000;
const MAX_REQUEST_TIMEOUT_MS = 5 * 60 * 1000;
const SESSION_ESTABLISH_TIMEOUT_MS = 10 * 1000;
const SESSION_FATAL_HTTP_STATUSES = new Set([400, 401, 409, 425]);
const REQUEST_LOCAL_HTTP_STATUSES = new Set([403, 404, 408, 429]);
const CONFIG_CACHE_NAME = 'steve-sdk-config-v1';
const CONFIG_CACHE_PATH = '.steve-sdk/config-v1';

function defaultConfig() {
  return {
    enclaveOrigin: self.location.origin,
    passthroughPaths: [...DEFAULT_BOOTSTRAP_PATHS],
    excludePrefixes: ['/attestation', '/e2p/'],
    emitEncryptedPayloads: false,
    requestTimeoutMs: DEFAULT_REQUEST_TIMEOUT_MS
  };
}

let config = defaultConfig();
let configRestoreError = null;
let configReady = initializeConfig();

let state = freshState();

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(clients.claim()));
self.addEventListener('message', event => event.waitUntil(handleMessage(event)));
self.addEventListener('fetch', event => {
  event.respondWith(routeRequest(event.request));
});

async function handleMessage(event) {
  const { type } = event.data;
  const port = event.ports[0];
  try {
    await configReady;
    switch (type) {
      case 'get-status':
        port?.postMessage(statusMessage());
        break;
      case 'initialize':
        await ensureSession('explicit-initialize');
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
      case 'configure': {
        await configureAndPersist(event.data.config || {});
        port?.postMessage({ type: 'configured', success: true, config });
        break;
      }
      default:
        throw new Error('unknown service-worker command');
    }
  } catch (error) {
    port?.postMessage({ type, success: false, error: publicError(error) });
  }
}

async function routeRequest(request) {
  await configReady;
  const url = new URL(request.url);
  if (!shouldProtectUrl(url)) return fetch(request);
  return handleProtectedRequest(request);
}

async function handleProtectedRequest(request) {
  let session;
  let sequence;
  try {
    const url = new URL(request.url);
    const requestBody = new Uint8Array(await request.arrayBuffer());
    const plaintext = encodeCBOR({
      method: request.method,
      path: url.pathname + url.search,
      headers: Object.fromEntries(request.headers),
      body: requestBody.length === 0 ? null : requestBody
    });

    session = await currentSession();
    sequence = await session.sequences.allocate();
    const protectedResponse = await withDeadline(
      config.requestTimeoutMs,
      request.signal,
      async signal => {
        throwIfAborted(signal);
        const ciphertext = await seal(
          session.material,
          Direction.CLIENT_TO_SERVER,
          MessageType.APPLICATION,
          session.id,
          sequence,
          plaintext
        );
        throwIfAborted(signal);
        const envelope = encodeEnvelope(session.id, sequence, ciphertext);

        if (config.emitEncryptedPayloads) {
          await notifyClients(
            'encrypted-request',
            encryptedPayloadTrace(session, sequence, envelope)
          );
        }

        const response = await protocolFetch(REQUEST_ENDPOINT, envelope, signal);
        if (!response.ok) {
          throw new ProtocolHttpError(response.status, 'v2 request');
        }
        const responseBytes = new Uint8Array(await response.arrayBuffer());
        throwIfAborted(signal);
        const responseEnvelope = decodeEnvelope(responseBytes);
        if (!equalBytes(responseEnvelope.session_id, session.id)
            || responseEnvelope.sequenceValue !== sequence) {
          throw new Error('unexpected v2 response envelope');
        }

        const responsePlaintext = await open(
          session.material,
          Direction.SERVER_TO_CLIENT,
          MessageType.APPLICATION,
          session.id,
          sequence,
          responseEnvelope.ciphertext
        );
        throwIfAborted(signal);
        const decoded = decodeCBOR(responsePlaintext);
        validateApplicationResponse(decoded);

        const body = decoded.body instanceof Uint8Array
          ? decoded.body
          : decoded.error
            ? new TextEncoder().encode(JSON.stringify({ error: decoded.error }))
            : null;
        return {
          response: new Response(body, { status: decoded.status, headers: decoded.headers || {} }),
          sequenceValue: responseEnvelope.sequenceValue,
          responseEnvelope: responseBytes
        };
      },
      'v2 request timed out'
    );

    session.sequences.accept(sequence, protectedResponse.sequenceValue);
    if (config.emitEncryptedPayloads) {
      await notifyClients(
        'encrypted-response',
        encryptedPayloadTrace(session, sequence, protectedResponse.responseEnvelope)
      );
    }
    return protectedResponse.response;
  } catch (error) {
    if (session && sequence !== undefined && isRequestLocalFailure(error)) {
      session.sequences.retire(sequence);
    } else if (session) {
      session.sequences.close(new Error(publicError(error)));
    }
    if (session
      ? !isRequestLocalFailure(error) && state.session === session
      : !hasValidSession(state.session)) {
      resetState(publicError(error));
    }
    notifyClients('error', {
      message: publicError(error),
      url: request.url,
      stage: session ? 'request' : 'initialization'
    });
    return new Response(JSON.stringify({ error: 'secure channel failed' }), {
      status: error instanceof ProtocolTimeoutError ? 504 : 502,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
    });
  }
}

async function currentSession() {
  const session = await ensureSession('protected-request');
  if (Date.now() - session.createdAt >= ROTATION_INTERVAL_MS) {
    return rotateSession();
  }
  return session;
}

// Indirection so tests can substitute a controllable stub without mocking
// crypto/fetch; production code always leaves this pointed at establishSession.
let establishSessionFn = establishSession;

async function ensureSession(trigger = 'protected-request') {
  if (state.session) return state.session;
  if (!state.sessionPromise) {
    const s = state;
    s.trigger = trigger;
    s.stage = 'creating-session';
    s.sessionPromise = Promise.resolve()
      .then(() => establishSessionFn(trigger, s))
      .then(session => {
        if (state === s) {
          session.trigger = trigger;
          s.session = session;
          s.error = null;
          s.stage = null;
          notifyStatus();
          void notifyClients('initialized', {
            ...session.attestation,
            status: statusMessage()
          });
        }
        return session;
      })
      .catch(error => {
        if (state === s) {
          s.error = publicError(error);
          s.stage = null;
        }
        throw error;
      })
      .finally(() => {
        if (state === s) {
          s.sessionPromise = null;
          notifyStatus();
        }
      });
    notifyStatus();
  }
  return state.sessionPromise;
}

async function rotateSession() {
  if (state.rotationPromise) return state.rotationPromise;
  const s = state;
  s.stage = 'creating-session';
  s.rotationPromise = Promise.resolve().then(() => establishSessionFn('rotation', s));
  notifyStatus();
  let rotatedSession;
  try {
    rotatedSession = await s.rotationPromise;
    if (state === s) {
      rotatedSession.trigger = 'rotation';
      s.session = rotatedSession;
      s.error = null;
      s.stage = null;
    }
    return rotatedSession;
  } finally {
    if (state === s) {
      s.rotationPromise = null;
      s.stage = null;
      notifyStatus();
      if (rotatedSession) {
        void notifyClients('key-rotated', {
          timestamp: rotatedSession.createdAt,
          status: statusMessage()
        });
      }
    }
  }
}

async function establishSession(_trigger, targetState) {
  return withDeadline(
    SESSION_ESTABLISH_TIMEOUT_MS,
    null,
    signal => establishSessionWithinDeadline(signal, targetState),
    'session establishment timed out'
  );
}

async function establishSessionWithinDeadline(signal, targetState) {
  updateStage(targetState, 'creating-session');
  const clientNonce = crypto.getRandomValues(new Uint8Array(32));
  const clientKeyPair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  throwIfAborted(signal);
  const clientPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', clientKeyPair.publicKey));
  throwIfAborted(signal);
  const contextHash = await hashOrigin(self.location.origin);
  throwIfAborted(signal);
  const response = await protocolFetch(
    SESSION_ENDPOINT,
    encodeSessionRequest(clientNonce, clientPublicKey, contextHash),
    signal
  );
  if (!response.ok) throw new ProtocolHttpError(response.status, 'session creation');
  const sessionResponse = decodeSessionResponse(new Uint8Array(await response.arrayBuffer()));
  throwIfAborted(signal);
  const transcript = buildTranscript(
    clientNonce,
    clientPublicKey,
    sessionResponse.server_public_key,
    sessionResponse.session_id,
    contextHash
  );
  const transcriptHash = await sha256(transcript);
  throwIfAborted(signal);
  const serverPublicKey = await crypto.subtle.importKey(
    'raw',
    sessionResponse.server_public_key,
    { name: 'X25519' },
    false,
    []
  );
  throwIfAborted(signal);
  const sharedSecret = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'X25519', public: serverPublicKey },
    clientKeyPair.privateKey,
    256
  ));
  throwIfAborted(signal);
  const material = await deriveMaterial(sharedSecret, transcriptHash);
  throwIfAborted(signal);

  updateStage(targetState, 'verifying-attestation');
  const attestation = await verifyAttestation(
    sessionResponse.attestation_document,
    { nonce: clientNonce }
  );
  throwIfAborted(signal);
  validateAttestationResult(
    attestation,
    sessionResponse.session_id,
    transcriptHash,
    material.binder
  );

  updateStage(targetState, 'confirming-session');
  const confirmationCiphertext = await seal(
    material,
    Direction.CLIENT_TO_SERVER,
    MessageType.CONFIRMATION,
    sessionResponse.session_id,
    0n,
    transcriptHash
  );
  throwIfAborted(signal);
  const confirmationResponse = await protocolFetch(
    CONFIRM_ENDPOINT,
    encodeEnvelope(sessionResponse.session_id, 0n, confirmationCiphertext),
    signal
  );
  if (!confirmationResponse.ok) {
    throw new ProtocolHttpError(confirmationResponse.status, 'session confirmation');
  }
  const confirmationEnvelope = decodeEnvelope(
    new Uint8Array(await confirmationResponse.arrayBuffer())
  );
  throwIfAborted(signal);
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
  throwIfAborted(signal);
  if (!equalBytes(confirmedHash, transcriptHash)) throw new Error('session confirmation mismatch');

  const session = {
    id: sessionResponse.session_id,
    material,
    sequences: new SequenceTracker(),
    createdAt: Date.now(),
    transcriptHash,
    confirmation: 'verified',
    attestation: {
      verified: true,
      profile: ATTESTATION_PROFILE.id,
      trustAnchor: ATTESTATION_PROFILE.trustAnchor,
      synthetic: ATTESTATION_PROFILE.synthetic,
      pcrs: attestation.pcrs,
      moduleId: attestation.moduleId,
      checks: {
        certificateChain: 'verified',
        nonceBinding: 'verified',
        sessionBinding: 'verified',
        keyConfirmation: 'verified',
        expectedPcrPolicy: 'not-checked'
      }
    }
  };
  return session;
}

async function protocolFetch(path, body, signal) {
  try {
    return await fetch(resolveProtocolUrl(path), {
      method: 'POST',
      headers: { 'Content-Type': 'application/cbor' },
      body,
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
      signal
    });
  } catch (error) {
    if (signal?.aborted) throw new ProtocolAbortError();
    throw new ProtocolTransportError(error);
  }
}

class ProtocolTimeoutError extends Error {
  constructor(message = 'v2 operation timed out') {
    super(message);
    this.name = 'ProtocolTimeoutError';
  }
}

class ProtocolAbortError extends Error {
  constructor(message = 'v2 request aborted') {
    super(message);
    this.name = 'ProtocolAbortError';
  }
}

class ProtocolTransportError extends Error {
  constructor(cause) {
    super('v2 transport failed');
    this.name = 'ProtocolTransportError';
    this.cause = cause;
  }
}

class ProtocolHttpError extends Error {
  constructor(status, stage) {
    super(`${stage} rejected (${status})`);
    this.name = 'ProtocolHttpError';
    this.status = status;
  }
}

async function withDeadline(timeoutMs, externalSignal, operation, timeoutMessage) {
  const controller = new AbortController();
  let timedOut = false;
  let forwardAbort;
  const abortPromise = new Promise((_, reject) => {
    controller.signal.addEventListener('abort', () => {
      reject(timedOut
        ? new ProtocolTimeoutError(timeoutMessage)
        : new ProtocolAbortError());
    }, { once: true });
  });

  if (externalSignal) {
    forwardAbort = () => controller.abort(externalSignal.reason);
    if (externalSignal.aborted) {
      forwardAbort();
    } else {
      externalSignal.addEventListener('abort', forwardAbort, { once: true });
    }
  }

  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  try {
    return await Promise.race([
      Promise.resolve().then(() => operation(controller.signal)),
      abortPromise
    ]);
  } finally {
    clearTimeout(timer);
    if (externalSignal && forwardAbort) {
      externalSignal.removeEventListener('abort', forwardAbort);
    }
  }
}

function throwIfAborted(signal) {
  if (signal.aborted) throw new ProtocolAbortError();
}

function isRequestLocalFailure(error) {
  if (error instanceof ProtocolTimeoutError || error instanceof ProtocolAbortError
      || error instanceof ProtocolTransportError) {
    return true;
  }
  if (!(error instanceof ProtocolHttpError)) return false;
  if (SESSION_FATAL_HTTP_STATUSES.has(error.status)) return false;
  return REQUEST_LOCAL_HTTP_STATUSES.has(error.status)
    || (error.status >= 500 && error.status <= 599);
}

function resolveProtocolUrl(path) {
  return new URL(path, `${config.enclaveOrigin}/`).href;
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

function shouldProtectUrl(value) {
  const url = value instanceof URL ? value : new URL(value);
  if (url.origin !== config.enclaveOrigin) return false;
  return !isPassthrough(url);
}

function isPassthrough(url) {
  const localBootstrap = url.origin === self.location.origin
    && config.passthroughPaths.includes(url.pathname);
  return localBootstrap
    || config.excludePrefixes.some(prefix => url.pathname.startsWith(prefix));
}

function configure(update) {
  const allowed = [
    'enclaveOrigin',
    'passthroughPaths',
    'excludePrefixes',
    'emitEncryptedPayloads',
    'requestTimeoutMs'
  ];
  for (const key of Object.keys(update)) {
    if (!allowed.includes(key)) throw new Error(`unsupported configuration key: ${key}`);
  }
  if ('passthroughPaths' in update) validatePathList(update.passthroughPaths);
  if ('excludePrefixes' in update) validatePathList(update.excludePrefixes);
  if ('requestTimeoutMs' in update) validateRequestTimeout(update.requestTimeoutMs);

  const next = { ...config, ...update };
  if ('enclaveOrigin' in update) {
    next.enclaveOrigin = normalizeEnclaveOrigin(update.enclaveOrigin);
  }
  next.passthroughPaths = [
    ...new Set([...DEFAULT_BOOTSTRAP_PATHS, ...next.passthroughPaths])
  ];
  next.excludePrefixes = [
    ...new Set([...PROTOCOL_EXCLUDE_PREFIXES, ...next.excludePrefixes])
  ];
  const enclaveChanged = next.enclaveOrigin !== config.enclaveOrigin;
  if (enclaveChanged) resetState();
  config = next;
}

async function initializeConfig() {
  try {
    await restoreConfig();
    configRestoreError = null;
  } catch (error) {
    configRestoreError = publicError(error);
  }
}

async function configureAndPersist(update) {
  const previous = config;
  configure(update);
  try {
    await persistConfig();
    configRestoreError = null;
  } catch (error) {
    config = previous;
    throw error;
  }
}

function configCacheKey() {
  if (typeof self.registration?.scope !== 'string') {
    throw new Error('service worker scope unavailable');
  }
  return new URL(CONFIG_CACHE_PATH, self.registration.scope).href;
}

async function restoreConfig() {
  if (!self.caches) return;
  const cache = await self.caches.open(CONFIG_CACHE_NAME);
  const response = await cache.match(configCacheKey());
  if (response) configure(await response.json());
}

async function persistConfig() {
  if (!self.caches) return;
  const cache = await self.caches.open(CONFIG_CACHE_NAME);
  await cache.put(
    configCacheKey(),
    new Response(JSON.stringify(config), {
      headers: { 'Content-Type': 'application/json' }
    })
  );
}

function normalizeEnclaveOrigin(value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error('enclaveOrigin must be an absolute HTTP(S) origin');
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error('enclaveOrigin must be an absolute HTTP(S) origin');
  }
  if (!['http:', 'https:'].includes(url.protocol)
      || url.username || url.password
      || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('enclaveOrigin must be an absolute HTTP(S) origin');
  }
  return url.origin;
}

function validateRequestTimeout(value) {
  if (!Number.isInteger(value)
      || value < MIN_REQUEST_TIMEOUT_MS
      || value > MAX_REQUEST_TIMEOUT_MS) {
    throw new Error(
      `requestTimeoutMs must be an integer between ${MIN_REQUEST_TIMEOUT_MS} and ${MAX_REQUEST_TIMEOUT_MS}`
    );
  }
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
  const session = state.session;
  return {
    type: 'status',
    state: lifecycleState(),
    stage: state.stage,
    initialized: Boolean(session),
    error: state.error,
    protocol: {
      id: PROTOCOL_ID,
      version: VERSION,
      keyEstablishment: KEY_ESTABLISHMENT_SUITE,
      keyDerivation: KEY_DERIVATION,
      recordProtection: RECORD_PROTECTION
    },
    session: session
      ? {
          id: encodeDiagnosticBytes(session.id),
          transcriptHash: encodeDiagnosticBytes(session.transcriptHash),
          establishedAt: session.createdAt,
          rotatesAt: session.createdAt + ROTATION_INTERVAL_MS,
          trigger: session.trigger || null,
          confirmation: session.confirmation || 'verified'
        }
      : null,
    attestationVerifier: ATTESTATION_PROFILE,
    attestation: session?.attestation || null,
    lastKeyRotation: session?.createdAt || null,
    protocolVersion: VERSION
  };
}

function encodeDiagnosticBytes(value) {
  return value instanceof Uint8Array ? encodeBase64Url(value) : null;
}

function encryptedPayloadTrace(session, sequence, envelope) {
  return {
    endpoint: REQUEST_ENDPOINT,
    sessionId: encodeDiagnosticBytes(session.id),
    sequence: sequence.toString(),
    size: envelope.length,
    envelope: encodeBase64Url(envelope)
  };
}

function lifecycleState() {
  if (state.rotationPromise) return 'rotating';
  if (state.session) return 'ready';
  if (state.sessionPromise) return 'establishing';
  if (state.error) return 'error';
  return 'idle';
}

function hasValidSession(session) {
  return Boolean(session) && Date.now() - session.createdAt < ROTATION_INTERVAL_MS;
}

function freshState(error = null) {
  return {
    session: null,
    sessionPromise: null,
    rotationPromise: null,
    error,
    stage: null,
    trigger: null
  };
}

function resetState(error = null) {
  state.session?.sequences?.close(new Error(error || 'secure channel reset'));
  state = freshState(error);
  notifyStatus();
}

function publicError(error) {
  return error instanceof Error ? error.message : 'secure channel error';
}

async function notifyClients(type, data) {
  const allClients = await self.clients.matchAll({ type: 'window' });
  for (const client of allClients) client.postMessage({ ...data, type: `enclave:${type}` });
}

function notifyStatus() {
  void notifyClients('status', statusMessage());
}

function updateStage(targetState, stage) {
  if (state !== targetState) return;
  targetState.stage = stage;
  notifyStatus();
}

// Test-only surface, attached as a plain global rather than an ESM export.
// This file is bundled by esbuild and shipped as dist/enclave-sw.js, which is
// registered as a *classic* (non-module) service worker script (see
// register.js: navigator.serviceWorker.register() with no `type: 'module'`).
// A top-level `export` statement would survive bundling and throw a
// SyntaxError when that classic script is parsed by the browser, so tests
// reach internals via `self.__ENCLAVE_SW_TEST__` instead. Do not use outside
// tests.
self.__ENCLAVE_SW_TEST__ = {
  configure,
  hasValidSession,
  lifecycleState,
  statusMessage,
  resetState,
  ensureSession,
  rotateSession,
  handleProtectedRequest,
  protocolFetch,
  withDeadline,
  ProtocolHttpError,
  ProtocolTimeoutError,
  ProtocolTransportError,
  isRequestLocalFailure,
  configureAndPersist,
  configCacheKey,
  initializeConfig,
  persistConfig,
  restoreConfig,
  resolveProtocolUrl,
  shouldProtectUrl,
  getConfigRestoreError: () => configRestoreError,
  getState: () => state,
  getConfig: () => config,
  resetConfig: () => { config = defaultConfig(); },
  setEstablishSession: fn => { establishSessionFn = fn; },
  resetEstablishSession: () => { establishSessionFn = establishSession; }
};
