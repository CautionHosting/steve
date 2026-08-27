import {
  decode as decodeCBOR,
  encode as encodeCBOR
} from 'tee-attestation-js/lib/cbor';
import { ATTESTATION_PROFILE, verifyAttestation } from './attestation-verifier.js';
import { createClientKeyExchange, loadVerifiedXWingModule } from './key-exchange.js';
import {
  createBrowserPcrPolicyStorage,
  enforceTofuPcrPolicy,
  normalizePcrPolicy,
  pcrPoliciesEqual,
  verifyPinnedPcrPolicy
} from './pcr-policy.js';
import {
  CONFIRM_ENDPOINT,
  DEFAULT_KEY_EXCHANGE,
  Direction,
  KEY_DERIVATION,
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
  requireKeyExchange,
  seal,
  sha256,
  validateAttestationResult
} from './protocol-v2.js';

const DEFAULT_BOOTSTRAP_PATHS = [
  '/enclave-sw.js',
  '/register.js',
  '/attestation-widget.js',
  '/xwing/steve_xwing_wasm_bg.wasm'
];
const SCOPED_BOOTSTRAP_PATHS = [
  'enclave-sw.js',
  'register.js',
  'attestation-widget.js',
  'xwing/steve_xwing_wasm_bg.wasm'
];
const SAFE_BOOTSTRAP_METHODS = new Set(['GET', 'HEAD']);
const ROTATION_INTERVAL_MS = 25 * 60 * 1000;
const PROTOCOL_EXCLUDE_PREFIXES = ['/e2p/'];
const DEFAULT_REQUEST_TIMEOUT_MS = 30 * 1000;
const MIN_REQUEST_TIMEOUT_MS = 1000;
const MAX_REQUEST_TIMEOUT_MS = 5 * 60 * 1000;
const SESSION_ESTABLISH_TIMEOUT_MS = 10 * 1000;
const MAX_SESSION_RESPONSE_BYTES = 64 * 1024;
const MAX_CONFIRMATION_RESPONSE_BYTES = 4 * 1024;
const MAX_APPLICATION_RESPONSE_BYTES = 32 * 1024 * 1024 + 64 * 1024;
const SESSION_FATAL_HTTP_STATUSES = new Set([400, 401, 409, 425]);
const REQUEST_LOCAL_HTTP_STATUSES = new Set([403, 404, 408, 413, 429]);
const CONFIG_CACHE_NAME = 'steve-sdk-config-v1';
const CONFIG_CACHE_PATH = '.steve-sdk/config-v1';

function defaultConfig() {
  return {
    enclaveOrigin: self.location.origin,
    passthroughPaths: [...DEFAULT_BOOTSTRAP_PATHS],
    excludePrefixes: ['/attestation', '/e2p/'],
    emitEncryptedPayloads: false,
    requestTimeoutMs: DEFAULT_REQUEST_TIMEOUT_MS,
    expectedKeyExchange: DEFAULT_KEY_EXCHANGE,
    pcrPolicy: null
  };
}

let config = defaultConfig();
let configRestoreError = null;
let configurationReady = false;
let configurationTail = Promise.resolve();
let configGeneration = 0;
let pcrStorage = globalThis.__STEVE_ENABLE_TEST_HOOKS__ === true
  && self.__STEVE_PCR_STORAGE_TEST__
  ? self.__STEVE_PCR_STORAGE_TEST__
  : createBrowserPcrPolicyStorage();
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
        port?.postMessage({ type: 'initialized', success: true, status: statusMessage() });
        break;
      case 'rotate-session':
      case 'rotate-key':
        await rotateSession();
        port?.postMessage({ type: 'session-rotated', success: true, status: statusMessage() });
        break;
      case 'reset':
        resetState();
        port?.postMessage({ type: 'reset', success: true, status: statusMessage() });
        break;
      case 'configure': {
        await configureAndPersist(event.data.config || {});
        port?.postMessage({
          type: 'configured',
          success: true,
          config,
          status: statusMessage()
        });
        break;
      }
      case 'protected-send': {
        const result = await protectedSend(event.data.request);
        port?.postMessage({ type: 'protected-response', success: true, ...result });
        break;
      }
      case 'get-pcr-policy':
        await configurationTail;
        requireConfiguration();
        port?.postMessage({
          type: 'pcr-policy',
          success: true,
          policy: clonePcrPolicy()
        });
        break;
      case 'replace-pcr-policy': {
        await configureAndPersist({ pcrPolicy: event.data.policy });
        port?.postMessage({
          type: 'pcr-policy-replaced',
          success: true,
          policy: clonePcrPolicy(),
          status: statusMessage()
        });
        break;
      }
      default:
        throw new Error('unknown service-worker command');
    }
  } catch (error) {
    port?.postMessage({
      type,
      success: false,
      error: errorDetails(error, commandStage(type))
    });
  }
}

async function protectedSend(input) {
  requireConfiguration();
  const requestConfig = config;
  const requestGeneration = configGeneration;
  const request = deserializeProtectedRequest(input, requestConfig);
  const result = await handleProtectedRequest(
    request,
    requestConfig,
    requestGeneration,
    true
  );
  return {
    status: result.response.status,
    headers: [...result.response.headers.entries()],
    body: new Uint8Array(await result.response.arrayBuffer()),
    sessionId: result.sessionId,
    exchange: result.exchange
  };
}

function deserializeProtectedRequest(input, activeConfig) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw sdkError('INVALID_REQUEST', 'request', 'protected request must be an object');
  }
  const path = input.path;
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//')) {
    throw sdkError('INVALID_REQUEST', 'request', 'protected request path must be relative');
  }
  const url = new URL(path, `${activeConfig.enclaveOrigin}/`);
  if (url.origin !== activeConfig.enclaveOrigin || url.hash) {
    throw sdkError('INVALID_REQUEST', 'request', 'protected request path must be relative');
  }
  if (!Array.isArray(input.headers)
      || input.headers.some(header => !Array.isArray(header)
        || header.length !== 2
        || typeof header[0] !== 'string'
        || typeof header[1] !== 'string')) {
    throw sdkError('INVALID_REQUEST', 'request', 'protected request headers are invalid');
  }
  const method = typeof input.method === 'string' ? input.method.toUpperCase() : 'GET';
  const body = input.body instanceof Uint8Array
    ? input.body
    : input.body instanceof ArrayBuffer
      ? new Uint8Array(input.body)
      : null;
  try {
    return new Request(url, {
      method,
      headers: input.headers,
      body: body?.length ? body : undefined,
      credentials: 'omit',
      redirect: 'error'
    });
  } catch (cause) {
    throw sdkError('INVALID_REQUEST', 'request', 'protected request is invalid', cause);
  }
}

async function routeRequest(request) {
  await configReady;
  await configurationTail;
  if (!configurationReady || configRestoreError) {
    if (fixedBootstrapDisposition(request, new URL(request.url)) === true) {
      return fetch(request);
    }
    return configurationFailureResponse();
  }
  const requestConfig = config;
  const requestGeneration = configGeneration;
  if (!shouldProtectRequest(request, requestConfig)) return fetch(request);
  return handleProtectedRequest(request, requestConfig, requestGeneration);
}

async function handleProtectedRequest(
  request,
  requestConfig = config,
  requestGeneration = configGeneration,
  returnDetails = false
) {
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
    if (requestGeneration !== configGeneration
        || session.configGeneration !== requestGeneration) {
      throw new Error('configuration changed before protected request');
    }
    sequence = await session.sequences.allocate();
    const protectedResponse = await withDeadline(
      requestConfig.requestTimeoutMs,
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

        if (requestConfig.emitEncryptedPayloads) {
          await notifyClients(
            'encrypted-request',
            encryptedPayloadTrace(session, sequence, envelope)
          );
        }

        const response = await protocolFetch(
          REQUEST_ENDPOINT,
          envelope,
          signal,
          session.enclaveOrigin
        );
        const outerStatus = response.status;
        if (!response.ok) {
          throw new ProtocolHttpError(outerStatus, 'request', 'v2 request');
        }
        const responseBytes = await readBoundedResponse(
          response,
          MAX_APPLICATION_RESPONSE_BYTES
        );
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
          response: new Response(body, { status: decoded.status, headers: decoded.headers }),
          sequenceValue: responseEnvelope.sequenceValue,
          responseEnvelope: responseBytes,
          exchange: {
            protocolName: PROTOCOL_ID,
            protection: RECORD_PROTECTION,
            sessionId: encodeDiagnosticBytes(session.id),
            sequence: sequence.toString(),
            keyExchange: session.keyExchange,
            pcrTrust: session.attestation.pcrTrust,
            outerStatus,
            requestPlaintextBytes: plaintext.length,
            requestCiphertextBytes: ciphertext.length,
            requestEnvelopeBytes: envelope.length,
            responseEnvelopeBytes: responseBytes.length,
            responseCiphertextBytes: responseEnvelope.ciphertext.length,
            responsePlaintextBytes: responsePlaintext.length
          }
        };
      },
      'v2 request timed out',
      'request'
    );

    session.sequences.accept(sequence, protectedResponse.sequenceValue);
    if (requestConfig.emitEncryptedPayloads) {
      await notifyClients(
        'encrypted-response',
        encryptedPayloadTrace(session, sequence, protectedResponse.responseEnvelope)
      );
    }
    return returnDetails
      ? {
          response: protectedResponse.response,
          sessionId: encodeDiagnosticBytes(session.id),
          exchange: protectedResponse.exchange
        }
      : protectedResponse.response;
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
    const requestUrl = new URL(request.url);
    notifyClients('error', {
      ...errorDetails(error, session ? 'request' : 'initialization'),
      operation: session ? 'request' : 'initialization',
      url: requestUrl.origin + requestUrl.pathname,
    });
    if (returnDetails) throw error;
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
  requireConfiguration();
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
  requireConfiguration();
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
    'session establishment timed out',
    'initialization'
  );
}

async function establishSessionWithinDeadline(signal, targetState) {
  const sessionConfig = config;
  const sessionGeneration = configGeneration;
  const keyExchange = sessionConfig.expectedKeyExchange;
  updateStage(targetState, 'creating-session');
  const clientNonce = crypto.getRandomValues(new Uint8Array(32));
  const clientKeyExchange = await createClientKeyExchange(
    keyExchange,
    loadVerifiedXWingModule
  );
  try {
    throwIfAborted(signal);
    const clientKeyMaterial = clientKeyExchange.publicKey;
    const contextHash = await hashOrigin(self.location.origin);
    throwIfAborted(signal);
    const response = await protocolFetch(
      SESSION_ENDPOINT,
      encodeSessionRequest(
        keyExchange,
        clientNonce,
        clientKeyMaterial,
        contextHash
      ),
      signal,
      sessionConfig.enclaveOrigin
    );
    if (!response.ok) {
      throw new ProtocolHttpError(response.status, 'initialization', 'session creation');
    }
    const sessionResponse = decodeSessionResponse(
      await readBoundedResponse(response, MAX_SESSION_RESPONSE_BYTES),
      keyExchange
    );
    throwIfAborted(signal);
    const transcript = buildTranscript(
      keyExchange,
      clientNonce,
      clientKeyMaterial,
      sessionResponse.server_key_material,
      sessionResponse.session_id,
      contextHash
    );
    const transcriptHash = await sha256(transcript);
    throwIfAborted(signal);
    const sharedSecret = await clientKeyExchange.decapsulate(
      sessionResponse.server_key_material
    );
    const material = await deriveMaterial(sharedSecret, transcriptHash);
    throwIfAborted(signal);

    updateStage(targetState, 'verifying-attestation');
    let attestation;
    try {
      attestation = await verifyAttestation(
        sessionResponse.attestation_document,
        { nonce: clientNonce }
      );
      throwIfAborted(signal);
      validateAttestationResult(
        attestation,
        keyExchange,
        sessionResponse.session_id,
        transcriptHash,
        material.binder
      );
    } catch (cause) {
      if (cause?.code === 'ABORTED') throw cause;
      throw sdkError(
        'ATTESTATION_INVALID',
        'attestation',
        publicError(cause),
        cause
      );
    }
    const pinnedTrust = sessionConfig.pcrPolicy?.mode === 'pinned'
      ? verifyPinnedPcrPolicy(sessionConfig.pcrPolicy, attestation.pcrs)
      : null;

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
      signal,
      sessionConfig.enclaveOrigin
    );
    if (!confirmationResponse.ok) {
      throw new ProtocolHttpError(
        confirmationResponse.status,
        'confirmation',
        'session confirmation'
      );
    }
    const confirmationEnvelope = decodeEnvelope(
      await readBoundedResponse(confirmationResponse, MAX_CONFIRMATION_RESPONSE_BYTES)
    );
    throwIfAborted(signal);
    if (confirmationEnvelope.sequenceValue !== 0n
        || !equalBytes(confirmationEnvelope.session_id, sessionResponse.session_id)) {
      throw sdkError(
        'CONFIRMATION_INVALID',
        'confirmation',
        'unexpected confirmation response'
      );
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
    if (!equalBytes(confirmedHash, transcriptHash)) {
      throw sdkError(
        'CONFIRMATION_INVALID',
        'confirmation',
        'session confirmation mismatch'
      );
    }

    const pcrTrust = await finalizePcrTrust(
      sessionConfig,
      sessionGeneration,
      targetState,
      attestation.pcrs,
      pinnedTrust,
      signal
    );

    const session = {
      id: sessionResponse.session_id,
      keyExchange,
      material,
      sequences: new SequenceTracker(),
      createdAt: Date.now(),
      enclaveOrigin: sessionConfig.enclaveOrigin,
      configGeneration: sessionGeneration,
      transcriptHash,
      confirmation: 'verified',
      attestation: {
        verified: true,
        profile: ATTESTATION_PROFILE.id,
        trustAnchor: ATTESTATION_PROFILE.trustAnchor,
        synthetic: ATTESTATION_PROFILE.synthetic,
        pcrs: attestation.pcrs,
        pcrTrust,
        moduleId: attestation.moduleId,
        checks: {
          certificateChain: 'verified',
          nonceBinding: 'verified',
          sessionBinding: 'verified',
          keyConfirmation: 'verified',
          expectedPcrPolicy: pcrTrust === 'not-checked' ? 'not-checked' : 'verified'
        }
      }
    };
    return session;
  } finally {
    clientKeyExchange.destroy();
  }
}

async function finalizePcrTrust(
  sessionConfig,
  sessionGeneration,
  targetState,
  observedPcrs,
  pinnedTrust,
  signal
) {
  return serializeConfiguration(async () => {
    throwIfAborted(signal);
    if (config !== sessionConfig
        || configGeneration !== sessionGeneration
        || state !== targetState) {
      throw new Error('configuration changed during session establishment');
    }
    if (!sessionConfig.pcrPolicy) return 'not-checked';
    if (pinnedTrust) return pinnedTrust;

    const status = await enforceTofuPcrPolicy(
      sessionConfig.pcrPolicy,
      observedPcrs,
      {
        scope: serviceWorkerScope(),
        enclaveOrigin: sessionConfig.enclaveOrigin,
        suite: sessionConfig.expectedKeyExchange
      },
      pcrStorage
    );
    throwIfAborted(signal);
    return status;
  });
}

function clonePcrPolicy() {
  return config.pcrPolicy === null
    ? null
    : JSON.parse(JSON.stringify(config.pcrPolicy));
}

async function protocolFetch(path, body, signal, enclaveOrigin = config.enclaveOrigin) {
  const stage = path === REQUEST_ENDPOINT
    ? 'request'
    : path === CONFIRM_ENDPOINT
      ? 'confirmation'
      : 'initialization';
  try {
    return await fetch(resolveProtocolUrl(path, enclaveOrigin), {
      method: 'POST',
      headers: { 'Content-Type': 'application/cbor' },
      body,
      credentials: 'omit',
      redirect: 'error',
      signal
    });
  } catch (error) {
    if (signal?.aborted) throw new ProtocolAbortError(undefined, stage);
    throw new ProtocolTransportError(error, stage);
  }
}

function requireConfiguration() {
  if (!configurationReady || configRestoreError) {
    throw sdkError(
      'CONFIGURATION_UNAVAILABLE',
      'configuration',
      configRestoreError || 'service worker configuration unavailable'
    );
  }
}

function configurationFailureResponse() {
  return new Response(JSON.stringify({ error: 'secure channel unavailable' }), {
    status: 503,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
  });
}

async function readBoundedResponse(response, limit) {
  const declaredLength = response.headers.get('content-length');
  if (declaredLength !== null && /^[0-9]+$/u.test(declaredLength)) {
    const length = Number(declaredLength);
    if (!Number.isSafeInteger(length) || length > limit) {
      throw new Error('protocol response too large');
    }
  }
  if (!response.body) return new Uint8Array();

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value.byteLength > limit - total) {
        await reader.cancel().catch(() => {});
        throw new Error('protocol response too large');
      }
      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

class ProtocolTimeoutError extends Error {
  constructor(message = 'v2 operation timed out', stage = 'request') {
    super(message);
    this.name = 'ProtocolTimeoutError';
    this.code = 'TIMEOUT';
    this.stage = stage;
  }
}

class ProtocolAbortError extends Error {
  constructor(message = 'v2 request aborted', stage = 'request') {
    super(message);
    this.name = 'ProtocolAbortError';
    this.code = 'ABORTED';
    this.stage = stage;
  }
}

class ProtocolTransportError extends Error {
  constructor(cause, stage = 'transport') {
    super('v2 transport failed');
    this.name = 'ProtocolTransportError';
    this.code = 'TRANSPORT';
    this.stage = stage;
    this.cause = cause;
  }
}

class ProtocolHttpError extends Error {
  constructor(status, stage, operation = stage) {
    super(`${operation} rejected (${status})`);
    this.name = 'ProtocolHttpError';
    this.code = 'HTTP_STATUS';
    this.stage = stage;
    this.status = status;
    this.httpStatus = status;
  }
}

async function withDeadline(
  timeoutMs,
  externalSignal,
  operation,
  timeoutMessage,
  stage = 'request'
) {
  const controller = new AbortController();
  let timedOut = false;
  let forwardAbort;
  const abortPromise = new Promise((_, reject) => {
    controller.signal.addEventListener('abort', () => {
      reject(timedOut
        ? new ProtocolTimeoutError(timeoutMessage, stage)
        : new ProtocolAbortError(undefined, stage));
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

function resolveProtocolUrl(path, enclaveOrigin = config.enclaveOrigin) {
  return new URL(path, `${enclaveOrigin}/`).href;
}

function validateApplicationResponse(response) {
  if (!response || !Number.isInteger(response.status) || response.status < 200 || response.status > 599) {
    throw new Error('invalid protected application response');
  }
  if (!Array.isArray(response.headers)
      || response.headers.some(header => !Array.isArray(header)
        || header.length !== 2
        || typeof header[0] !== 'string'
        || typeof header[1] !== 'string')) {
    throw new Error('invalid protected application headers');
  }
  if (response.body !== null && response.body !== undefined && !(response.body instanceof Uint8Array)) {
    throw new Error('invalid protected application body');
  }
  if (Object.prototype.hasOwnProperty.call(response, 'error')
      && typeof response.error !== 'string') {
    throw new Error('invalid protected application error');
  }
}

function shouldProtectRequest(request, activeConfig = config) {
  const url = new URL(request.url);
  if (url.origin !== activeConfig.enclaveOrigin) return false;
  return !isPassthrough(request, url, activeConfig);
}

function isPassthrough(request, url, activeConfig = config) {
  const fixedBootstrap = fixedBootstrapDisposition(request, url);
  if (fixedBootstrap !== null) return fixedBootstrap;
  const localOrigin = url.origin === self.location.origin;
  const configuredPassthrough = activeConfig.passthroughPaths.includes(url.pathname);
  const localBootstrap = localOrigin && configuredPassthrough;
  return (localBootstrap && SAFE_BOOTSTRAP_METHODS.has(request.method))
    || activeConfig.excludePrefixes.some(prefix => url.pathname.startsWith(prefix));
}

function fixedBootstrapDisposition(request, url) {
  const localOrigin = url.origin === self.location.origin;
  const registrationScope = new URL(self.registration.scope);
  const bootstrapNavigation = localOrigin
    && (url.pathname === '/' || url.pathname === registrationScope.pathname)
    && request.method === 'GET'
    && request.mode === 'navigate'
    && request.destination === 'document';
  if (bootstrapNavigation) return true;

  const bootstrapNavigationTarget = localOrigin
    && (url.pathname === '/' || url.pathname === registrationScope.pathname)
    && request.mode === 'navigate'
    && request.destination === 'document';
  if (bootstrapNavigationTarget) return false;

  const builtInBootstrap = localOrigin
    && (
      DEFAULT_BOOTSTRAP_PATHS.includes(url.pathname)
      || SCOPED_BOOTSTRAP_PATHS.some(
        path => new URL(path, registrationScope).pathname === url.pathname
      )
  );
  if (builtInBootstrap) return SAFE_BOOTSTRAP_METHODS.has(request.method);
  return null;
}

function configure(update) {
  const allowed = [
    'enclaveOrigin',
    'passthroughPaths',
    'excludePrefixes',
    'emitEncryptedPayloads',
    'requestTimeoutMs',
    'expectedKeyExchange',
    'pcrPolicy'
  ];
  for (const key of Object.keys(update)) {
    if (!allowed.includes(key)) throw new Error(`unsupported configuration key: ${key}`);
  }
  if ('passthroughPaths' in update) validatePathList(update.passthroughPaths);
  if ('excludePrefixes' in update) validatePathList(update.excludePrefixes);
  if ('requestTimeoutMs' in update) validateRequestTimeout(update.requestTimeoutMs);
  if ('expectedKeyExchange' in update) {
    requireKeyExchange(update.expectedKeyExchange);
  }
  let nextPolicy = config.pcrPolicy;
  if ('pcrPolicy' in update) {
    try {
      nextPolicy = normalizePcrPolicy(update.pcrPolicy);
    } catch (cause) {
      throw sdkError('PCR_POLICY_INVALID', 'configuration', publicError(cause), cause);
    }
  }

  const next = { ...config, ...update, pcrPolicy: nextPolicy };
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
  const keyExchangeChanged = next.expectedKeyExchange !== config.expectedKeyExchange;
  const pcrPolicyChanged = !pcrPoliciesEqual(next.pcrPolicy, config.pcrPolicy);
  if (enclaveChanged || keyExchangeChanged || pcrPolicyChanged) {
    configGeneration += 1;
    resetState();
  }
  config = next;
}

async function initializeConfig() {
  configurationReady = false;
  try {
    await restoreConfig();
    configRestoreError = null;
  } catch (error) {
    configRestoreError = publicError(error);
  }
}

async function configureAndPersist(update) {
  return serializeConfiguration(() => configureAndPersistNow(update));
}

async function configureAndPersistNow(update) {
  const previous = config;
  let policyRequired;
  try {
    policyRequired = await pcrStorage.isPolicyRequired(serviceWorkerScope());
  } catch (error) {
    blockConfiguration(previous, error);
    throw error;
  }
  if (policyRequired && !previous.pcrPolicy && !('pcrPolicy' in update)) {
    const error = new Error('persisted PCR policy configuration is missing');
    blockConfiguration(previous, error);
    throw error;
  }
  configure(update);
  try {
    if (!policyRequired && config.pcrPolicy) {
      await pcrStorage.setPolicyRequired(serviceWorkerScope(), true);
    }
    await persistConfig();
    if (policyRequired && !config.pcrPolicy) {
      await pcrStorage.setPolicyRequired(serviceWorkerScope(), false);
    }
    configurationReady = true;
    configRestoreError = null;
  } catch (error) {
    blockConfiguration(previous, error);
    throw error;
  }
}

function blockConfiguration(previous, error) {
  config = previous;
  configurationReady = false;
  configRestoreError = publicError(error);
  resetState(configRestoreError);
}

function serializeConfiguration(operation) {
  const result = configurationTail.then(operation);
  configurationTail = result.catch(() => {});
  return result;
}

function configCacheKey() {
  if (typeof self.registration?.scope !== 'string') {
    throw new Error('service worker scope unavailable');
  }
  return new URL(CONFIG_CACHE_PATH, self.registration.scope).href;
}

async function restoreConfig() {
  const policyRequired = await pcrStorage.isPolicyRequired(serviceWorkerScope());
  if (!self.caches) throw new Error('configuration storage unavailable');
  const cache = await self.caches.open(CONFIG_CACHE_NAME);
  const response = await cache.match(configCacheKey());
  if (!response) {
    if (policyRequired) throw new Error('persisted PCR policy configuration is missing');
    return;
  }
  configure(await response.json());
  if (policyRequired && !config.pcrPolicy) {
    throw new Error('persisted PCR policy configuration is missing');
  }
  if (config.pcrPolicy && !policyRequired) {
    await pcrStorage.setPolicyRequired(serviceWorkerScope(), true);
  }
  configurationReady = true;
}

async function persistConfig() {
  if (!self.caches) throw new Error('configuration storage unavailable');
  const cache = await self.caches.open(CONFIG_CACHE_NAME);
  await cache.put(
    configCacheKey(),
    new Response(JSON.stringify(config), {
      headers: { 'Content-Type': 'application/json' }
    })
  );
}

function serviceWorkerScope() {
  if (typeof self.registration?.scope !== 'string') {
    throw new Error('service worker scope unavailable');
  }
  return new URL(self.registration.scope).href;
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
    error: state.error || configRestoreError,
    protocol: {
      id: PROTOCOL_ID,
      version: VERSION,
      keyEstablishment: session?.keyExchange || config.expectedKeyExchange,
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
  if (state.error || configRestoreError) return 'error';
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

function sdkError(code, stage, message, cause, httpStatus) {
  const error = new Error(message);
  error.code = code;
  error.stage = stage;
  if (cause !== undefined) error.cause = cause;
  if (httpStatus !== undefined) error.httpStatus = httpStatus;
  return error;
}

function errorDetails(error, fallbackStage = 'internal') {
  const stage = typeof error?.stage === 'string' ? error.stage : fallbackStage;
  const details = {
    code: typeof error?.code === 'string'
      ? error.code
      : `${stage.replaceAll('-', '_').toUpperCase()}_FAILED`,
    stage,
    message: publicError(error)
  };
  const httpStatus = error?.httpStatus ?? error?.status;
  if (Number.isInteger(httpStatus)) details.httpStatus = httpStatus;
  return details;
}

function commandStage(type) {
  switch (type) {
    case 'configure':
    case 'get-pcr-policy':
    case 'replace-pcr-policy':
      return 'configuration';
    case 'rotate-key':
    case 'rotate-session':
      return 'rotation';
    case 'protected-send':
      return 'request';
    case 'initialize':
      return 'initialization';
    default:
      return 'service-worker';
  }
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

globalThis.__STEVE_ENABLE_TEST_HOOKS__ === true && (self.__ENCLAVE_SW_TEST__ = {
  handleMessage,
  configure,
  hasValidSession,
  lifecycleState,
  statusMessage,
  resetState,
  ensureSession,
  rotateSession,
  handleProtectedRequest,
  protectedSend,
  protocolFetch,
  readBoundedResponse,
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
  finalizePcrTrust,
  errorDetails,
  resolveProtocolUrl,
  shouldProtectRequest,
  getConfigRestoreError: () => configRestoreError,
  isConfigurationReady: () => configurationReady,
  getConfigGeneration: () => configGeneration,
  getState: () => state,
  getConfig: () => config,
  resetConfig: () => {
    config = defaultConfig();
    configurationReady = false;
    configRestoreError = null;
  },
  setPcrStorage: storage => { pcrStorage = storage; },
  setEstablishSession: fn => { establishSessionFn = fn; },
  resetEstablishSession: () => { establishSessionFn = establishSession; }
});
