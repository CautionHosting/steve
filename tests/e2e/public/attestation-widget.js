import { registerEnclaveServiceWorker } from './register.js';

const KEY_EXCHANGE_META = 'meta[name="steve-key-exchange"]';
const PROFILE_META = 'meta[name="steve-profile"]';
const DEFAULT_ORIGIN_META = 'meta[name="steve-default-origin"]';
const REQUEST_TIMEOUT_META = 'meta[name="steve-request-timeout-ms"]';
const EXPECTED_PCR_META = index => `meta[name="steve-expected-pcr${index}"]`;
const RECOVERY_PARAM = 'steve-sw-recovery';
const MAX_EVENTS = 100;
const FIXTURE_CONTRACT = 'steve-test-fixture/v1';
const CONTROLLED_TIMEOUT_MS = 3000;
const CONTROLLED_DELAY_MS = 5000;
const supportedKeyExchanges = new Set(['X25519', 'XWING-DRAFT10']);
const elements = Object.fromEntries(
  [
    'target-form',
    'target-origin-input',
    'target-suite-input',
    'apply-target',
    'trust-warning',
    'system-status',
    'runtime-worker',
    'session-state',
    'session-stage',
    'session-trigger',
    'protocol-id',
    'key-establishment',
    'key-derivation',
    'record-protection',
    'session-id',
    'transcript-hash',
    'established-at',
    'rotates-at',
    'attestation-profile',
    'trust-anchor',
    'module-id',
    'pcr-trust',
    'verification-checks',
    'pcr-details',
    'pcr-values',
    'pcr-policy-note',
    'target-origin',
    'target-kind',
    'boundary-note',
    'request-body',
    'application-request-meta',
    'application-request-body',
    'wire-request-meta',
    'wire-request-envelope',
    'wire-response-meta',
    'wire-response-envelope',
    'application-response-meta',
    'application-response-body',
    'scenario-result',
    'events',
    'raw-status'
  ].map(id => [id, document.querySelector(`#${id}`)])
);
const actionButtons = [...document.querySelectorAll('button[data-action]')];
const requestActions = new Set([
  'echo',
  'largeEcho',
  'compressed',
  'unauthorized',
  'timeout',
  'concurrency'
]);

function requiredMeta(selector, name) {
  const value = document.querySelector(selector)?.content;
  if (!value) throw new Error(`${name} is missing`);
  return value;
}

function normalizeOrigin(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error('STEVE origin must be an absolute HTTP(S) origin');
  }
  if (
    !['http:', 'https:'].includes(url.protocol)
    || url.username
    || url.password
    || url.pathname !== '/'
    || url.search
    || url.hash
  ) {
    throw new Error('STEVE origin must be an absolute HTTP(S) origin');
  }
  return url.origin;
}

function normalizeKeyExchange(value) {
  if (!supportedKeyExchanges.has(value)) {
    throw new Error('expected suite must be exactly X25519 or XWING-DRAFT10');
  }
  return value;
}

function requiredPcr(index) {
  const value = requiredMeta(EXPECTED_PCR_META(index), `expected PCR${index}`);
  if (!/^[0-9a-f]{96}$/iu.test(value) || value.toLowerCase() === '0'.repeat(96)) {
    throw new Error(`expected PCR${index} must be a nonzero 96-character hexadecimal value`);
  }
  return value.toLowerCase();
}

const profile = requiredMeta(PROFILE_META, 'STEVE evidence profile');
if (!['local', 'nitro'].includes(profile)) {
  throw new Error('STEVE evidence profile must be exactly local or nitro');
}
const requestTimeoutMs = Number(requiredMeta(REQUEST_TIMEOUT_META, 'request timeout'));
if (!Number.isInteger(requestTimeoutMs)) {
  throw new Error('request timeout must be an integer');
}
const expectedPcrs = {
  PCR0: requiredPcr(0),
  PCR1: requiredPcr(1),
  PCR2: requiredPcr(2)
};
const query = new URL(location.href).searchParams;
let enclaveOrigin = normalizeOrigin(
  query.get('origin') || requiredMeta(DEFAULT_ORIGIN_META, 'default STEVE origin')
);
let keyExchange = normalizeKeyExchange(
  query.get('suite') || requiredMeta(KEY_EXCHANGE_META, 'default STEVE suite')
);

elements['target-origin-input'].value = enclaveOrigin;
elements['target-suite-input'].value = keyExchange;

const stateLabels = {
  idle: 'Idle',
  establishing: 'Establishing',
  ready: 'Ready',
  rotating: 'Rotating',
  error: 'Error'
};
const stageLabels = {
  'creating-session': 'Creating session',
  'verifying-attestation': 'Verifying attestation',
  'confirming-session': 'Confirming traffic keys'
};
const triggerLabels = {
  'explicit-initialize': 'Explicit establishment',
  'protected-request': 'First protected request',
  rotation: 'Rotation'
};
const checkLabels = {
  certificateChain: 'Certificate chain',
  nonceBinding: 'Fresh nonce binding',
  sessionBinding: 'Transcript and binder',
  keyConfirmation: 'Traffic-key confirmation',
  expectedPcrPolicy: 'Expected PCR policy'
};

let activeClient;
let latestStatus;
let lastStage;
let busy = false;
let inspectedExchange;

function setText(id, value, title = '') {
  const element = elements[id];
  element.textContent = value ?? '—';
  element.title = title;
}

function shortIdentifier(value) {
  if (!value) return '—';
  return value.length > 24 ? `${value.slice(0, 12)}…${value.slice(-8)}` : value;
}

function formatTime(value) {
  if (!Number.isFinite(value)) return '—';
  const date = new Date(value);
  const local = new Date(value - date.getTimezoneOffset() * 60_000);
  return local.toISOString().replace('T', ' ').slice(0, 19);
}

function formatDuration(milliseconds) {
  return milliseconds < 1000
    ? `${Math.round(milliseconds)} ms`
    : `${(milliseconds / 1000).toFixed(2)} s`;
}

function bytes(value) {
  return new TextEncoder().encode(value).length;
}

function readableName(value) {
  if (!value) return '—';
  const words = value
    .replace(/([a-z])([A-Z])/gu, '$1 $2')
    .replaceAll('-', ' ');
  return `${words[0].toUpperCase()}${words.slice(1)}`;
}

function beginExchange(method, path, body) {
  inspectedExchange = { key: null };
  setText('application-request-meta', `${method} ${path} · ${bytes(body)} plaintext bytes`);
  setText('application-request-body', body || '(empty body)');
  setText('wire-request-meta', 'Encrypting in the service worker…');
  setText('wire-request-envelope', '—');
  setText('wire-response-meta', 'Waiting for STEVE…');
  setText('wire-response-envelope', '—');
  setText('application-response-meta', 'Waiting for the decrypted response…');
  setText('application-response-body', '—');
}

function renderWireEnvelope(direction, data) {
  if (!inspectedExchange) return false;
  const key = `${data.sessionId}:${data.sequence}`;
  if (direction === 'request') {
    if (inspectedExchange.key) return false;
    inspectedExchange.key = key;
  } else if (inspectedExchange.key !== key) {
    return false;
  }

  setText(
    `wire-${direction}-meta`,
    `${direction === 'request' ? 'POST' : 'Response from'} ${data.endpoint} · session ${shortIdentifier(data.sessionId)} · sequence ${data.sequence} · ${data.size} bytes`,
    data.sessionId
  );
  setText(`wire-${direction}-envelope`, data.envelope);
  return true;
}

function finishExchange(status, body, duration) {
  setText(
    'application-response-meta',
    `HTTP ${status} · ${bytes(body)} plaintext bytes · ${formatDuration(duration)}`
  );
  setText('application-response-body', body || '(empty body)');
}

function failExchange(error, duration) {
  setText(
    'application-response-meta',
    `Request failed · ${formatDuration(duration)}`
  );
  setText('application-response-body', error.message);
}

function renderStatus(status) {
  latestStatus = status;
  const lifecycle = status.state || (status.initialized ? 'ready' : status.error ? 'error' : 'idle');
  const stage = status.stage || null;
  const session = status.session;
  const protocol = status.protocol || {};
  const verifier = status.attestationVerifier || {};
  const attestation = status.attestation;

  elements['system-status'].dataset.state = lifecycle;
  elements['system-status'].textContent = {
    idle: 'Service worker active · session idle',
    establishing: `Service worker active · ${stageLabels[stage] || (stage ? readableName(stage) : 'establishing session')}`,
    ready: 'Service worker active · secure session ready',
    rotating: `Service worker active · ${stageLabels[stage] || (stage ? readableName(stage) : 'rotating session')}`,
    error: `Service worker active · session error${status.error ? `: ${status.error}` : ''}`
  }[lifecycle] || 'Service worker active';

  setText('runtime-worker', 'Active and controlling this page');
  setText('session-state', stateLabels[lifecycle] || lifecycle);
  setText('session-stage', stageLabels[stage] || readableName(stage));
  setText('session-trigger', triggerLabels[session?.trigger] || readableName(session?.trigger));

  setText(
    'protocol-id',
    protocol.id ? `${protocol.id} (v${protocol.version})` : `v${status.protocolVersion ?? '—'}`
  );
  setText('key-establishment', protocol.keyEstablishment || '—');
  setText('key-derivation', protocol.keyDerivation || '—');
  setText('record-protection', protocol.recordProtection || '—');

  setText('session-id', shortIdentifier(session?.id), session?.id || '');
  setText(
    'transcript-hash',
    shortIdentifier(session?.transcriptHash),
    session?.transcriptHash || ''
  );
  setText('established-at', formatTime(session?.establishedAt));
  setText('rotates-at', formatTime(session?.rotatesAt));

  setText('attestation-profile', attestation?.profile || verifier.id || '—');
  setText('trust-anchor', attestation?.trustAnchor || verifier.trustAnchor || '—');
  setText('module-id', attestation?.moduleId || '—');
  setText('pcr-trust', attestation?.pcrTrust || '—');
  setText('target-origin', enclaveOrigin);
  setText('pcr-policy-note', {
    pinned: 'Matched one complete independently supplied PCR profile.',
    'tofu-enrolled': 'Enrolled the exact selected PCR set after key confirmation.',
    'tofu-matched': 'Matched the exact selected PCR set enrolled previously.',
    'not-checked': 'Reported only; no PCR policy was supplied.'
  }[attestation?.pcrTrust] || 'Waiting for PCR policy verification.');

  const warning = elements['trust-warning'];
  if (verifier.synthetic || attestation?.synthetic) {
    warning.hidden = false;
    warning.textContent =
      'Synthetic test-root attestation. Protocol and binding checks only; this is not an enclave.';
    setText('target-kind', 'local synthetic evaluation server; not an enclave');
    setText(
      'boundary-note',
      'The browser encrypts before the wire. The local STEVE evaluation server decrypts and forwards the request, but it is not an enclave.'
    );
  } else {
    warning.hidden = true;
    warning.textContent = '';
    setText('target-kind', `${attestation?.profile || verifier.id || 'attested'} runtime`);
    setText(
      'boundary-note',
      'The browser encrypts before the wire. STEVE decrypts and forwards inside the attested runtime, then encrypts the application response.'
    );
  }

  renderChecks(attestation?.checks);
  renderPcrs(attestation?.pcrs);
  elements['raw-status'].textContent = JSON.stringify(status, null, 2);
  updateButtonStates();
}

function renderChecks(checks) {
  const list = elements['verification-checks'];
  list.replaceChildren();
  if (!checks) {
    const item = document.createElement('li');
    item.append(
      Object.assign(document.createElement('span'), { textContent: 'Session not established' }),
      Object.assign(document.createElement('span'), { textContent: '—' })
    );
    list.append(item);
    return;
  }

  for (const [id, result] of Object.entries(checks)) {
    const item = document.createElement('li');
    const label = document.createElement('span');
    const value = document.createElement('span');
    label.textContent = checkLabels[id] || readableName(id);
    value.className = 'check-result';
    value.dataset.result = result;
    value.textContent = result;
    item.append(label, value);
    list.append(item);
  }
}

function renderPcrs(pcrs) {
  const entries = Object.entries(pcrs || {});
  const details = elements['pcr-details'];
  const list = elements['pcr-values'];
  list.replaceChildren();
  details.hidden = entries.length === 0;
  if (entries.length === 0) {
    details.open = false;
    return;
  }

  for (const [name, value] of entries) {
    const term = document.createElement('dt');
    const description = document.createElement('dd');
    const code = document.createElement('code');
    term.textContent = name;
    code.textContent = String(value);
    description.append(code);
    list.append(term, description);
  }
}

function updateButtonStates() {
  const lifecycle = latestStatus?.state;
  for (const button of actionButtons) {
    const action = button.dataset.action;
    let disabled = busy || !activeClient;
    if (action === 'initialize') {
      disabled ||= ['establishing', 'rotating', 'ready'].includes(lifecycle);
    } else if (action === 'rotate') {
      disabled ||= lifecycle !== 'ready';
    } else if (action === 'reset') {
      disabled ||= lifecycle === 'idle';
    } else if (requestActions.has(action)) {
      disabled ||= ['establishing', 'rotating'].includes(lifecycle);
    }
    button.disabled = disabled;
  }
}

function setBusy(value) {
  busy = value;
  updateButtonStates();
}

function appendEvent(kind, summary, level = 'info') {
  const item = document.createElement('li');
  const timestamp = document.createElement('time');
  const category = document.createElement('span');
  const message = document.createElement('span');
  item.className = 'event';
  item.dataset.level = level;
  timestamp.dateTime = new Date().toISOString();
  timestamp.textContent = new Date().toLocaleTimeString();
  category.className = 'event-kind';
  category.textContent = kind;
  message.textContent = summary;
  item.append(timestamp, category, message);
  elements.events.append(item);
  while (elements.events.children.length > MAX_EVENTS) {
    elements.events.firstElementChild.remove();
  }
  elements.events.scrollTop = elements.events.scrollHeight;
}

function clearRecoveryParam() {
  const url = new URL(location.href);
  if (url.searchParams.delete(RECOVERY_PARAM)) {
    history.replaceState(null, '', url);
  }
}

async function recoverStaleRegistration(error) {
  if (!error.message.includes('does not control this page')) return false;
  const url = new URL(location.href);
  if (url.searchParams.has(RECOVERY_PARAM)) return false;

  const registration = await navigator.serviceWorker.getRegistration(
    new URL('./', location.href).href
  );
  await registration?.unregister();
  url.searchParams.set(RECOVERY_PARAM, '1');
  location.replace(url);
  return true;
}

function attachClientEvents(client) {
  client.on('status', data => {
    renderStatus(data);
    if (data.stage && data.stage !== lastStage) {
      const summary = {
        'creating-session': `Generating an ephemeral ${data.protocol?.keyEstablishment || 'session'} exchange`,
        'verifying-attestation': 'Verifying the evidence chain, nonce, transcript, and binder',
        'confirming-session': 'Confirming possession of the derived directional traffic keys'
      }[data.stage] || `Running ${readableName(data.stage).toLowerCase()}`;
      appendEvent('handshake', summary);
    }
    lastStage = data.stage || null;
  });
  client.on('initialized', data => {
    if (data.status) renderStatus(data.status);
    const trigger = data.status?.session?.trigger;
    appendEvent(
      'session',
      `Session established via ${triggerLabels[trigger]?.toLowerCase() || 'session establishment'}`,
      'success'
    );
  });
  client.on('key-rotated', data => {
    if (data.status) renderStatus(data.status);
    appendEvent('session', 'Session rotated to fresh key material', 'success');
  });
  client.on('encrypted-request', data => {
    if (renderWireEnvelope('request', data)) {
      appendEvent(
        'wire',
        `Encrypted request sequence ${data.sequence} · ${data.size} bytes`
      );
    }
  });
  client.on('encrypted-response', data => {
    if (renderWireEnvelope('response', data)) {
      appendEvent(
        'wire',
        `Encrypted response sequence ${data.sequence} · ${data.size} bytes`
      );
    }
  });
  client.on('error', data => {
    appendEvent(
      data.stage || 'error',
      data.message || 'Secure-channel operation failed',
      'failure'
    );
  });
}

async function refreshStatus() {
  const status = await activeClient.getStatus();
  renderStatus(status);
  return status;
}

const ready = (async () => {
  try {
    const profileBase = new URL('./', location.href).pathname;
    const client = await registerEnclaveServiceWorker({
      swPath: new URL('enclave-sw.js', location.href).pathname,
      scope: profileBase,
      config: {
        enclaveOrigin,
        emitEncryptedPayloads: true,
        requestTimeoutMs,
        expectedKeyExchange: keyExchange,
        pcrPolicy: { mode: 'pinned', profiles: [expectedPcrs] },
        passthroughPaths: [
          `${profileBase}attestation-widget.js`,
          `${profileBase}register.js`,
          `${profileBase}enclave-sw.js`,
          `${profileBase}xwing/steve_xwing_wasm_bg.wasm`
        ]
      }
    });
    activeClient = client;
    attachClientEvents(client);
    clearRecoveryParam();
    const status = await refreshStatus();
    appendEvent(
      'runtime',
      status.state === 'ready'
        ? 'Service worker resumed an existing secure session'
        : 'Service worker active and controlling this page',
      'success'
    );
    return client;
  } catch (error) {
    if (await recoverStaleRegistration(error)) {
      await new Promise(() => {});
    }
    elements['system-status'].dataset.state = 'error';
    elements['system-status'].textContent = `Service worker startup failed: ${error.message}`;
    setText('runtime-worker', 'Startup failed');
    elements['raw-status'].textContent = JSON.stringify({ error: error.message }, null, 2);
    appendEvent('runtime', `Service worker startup failed: ${error.message}`, 'failure');
    throw error;
  }
})();

async function initialize() {
  const client = await ready;
  await client.initialize();
  return refreshStatus();
}

async function status() {
  await ready;
  return refreshStatus();
}

async function rotate() {
  const client = await ready;
  await client.rotateSession();
  return refreshStatus();
}

async function reset() {
  const client = await ready;
  await client.reset();
  inspectedExchange = null;
  setText('application-request-meta', 'No request sent.');
  setText('application-request-body', '—');
  setText('wire-request-meta', 'Waiting for a request.');
  setText('wire-request-envelope', '—');
  setText('wire-response-meta', 'Waiting for a response.');
  setText('wire-response-envelope', '—');
  setText('application-response-meta', 'Waiting for a response.');
  setText('application-response-body', '—');
  return refreshStatus();
}

async function applyTarget(origin, suite) {
  const nextOrigin = normalizeOrigin(origin);
  const nextSuite = normalizeKeyExchange(suite);
  const client = await ready;
  await client.configure({
    enclaveOrigin: nextOrigin,
    expectedKeyExchange: nextSuite,
    requestTimeoutMs
  });
  enclaveOrigin = nextOrigin;
  keyExchange = nextSuite;
  elements['target-origin-input'].value = enclaveOrigin;
  elements['target-suite-input'].value = keyExchange;
  const url = new URL(location.href);
  url.searchParams.set('origin', enclaveOrigin);
  url.searchParams.set('suite', keyExchange);
  history.replaceState(null, '', url);
  inspectedExchange = null;
  setText('target-origin', enclaveOrigin);
  appendEvent(
    'target',
    `${profile === 'nitro' ? 'Nitro' : 'local'} profile configured for ${keyExchange} at ${enclaveOrigin}`,
    'success'
  );
  return refreshStatus();
}

async function configurePcrPolicy(pcrPolicy) {
  const client = await ready;
  await client.configure({ pcrPolicy });
  return refreshStatus();
}

async function request(path, options, inspect = true) {
  const started = performance.now();
  const method = options?.method || 'GET';
  const body = typeof options?.body === 'string' ? options.body : '';
  if (inspect) beginExchange(method, path, body);
  try {
    const response = await fetch(`${enclaveOrigin}${path}`, options);
    const responseBody = await response.text();
    if (inspect) finishExchange(response.status, responseBody, performance.now() - started);
    return { status: response.status, body: responseBody };
  } catch (error) {
    if (inspect) failExchange(error, performance.now() - started);
    throw error;
  }
}

function echoRequest(value = elements['request-body'].value, inspect = true) {
  return request('/echo', {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: value
  }, inspect);
}

function unauthorizedRequest(inspect = true) {
  return request('/unauthorized', undefined, inspect);
}

function timeoutRequest(inspect = true) {
  return request(`/delay?ms=${requestTimeoutMs + 2000}`, undefined, inspect);
}

async function echo(value = elements['request-body'].value) {
  const result = await echoRequest(value);
  await refreshStatus();
  return result;
}

async function fixture() {
  const result = await request('/.well-known/steve-test-fixture', undefined, false);
  if (result.status !== 200) {
    throw new Error(`fixture capability request returned HTTP ${result.status}`);
  }
  let capabilities;
  try {
    capabilities = JSON.parse(result.body);
  } catch {
    throw new Error('fixture capability response was not JSON');
  }
  if (capabilities.contract !== FIXTURE_CONTRACT) {
    throw new Error(`expected fixture contract ${FIXTURE_CONTRACT}`);
  }
  return capabilities;
}

async function largeEcho() {
  const payload = 'x'.repeat(100 * 1024);
  const result = await echoRequest(payload, false);
  await refreshStatus();
  return result;
}

async function unauthorized() {
  const result = await unauthorizedRequest();
  await refreshStatus();
  return result;
}

async function timeout() {
  const client = await ready;
  await client.configure({ requestTimeoutMs: CONTROLLED_TIMEOUT_MS });
  try {
    const result = await request(`/delay?ms=${CONTROLLED_DELAY_MS}`);
    await refreshStatus();
    return result;
  } finally {
    await client.configure({ requestTimeoutMs });
  }
}

async function compressed() {
  const response = await fetch(`${enclaveOrigin}/compressed`);
  const result = {
    status: response.status,
    body: await response.text(),
    contentEncoding: response.headers.get('content-encoding'),
    contentLength: response.headers.get('content-length'),
    upstreamAcceptEncoding: response.headers.get('x-upstream-accept-encoding')
  };
  await refreshStatus();
  return result;
}

async function concurrency() {
  const results = await Promise.all(
    Array.from(
      { length: 16 },
      (_, index) => echoRequest(`concurrent-${index}`, false)
    )
  );
  await refreshStatus();
  return results;
}

async function windowPressure() {
  const slow = timeoutRequest(false);
  await new Promise(resolve => setTimeout(resolve, 25));
  const fast = Array.from(
    { length: 64 },
    (_, index) => echoRequest(`request-${index}`, false)
  );
  const results = await Promise.all([slow, ...fast]);
  await refreshStatus();
  return results;
}

function resultSummary(action, result, duration) {
  const elapsed = formatDuration(duration);
  if (action === 'initialize') {
    return `Session ready via ${triggerLabels[result.session?.trigger]?.toLowerCase()} · ${elapsed}`;
  }
  if (action === 'rotate') return `Session rotation completed · ${elapsed}`;
  if (action === 'reset') return `Session reset to idle · ${elapsed}`;
  if (action === 'concurrency') {
    const counts = result.reduce((total, response) => {
      total[response.status] = (total[response.status] || 0) + 1;
      return total;
    }, {});
    return `${result.length} requests · ${counts[200] || 0} HTTP 200 · ${elapsed}`;
  }
  const bodySize = bytes(result.body);
  return `${result.status} HTTP · ${bodySize} response bytes · ${elapsed}`;
}

function renderScenarioResult(action, result) {
  if (action === 'unauthorized') {
    setText(
      'scenario-result',
      `Observed encrypted application HTTP ${result.status}; session is ${latestStatus?.state}.`
    );
  } else if (action === 'timeout') {
    setText(
      'scenario-result',
      `Observed local HTTP ${result.status} timeout; sequence retired and session is ${latestStatus?.state}.`
    );
  } else if (action === 'concurrency') {
    const successes = result.filter(response => response.status === 200).length;
    setText(
      'scenario-result',
      `${successes} concurrent requests completed; the session remains usable.`
    );
  }
}

window.steveDemo = {
  ready,
  profile,
  initialize,
  status,
  rotate,
  reset,
  applyTarget,
  configurePcrPolicy,
  fixture,
  echo,
  largeEcho,
  compressed,
  unauthorized,
  timeout,
  concurrency,
  windowPressure
};

elements['target-form'].addEventListener('submit', async event => {
  event.preventDefault();
  setBusy(true);
  try {
    await applyTarget(
      elements['target-origin-input'].value,
      elements['target-suite-input'].value
    );
  } catch (error) {
    appendEvent('target', error.message, 'failure');
  } finally {
    setBusy(false);
  }
});

actionButtons.forEach(button => {
  button.addEventListener('click', async () => {
    const action = button.dataset.action;
    const label = button.textContent.trim();
    const started = performance.now();
    setBusy(true);
    try {
      const result = await window.steveDemo[action]();
      renderScenarioResult(action, result);
      appendEvent(
        'action',
        `${label}: ${resultSummary(action, result, performance.now() - started)}`,
        'success'
      );
    } catch (error) {
      await refreshStatus().catch(() => {});
      appendEvent(
        'action',
        `${label}: ${error.message} · ${formatDuration(performance.now() - started)}`,
        'failure'
      );
    } finally {
      setBusy(false);
    }
  });
});
