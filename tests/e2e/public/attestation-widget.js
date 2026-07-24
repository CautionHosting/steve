import { registerEnclaveServiceWorker } from '/register.js';

const ENCLAVE_ORIGIN = `http://${location.hostname}:49500`;
const RECOVERY_PARAM = 'steve-sw-recovery';
const MAX_EVENTS = 100;
const elements = Object.fromEntries(
  [
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
    'verification-checks',
    'pcr-details',
    'pcr-values',
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
const requestActions = new Set(['echo', 'unauthorized', 'timeout', 'concurrency']);

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
  setText('target-origin', ENCLAVE_ORIGIN);

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

  const registration = await navigator.serviceWorker.getRegistration('/');
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
    const client = await registerEnclaveServiceWorker({
      swPath: '/enclave-sw.js',
      scope: '/',
      config: {
        enclaveOrigin: ENCLAVE_ORIGIN,
        emitEncryptedPayloads: true,
        requestTimeoutMs: 1000
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
  await client.rotateKey();
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

async function request(path, options, inspect = true) {
  const started = performance.now();
  const method = options?.method || 'GET';
  const body = typeof options?.body === 'string' ? options.body : '';
  if (inspect) beginExchange(method, path, body);
  try {
    const response = await fetch(`${ENCLAVE_ORIGIN}${path}`, options);
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
  return request('/delay?ms=2500', undefined, inspect);
}

async function echo(value = elements['request-body'].value) {
  const result = await echoRequest(value);
  await refreshStatus();
  return result;
}

async function unauthorized() {
  const result = await unauthorizedRequest();
  await refreshStatus();
  return result;
}

async function timeout() {
  const result = await timeoutRequest();
  await refreshStatus();
  return result;
}

async function concurrency() {
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
    return `${result.length} requests · ${counts[200] || 0} HTTP 200 · ${counts[504] || 0} HTTP 504 · ${elapsed}`;
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
    const timeouts = result.filter(response => response.status === 504).length;
    const successes = result.filter(response => response.status === 200).length;
    setText(
      'scenario-result',
      `${successes} completed, ${timeouts} timed out; sequence window reopened without rotating the session.`
    );
  }
}

window.steveDemo = {
  ready,
  initialize,
  status,
  rotate,
  reset,
  echo,
  unauthorized,
  timeout,
  concurrency
};

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
