import { registerEnclaveServiceWorker } from '/register.js';

const ENCLAVE_ORIGIN = `http://${location.hostname}:49500`;
const RECOVERY_PARAM = 'steve-sw-recovery';
const output = document.querySelector('#output');
const systemStatus = document.querySelector('#system-status');
const actionButtons = [...document.querySelectorAll('button[data-action]')];

function log(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  output.textContent += `${output.textContent ? '\n\n' : ''}${text}`;
  output.scrollTop = output.scrollHeight;
}

function setSystemStatus(state, text) {
  systemStatus.dataset.state = state;
  systemStatus.textContent = text;
}

function setActionsDisabled(disabled) {
  for (const button of actionButtons) button.disabled = disabled;
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

const ready = (async () => {
  try {
    const client = await registerEnclaveServiceWorker({
      swPath: '/enclave-sw.js',
      scope: '/',
      config: {
        enclaveOrigin: ENCLAVE_ORIGIN,
        requestTimeoutMs: 1000
      }
    });
    clearRecoveryParam();
    output.textContent = '';
    setSystemStatus('ready', 'Service worker active · secure session not initialized');
    log('✓ Service worker active and controlling this page.');
    log('✓ SDK configured. Click Initialize to establish the secure session.');
    return client;
  } catch (error) {
    if (await recoverStaleRegistration(error)) {
      await new Promise(() => {});
    }
    output.textContent = '';
    setSystemStatus('failure', 'Service worker startup failed');
    log(`✗ Service worker startup failed: ${error.message}`);
    throw error;
  }
})();
void ready.then(
  () => setActionsDisabled(false),
  () => setActionsDisabled(true)
);

async function initialize() {
  const client = await ready;
  try {
    await client.initialize();
    const currentStatus = await client.getStatus();
    setSystemStatus('success', 'Service worker active · secure session initialized');
    return currentStatus;
  } catch (error) {
    setSystemStatus('failure', 'Service worker active · secure session failed');
    throw error;
  }
}

async function status() {
  return (await ready).getStatus();
}

async function request(path, options) {
  const response = await fetch(`${ENCLAVE_ORIGIN}${path}`, options);
  return { status: response.status, body: await response.text() };
}

async function echo(value = 'steve-e2e-secret') {
  return request('/echo', {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: value
  });
}

async function unauthorized() {
  return request('/unauthorized');
}

async function timeout() {
  return request('/delay?ms=2500');
}

async function concurrency() {
  const slow = timeout();
  await new Promise(resolve => setTimeout(resolve, 25));
  const fast = Array.from({ length: 64 }, (_, index) => echo(`request-${index}`));
  return Promise.all([slow, ...fast]);
}

window.steveDemo = {
  ready,
  initialize,
  status,
  echo,
  unauthorized,
  timeout,
  concurrency
};

actionButtons.forEach(button => {
  button.addEventListener('click', async () => {
    const label = button.textContent.trim();
    setActionsDisabled(true);
    log(`> ${label}`);
    try {
      const result = await window.steveDemo[button.dataset.action]();
      if (button.dataset.action === 'initialize') {
        log('✓ Secure session initialized and attestation verified.');
      }
      log(result);
    } catch (error) {
      log(`✗ ${label} failed: ${error.message}`);
    } finally {
      setActionsDisabled(false);
    }
  });
});
