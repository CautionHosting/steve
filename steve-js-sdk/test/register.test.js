import assert from 'node:assert/strict';
import test from 'node:test';

const serviceWorker = {
  addEventListener: () => {},
  controller: null
};
Object.defineProperty(globalThis, 'navigator', {
  value: { serviceWorker },
  configurable: true
});

const { EnclaveClient } = await import('../src/register.js');

test.afterEach(() => {
  serviceWorker.controller = null;
});

test('sendMessage supports a bounded caller-selected timeout', async () => {
  serviceWorker.controller = { postMessage: () => {} };
  const client = new EnclaveClient({});

  await assert.rejects(
    client.sendMessage('never-replies', {}, 10),
    /Message timeout/u
  );
});

test('initialize clears its message timer after the worker replies', async () => {
  serviceWorker.controller = {
    postMessage: (message, ports) => {
      ports[0].postMessage({ type: message.type, success: true });
    }
  };
  const client = new EnclaveClient({});
  const originalClearTimeout = globalThis.clearTimeout;
  let cleared = 0;
  globalThis.clearTimeout = timer => {
    cleared += 1;
    return originalClearTimeout(timer);
  };

  try {
    const response = await client.initialize();
    assert.equal(response.type, 'initialize');
    assert.equal(cleared, 1);
  } finally {
    globalThis.clearTimeout = originalClearTimeout;
  }
});
