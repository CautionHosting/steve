import assert from 'node:assert/strict';
import test from 'node:test';

const serviceWorker = {
  listeners: new Map(),
  addEventListener(type, listener) {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type).add(listener);
  },
  removeEventListener(type, listener) {
    this.listeners.get(type)?.delete(listener);
  },
  dispatch(type) {
    for (const listener of this.listeners.get(type) || []) listener();
  },
  controller: null,
  register: null
};
Object.defineProperty(globalThis, 'navigator', {
  value: { serviceWorker },
  configurable: true
});

const { EnclaveClient, registerEnclaveServiceWorker } = await import('../src/register.js');

test.afterEach(() => {
  serviceWorker.controller = null;
  serviceWorker.register = null;
  serviceWorker.listeners.clear();
});

test('sendMessage supports a bounded caller-selected timeout', async () => {
  serviceWorker.controller = { postMessage: () => {} };
  const client = new EnclaveClient({});

  await assert.rejects(
    client.sendMessage('never-replies', {}, 10),
    /Message timeout/u
  );
});

test('sendMessage fails immediately when the page is not controlled', async () => {
  const client = new EnclaveClient({});
  await assert.rejects(client.getStatus(), /does not control this page/u);
});

test('registration configures the newly activated controller, not its predecessor', async () => {
  const oldController = {
    messages: [],
    postMessage(message, ports) {
      this.messages.push(message);
      ports[0].postMessage({ type: message.type, success: true });
    }
  };
  const newController = {
    state: 'activated',
    messages: [],
    postMessage(message, ports) {
      this.messages.push(message);
      ports[0].postMessage({ type: message.type, success: true });
    }
  };
  const registration = { active: newController, installing: null, waiting: null };
  let registered;
  serviceWorker.controller = oldController;
  serviceWorker.register = async (...args) => {
    registered = args;
    return registration;
  };

  const registrationPromise = registerEnclaveServiceWorker({
    config: { enclaveOrigin: 'https://enclave.example' }
  });
  queueMicrotask(() => {
    serviceWorker.controller = newController;
    serviceWorker.dispatch('controllerchange');
  });

  await registrationPromise;
  assert.deepEqual(registered, [
    '/enclave-sw.js',
    { scope: '/', type: 'module' }
  ]);
  assert.deepEqual(oldController.messages, []);
  assert.deepEqual(newController.messages, [{
    type: 'configure',
    config: { enclaveOrigin: 'https://enclave.example' }
  }]);
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
