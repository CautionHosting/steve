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

const { EnclaveClient, SteveError, registerEnclaveServiceWorker } = await import('../src/register.js');

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

test('getStatus returns a lifecycle error instead of treating it as a command failure', async () => {
  serviceWorker.controller = {
    postMessage: (_message, ports) => {
      ports[0].postMessage({ type: 'status', state: 'error', error: 'policy rejected' });
    }
  };
  const client = new EnclaveClient({});

  assert.deepEqual(await client.getStatus(), {
    type: 'status',
    state: 'error',
    error: 'policy rejected'
  });
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

test('registration always completes explicit configuration, including the legacy empty config', async () => {
  const controller = {
    state: 'activated',
    messages: [],
    postMessage(message, ports) {
      this.messages.push(message);
      ports[0].postMessage({ type: message.type, success: true });
    }
  };
  serviceWorker.controller = controller;
  serviceWorker.register = async () => ({
    active: controller,
    installing: null,
    waiting: null
  });

  await registerEnclaveServiceWorker();

  assert.deepEqual(controller.messages, [{ type: 'configure', config: {} }]);
});

test('initialize clears its message timer after the worker replies', async () => {
  const status = { type: 'status', state: 'ready', initialized: true };
  serviceWorker.controller = {
    postMessage: (message, ports) => {
      ports[0].postMessage({ type: message.type, success: true, status });
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
    assert.deepEqual(response, status);
    assert.equal(cleared, 1);
  } finally {
    globalThis.clearTimeout = originalClearTimeout;
  }
});

test('lifecycle methods return status and rotateKey remains an alias', async () => {
  const messages = [];
  serviceWorker.controller = {
    postMessage: (message, ports) => {
      messages.push(message);
      ports[0].postMessage({
        type: message.type,
        success: true,
        status: { type: 'status', state: message.type === 'reset' ? 'idle' : 'ready' }
      });
    }
  };
  const client = new EnclaveClient({});

  assert.equal((await client.rotateSession()).state, 'ready');
  assert.equal((await client.rotateKey()).state, 'ready');
  assert.equal((await client.reset()).state, 'idle');
  assert.deepEqual(messages.map(message => message.type), [
    'rotate-session',
    'rotate-session',
    'reset'
  ]);
});

test('worker failures expose stable structured errors', async () => {
  serviceWorker.controller = {
    postMessage: (_message, ports) => {
      ports[0].postMessage({
        success: false,
        error: {
          code: 'PCR_POLICY_MISMATCH',
          stage: 'pcr-policy',
          message: 'attested PCRs did not match',
          httpStatus: 403
        }
      });
    }
  };
  const client = new EnclaveClient({});

  await assert.rejects(client.initialize(), error =>
    error instanceof SteveError
      && error.code === 'PCR_POLICY_MISMATCH'
      && error.stage === 'pcr-policy'
      && error.message === 'attested PCRs did not match'
      && error.httpStatus === 403
  );
});

test('waitForInitialization propagates granular establishment errors', async () => {
  const client = new EnclaveClient({});
  client.getStatus = async () => ({ initialized: false });
  const waiting = client.waitForInitialization(1000);
  await Promise.resolve();

  client.emit('error', {
    operation: 'initialization',
    code: 'PCR_POLICY_MISMATCH',
    stage: 'pcr-policy',
    message: 'attested PCRs did not match'
  });

  await assert.rejects(waiting, error =>
    error instanceof SteveError
      && error.code === 'PCR_POLICY_MISMATCH'
      && error.stage === 'pcr-policy'
  );
});

test('send returns the protected response, compatibility session ID, and exchange metadata', async () => {
  const messages = [];
  const timeoutDelays = [];
  const originalSetTimeout = globalThis.setTimeout;
  globalThis.setTimeout = (callback, delay, ...args) => {
    timeoutDelays.push(delay);
    return originalSetTimeout(callback, delay, ...args);
  };
  serviceWorker.controller = {
    postMessage: (message, ports) => {
      messages.push(message);
      ports[0].postMessage({
        type: 'protected-response',
        success: true,
        status: 201,
        headers: [['content-type', 'text/plain']],
        body: new TextEncoder().encode('created'),
        sessionId: 'session-id',
        exchange: {
          protocolName: 'STEVE-E2P-V2',
          protection: 'AES-256-GCM',
          sessionId: 'session-id',
          sequence: '1',
          keyExchange: 'X25519',
          pcrTrust: 'pinned',
          outerStatus: 200,
          requestPlaintextBytes: 64,
          requestCiphertextBytes: 80,
          requestEnvelopeBytes: 123,
          responseEnvelopeBytes: 120,
          responseCiphertextBytes: 77,
          responsePlaintextBytes: 61
        }
      });
    }
  };
  const client = new EnclaveClient({});

  let result;
  try {
    result = await client.send('/items?q=1', {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: 'payload'
    });
  } finally {
    globalThis.setTimeout = originalSetTimeout;
  }
  const { response, sessionId, exchange } = result;

  assert.equal(messages.length, 1);
  assert.equal(messages[0].type, 'protected-send');
  assert.equal(messages[0].request.path, '/items?q=1');
  assert.equal(messages[0].request.method, 'POST');
  assert.equal(new TextDecoder().decode(messages[0].request.body), 'payload');
  assert.equal(response.status, 201);
  assert.equal(await response.text(), 'created');
  assert.equal(sessionId, 'session-id');
  assert.deepEqual(exchange, {
    protocolName: 'STEVE-E2P-V2',
    protection: 'AES-256-GCM',
    sessionId: 'session-id',
    sequence: '1',
    keyExchange: 'X25519',
    pcrTrust: 'pinned',
    outerStatus: 200,
    requestPlaintextBytes: 64,
    requestCiphertextBytes: 80,
    requestEnvelopeBytes: 123,
    responseEnvelopeBytes: 120,
    responseCiphertextBytes: 77,
    responsePlaintextBytes: 61
  });
  assert.ok(timeoutDelays.includes(315000));
});

test('send rejects absolute paths and browser retry or redirect options', async () => {
  const client = new EnclaveClient({});
  for (const [path, options] of [
    ['https://enclave.example/data', {}],
    ['//enclave.example/data', {}],
    ['/data#fragment', {}],
    ['/data', { redirect: 'follow' }]
  ]) {
    await assert.rejects(client.send(path, options), error =>
      error instanceof SteveError
        && error.code === 'INVALID_REQUEST'
        && error.stage === 'request'
    );
  }
});

test('PCR policy management remains worker-authoritative', async () => {
  const messages = [];
  serviceWorker.controller = {
    postMessage: (message, ports) => {
      messages.push(message);
      const common = { type: message.type, success: true };
      if (message.type === 'get-pcr-policy') {
        ports[0].postMessage({ ...common, policy: { mode: 'tofu', additionalPcrIndices: [3] } });
      } else if (message.type === 'replace-pcr-policy') {
        ports[0].postMessage({ ...common, policy: message.policy, status: { state: 'idle' } });
      } else {
        ports[0].postMessage({ ...common, status: { state: 'idle' } });
      }
    }
  };
  const client = new EnclaveClient({});
  const policy = { mode: 'tofu', additionalPcrIndices: [3] };

  assert.deepEqual(await client.getPcrPolicy(), policy);
  assert.deepEqual(await client.replacePcrPolicy(policy), { policy, status: { state: 'idle' } });
  assert.deepEqual(messages.map(message => message.type), [
    'get-pcr-policy',
    'replace-pcr-policy'
  ]);
});
