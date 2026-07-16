import assert from 'node:assert/strict';
import test from 'node:test';

// enclave-sw.js is a service-worker script: it calls self.addEventListener()
// at module top-level. Stub the minimal SW globals it needs before import so
// those calls are no-ops instead of throwing in Node.
globalThis.self = {
  addEventListener: () => {},
  location: { origin: 'https://example.test' },
  clients: { matchAll: async () => [] }
};

await import('../src/enclave-sw.js');
const { configure, hasValidSession, resetState, ensureSession, getState, getConfig,
  setEstablishSession, resetEstablishSession } = globalThis.self.__ENCLAVE_SW_TEST__;

const ROTATION_INTERVAL_MS = 25 * 60 * 1000;

test.afterEach(() => {
  resetState();
  resetEstablishSession();
});

test('configure() cannot drop the /e2p/ protocol prefix', () => {
  configure({ excludePrefixes: ['/attestation'] });
  const excludePrefixes = getConfig().excludePrefixes;
  assert.ok(excludePrefixes.includes('/e2p/'), 'protocol prefix must remain excluded');
  assert.ok(excludePrefixes.includes('/attestation'), 'user-supplied prefix must be kept');
});

test('configure() de-duplicates the forced prefix across repeated calls', () => {
  configure({ excludePrefixes: ['/e2p/', '/foo'] });
  configure({ excludePrefixes: ['/bar'] });
  const excludePrefixes = getConfig().excludePrefixes;
  assert.equal(excludePrefixes.filter(p => p === '/e2p/').length, 1);
  assert.ok(excludePrefixes.includes('/bar'));
});

test('hasValidSession: false for null/undefined session', () => {
  assert.equal(hasValidSession(null), false);
  assert.equal(hasValidSession(undefined), false);
});

test('hasValidSession: true for a freshly created session', () => {
  assert.equal(hasValidSession({ createdAt: Date.now() }), true);
});

test('hasValidSession: false once past the rotation interval', () => {
  const stale = { createdAt: Date.now() - ROTATION_INTERVAL_MS - 1 };
  assert.equal(hasValidSession(stale), false);
});

test('a reset() during in-flight session establishment is not clobbered by the stale promise', async () => {
  let releaseEstablish;
  const pending = new Promise(resolve => { releaseEstablish = resolve; });
  setEstablishSession(() => pending.then(() => ({ id: 'session-a', createdAt: Date.now() })));

  const establishing = ensureSession();

  // Simulate a concurrent 'reset' service-worker message arriving before the
  // in-flight establishSession() call resolves.
  resetState();
  const stateAfterReset = getState();

  releaseEstablish();
  const resolvedSession = await establishing;

  // The promise still resolves with the session it built...
  assert.equal(resolvedSession.id, 'session-a');
  // ...but must not be written back into the (reset) module state, since a
  // newer generation has since taken over.
  assert.equal(getState().session, null);
  assert.equal(getState(), stateAfterReset);
});
