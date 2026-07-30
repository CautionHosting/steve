import { expect, test } from '@playwright/test';

const keyExchange = process.env.STEVE_KEY_EXCHANGE;
const rawRemoteOrigin = process.env.STEVE_REMOTE_ORIGIN;
const expectedBody = process.env.STEVE_REMOTE_EXPECTED_BODY ?? 'xwing demo app\n';
const rawRequireNonzeroPcrs = process.env.STEVE_REMOTE_REQUIRE_NONZERO_PCRS ?? '0';
const requireNonzeroPcrs = rawRequireNonzeroPcrs === '1';

if (!['X25519', 'XWING-DRAFT10'].includes(keyExchange)) {
  throw new Error('STEVE_KEY_EXCHANGE must be explicitly set to X25519 or XWING-DRAFT10');
}
if (!rawRemoteOrigin) {
  throw new Error('STEVE_REMOTE_ORIGIN is required');
}
if (!['0', '1'].includes(rawRequireNonzeroPcrs)) {
  throw new Error('STEVE_REMOTE_REQUIRE_NONZERO_PCRS must be exactly 0 or 1');
}

const remoteUrl = new URL(rawRemoteOrigin);
if (!['http:', 'https:'].includes(remoteUrl.protocol)
    || remoteUrl.username || remoteUrl.password
    || remoteUrl.pathname !== '/' || remoteUrl.search || remoteUrl.hash) {
  throw new Error('STEVE_REMOTE_ORIGIN must be an absolute HTTP(S) origin');
}
const remoteOrigin = remoteUrl.origin;

async function registerClient(page, expectedKeyExchange) {
  await page.goto('/');
  return page.evaluate(async ({ enclaveOrigin, suite }) => {
    const { registerEnclaveServiceWorker } = await import('/register.js');
    const client = await registerEnclaveServiceWorker({
      swPath: '/enclave-sw.js',
      scope: '/',
      config: {
        enclaveOrigin,
        expectedKeyExchange: suite
      }
    });
    window.steveNitroClient = client;
    return client.getStatus();
  }, { enclaveOrigin: remoteOrigin, suite: expectedKeyExchange });
}

test('verifies real Nitro evidence and completes an encrypted application request', async ({
  page
}) => {
  const idle = await registerClient(page, keyExchange);
  expect(idle.attestationVerifier).toEqual({
    id: 'aws-nitro',
    trustAnchor: 'AWS Nitro root CA',
    synthetic: false
  });

  const status = await page.evaluate(async () => {
    await window.steveNitroClient.initialize();
    return window.steveNitroClient.getStatus();
  });

  expect(status.state).toBe('ready');
  expect(status.initialized).toBe(true);
  expect(status.protocol.keyEstablishment).toBe(keyExchange);
  expect(status.session.confirmation).toBe('verified');
  expect(status.attestation.verified).toBe(true);
  expect(status.attestation.profile).toBe('aws-nitro');
  expect(status.attestation.synthetic).toBe(false);
  expect(status.attestation.moduleId).toEqual(expect.any(String));
  expect(status.attestation.checks).toEqual({
    certificateChain: 'verified',
    nonceBinding: 'verified',
    sessionBinding: 'verified',
    keyConfirmation: 'verified',
    expectedPcrPolicy: 'not-checked'
  });

  for (const pcr of ['PCR0', 'PCR1', 'PCR2']) {
    expect(status.attestation.pcrs[pcr]).toMatch(/^[0-9a-f]{96}$/u);
    if (requireNonzeroPcrs) {
      expect(status.attestation.pcrs[pcr]).not.toBe('0'.repeat(96));
    }
  }

  const response = await page.evaluate(async enclaveOrigin => {
    const result = await fetch(`${enclaveOrigin}/index.html`, { cache: 'no-store' });
    return { status: result.status, body: await result.text() };
  }, remoteOrigin);
  expect(response).toEqual({ status: 200, body: expectedBody });
});

test('fails closed when the configured suite does not match the enclave', async ({
  page
}) => {
  const mismatchedKeyExchange = keyExchange === 'X25519'
    ? 'XWING-DRAFT10'
    : 'X25519';
  await registerClient(page, mismatchedKeyExchange);

  const error = await page.evaluate(async () => {
    try {
      await window.steveNitroClient.initialize();
      return null;
    } catch (failure) {
      return failure.message;
    }
  });

  expect(error).toMatch(/session creation rejected \(400\)/u);
});
