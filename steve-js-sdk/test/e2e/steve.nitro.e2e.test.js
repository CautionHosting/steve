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

async function initializeClient(page) {
  await registerClient(page, keyExchange);
  return page.evaluate(async () => {
    await window.steveNitroClient.initialize();
    return window.steveNitroClient.getStatus();
  });
}

async function protectedGet(page) {
  return page.evaluate(async enclaveOrigin => {
    const result = await fetch(`${enclaveOrigin}/index.html`, { cache: 'no-store' });
    return { status: result.status, body: await result.text() };
  }, remoteOrigin);
}

function expectApplicationResponse(response) {
  expect(response).toEqual({ status: 200, body: expectedBody });
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

  expectApplicationResponse(await protectedGet(page));
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

test('establishes the session lazily on the first protected request', async ({ page }) => {
  const idle = await registerClient(page, keyExchange);
  expect(idle.state).toBe('idle');
  expect(idle.initialized).toBe(false);

  expectApplicationResponse(await protectedGet(page));

  const status = await page.evaluate(() => window.steveNitroClient.getStatus());
  expect(status.state).toBe('ready');
  expect(status.session.trigger).toBe('protected-request');
  expect(status.attestation.synthetic).toBe(false);
});

test('rotates to a fresh attested session and continues encrypted requests', async ({
  page
}) => {
  const before = await initializeClient(page);
  expectApplicationResponse(await protectedGet(page));

  const after = await page.evaluate(async () => {
    await window.steveNitroClient.rotateKey();
    return window.steveNitroClient.getStatus();
  });

  expect(after.state).toBe('ready');
  expect(after.session.trigger).toBe('rotation');
  expect(after.session.id).not.toBe(before.session.id);
  expect(after.attestation.synthetic).toBe(false);
  expectApplicationResponse(await protectedGet(page));
});

test('preserves the live session across a page reload', async ({ page }) => {
  const before = await initializeClient(page);
  expectApplicationResponse(await protectedGet(page));

  await page.reload({ waitUntil: 'domcontentloaded' });
  const after = await registerClient(page, keyExchange);

  expect(after.state).toBe('ready');
  expect(after.session.id).toBe(before.session.id);
  expectApplicationResponse(await protectedGet(page));
});

test('restores configuration and re-attests after a service-worker restart', async ({
  page,
  browserName
}) => {
  test.skip(browserName !== 'chromium', 'service-worker process control requires Chromium CDP');
  const before = await initializeClient(page);
  expectApplicationResponse(await protectedGet(page));

  const cdp = await page.context().newCDPSession(page);
  await cdp.send('ServiceWorker.enable');
  await cdp.send('ServiceWorker.stopAllWorkers');

  const after = await page.evaluate(async () => {
    await window.steveNitroClient.initialize();
    return window.steveNitroClient.getStatus();
  });

  expect(after.state).toBe('ready');
  expect(after.session.id).not.toBe(before.session.id);
  expect(after.attestation.synthetic).toBe(false);
  expectApplicationResponse(await protectedGet(page));
});

test('handles concurrent encrypted requests and remains usable', async ({ page }) => {
  const before = await initializeClient(page);

  const result = await page.evaluate(async ({ enclaveOrigin, count }) => {
    const errors = [];
    window.steveNitroClient.on('error', error => errors.push(error));
    const responses = await Promise.all(
      Array.from({ length: count }, async (_, index) => {
        const response = await fetch(
          `${enclaveOrigin}/index.html?request=${index}`,
          { cache: 'no-store' }
        );
        return { index, status: response.status, body: await response.text() };
      })
    );
    return {
      errors,
      responses,
      status: await window.steveNitroClient.getStatus()
    };
  }, { enclaveOrigin: remoteOrigin, count: 16 });

  const failures = result.responses.filter(
    response => response.status !== 200 || response.body !== expectedBody
  );
  expect(
    failures,
    `secure-channel failures: ${JSON.stringify(result.errors)}`
  ).toEqual([]);
  expect(result.responses).toHaveLength(16);

  expect(result.status.state).toBe('ready');
  expect(result.status.session.id).toBe(before.session.id);
  expectApplicationResponse(await protectedGet(page));
});
