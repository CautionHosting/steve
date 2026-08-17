import { expect, test } from '@playwright/test';

const profile = process.env.STEVE_E2E_PROFILE || 'local';
const keyExchange = process.env.STEVE_KEY_EXCHANGE || 'X25519';
const isNitro = profile === 'nitro';
const fixtureContract = {
  contract: 'steve-test-fixture/v1',
  capabilities: ['echo', 'unauthorized', 'delay', 'compressed'],
  max_echo_bytes: 1024 * 1024,
  max_delay_ms: 10_000
};

async function timedNitroOperation(label, operation) {
  const started = performance.now();
  try {
    return await operation();
  } finally {
    if (isNitro) {
      console.log(`[nitro timing] ${label}: ${Math.round(performance.now() - started)} ms`);
    }
  }
}

if (!['local', 'nitro'].includes(profile)) {
  throw new Error('STEVE_E2E_PROFILE must be exactly local or nitro');
}
if (!['X25519', 'XWING-DRAFT10'].includes(keyExchange)) {
  throw new Error('STEVE_KEY_EXCHANGE must be exactly X25519 or XWING-DRAFT10');
}

function requiredPcr(name) {
  const value = process.env[name];
  if (!value || !/^[0-9a-f]{96}$/iu.test(value)) {
    throw new Error(`${name} must contain exactly 96 hexadecimal characters`);
  }
  if (value.toLowerCase() === '0'.repeat(96)) {
    throw new Error(`${name} must be nonzero; deploy without Caution debug mode`);
  }
  return value.toLowerCase();
}

function normalizeRemoteOrigin(value) {
  if (!value) throw new Error('STEVE_REMOTE_ORIGIN is required');
  const url = new URL(value);
  if (
    !['http:', 'https:'].includes(url.protocol)
    || url.username
    || url.password
    || url.pathname !== '/'
    || url.search
    || url.hash
  ) {
    throw new Error('STEVE_REMOTE_ORIGIN must be an absolute HTTP(S) origin');
  }
  return url.origin;
}

const targetOrigin = isNitro
  ? normalizeRemoteOrigin(process.env.STEVE_REMOTE_ORIGIN)
  : 'http://127.0.0.1:49500';
const expectedPcrs = isNitro
  ? {
      PCR0: requiredPcr('STEVE_EXPECTED_PCR0'),
      PCR1: requiredPcr('STEVE_EXPECTED_PCR1'),
      PCR2: requiredPcr('STEVE_EXPECTED_PCR2')
    }
  : {
      PCR0: '10'.repeat(48),
      PCR1: '11'.repeat(48),
      PCR2: '12'.repeat(48)
    };

function demoPath(origin = targetOrigin, suite = keyExchange) {
  const params = new URLSearchParams({ origin, suite });
  return `/${profile}/?${params}`;
}

async function openDemo(page, options = {}) {
  const pageOrigin = options.pageOrigin || '';
  await page.goto(`${pageOrigin}${demoPath(options.origin, options.suite)}`);
  await page.waitForFunction(() => Boolean(window.steveDemo));
  await expect(page.locator('#system-status')).toContainText('Service worker active');
  return page.evaluate(async () => {
    const client = await window.steveDemo.ready;
    return client.getStatus();
  });
}

async function initialize(page) {
  await openDemo(page);
  await expect(page.getByRole('button', { name: 'Establish session' })).toBeEnabled();
  return timedNitroOperation(
    'session establishment',
    () => page.evaluate(() => window.steveDemo.initialize())
  );
}

async function currentStatus(page) {
  return page.evaluate(() => window.steveDemo.status());
}

async function upstreamCount(page, method, path) {
  return page.evaluate(async ({ method, path }) => {
    const params = new URLSearchParams({ method, path });
    const response = await fetch(`/__steve_e2e_upstream_count?${params}`);
    return Number(await response.text());
  }, { method, path });
}

function expectAttestationProfile(status) {
  if (isNitro) {
    expect(status.attestationVerifier).toEqual({
      id: 'aws-nitro',
      trustAnchor: 'AWS Nitro root CA',
      synthetic: false
    });
    expect(status.attestation.synthetic).toBe(false);
    expect(status.attestation.moduleId).toEqual(expect.any(String));
    expect(status.attestation.pcrs).toMatchObject(expectedPcrs);
  } else {
    expect(status.attestationVerifier).toEqual({
      id: 'synthetic-eval',
      trustAnchor: 'STEVE Local Eval Root',
      synthetic: true
    });
    expect(status.attestation.synthetic).toBe(true);
    expect(status.attestation.moduleId).toBe('steve-local-eval');
    expect(Object.keys(status.attestation.pcrs)).toEqual(['PCR0', 'PCR1', 'PCR2', 'PCR3']);
  }
}

test('starts idle with the selected evidence profile and suite', async ({ page }) => {
  const status = await openDemo(page);

  await expect(page.locator('meta[name="steve-profile"]')).toHaveAttribute(
    'content',
    profile
  );
  await expect(page.locator('#target-origin-input')).toHaveValue(targetOrigin);
  await expect(page.locator('#target-suite-input')).toHaveValue(keyExchange);
  expect(status.state).toBe('idle');
  expect(status.initialized).toBe(false);
  expect(status.protocol.keyEstablishment).toBe(keyExchange);
  expect(status.attestationVerifier.synthetic).toBe(!isNitro);
  await expect(page.getByRole('button', { name: 'Rotate session' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Reset session' })).toBeDisabled();
  if (isNitro) {
    await expect(page.locator('#trust-warning')).toBeHidden();
  } else {
    await expect(page.locator('#trust-warning')).toContainText('this is not an enclave');
  }
});

test('establishes an attested session and uses the versioned fixture', async ({ page }) => {
  const status = await initialize(page);

  expect(status.state).toBe('ready');
  expect(status.protocol.keyEstablishment).toBe(keyExchange);
  expect(status.session.trigger).toBe('explicit-initialize');
  expect(status.session.confirmation).toBe('verified');
  expect(status.attestation.verified).toBe(true);
  expect(status.attestation.checks).toEqual({
    certificateChain: 'verified',
    nonceBinding: 'verified',
    sessionBinding: 'verified',
    keyConfirmation: 'verified',
    expectedPcrPolicy: 'verified'
  });
  expect(status.attestation.pcrTrust).toBe('pinned');
  expectAttestationProfile(status);
  expect(await page.evaluate(() => window.steveDemo.fixture())).toEqual(fixtureContract);
  expect(await page.evaluate(() => window.steveDemo.echo('browser-to-steve'))).toEqual({
    status: 200,
    body: 'browser-to-steve'
  });
});

test('protects a 100 KiB body and requests an identity response', async ({ page }) => {
  await initialize(page);
  const large = await timedNitroOperation(
    '100 KiB echo',
    () => page.evaluate(() => window.steveDemo.largeEcho())
  );

  expect(large.status).toBe(200);
  expect(large.body).toBe('x'.repeat(100 * 1024));
  expect(await timedNitroOperation(
    'identity response',
    () => page.evaluate(() => window.steveDemo.compressed())
  )).toEqual({
    status: 200,
    body: 'identity-through-steve',
    contentEncoding: null,
    contentLength: null,
    upstreamAcceptEncoding: 'identity'
  });
});

test('client.send returns one protected exchange without exposing payloads', async ({ page }) => {
  await openDemo(page);
  const before = isNitro ? null : await upstreamCount(page, 'POST', '/echo');
  const result = await page.evaluate(async () => {
    const client = await window.steveDemo.ready;
    const { response, sessionId, exchange } = await client.send('/echo', {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: 'explicit-protected-send'
    });
    return { status: response.status, body: await response.text(), sessionId, exchange };
  });

  const current = await currentStatus(page);
  expect(result.status).toBe(200);
  expect(result.body).toBe('explicit-protected-send');
  expect(result.sessionId).toBe(current.session.id);
  expect(result.exchange).toMatchObject({
    protocolName: 'STEVE-E2P-V2',
    protection: 'AES-256-GCM',
    sessionId: current.session.id,
    keyExchange,
    pcrTrust: 'pinned',
    outerStatus: 200
  });
  expect(result.exchange.sequence).toMatch(/^[1-9][0-9]*$/u);
  for (const name of [
    'requestPlaintextBytes',
    'requestCiphertextBytes',
    'requestEnvelopeBytes',
    'responseEnvelopeBytes',
    'responseCiphertextBytes',
    'responsePlaintextBytes'
  ]) expect(result.exchange[name]).toBeGreaterThan(0);
  expect(JSON.stringify(result.exchange)).not.toContain('explicit-protected-send');
  if (!isNitro) {
    expect(await upstreamCount(page, 'POST', '/echo')).toBe(before + 1);
  }
});

test('fails closed when the browser and server suites disagree', async ({ page }) => {
  await openDemo(page);
  const mismatched = keyExchange === 'X25519' ? 'XWING-DRAFT10' : 'X25519';

  const error = await page.evaluate(async suite => {
    const client = await window.steveDemo.ready;
    await client.configure({ expectedKeyExchange: suite });
    try {
      await client.initialize();
      return null;
    } catch (failure) {
      return failure.message;
    }
  }, mismatched);

  expect(error).toMatch(/session creation rejected \(400\)/u);
  await expect(page.locator('#system-status')).toHaveAttribute('data-state', 'error');
});

test('preserves legacy not-checked behavior only when PCR policy is explicitly omitted', async ({ page }) => {
  await openDemo(page);
  await page.evaluate(() => window.steveDemo.configurePcrPolicy(null));

  const status = await page.evaluate(() => window.steveDemo.initialize());

  expect(status.attestation.pcrTrust).toBe('not-checked');
  expect(status.attestation.checks.expectedPcrPolicy).toBe('not-checked');
  expect(await page.evaluate(() => window.steveDemo.echo('legacy-no-policy'))).toEqual({
    status: 200,
    body: 'legacy-no-policy'
  });
});

test('rejects a mutated pinned profile before application traffic', async ({ page }) => {
  await openDemo(page);
  const protocolPaths = [];
  const observeProtocolRequest = request => {
    const url = new URL(request.url());
    if (url.origin === targetOrigin && url.pathname.startsWith('/e2p/v2/')) {
      protocolPaths.push(url.pathname);
    }
  };
  page.context().on('request', observeProtocolRequest);
  let rejected;
  try {
    rejected = await page.evaluate(async profilePcrs => {
      const mutated = {
        ...profilePcrs,
        PCR2: `${profilePcrs.PCR2.slice(0, -2)}${profilePcrs.PCR2.endsWith('00') ? '01' : '00'}`
      };
      await window.steveDemo.configurePcrPolicy({
        mode: 'pinned',
        profiles: [mutated]
      });
      const client = await window.steveDemo.ready;
      try {
        await client.send('/echo', { method: 'POST', body: 'must-not-reach-upstream' });
        return null;
      } catch (error) {
        return { code: error.code, stage: error.stage, message: error.message };
      }
    }, expectedPcrs);
  } finally {
    page.context().off('request', observeProtocolRequest);
  }

  expect(rejected).toEqual({
    code: 'PCR_POLICY_MISMATCH',
    stage: 'pcr-policy',
    message: 'attested PCRs did not match one complete pinned profile'
  });
  expect(protocolPaths).toContain('/e2p/v2/session');
  expect(protocolPaths).not.toContain('/e2p/v2/request');
  expect((await currentStatus(page)).session).toBeNull();
});

test('establishes lazily on the first protected request', async ({ page }) => {
  const before = await openDemo(page);
  expect(before.state).toBe('idle');

  expect(await page.evaluate(() => window.steveDemo.echo('lazy-session'))).toEqual({
    status: 200,
    body: 'lazy-session'
  });
  const after = await currentStatus(page);
  expect(after.state).toBe('ready');
  expect(after.session.trigger).toBe('protected-request');
  expectAttestationProfile(after);
});

test('preserves the live session across a page reload', async ({ page }) => {
  const before = await initialize(page);
  await page.reload({ waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => Boolean(window.steveDemo));

  const after = await currentStatus(page);
  expect(after.state).toBe('ready');
  expect(after.session.id).toBe(before.session.id);
  expect(await page.evaluate(() => window.steveDemo.echo('after-reload'))).toEqual({
    status: 200,
    body: 'after-reload'
  });
});

test('rotates to fresh attested keys and resets to idle', async ({ page }) => {
  const before = await initialize(page);
  const rotated = await page.evaluate(() => window.steveDemo.rotate());

  expect(rotated.state).toBe('ready');
  expect(rotated.session.trigger).toBe('rotation');
  expect(rotated.session.id).not.toBe(before.session.id);
  expectAttestationProfile(rotated);
  expect(await page.evaluate(() => window.steveDemo.echo('after-rotation'))).toEqual({
    status: 200,
    body: 'after-rotation'
  });

  const reset = await page.evaluate(() => window.steveDemo.reset());
  expect(reset.state).toBe('idle');
  expect(reset.session).toBeNull();
});

test('preserves the session across an encrypted application 401', async ({ page }) => {
  const before = await initialize(page);
  const unauthorized = await page.evaluate(() => window.steveDemo.unauthorized());
  const echo = await page.evaluate(() => window.steveDemo.echo('after-401'));
  const after = await currentStatus(page);

  expect(unauthorized).toEqual({
    status: 401,
    body: 'application unauthorized\n'
  });
  expect(echo).toEqual({ status: 200, body: 'after-401' });
  expect(after.session.id).toBe(before.session.id);
});

test('retires a timed-out request and keeps the session usable', async ({ page }) => {
  const before = await initialize(page);
  const timedOut = await timedNitroOperation(
    'controlled 3s timeout',
    () => page.evaluate(() => window.steveDemo.timeout())
  );
  const echo = await timedNitroOperation(
    'request after timeout',
    () => page.evaluate(() => window.steveDemo.echo('after-timeout'))
  );
  const after = await currentStatus(page);

  expect(timedOut.status).toBe(504);
  expect(echo).toEqual({ status: 200, body: 'after-timeout' });
  expect(after.session.id).toBe(before.session.id);
});

test('restores configuration and re-attests after a service-worker restart', async ({
  page,
  browserName
}) => {
  test.skip(browserName !== 'chromium', 'service-worker process control requires Chromium CDP');
  const before = await initialize(page);

  const cdp = await page.context().newCDPSession(page);
  await cdp.send('ServiceWorker.enable');
  await cdp.send('ServiceWorker.stopAllWorkers');

  const after = await page.evaluate(() => window.steveDemo.initialize());
  expect(after.state).toBe('ready');
  expect(after.session.id).not.toBe(before.session.id);
  expectAttestationProfile(after);
  expect(await page.evaluate(() => window.steveDemo.echo('after-worker-restart'))).toEqual({
    status: 200,
    body: 'after-worker-restart'
  });
});

test('TOFU enrolls after confirmation, matches on rotation, and survives worker restart', async ({
  page,
  browserName
}) => {
  test.skip(browserName !== 'chromium', 'service-worker process control requires Chromium CDP');
  await openDemo(page);
  const policy = isNitro
    ? { mode: 'tofu' }
    : { mode: 'tofu', additionalPcrIndices: [3, 1, 3] };
  await page.evaluate(
    pcrPolicy => window.steveDemo.configurePcrPolicy(pcrPolicy),
    policy
  );

  const enrolled = await page.evaluate(() => window.steveDemo.initialize());
  expect(enrolled.attestation.pcrTrust).toBe('tofu-enrolled');
  expect(enrolled.attestation.checks.expectedPcrPolicy).toBe('verified');
  expect(await page.evaluate(() => window.steveDemo.echo('after-tofu-enrollment'))).toEqual({
    status: 200,
    body: 'after-tofu-enrollment'
  });

  const rotated = await page.evaluate(() => window.steveDemo.rotate());
  expect(rotated.attestation.pcrTrust).toBe('tofu-matched');
  expect(rotated.session.id).not.toBe(enrolled.session.id);
  expect(await page.evaluate(() => window.steveDemo.echo('after-tofu-rotation'))).toEqual({
    status: 200,
    body: 'after-tofu-rotation'
  });

  const cdp = await page.context().newCDPSession(page);
  await cdp.send('ServiceWorker.enable');
  await cdp.send('ServiceWorker.stopAllWorkers');

  const restored = await page.evaluate(() => window.steveDemo.initialize());
  expect(restored.attestation.pcrTrust).toBe('tofu-matched');
  expect(restored.session.id).not.toBe(rotated.session.id);
  expect(await page.evaluate(() => window.steveDemo.echo('after-tofu-restart'))).toEqual({
    status: 200,
    body: 'after-tofu-restart'
  });
});

test('handles bounded concurrency and remains usable', async ({ page }) => {
  const before = await initialize(page);
  const responses = await timedNitroOperation(
    '16 concurrent requests',
    () => page.evaluate(() => window.steveDemo.concurrency())
  );
  const afterWindow = await timedNitroOperation(
    'request after concurrency',
    () => page.evaluate(() => window.steveDemo.echo('after-concurrency'))
  );
  const after = await currentStatus(page);

  expect(responses).toHaveLength(16);
  expect(responses.every(response => response.status === 200)).toBe(true);
  expect(responses.map(response => response.body)).toEqual(
    Array.from({ length: 16 }, (_, index) => `concurrent-${index}`)
  );
  expect(afterWindow).toEqual({ status: 200, body: 'after-concurrency' });
  expect(after.session.id).toBe(before.session.id);
});

test.describe('local synthetic profile', () => {
  test.skip(isNitro, 'local-only deterministic and bootstrap coverage');

  test('works when manually opened through localhost', async ({ page }) => {
    await openDemo(page, { pageOrigin: 'http://localhost:3000' });
    const status = await page.evaluate(() => window.steveDemo.initialize());
    expect(status.attestation.synthetic).toBe(true);
    expect(await page.evaluate(() => window.steveDemo.echo('localhost-demo'))).toEqual({
      status: 200,
      body: 'localhost-demo'
    });
  });

  test('passes scoped bootstrap assets through for a same-origin target', async ({ page }) => {
    await openDemo(page);
    await page.evaluate(async suite => {
      const client = await window.steveDemo.ready;
      await client.configure({
        enclaveOrigin: location.origin,
        expectedKeyExchange: suite
      });
    }, keyExchange);

    const fetched = await page.evaluate(async currentProfile => {
      const base = `/${currentProfile}/`;
      const read = async path => {
        const response = await fetch(path, { cache: 'no-store' });
        return { status: response.status, body: (await response.text()).slice(0, 64) };
      };
      const bootstrapPaths = [
        `${base}attestation-widget.js`,
        `${base}register.js`,
        `${base}enclave-sw.js`,
        `${base}xwing/steve_xwing_wasm_bg.wasm`
      ];
      return {
        bootstrap: Object.fromEntries(
          await Promise.all(bootstrapPaths.map(async path => [path, await read(path)]))
        ),
        protected: await read(`${base}not-a-bootstrap-path.js`),
        rootPost: await fetch(base, {
          method: 'POST',
          body: 'must-not-pass-through'
        }).then(async response => ({
          status: response.status,
          body: await response.text()
        }))
      };
    }, profile);

    for (const response of Object.values(fetched.bootstrap)) {
      expect(response.status).toBe(200);
      expect(response.body).not.toContain('secure channel failed');
    }
    expect(fetched.protected.body).toContain('secure channel failed');
    expect(fetched.rootPost.body).toContain('secure channel failed');
  });

  test('recovers after persisted routing configuration is lost', async ({
    page,
    browserName
  }) => {
    test.skip(browserName !== 'chromium', 'service-worker process control requires Chromium CDP');
    await initialize(page);

    await page.evaluate(() => caches.delete('steve-sdk-config-v1'));
    const cdp = await page.context().newCDPSession(page);
    await cdp.send('ServiceWorker.enable');
    await cdp.send('ServiceWorker.stopAllWorkers');
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => Boolean(window.steveDemo));

    const status = await page.evaluate(() => window.steveDemo.initialize());
    expect(status.initialized).toBe(true);
    expect(await page.evaluate(() => window.steveDemo.echo('after-config-loss'))).toEqual({
      status: 200,
      body: 'after-config-loss'
    });
  });

  test('TOFU selection changes conflict and dispatch no application traffic', async ({ page }) => {
    await openDemo(page);
    await page.evaluate(() => window.steveDemo.configurePcrPolicy({ mode: 'tofu' }));
    const enrolled = await page.evaluate(() => window.steveDemo.initialize());
    expect(enrolled.attestation.pcrTrust).toBe('tofu-enrolled');
    const before = await upstreamCount(page, 'POST', '/echo');

    await page.evaluate(() => window.steveDemo.configurePcrPolicy({
      mode: 'tofu',
      additionalPcrIndices: [3]
    }));
    const rejected = await page.evaluate(() => window.steveDemo.echo('selection-conflict'));

    expect(rejected.status).toBe(502);
    expect(await upstreamCount(page, 'POST', '/echo')).toBe(before);
    expect((await currentStatus(page)).session).toBeNull();
  });

  test('failed TOFU rotation preserves the prior accepted session', async ({ page }) => {
    await openDemo(page);
    await page.evaluate(() => window.steveDemo.configurePcrPolicy({ mode: 'tofu' }));
    const enrolled = await page.evaluate(() => window.steveDemo.initialize());

    await page.evaluate(async () => {
      const database = await new Promise((resolve, reject) => {
        const request = indexedDB.open('steve-sdk-pcr-policy-v1', 1);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      try {
        await new Promise((resolve, reject) => {
          const transaction = database.transaction('state', 'readwrite', {
            durability: 'strict'
          });
          const store = transaction.objectStore('state');
          const keys = store.getAllKeys();
          keys.onsuccess = () => {
            const trustKey = keys.result.find(key => String(key).startsWith('trust:'));
            const record = store.get(trustKey);
            record.onsuccess = () => {
              store.put({ ...record.result, PCR0: '99'.repeat(48) }, trustKey);
            };
          };
          transaction.oncomplete = resolve;
          transaction.onerror = () => reject(transaction.error);
          transaction.onabort = () => reject(transaction.error);
        });
      } finally {
        database.close();
      }
    });

    const error = await page.evaluate(async () => {
      try {
        await window.steveDemo.rotate();
        return null;
      } catch (failure) {
        return failure.message;
      }
    });
    expect(error).toMatch(/enrolled TOFU record/u);
    const after = await currentStatus(page);
    expect(after.session.id).toBe(enrolled.session.id);
    expect(await page.evaluate(() => window.steveDemo.echo('after-failed-rotation'))).toEqual({
      status: 200,
      body: 'after-failed-rotation'
    });
  });

  test('TOFU storage failure dispatches no application traffic', async ({ page }) => {
    await openDemo(page);
    await page.evaluate(() => window.steveDemo.configurePcrPolicy({ mode: 'tofu' }));
    await page.evaluate(async () => {
      const database = await new Promise((resolve, reject) => {
        const request = indexedDB.open('steve-sdk-pcr-policy-v1', 2);
        request.onupgradeneeded = () => request.result.deleteObjectStore('state');
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      database.close();
    });
    const before = await upstreamCount(page, 'POST', '/echo');

    const rejected = await page.evaluate(() => window.steveDemo.echo('storage-failure'));

    expect(rejected.status).toBe(502);
    expect(await upstreamCount(page, 'POST', '/echo')).toBe(before);
    expect((await currentStatus(page)).session).toBeNull();
  });

  test('reopens the exact 64-entry sequence window after timeout', async ({ page }) => {
    const before = await initialize(page);
    const responses = await page.evaluate(() => window.steveDemo.windowPressure());
    const afterWindow = await page.evaluate(() => window.steveDemo.echo('after-window'));
    const after = await currentStatus(page);

    expect(responses.filter(response => response.status === 504)).toHaveLength(1);
    expect(responses.filter(response => response.status === 200)).toHaveLength(64);
    expect(afterWindow).toEqual({ status: 200, body: 'after-window' });
    expect(after.session.id).toBe(before.session.id);
  });
});
