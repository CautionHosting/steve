import { expect, test } from '@playwright/test';

const keyExchange = process.env.STEVE_KEY_EXCHANGE || 'X25519';
if (!['X25519', 'XWING-DRAFT10'].includes(keyExchange)) {
  throw new Error('STEVE_KEY_EXCHANGE must be exactly X25519 or XWING-DRAFT10');
}

async function openDemo(page, url = '/') {
  await page.goto(url);
  await page.waitForFunction(() => Boolean(window.steveDemo));
  await expect(page.locator('#system-status')).toContainText('Service worker active');
  return page.evaluate(async () => {
    // Do not repair the suite here: manual browser use must receive the same
    // deployment-pinned configuration as the automated test.
    const client = await window.steveDemo.ready;
    return client.getStatus();
  });
}

async function initialize(page) {
  await openDemo(page);
  await expect(page.getByRole('button', { name: 'Establish session' })).toBeEnabled();
  return page.evaluate(() => window.steveDemo.initialize());
}

test('starts with an honest idle state and synthetic verifier profile', async ({ page }) => {
  const status = await openDemo(page);

  await expect(page.locator('meta[name="steve-key-exchange"]')).toHaveAttribute(
    'content',
    keyExchange
  );
  expect(status.state).toBe('idle');
  expect(status.initialized).toBe(false);
  expect(status.session).toBeNull();
  expect(status.protocol).toEqual({
    id: 'STEVE-E2P-V2',
    version: 2,
    keyEstablishment: keyExchange,
    keyDerivation: 'HKDF-SHA256',
    recordProtection: 'AES-256-GCM'
  });
  expect(status.attestationVerifier).toEqual({
    id: 'synthetic-eval',
    trustAnchor: 'STEVE Local Eval Root',
    synthetic: true
  });
  await expect(page.locator('#system-status')).toContainText('session idle');
  await expect(page.locator('#trust-warning')).toContainText('this is not an enclave');
  await expect(page.getByRole('button', { name: 'Rotate session' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Reset session' })).toBeDisabled();
});

test('establishes a signed eval session and completes an encrypted echo', async ({ page }) => {
  const status = await initialize(page);

  expect(status.state).toBe('ready');
  expect(status.initialized).toBe(true);
  expect(status.session.trigger).toBe('explicit-initialize');
  expect(status.session.confirmation).toBe('verified');
  expect(status.session.id).toHaveLength(22);
  expect(status.session.transcriptHash).toHaveLength(43);
  expect(status.attestation.verified).toBe(true);
  expect(status.attestation.synthetic).toBe(true);
  expect(status.attestation.moduleId).toBe('steve-local-eval');
  expect(Object.keys(status.attestation.pcrs)).toEqual(['PCR0', 'PCR1', 'PCR2']);
  expect(status.attestation.checks).toEqual({
    certificateChain: 'verified',
    nonceBinding: 'verified',
    sessionBinding: 'verified',
    keyConfirmation: 'verified',
    expectedPcrPolicy: 'not-checked'
  });
  await expect(page.locator('#verification-checks')).toContainText('Expected PCR policy');
  await expect(page.locator('#verification-checks')).toContainText('not-checked');
  await expect(page.locator('#pcr-details')).toContainText(
    'Reported only; not compared with an approved PCR policy.'
  );

  expect(await page.evaluate(() => window.steveDemo.echo('browser-to-steve'))).toEqual({
    status: 200,
    body: 'browser-to-steve'
  });
});

test('reports lazy establishment by the first protected request', async ({ page }) => {
  const before = await openDemo(page);
  expect(before.state).toBe('idle');

  await page.locator('#request-body').fill('lazy-session');
  await page.getByRole('button', { name: 'Send protected request' }).click();
  await expect(page.locator('#application-response-body')).toHaveText('lazy-session');
  const after = await page.evaluate(() => window.steveDemo.status());

  expect(after.state).toBe('ready');
  expect(after.session.trigger).toBe('protected-request');
  await expect(page.locator('#session-trigger')).toHaveText('First protected request');
  await expect(page.locator('#events')).toContainText('first protected request');
  await expect(page.locator('#application-request-meta')).toContainText('POST /echo');
  await expect(page.locator('#application-request-body')).toHaveText('lazy-session');
  await expect(page.locator('#wire-request-meta')).toContainText('POST /e2p/v2/request');
  await expect(page.locator('#wire-request-meta')).toContainText('sequence 1');
  await expect(page.locator('#wire-request-envelope')).not.toHaveText('—');
  await expect(page.locator('#wire-response-meta')).toContainText(
    'Response from /e2p/v2/request'
  );
  await expect(page.locator('#wire-response-envelope')).not.toHaveText('—');
  await expect(page.locator('#application-response-meta')).toContainText('HTTP 200');
  expect(await page.locator('#wire-request-envelope').textContent()).not.toContain('lazy-session');
});

test('restores the live session status after a page reload', async ({ page }) => {
  const before = await initialize(page);
  await page.reload({ waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => Boolean(window.steveDemo));

  const after = await page.evaluate(() => window.steveDemo.status());
  expect(after.state).toBe('ready');
  expect(after.session.id).toBe(before.session.id);
  await expect(page.locator('#system-status')).toContainText('secure session ready');
  await expect(page.locator('#events')).toContainText('resumed an existing secure session');
});

test('rotates to a fresh session and resets diagnostics to idle', async ({ page }) => {
  const before = await initialize(page);
  const rotated = await page.evaluate(() => window.steveDemo.rotate());

  expect(rotated.state).toBe('ready');
  expect(rotated.session.trigger).toBe('rotation');
  expect(rotated.session.id).not.toBe(before.session.id);

  const reset = await page.evaluate(() => window.steveDemo.reset());
  expect(reset.state).toBe('idle');
  expect(reset.initialized).toBe(false);
  expect(reset.session).toBeNull();
  await expect(page.locator('#system-status')).toContainText('session idle');
  await expect(page.locator('#session-id')).toHaveText('—');
});

test('initializes from the manually opened localhost demo', async ({ page }) => {
  await openDemo(page, 'http://localhost:3000/');

  const status = await page.evaluate(() => window.steveDemo.initialize());
  const echo = await page.evaluate(() => window.steveDemo.echo('localhost-demo'));

  expect(status.initialized).toBe(true);
  expect(status.attestation.verified).toBe(true);
  expect(echo).toEqual({ status: 200, body: 'localhost-demo' });
});

test('serves bootstrap scripts through a controlling worker even when the enclave shares the page origin', async ({
  page
}) => {
  await page.goto('/');
  await page.waitForFunction(() => Boolean(window.steveDemo));
  await expect(page.locator('#system-status')).toContainText('Service worker active');

  // Force the worst case: point the enclave at the page's own origin so the
  // worker treats same-origin traffic as protected. The bootstrap scripts must
  // still pass through untouched, or the page can never load the code that
  // configures the worker — the self-perpetuating deadlock this guards against.
  await page.evaluate(async expectedKeyExchange => {
    const client = await window.steveDemo.ready;
    await client.configure({
      enclaveOrigin: location.origin,
      expectedKeyExchange
    });
  }, keyExchange);

  const fetched = await page.evaluate(async () => {
    const read = async path => {
      const response = await fetch(path, { cache: 'no-store' });
      return { status: response.status, body: (await response.text()).slice(0, 64) };
    };
    return {
      bootstrap: Object.fromEntries(
        await Promise.all(
          [
            '/attestation-widget.js',
            '/register.js',
            '/enclave-sw.js',
            '/xwing/steve_xwing_wasm_bg.wasm'
          ].map(
            async path => [path, await read(path)]
          )
        )
      ),
      // A same-origin path that is NOT a bootstrap script must be captured,
      // proving the worker really is protecting this origin.
      protected: await read('/not-a-bootstrap-path.js'),
      rootPost: await fetch('/', {
        method: 'POST',
        body: 'must-not-pass-through'
      }).then(async response => ({
        status: response.status,
        body: await response.text()
      }))
    };
  });

  for (const path of [
    '/attestation-widget.js',
    '/register.js',
    '/enclave-sw.js',
    '/xwing/steve_xwing_wasm_bg.wasm'
  ]) {
    expect(fetched.bootstrap[path].status).toBe(200);
    expect(fetched.bootstrap[path].body).not.toContain('secure channel failed');
  }
  expect(fetched.protected.body).toContain('secure channel failed');
  expect(fetched.rootPost.body).toContain('secure channel failed');
});

test('preserves the session across an encrypted application 401', async ({ page }) => {
  const before = await initialize(page);
  const unauthorized = await page.evaluate(() => window.steveDemo.unauthorized());
  const echo = await page.evaluate(() => window.steveDemo.echo('after-401'));
  const after = await page.evaluate(() => window.steveDemo.status());

  expect(unauthorized.status).toBe(401);
  expect(echo).toEqual({ status: 200, body: 'after-401' });
  expect(after.lastKeyRotation).toBe(before.lastKeyRotation);
});

test('renders concise outcomes for request-debugging controls', async ({ page }) => {
  await initialize(page);

  await page.getByRole('button', { name: 'Encrypted application 401' }).click();
  await expect(page.locator('#events')).toContainText('401 HTTP');
  await expect(page.locator('#scenario-result')).toContainText(
    'encrypted application HTTP 401; session is ready'
  );

  await page.getByRole('button', { name: 'Client request timeout' }).click();
  await expect(page.locator('#events')).toContainText('504 HTTP');
  await expect(page.locator('#scenario-result')).toContainText(
    'sequence retired and session is ready'
  );

  await page.getByRole('button', { name: 'Sequence-window pressure' }).click();
  await expect(page.locator('#events')).toContainText(
    '65 requests · 64 HTTP 200 · 1 HTTP 504'
  );
  await expect(page.locator('#scenario-result')).toContainText(
    'sequence window reopened without rotating the session'
  );
});

test('restores routing configuration after the service worker is restarted', async ({
  page,
  browserName
}) => {
  test.skip(browserName !== 'chromium', 'service-worker process control requires Chromium CDP');
  await initialize(page);

  const cdp = await page.context().newCDPSession(page);
  await cdp.send('ServiceWorker.enable');
  await cdp.send('ServiceWorker.stopAllWorkers');

  const status = await page.evaluate(async expectedKeyExchange => {
    const client = await window.steveDemo.ready;
    await client.configure({ expectedKeyExchange });
    return window.steveDemo.initialize();
  }, keyExchange);
  const echo = await page.evaluate(() => window.steveDemo.echo('after-worker-restart'));
  expect(status.initialized).toBe(true);
  expect(echo).toEqual({ status: 200, body: 'after-worker-restart' });
});

test('reconfigures after persisted routing configuration is lost', async ({
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
  await expect(page.locator('#system-status')).toContainText('Service worker active');
  const status = await page.evaluate(async expectedKeyExchange => {
    const client = await window.steveDemo.ready;
    await client.configure({ expectedKeyExchange });
    return window.steveDemo.initialize();
  }, keyExchange);
  const echo = await page.evaluate(() => window.steveDemo.echo('after-config-loss'));

  expect(status.initialized).toBe(true);
  expect(echo).toEqual({ status: 200, body: 'after-config-loss' });
});

test('retires a timed-out oldest request and unblocks the replay window', async ({ page }) => {
  const before = await initialize(page);
  const responses = await page.evaluate(() => window.steveDemo.concurrency());
  const afterWindow = await page.evaluate(() => window.steveDemo.echo('after-window'));
  const after = await page.evaluate(() => window.steveDemo.status());

  expect(responses.filter(response => response.status === 504)).toHaveLength(1);
  expect(responses.filter(response => response.status === 200)).toHaveLength(64);
  expect(afterWindow).toEqual({ status: 200, body: 'after-window' });
  expect(after.lastKeyRotation).toBe(before.lastKeyRotation);
});
