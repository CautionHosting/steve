import { expect, test } from '@playwright/test';

async function initialize(page) {
  await page.goto('/');
  await page.waitForFunction(() => Boolean(window.steveDemo));
  await expect(page.locator('#system-status')).toContainText('Service worker active');
  await expect(page.getByRole('button', { name: 'Initialize' })).toBeEnabled();
  return page.evaluate(() => window.steveDemo.initialize());
}

test('establishes a signed eval session and completes an encrypted echo', async ({ page }) => {
  const status = await initialize(page);

  expect(status.initialized).toBe(true);
  expect(status.attestation.verified).toBe(true);
  expect(status.attestation.moduleId).toBe('steve-local-eval');
  expect(Object.keys(status.attestation.pcrs)).toEqual(['PCR0', 'PCR1', 'PCR2']);

  expect(await page.evaluate(() => window.steveDemo.echo('browser-to-steve'))).toEqual({
    status: 200,
    body: 'browser-to-steve'
  });
});

test('initializes from the manually opened localhost demo', async ({ page }) => {
  await page.goto('http://localhost:3000/');
  await page.waitForFunction(() => Boolean(window.steveDemo));
  await expect(page.locator('#system-status')).toContainText('Service worker active');

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
  await page.evaluate(async () => {
    const client = await window.steveDemo.ready;
    await client.configure({ enclaveOrigin: location.origin });
  });

  const fetched = await page.evaluate(async () => {
    const read = async path => {
      const response = await fetch(path, { cache: 'no-store' });
      return { status: response.status, body: (await response.text()).slice(0, 64) };
    };
    return {
      bootstrap: Object.fromEntries(
        await Promise.all(
          ['/attestation-widget.js', '/register.js', '/enclave-sw.js'].map(
            async path => [path, await read(path)]
          )
        )
      ),
      // A same-origin path that is NOT a bootstrap script must be captured,
      // proving the worker really is protecting this origin.
      protected: await read('/not-a-bootstrap-path.js')
    };
  });

  for (const path of ['/attestation-widget.js', '/register.js', '/enclave-sw.js']) {
    expect(fetched.bootstrap[path].status).toBe(200);
    expect(fetched.bootstrap[path].body).not.toContain('secure channel failed');
  }
  expect(fetched.protected.body).toContain('secure channel failed');
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

test('restores routing configuration after the service worker is restarted', async ({
  page,
  browserName
}) => {
  test.skip(browserName !== 'chromium', 'service-worker process control requires Chromium CDP');
  await initialize(page);

  const cdp = await page.context().newCDPSession(page);
  await cdp.send('ServiceWorker.enable');
  await cdp.send('ServiceWorker.stopAllWorkers');

  const status = await page.evaluate(() => window.steveDemo.initialize());
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
  const status = await page.evaluate(() => window.steveDemo.initialize());
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
