import { defineConfig } from '@playwright/test';

const channel = process.env.STEVE_E2E_BROWSER_CHANNEL;
const browserName = process.env.STEVE_E2E_BROWSER || 'chromium';

export default defineConfig({
  testDir: '.',
  testMatch: 'steve.e2e.test.js',
  outputDir: '../../../tests/e2e/test-results',
  timeout: 20_000,
  fullyParallel: false,
  workers: 1,
  use: {
    baseURL: 'http://127.0.0.1:3000',
    browserName,
    serviceWorkers: 'allow',
    ...(channel && browserName === 'chromium' ? { channel } : {})
  }
});
