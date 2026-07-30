import { defineConfig } from '@playwright/test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const channel = process.env.STEVE_E2E_BROWSER_CHANNEL;
const browserName = process.env.STEVE_E2E_BROWSER || 'chromium';
const sdkDirectory = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../..'
);

export default defineConfig({
  testDir: '.',
  testMatch: 'steve.nitro.e2e.test.js',
  outputDir: '../../../tests/e2e/test-results/nitro',
  timeout: 45_000,
  fullyParallel: false,
  workers: 1,
  webServer: {
    command: 'node test/e2e/production-sdk-server.mjs',
    cwd: sdkDirectory,
    url: 'http://127.0.0.1:3000/__steve_nitro_e2e_health',
    timeout: 10_000,
    reuseExistingServer: false
  },
  use: {
    baseURL: 'http://127.0.0.1:3000',
    browserName,
    serviceWorkers: 'allow',
    ...(channel && browserName === 'chromium' ? { channel } : {})
  }
});
