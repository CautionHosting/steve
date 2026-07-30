import { defineConfig } from '@playwright/test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const channel = process.env.STEVE_E2E_BROWSER_CHANNEL;
const browserName = process.env.STEVE_E2E_BROWSER || 'chromium';
const profile = process.env.STEVE_E2E_PROFILE || 'local';
const repositoryDirectory = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../..'
);

if (!['local', 'nitro'].includes(profile)) {
  throw new Error('STEVE_E2E_PROFILE must be exactly local or nitro');
}

export default defineConfig({
  testDir: '.',
  testMatch: 'steve.e2e.test.js',
  outputDir: `../../../tests/e2e/test-results/${profile}`,
  timeout: profile === 'nitro' ? 60_000 : 20_000,
  fullyParallel: false,
  workers: 1,
  ...(profile === 'nitro'
    ? {
        webServer: {
          command: 'node tests/e2e/fixture-server.mjs',
          cwd: repositoryDirectory,
          env: {
            ...process.env,
            STEVE_E2E_UI_ONLY: '1'
          },
          url: 'http://127.0.0.1:3000/__steve_e2e_health',
          timeout: 10_000,
          reuseExistingServer: false
        }
      }
    : {}),
  use: {
    baseURL: 'http://127.0.0.1:3000',
    browserName,
    serviceWorkers: 'allow',
    ...(channel && browserName === 'chromium' ? { channel } : {})
  }
});
