import assert from 'node:assert/strict';
import { access, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const sdk = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('host builds cannot produce browser artifacts', async t => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'steve-host-build-'));
  const output = path.join(temporary, 'dist');
  const environment = { ...process.env };
  delete environment.STEVE_STAGEX_BUILD;
  t.after(() => rm(temporary, { recursive: true, force: true }));

  const result = spawnSync(
    process.execPath,
    ['build.js', '--outdir', output],
    { cwd: sdk, encoding: 'utf8', env: environment }
  );

  assert.notEqual(result.status, 0);
  assert.match(
    result.stderr,
    /Browser artifacts must be built through the StageX Make targets/u
  );
  await assert.rejects(access(output), { code: 'ENOENT' });
});
