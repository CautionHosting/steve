import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const sdk = path.join(root, 'steve-js-sdk');

const packageJson = JSON.parse(
  await readFile(path.join(sdk, 'package.json'), 'utf8')
);
const stageXArtifactScripts = {
  build: 'make build',
  'build:wasm': 'make build-wasm',
  'build:e2e': 'make build-e2e',
  'test:wasm': 'make test-wasm'
};
for (const [name, expected] of Object.entries(stageXArtifactScripts)) {
  if (packageJson.scripts?.[name] !== expected) {
    throw new Error(`${name} must delegate to ${expected}`);
  }
}
const hostArtifactScript = Object.entries(packageJson.scripts || {}).find(
  ([, command]) => /(?:build-wasm\.js|node\s+build\.js)/u.test(command)
);
if (hostArtifactScript) {
  throw new Error(
    `host artifact build is not allowed in npm script ${hostArtifactScript[0]}`
  );
}

function run(command, args, cwd, env = process.env) {
  const result = spawnSync(command, args, {
    cwd,
    env,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit']
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed with status ${result.status}`);
  }
  return result.stdout;
}

const npmCache = await mkdtemp(path.join(os.tmpdir(), 'steve-e2e-npm-'));
let packOutput;
try {
  packOutput = run(
    'npm',
    ['pack', '--dry-run', '--json', '--ignore-scripts'],
    sdk,
    { ...process.env, npm_config_cache: npmCache }
  );
} finally {
  await rm(npmCache, { recursive: true, force: true });
}
const packResult = JSON.parse(packOutput);
const pack = Array.isArray(packResult) ? packResult[0] : Object.values(packResult)[0];
if (!pack?.files) {
  throw new Error('npm pack did not return a package file list');
}
const packedFiles = pack.files.map(file => file.path);
const requiredPackageFiles = [
  'dist/enclave-sw.js',
  'dist/register.js',
  'dist/xwing/steve_xwing_wasm_bg.wasm'
];
const missingPackageFiles = requiredPackageFiles.filter(
  file => !packedFiles.includes(file)
);
if (missingPackageFiles.length > 0) {
  throw new Error(
    `required production package files missing: ${missingPackageFiles.join(', ')}`
  );
}

const worker = await readFile(path.join(sdk, 'dist/enclave-sw.js'), 'utf8');
const wasm = await readFile(
  path.join(sdk, 'dist/xwing/steve_xwing_wasm_bg.wasm')
);
const wasmDigest = createHash('sha256').update(wasm).digest('hex');
if (!worker.includes(wasmDigest)) {
  throw new Error('production service worker does not bind the packaged X-Wing WASM digest');
}

const forbiddenPaths = packedFiles.filter(file =>
  /(?:^|\/)(?:test\/e2e|tests\/e2e|steve-eval|generated)(?:\/|$)|\.pem$/u.test(file)
);
if (forbiddenPaths.length > 0) {
  throw new Error(`eval-only files in production npm package: ${forbiddenPaths.join(', ')}`);
}

const forbiddenMarkers = [
  'steve-local-eval',
  'STEVE Local Eval Root',
  'BEGIN PRIVATE KEY',
  '__ENCLAVE_SW_TEST__'
];
for (const file of packedFiles) {
  const contents = await readFile(path.join(sdk, file), 'utf8').catch(() => '');
  const marker = forbiddenMarkers.find(value => contents.includes(value));
  if (marker) {
    throw new Error(`eval-only marker ${JSON.stringify(marker)} in npm package file ${file}`);
  }
}

const productionContainerfile = await readFile(path.join(root, 'Containerfile'), 'utf8');
if (
  /^COPY\s+\.\s+/mu.test(productionContainerfile) ||
  productionContainerfile.includes('tests/e2e')
) {
  throw new Error('production Containerfile must not copy eval-only test material');
}

const metadata = JSON.parse(
  run('cargo', ['metadata', '--no-deps', '--format-version', '1'], root)
);
const steve = metadata.packages.find(pkg => pkg.name === 'steve');
if (!steve || steve.features.default?.length !== 0) {
  throw new Error('steve default features must remain empty');
}
const evalBinary = steve.targets.find(target => target.name === 'steve-eval');
const requiredFeatures = evalBinary?.['required-features'];
if (
  !evalBinary ||
  evalBinary.kind[0] !== 'bin' ||
  requiredFeatures?.length !== 1 ||
  requiredFeatures[0] !== 'eval-attestation'
) {
  throw new Error('steve-eval must require the non-default eval-attestation feature');
}

console.log('production package excludes eval trust material and eval-only artifacts');
