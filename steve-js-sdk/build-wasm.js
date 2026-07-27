import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const WASM_BINDGEN_VERSION = '0.2.106';
const directory = path.dirname(fileURLToPath(import.meta.url));
const repository = path.resolve(directory, '..');
const cargoOverride = process.env.CARGO;
const cargo = cargoOverride || rustupTool('cargo');
const rustc = process.env.RUSTC || (cargoOverride ? 'rustc' : rustupTool('rustc'));
const wasmBindgen = process.env.WASM_BINDGEN || 'wasm-bindgen';
const targetWasm = path.join(
  repository,
  'target/wasm32-unknown-unknown/release/steve_xwing_wasm.wasm'
);
const output = path.join(directory, 'wasm-pkg');

run(cargo, [
  'build',
  '--locked',
  '--offline',
  '--release',
  '--package',
  'steve-xwing-wasm',
  '--target',
  'wasm32-unknown-unknown'
], repository, false, { RUSTC: rustc });

const version = run(wasmBindgen, ['--version'], repository, true).trim();
if (version !== `wasm-bindgen ${WASM_BINDGEN_VERSION}`) {
  throw new Error(
    `wasm-bindgen-cli ${WASM_BINDGEN_VERSION} is required; found ${version || 'nothing'}`
  );
}

run(wasmBindgen, [
  targetWasm,
  '--target',
  'web',
  '--out-dir',
  output,
  '--out-name',
  'steve_xwing_wasm',
  '--no-typescript'
], repository);

function run(command, args, cwd, capture = false, environment = {}) {
  const result = spawnSync(command, args, {
    cwd,
    env: { ...process.env, ...environment },
    encoding: 'utf8',
    stdio: capture ? ['ignore', 'pipe', 'inherit'] : 'inherit'
  });
  if (result.error?.code === 'ENOENT') {
    throw new Error(`${command} is required but was not found`);
  }
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} exited with status ${result.status}`);
  }
  return result.stdout || '';
}

function rustupTool(tool) {
  return run('rustup', ['which', tool], repository, true).trim();
}
