import * as esbuild from 'esbuild';
import { createHash } from 'node:crypto';
import { copyFile, mkdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const watch = process.argv.includes('--watch');
const evalBuild = process.argv.includes('--eval');
const directory = path.dirname(fileURLToPath(import.meta.url));
const xwingPackage = path.resolve(directory, 'wasm-pkg');
const xwingGlue = path.join(xwingPackage, 'steve_xwing_wasm.js');
const xwingWasm = path.join(xwingPackage, 'steve_xwing_wasm_bg.wasm');
const xwingWasmSha256 = createHash('sha256')
  .update(await readFile(xwingWasm))
  .digest('hex');

const evalVerifierPlugin = {
  name: 'steve-eval-attestation-verifier',
  setup(build) {
    build.onResolve({ filter: /^\.\/attestation-verifier\.js$/u }, args => {
      if (path.basename(args.importer) !== 'enclave-sw.js') return null;
      return {
        path: path.resolve(directory, 'test/e2e/eval-attestation-verifier.js')
      };
    });
  }
};

const xwingBindingsPlugin = {
  name: 'steve-xwing-static-bindings',
  setup(build) {
    build.onResolve({ filter: /^\.\/xwing-bindings\.js$/u }, args => {
      if (path.basename(args.importer) !== 'key-exchange.js') return null;
      return { path: xwingGlue };
    });
  }
};

const buildOptions = {
  entryPoints: ['src/enclave-sw.js', 'src/register.js'],
  bundle: true,
  format: 'esm',
  outdir: evalBuild ? '../tests/e2e/public' : 'dist',
  minify: false,
  target: 'es2020',
  logLevel: 'info',
  loader: evalBuild ? { '.pem': 'text' } : {},
  define: {
    __STEVE_XWING_WASM_SHA256__: JSON.stringify(xwingWasmSha256)
  },
  plugins: evalBuild
    ? [evalVerifierPlugin, xwingBindingsPlugin]
    : [xwingBindingsPlugin]
};

if (watch) {
  const ctx = await esbuild.context(buildOptions);
  await ctx.watch();
  console.log('Watching for changes...');
} else {
  await esbuild.build(buildOptions);
  const xwingOutput = path.resolve(directory, buildOptions.outdir, 'xwing');
  await mkdir(xwingOutput, { recursive: true });
  await copyFile(
    xwingWasm,
    path.join(xwingOutput, 'steve_xwing_wasm_bg.wasm')
  );
}
