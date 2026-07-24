import * as esbuild from 'esbuild';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const watch = process.argv.includes('--watch');
const evalBuild = process.argv.includes('--eval');
const directory = path.dirname(fileURLToPath(import.meta.url));

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

const buildOptions = {
  entryPoints: ['src/enclave-sw.js', 'src/register.js'],
  bundle: true,
  format: 'esm',
  outdir: evalBuild ? '../tests/e2e/public' : 'dist',
  minify: false,
  target: 'es2020',
  logLevel: 'info',
  loader: evalBuild ? { '.pem': 'text' } : {},
  plugins: evalBuild ? [evalVerifierPlugin] : [],
};

if (watch) {
  const ctx = await esbuild.context(buildOptions);
  await ctx.watch();
  console.log('Watching for changes...');
} else {
  await esbuild.build(buildOptions);
}
