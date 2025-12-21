import * as esbuild from 'esbuild';

const watch = process.argv.includes('--watch');

const buildOptions = {
  entryPoints: ['src/enclave-sw.js', 'src/register.js'],
  bundle: true,
  format: 'esm',
  outdir: 'dist',
  minify: false,
  target: 'es2020',
  logLevel: 'info',
};

if (watch) {
  const ctx = await esbuild.context(buildOptions);
  await ctx.watch();
  console.log('Watching for changes...');
} else {
  await esbuild.build(buildOptions);
}
