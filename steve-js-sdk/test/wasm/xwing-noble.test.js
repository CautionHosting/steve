import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { XWing } from '@noble/post-quantum/hybrid.js';

const wasmModule = await import('../../wasm-pkg/steve_xwing_wasm.js');
const wasmBytes = await readFile(new URL(
  '../../wasm-pkg/steve_xwing_wasm_bg.wasm',
  import.meta.url
));
await wasmModule.default({ module_or_path: wasmBytes });

test('randomized RustCrypto/WASM clients interoperate with Noble X-Wing', () => {
  for (let iteration = 0; iteration < 8; iteration += 1) {
    const client = new wasmModule.XWingClient();
    const publicKey = client.public_key();
    const { cipherText, sharedSecret } = XWing.encapsulate(publicKey);
    const received = client.decapsulate_and_destroy(cipherText);

    assert.equal(publicKey.length, 1216);
    assert.equal(cipherText.length, 1120);
    assert.deepEqual(received, sharedSecret);
    assert.throws(
      () => client.decapsulate_and_destroy(cipherText),
      /already consumed/u
    );
    received.fill(0);
    sharedSecret.fill(0);
    client.free();
  }
});

test('malformed decapsulation consumes the WASM private key', () => {
  const client = new wasmModule.XWingClient();

  assert.throws(
    () => client.decapsulate_and_destroy(new Uint8Array(1)),
    /invalid X-Wing ciphertext/u
  );
  assert.throws(() => client.public_key(), /already consumed/u);
  client.free();
});
