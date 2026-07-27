import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { XWing } from '@noble/post-quantum/hybrid.js';

const vectorUrl = new URL('../../test-vectors/xwing-draft10.json', import.meta.url);
const vectorBytes = await readFile(vectorUrl);
const vectors = JSON.parse(vectorBytes);
const checksum = (
  await readFile(new URL('../../test-vectors/xwing-draft10.sha256', import.meta.url), 'utf8')
).split(/\s/u, 1)[0];
const bytes = value => Uint8Array.from(Buffer.from(value, 'hex'));
const hex = value => Buffer.from(value).toString('hex');

test('all three checksum-pinned X-Wing draft-10 KATs match Noble 0.6.1', () => {
  assert.equal(createHash('sha256').update(vectorBytes).digest('hex'), checksum);
  assert.equal(vectors.length, 3);

  for (const vector of vectors) {
    const seed = bytes(vector.seed);
    const { publicKey, secretKey } = XWing.keygen(seed);
    assert.equal(hex(secretKey), vector.sk);
    assert.equal(hex(publicKey), vector.pk);

    const { cipherText, sharedSecret } = XWing.encapsulate(
      publicKey,
      bytes(vector.eseed)
    );
    assert.equal(hex(cipherText), vector.ct);
    assert.equal(hex(sharedSecret), vector.ss);
    assert.equal(hex(XWing.decapsulate(cipherText, secretKey)), vector.ss);

    sharedSecret.fill(0);
  }
});
