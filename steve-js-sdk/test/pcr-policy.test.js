import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import {
  enforceTofuPcrPolicy,
  exactPcrsMatch,
  normalizePcrPolicy,
  pcrTrustKey,
  selectTofuPcrs,
  verifyPinnedPcrPolicy
} from '../src/pcr-policy.js';

const conformance = JSON.parse(await readFile(
  new URL('../../test-vectors/pcr-policy-v1.json', import.meta.url),
  'utf8'
));

const pcr = byte => byte.toString(16).padStart(2, '0').repeat(48);
const observed = {
  PCR0: pcr(0x10),
  PCR1: pcr(0x11),
  PCR2: pcr(0x12),
  PCR3: pcr(0x13),
  PCR8: pcr(0x18)
};

test('shared PCR policy vectors match browser normalization and policy semantics', () => {
  for (const vector of conformance.pinned) {
    const policy = normalizePcrPolicy({ mode: 'pinned', profiles: vector.profiles });
    if (vector.accepted) {
      assert.equal(verifyPinnedPcrPolicy(policy, conformance.observed), 'pinned', vector.name);
    } else {
      assert.throws(() => verifyPinnedPcrPolicy(policy, conformance.observed), undefined, vector.name);
    }
  }

  const tofuPolicy = normalizePcrPolicy({
    mode: 'tofu',
    additionalPcrIndices: conformance.tofu.additionalPcrIndices
  });
  const selected = selectTofuPcrs(tofuPolicy, conformance.observed);
  assert.deepEqual(selected, conformance.tofu.selected);
  for (const record of conformance.tofu.records) {
    assert.equal(exactPcrsMatch(record.pcrs, selected), record.matches, record.name);
  }
});

test('pinned policies normalize complete profiles and additional PCRs', () => {
  const policy = normalizePcrPolicy({
    mode: 'pinned',
    profiles: [{
      PCR3: observed.PCR3.toUpperCase(),
      PCR2: observed.PCR2,
      PCR0: observed.PCR0,
      PCR1: observed.PCR1
    }]
  });

  assert.deepEqual(policy, {
    mode: 'pinned',
    profiles: [{
      PCR0: observed.PCR0,
      PCR1: observed.PCR1,
      PCR2: observed.PCR2,
      PCR3: observed.PCR3
    }]
  });
  assert.equal(verifyPinnedPcrPolicy(policy, observed), 'pinned');
});

test('pinned policies reject empty, incomplete, malformed, zero, and unknown inputs', () => {
  const base = { PCR0: observed.PCR0, PCR1: observed.PCR1, PCR2: observed.PCR2 };
  const invalid = [
    { mode: 'pinned', profiles: [] },
    { mode: 'pinned', profiles: [{ PCR0: observed.PCR0, PCR1: observed.PCR1 }] },
    { mode: 'pinned', profiles: [{ ...base, PCR2: '12' }] },
    { mode: 'pinned', profiles: [{ ...base, PCR2: '0'.repeat(96) }] },
    { mode: 'pinned', profiles: [{ ...base, PCR256: observed.PCR3 }] },
    { mode: 'pinned', profiles: [base], extra: true }
  ];

  for (const policy of invalid) assert.throws(() => normalizePcrPolicy(policy));
});

test('pinned matching never mixes values from different profiles', () => {
  const policy = normalizePcrPolicy({
    mode: 'pinned',
    profiles: [
      { PCR0: pcr(0x20), PCR1: observed.PCR1, PCR2: observed.PCR2 },
      { PCR0: observed.PCR0, PCR1: pcr(0x21), PCR2: observed.PCR2 }
    ]
  });

  assert.throws(
    () => verifyPinnedPcrPolicy(policy, observed),
    /one complete pinned profile/u
  );
});

test('pinned matching accepts one complete profile from a rotation allowlist', () => {
  const policy = normalizePcrPolicy({
    mode: 'pinned',
    profiles: [
      { PCR0: pcr(0x20), PCR1: pcr(0x21), PCR2: pcr(0x22) },
      { PCR0: observed.PCR0, PCR1: observed.PCR1, PCR2: observed.PCR2, PCR3: observed.PCR3 }
    ]
  });

  assert.equal(verifyPinnedPcrPolicy(policy, observed), 'pinned');
});

test('TOFU selection is canonical and requires every selected nonzero PCR', () => {
  const policy = normalizePcrPolicy({
    mode: 'tofu',
    additionalPcrIndices: [8, 3, 1, 3]
  });
  assert.deepEqual(policy.additionalPcrIndices, [3, 8]);
  assert.deepEqual(selectTofuPcrs(policy, observed), observed);

  assert.throws(
    () => selectTofuPcrs(policy, { ...observed, PCR8: undefined }),
    /attested PCR8/u
  );
  assert.throws(
    () => selectTofuPcrs(policy, { ...observed, PCR3: '0'.repeat(96) }),
    /attested PCR3 must be nonzero/u
  );
});

test('TOFU records match the exact selected PCR set', () => {
  const selected = {
    PCR0: observed.PCR0,
    PCR1: observed.PCR1,
    PCR2: observed.PCR2
  };
  assert.equal(exactPcrsMatch(selected, selected), true);
  assert.equal(exactPcrsMatch({ ...selected, PCR3: observed.PCR3 }, selected), false);
  assert.equal(exactPcrsMatch({ PCR0: observed.PCR0, PCR1: observed.PCR1 }, selected), false);
  assert.equal(exactPcrsMatch({ ...selected, PCR2: pcr(0x99) }, selected), false);
});

test('TOFU key is scope, enclave-origin, and suite bound but selection independent', async () => {
  const scope = 'https://app.example/private/';
  const origin = 'https://enclave.example';
  const suite = 'X25519';
  const expected = createHash('sha256')
    .update('STEVE-E2P-V2-BROWSER-PCR-TOFU\0')
    .update(scope)
    .update('\0')
    .update(origin)
    .update('\0')
    .update(suite)
    .digest('hex');

  assert.equal(await pcrTrustKey(scope, origin, suite), expected);
  assert.notEqual(await pcrTrustKey(`${scope}other/`, origin, suite), expected);
  assert.notEqual(await pcrTrustKey(scope, 'https://other.example', suite), expected);
  assert.notEqual(await pcrTrustKey(scope, origin, 'XWING-DRAFT10'), expected);
});

test('concurrent TOFU enrollment produces one enrollment and one exact match', async () => {
  const records = new Map();
  let tail = Promise.resolve();
  const storage = {
    loadOrInsert(key, candidate) {
      const operation = tail.then(() => {
        if (records.has(key)) {
          return { status: 'existing', pcrs: records.get(key) };
        }
        records.set(key, structuredClone(candidate));
        return { status: 'inserted' };
      });
      tail = operation.then(() => {});
      return operation;
    }
  };
  const policy = normalizePcrPolicy({ mode: 'tofu', additionalPcrIndices: [3] });
  const context = {
    scope: 'https://app.example/',
    enclaveOrigin: 'https://enclave.example',
    suite: 'X25519'
  };

  assert.deepEqual(
    (await Promise.all([
      enforceTofuPcrPolicy(policy, observed, context, storage),
      enforceTofuPcrPolicy(policy, observed, context, storage)
    ])).sort(),
    ['tofu-enrolled', 'tofu-matched']
  );
});

test('TOFU fails closed on changed values, selection, or storage failure', async () => {
  const basePolicy = normalizePcrPolicy({ mode: 'tofu' });
  const strongerPolicy = normalizePcrPolicy({ mode: 'tofu', additionalPcrIndices: [3] });
  const context = {
    scope: 'https://app.example/',
    enclaveOrigin: 'https://enclave.example',
    suite: 'X25519'
  };
  let record;
  const storage = {
    async loadOrInsert(_key, candidate) {
      if (!record) {
        record = structuredClone(candidate);
        return { status: 'inserted' };
      }
      return { status: 'existing', pcrs: record };
    }
  };

  assert.equal(
    await enforceTofuPcrPolicy(basePolicy, observed, context, storage),
    'tofu-enrolled'
  );
  await assert.rejects(
    enforceTofuPcrPolicy(
      basePolicy,
      { ...observed, PCR2: pcr(0x99) },
      context,
      storage
    ),
    /enrolled TOFU record/u
  );
  await assert.rejects(
    enforceTofuPcrPolicy(strongerPolicy, observed, context, storage),
    /enrolled TOFU record/u
  );
  await assert.rejects(
    enforceTofuPcrPolicy(basePolicy, observed, context, {
      async loadOrInsert() { throw new Error('PCR policy storage failed'); }
    }),
    /PCR policy storage failed/u
  );
});
