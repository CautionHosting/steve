const DATABASE_NAME = 'steve-sdk-pcr-policy-v1';
const DATABASE_VERSION = 1;
const STORE_NAME = 'state';
const TRUST_KEY_DOMAIN = 'STEVE-E2P-V2-BROWSER-PCR-TOFU\0';
const PCR_HEX = /^[0-9a-f]{96}$/iu;
const PCR_NAME = /^PCR(0|[1-9][0-9]{0,2})$/u;
const ZERO_PCR = '0'.repeat(96);

export function normalizePcrPolicy(policy) {
  if (policy === null) return null;
  requireRecord(policy, 'pcrPolicy');

  if (policy.mode === 'pinned') {
    requireOnlyKeys(policy, ['mode', 'profiles'], 'pinned PCR policy');
    if (!Array.isArray(policy.profiles) || policy.profiles.length === 0) {
      throw new Error('pinned PCR policy requires at least one profile');
    }
    return {
      mode: 'pinned',
      profiles: policy.profiles.map((profile, index) => normalizeProfile(
        profile,
        `pinned PCR profile ${index}`
      ))
    };
  }

  if (policy.mode === 'tofu') {
    requireOnlyKeys(policy, ['mode', 'additionalPcrIndices'], 'TOFU PCR policy');
    const supplied = policy.additionalPcrIndices ?? [];
    if (!Array.isArray(supplied)) {
      throw new Error('additionalPcrIndices must be an array');
    }
    const indices = new Set();
    for (const index of supplied) {
      if (!Number.isInteger(index) || index < 0 || index > 255) {
        throw new Error('additional PCR indices must be integers from 0 through 255');
      }
      if (index > 2) indices.add(index);
    }
    return {
      mode: 'tofu',
      additionalPcrIndices: [...indices].sort((left, right) => left - right)
    };
  }

  throw new Error('pcrPolicy.mode must be exactly pinned or tofu');
}

export function pcrPoliciesEqual(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

export function verifyPinnedPcrPolicy(policy, observed) {
  if (policy?.mode !== 'pinned') throw new Error('pinned PCR policy required');
  requireRecord(observed, 'attested PCRs');
  if (policy.profiles.some(profile => profileMatches(profile, observed))) {
    return 'pinned';
  }
  throw new Error('attested PCRs did not match one complete pinned profile');
}

export function selectTofuPcrs(policy, observed) {
  if (policy?.mode !== 'tofu') throw new Error('TOFU PCR policy required');
  requireRecord(observed, 'attested PCRs');
  const selected = {};
  for (const index of [0, 1, 2, ...policy.additionalPcrIndices]) {
    selected[`PCR${index}`] = normalizePcrValue(
      observed[`PCR${index}`],
      `attested PCR${index}`
    );
  }
  return selected;
}

export async function pcrTrustKey(scope, enclaveOrigin, suite) {
  const normalizedScope = new URL(scope).href;
  const encoded = new TextEncoder().encode(
    `${TRUST_KEY_DOMAIN}${normalizedScope}\0${enclaveOrigin}\0${suite}`
  );
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoded));
  return [...digest].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

export function exactPcrsMatch(existing, observed) {
  let normalized;
  try {
    normalized = normalizeProfile(existing, 'stored PCR trust record');
  } catch {
    return false;
  }
  return JSON.stringify(normalized) === JSON.stringify(observed);
}

export async function enforceTofuPcrPolicy(policy, observed, context, storage) {
  const selected = selectTofuPcrs(policy, observed);
  const key = await pcrTrustKey(context.scope, context.enclaveOrigin, context.suite);
  const record = await storage.loadOrInsert(key, selected);
  if (record?.status === 'inserted') return 'tofu-enrolled';
  if (record?.status === 'existing' && exactPcrsMatch(record.pcrs, selected)) {
    return 'tofu-matched';
  }
  throw new Error('attested PCRs did not match the enrolled TOFU record');
}

export function createBrowserPcrPolicyStorage(databaseFactory = globalThis.indexedDB) {
  const openDatabase = () => openPcrDatabase(databaseFactory);
  return {
    async isPolicyRequired(scope) {
      return Boolean(await readValue(openDatabase, markerKey(scope)));
    },

    async setPolicyRequired(scope, required) {
      await writeValue(openDatabase, markerKey(scope), required ? true : undefined);
    },

    async loadOrInsert(key, observed) {
      const database = await openDatabase();
      try {
        return await new Promise((resolve, reject) => {
          let outcome;
          let transaction;
          try {
            transaction = database.transaction(
              STORE_NAME,
              'readwrite',
              { durability: 'strict' }
            );
          } catch (error) {
            reject(storageError(error));
            return;
          }
          const request = transaction.objectStore(STORE_NAME).get(`trust:${key}`);
          request.onsuccess = () => {
            if (request.result === undefined) {
              outcome = { status: 'inserted' };
              transaction.objectStore(STORE_NAME).add(observed, `trust:${key}`);
            } else {
              outcome = { status: 'existing', pcrs: request.result };
            }
          };
          transaction.oncomplete = () => resolve(outcome);
          transaction.onerror = () => reject(storageError(transaction.error));
          transaction.onabort = () => reject(storageError(transaction.error));
        });
      } finally {
        database.close();
      }
    }
  };
}

function normalizeProfile(profile, label) {
  requireRecord(profile, label);
  const entries = [];
  for (const [name, value] of Object.entries(profile)) {
    const match = PCR_NAME.exec(name);
    const index = match ? Number(match[1]) : -1;
    if (!match || index > 255) {
      throw new Error(`${label} contains an invalid PCR name: ${name}`);
    }
    entries.push([index, normalizePcrValue(value, `${label} PCR${index}`)]);
  }
  for (const required of [0, 1, 2]) {
    if (!entries.some(([index]) => index === required)) {
      throw new Error(`${label} must contain PCR0, PCR1, and PCR2`);
    }
  }
  entries.sort(([left], [right]) => left - right);
  return Object.fromEntries(entries.map(([index, value]) => [`PCR${index}`, value]));
}

function profileMatches(profile, observed) {
  return Object.entries(profile).every(([name, expected]) => {
    const value = observed[name];
    return typeof value === 'string'
      && PCR_HEX.test(value)
      && value.toLowerCase() !== ZERO_PCR
      && value.toLowerCase() === expected;
  });
}

function normalizePcrValue(value, label) {
  if (typeof value !== 'string' || !PCR_HEX.test(value)) {
    throw new Error(`${label} must contain exactly 96 hexadecimal characters`);
  }
  const normalized = value.toLowerCase();
  if (normalized === ZERO_PCR) throw new Error(`${label} must be nonzero`);
  return normalized;
}

function requireRecord(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
}

function requireOnlyKeys(value, allowed, label) {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) throw new Error(`${label} contains unsupported key: ${key}`);
  }
}

function markerKey(scope) {
  return `policy-required:${new URL(scope).href}`;
}

function openPcrDatabase(databaseFactory) {
  if (!databaseFactory) return Promise.reject(storageError());
  return new Promise((resolve, reject) => {
    let settled = false;
    let request;
    try {
      request = databaseFactory.open(DATABASE_NAME, DATABASE_VERSION);
    } catch (error) {
      reject(storageError(error));
      return;
    }
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) {
        request.result.createObjectStore(STORE_NAME);
      }
    };
    request.onsuccess = () => {
      if (settled) {
        request.result.close();
      } else {
        settled = true;
        resolve(request.result);
      }
    };
    request.onerror = () => {
      if (!settled) {
        settled = true;
        reject(storageError(request.error));
      }
    };
    request.onblocked = () => {
      if (!settled) {
        settled = true;
        reject(storageError());
      }
    };
  });
}

async function readValue(openDatabase, key) {
  const database = await openDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, 'readonly');
      const request = transaction.objectStore(STORE_NAME).get(key);
      let value;
      request.onsuccess = () => { value = request.result; };
      request.onerror = () => reject(storageError(request.error));
      transaction.oncomplete = () => resolve(value);
      transaction.onerror = () => reject(storageError(transaction.error));
      transaction.onabort = () => reject(storageError(transaction.error));
    });
  } finally {
    database.close();
  }
}

async function writeValue(openDatabase, key, value) {
  const database = await openDatabase();
  try {
    await new Promise((resolve, reject) => {
      let transaction;
      try {
        transaction = database.transaction(
          STORE_NAME,
          'readwrite',
          { durability: 'strict' }
        );
      } catch (error) {
        reject(storageError(error));
        return;
      }
      const store = transaction.objectStore(STORE_NAME);
      if (value === undefined) store.delete(key);
      else store.put(value, key);
      transaction.oncomplete = resolve;
      transaction.onerror = () => reject(storageError(transaction.error));
      transaction.onabort = () => reject(storageError(transaction.error));
    });
  } finally {
    database.close();
  }
}

function storageError(cause) {
  const error = new Error('PCR policy storage failed');
  error.cause = cause;
  return error;
}
