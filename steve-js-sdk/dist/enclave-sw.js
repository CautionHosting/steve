// node_modules/tee-attestation-js/src/lib/cbor.js
function decode(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    bytes = new Uint8Array(bytes);
  }
  let offset = 0;
  function read() {
    const initial = bytes[offset++];
    const majorType = initial >> 5;
    const additionalInfo = initial & 31;
    let value;
    if (additionalInfo < 24) {
      value = additionalInfo;
    } else if (additionalInfo === 24) {
      value = bytes[offset++];
    } else if (additionalInfo === 25) {
      value = bytes[offset++] << 8 | bytes[offset++];
    } else if (additionalInfo === 26) {
      value = (bytes[offset++] << 24 >>> 0) + (bytes[offset++] << 16) + (bytes[offset++] << 8) + bytes[offset++];
    } else if (additionalInfo === 27) {
      value = 0;
      for (let i = 0; i < 8; i++) {
        value = value * 256 + bytes[offset++];
      }
    } else if (additionalInfo === 31) {
      value = -1;
    } else {
      throw new Error(`Unsupported additional info: ${additionalInfo}`);
    }
    switch (majorType) {
      case 0:
        return value;
      case 1:
        return -1 - value;
      case 2: {
        const result = bytes.slice(offset, offset + value);
        offset += value;
        return result;
      }
      case 3: {
        const strBytes = bytes.slice(offset, offset + value);
        offset += value;
        return new TextDecoder().decode(strBytes);
      }
      case 4: {
        const arr = [];
        if (value < 0) {
          while (bytes[offset] !== 255) {
            arr.push(read());
          }
          offset++;
        } else {
          for (let i = 0; i < value; i++) {
            arr.push(read());
          }
        }
        return arr;
      }
      case 5: {
        const obj = {};
        if (value < 0) {
          while (bytes[offset] !== 255) {
            const key = read();
            obj[key] = read();
          }
          offset++;
        } else {
          for (let i = 0; i < value; i++) {
            const key = read();
            obj[key] = read();
          }
        }
        return obj;
      }
      case 6:
        return read();
      case 7: {
        if (additionalInfo === 20) return false;
        if (additionalInfo === 21) return true;
        if (additionalInfo === 22) return null;
        if (additionalInfo === 23) return void 0;
        throw new Error(`Unsupported simple value: ${additionalInfo}`);
      }
      default:
        throw new Error(`Unknown major type: ${majorType}`);
    }
  }
  return read();
}
function encode(value) {
  const chunks = [];
  function encodeItem(val) {
    if (val === null) {
      chunks.push(new Uint8Array([246]));
    } else if (val === void 0) {
      chunks.push(new Uint8Array([247]));
    } else if (typeof val === "boolean") {
      chunks.push(new Uint8Array([val ? 245 : 244]));
    } else if (typeof val === "number") {
      if (Number.isInteger(val) && val >= 0 && val < 24) {
        chunks.push(new Uint8Array([val]));
      } else if (Number.isInteger(val) && val >= 0 && val < 256) {
        chunks.push(new Uint8Array([24, val]));
      } else if (Number.isInteger(val) && val >= 0 && val < 65536) {
        chunks.push(new Uint8Array([25, val >> 8, val & 255]));
      } else {
        throw new Error("Complex number encoding not implemented");
      }
    } else if (typeof val === "string") {
      const strBytes = new TextEncoder().encode(val);
      encodeLength(3, strBytes.length);
      chunks.push(strBytes);
    } else if (val instanceof Uint8Array) {
      encodeLength(2, val.length);
      chunks.push(val);
    } else if (Array.isArray(val)) {
      encodeLength(4, val.length);
      for (const item of val) {
        encodeItem(item);
      }
    } else if (typeof val === "object") {
      const keys = Object.keys(val);
      encodeLength(5, keys.length);
      for (const key of keys) {
        encodeItem(key);
        encodeItem(val[key]);
      }
    }
  }
  function encodeLength(majorType, length) {
    if (length < 24) {
      chunks.push(new Uint8Array([majorType << 5 | length]));
    } else if (length < 256) {
      chunks.push(new Uint8Array([majorType << 5 | 24, length]));
    } else if (length < 65536) {
      chunks.push(new Uint8Array([majorType << 5 | 25, length >> 8, length & 255]));
    } else {
      throw new Error("Length too large");
    }
  }
  encodeItem(value);
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const result = new Uint8Array(totalLength);
  let off = 0;
  for (const chunk of chunks) {
    result.set(chunk, off);
    off += chunk.length;
  }
  return result;
}

// node_modules/tee-attestation-js/src/lib/x509.js
function parseCertificate(der) {
  if (!(der instanceof Uint8Array)) {
    der = new Uint8Array(der);
  }
  let offset = 0;
  function readByte() {
    return der[offset++];
  }
  function readLength() {
    const first = readByte();
    if (first < 128) return first;
    const numBytes = first & 127;
    let length = 0;
    for (let i = 0; i < numBytes; i++) {
      length = length << 8 | readByte();
    }
    return length;
  }
  function expectTag(expected) {
    const tag = readByte();
    if (tag !== expected) throw new Error(`Expected tag ${expected}, got ${tag}`);
    return readLength();
  }
  function skipElement() {
    readByte();
    const len = readLength();
    offset += len;
  }
  expectTag(48);
  const tbsStart = offset;
  const tbsLen = expectTag(48);
  const tbsEnd = offset + tbsLen;
  const tbsCertificate = der.slice(tbsStart, tbsEnd);
  if (der[offset] === 160) {
    offset++;
    const vLen = readLength();
    offset += vLen;
  }
  skipElement();
  skipElement();
  skipElement();
  const validityLen = expectTag(48);
  const validityEnd = offset + validityLen;
  readByte();
  const notBeforeLen = readLength();
  const notBeforeBytes = der.slice(offset, offset + notBeforeLen);
  const notBeforeStr = new TextDecoder().decode(notBeforeBytes);
  offset += notBeforeLen;
  readByte();
  const notAfterLen = readLength();
  const notAfterBytes = der.slice(offset, offset + notAfterLen);
  const notAfterStr = new TextDecoder().decode(notAfterBytes);
  offset = validityEnd;
  skipElement();
  const pubKeyStart = offset;
  const pubKeyOuterLen = expectTag(48);
  const pubKeyEnd = offset + pubKeyOuterLen;
  const publicKeyRaw = der.slice(pubKeyStart, pubKeyEnd);
  offset = tbsEnd;
  skipElement();
  readByte();
  const sigLen = readLength();
  readByte();
  const signature = der.slice(offset, offset + sigLen - 1);
  return {
    tbsCertificate,
    signature,
    publicKeyRaw,
    notBefore: parseASN1Time(notBeforeStr),
    notAfter: parseASN1Time(notAfterStr)
  };
}
function parseASN1Time(str) {
  str = str.replace("Z", "");
  if (str.length === 12) {
    const year = parseInt(str.slice(0, 2), 10);
    const fullYear = year >= 50 ? 1900 + year : 2e3 + year;
    return new Date(Date.UTC(
      fullYear,
      parseInt(str.slice(2, 4), 10) - 1,
      parseInt(str.slice(4, 6), 10),
      parseInt(str.slice(6, 8), 10),
      parseInt(str.slice(8, 10), 10),
      parseInt(str.slice(10, 12), 10)
    ));
  }
  return new Date(Date.UTC(
    parseInt(str.slice(0, 4), 10),
    parseInt(str.slice(4, 6), 10) - 1,
    parseInt(str.slice(6, 8), 10),
    parseInt(str.slice(8, 10), 10),
    parseInt(str.slice(10, 12), 10),
    parseInt(str.slice(12, 14), 10)
  ));
}
function ecdsaDerToRaw(der, curveBytes = 48) {
  let offset = 0;
  if (der[offset++] !== 48) throw new Error("Invalid DER signature");
  const seqLen = der[offset++];
  if (seqLen & 128) offset += seqLen & 127;
  if (der[offset++] !== 2) throw new Error("Invalid DER integer");
  let rLen = der[offset++];
  let rStart = offset;
  if (der[rStart] === 0) {
    rStart++;
    rLen--;
  }
  const r = der.slice(rStart, rStart + rLen);
  offset = rStart + rLen;
  if (der[offset++] !== 2) throw new Error("Invalid DER integer");
  let sLen = der[offset++];
  let sStart = offset;
  if (der[sStart] === 0) {
    sStart++;
    sLen--;
  }
  const s = der.slice(sStart, sStart + sLen);
  const result = new Uint8Array(curveBytes * 2);
  result.set(r, curveBytes - r.length);
  result.set(s, curveBytes * 2 - s.length);
  return result;
}
function pemToDer(pem) {
  const base64 = pem.replace(/-----BEGIN [^-]+-----/, "").replace(/-----END [^-]+-----/, "").replace(/\s/g, "");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
function bytesToHex(bytes) {
  if (!bytes) return "";
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function arraysEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// node_modules/tee-attestation-js/src/tee/nitro.js
var ROOT_CERT = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`;
function parse(document) {
  const coseSign1 = decode(document);
  if (!Array.isArray(coseSign1) || coseSign1.length !== 4) {
    throw new Error("Invalid COSE Sign1 structure");
  }
  const [protectedHeader, , payload, signature] = coseSign1;
  const decodedPayload = decode(payload);
  const pcrs = {};
  if (decodedPayload.pcrs) {
    for (const [index, value] of Object.entries(decodedPayload.pcrs)) {
      pcrs[`PCR${index}`] = bytesToHex(value);
    }
  }
  let userData = null;
  if (decodedPayload.user_data) {
    try {
      userData = JSON.parse(new TextDecoder().decode(decodedPayload.user_data));
    } catch {
      userData = { raw: bytesToHex(decodedPayload.user_data) };
    }
  }
  return {
    protectedHeader,
    payloadRaw: payload,
    payload: decodedPayload,
    signature,
    cabundle: decodedPayload.cabundle,
    pcrs,
    userData,
    nonce: decodedPayload.nonce ? bytesToHex(decodedPayload.nonce) : null,
    publicKey: decodedPayload.public_key || null,
    moduleId: decodedPayload.module_id,
    digest: decodedPayload.digest,
    timestamp: decodedPayload.timestamp
  };
}
async function verify(document, options = {}) {
  const result = {
    verified: false,
    pcrs: {},
    userData: null,
    error: null
  };
  try {
    const parsed = parse(document);
    const rootCert = options.rootCert || ROOT_CERT;
    const signingCert = parsed.payload.certificate;
    if (!signingCert) {
      throw new Error("No signing certificate in attestation document");
    }
    await verifyCertificateChain([...parsed.cabundle, signingCert], rootCert);
    await verifyCOSESignature(
      parsed.protectedHeader,
      parsed.payloadRaw,
      parsed.signature,
      signingCert
    );
    if (options.nonce) {
      const expectedNonce = options.nonce instanceof Uint8Array ? options.nonce : new Uint8Array(options.nonce);
      const receivedNonce = parsed.payload.nonce;
      if (!receivedNonce || !arraysEqual(new Uint8Array(receivedNonce), expectedNonce)) {
        throw new Error("Nonce mismatch - possible replay attack");
      }
    }
    if (options.pcrs) {
      for (const [pcr, expectedValue] of Object.entries(options.pcrs)) {
        const actualValue = parsed.pcrs[pcr];
        if (actualValue !== expectedValue.toLowerCase()) {
          throw new Error(`PCR mismatch: ${pcr} expected ${expectedValue}, got ${actualValue}`);
        }
      }
    }
    result.verified = true;
    result.pcrs = parsed.pcrs;
    result.userData = parsed.userData;
    result.publicKey = parsed.publicKey;
    result.moduleId = parsed.moduleId;
    result.digest = parsed.digest;
    result.timestamp = parsed.timestamp;
  } catch (error) {
    result.error = error.message;
  }
  return result;
}
async function verifyCertificateChain(cabundle, rootCertPem) {
  if (!cabundle || !Array.isArray(cabundle)) {
    throw new Error("Missing certificate bundle");
  }
  const rootDer = pemToDer(rootCertPem);
  const rootCert = parseCertificate(rootDer);
  let parentPublicKeyRaw = rootCert.publicKeyRaw;
  for (let i = 0; i < cabundle.length; i++) {
    const cert = parseCertificate(cabundle[i]);
    const now = Date.now();
    if (now < cert.notBefore.getTime() || now > cert.notAfter.getTime()) {
      throw new Error(`Certificate ${i} is not within validity period`);
    }
    const publicKey = await crypto.subtle.importKey(
      "spki",
      parentPublicKeyRaw,
      { name: "ECDSA", namedCurve: "P-384" },
      false,
      ["verify"]
    );
    const rawSignature = ecdsaDerToRaw(cert.signature);
    const isValid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-384" },
      publicKey,
      rawSignature,
      cert.tbsCertificate
    );
    if (!isValid) {
      throw new Error(`Certificate ${i} signature verification failed`);
    }
    parentPublicKeyRaw = cert.publicKeyRaw;
  }
}
async function verifyCOSESignature(protectedHeader, payload, signature, signingCertDer) {
  const cert = parseCertificate(signingCertDer);
  const sigStructure = encode([
    "Signature1",
    protectedHeader,
    new Uint8Array(0),
    payload
  ]);
  const publicKey = await crypto.subtle.importKey(
    "spki",
    cert.publicKeyRaw,
    { name: "ECDSA", namedCurve: "P-384" },
    false,
    ["verify"]
  );
  const isValid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-384" },
    publicKey,
    signature,
    sigStructure
  );
  if (!isValid) {
    throw new Error("COSE signature verification failed");
  }
}

// src/enclave-sw.js
var CONFIG = {
  attestationEndpoint: "/attestation",
  keyExchangeEndpoint: "/e2p/v1/create_shared_key",
  passthroughPaths: ["/", "/enclave-sw.js", "/register.js", "/attestation-widget.js"],
  excludePrefixes: ["/attestation", "/e2p/"],
  keyRotationInterval: 30 * 60 * 1e3,
  emitEncryptedPayloads: false
};
var state = {
  sessionKey: null,
  verifyingKey: null,
  enclaveEncryptedSharedKey: null,
  attestationResult: null,
  initialized: false,
  initPromise: null,
  lastKeyRotation: null,
  error: null
};
self.addEventListener("install", () => {
  self.skipWaiting();
});
self.addEventListener("activate", (event) => {
  event.waitUntil(clients.claim());
});
self.addEventListener("message", (event) => {
  handleMessage(event);
});
self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  const isPassthrough = CONFIG.passthroughPaths.includes(url.pathname);
  const isExcluded = CONFIG.excludePrefixes.some((prefix) => url.pathname.startsWith(prefix));
  if (isPassthrough || isExcluded) {
    return;
  }
  event.respondWith(handleEncryptedRequest(event.request));
});
async function handleMessage(event) {
  const { type } = event.data;
  const port = event.ports[0];
  switch (type) {
    case "get-status":
      port?.postMessage({
        type: "status",
        initialized: state.initialized,
        error: state.error,
        attestation: state.attestationResult ? {
          verified: state.attestationResult.verified,
          pcrs: state.attestationResult.pcrs,
          moduleId: state.attestationResult.moduleId
        } : null,
        lastKeyRotation: state.lastKeyRotation
      });
      break;
    case "initialize":
      try {
        await ensureInitialized();
        port?.postMessage({ type: "initialized", success: true });
      } catch (error) {
        port?.postMessage({ type: "initialized", success: false, error: error.message });
      }
      break;
    case "rotate-key":
      try {
        await rotateSessionKey();
        port?.postMessage({ type: "key-rotated", success: true });
      } catch (error) {
        port?.postMessage({ type: "key-rotated", success: false, error: error.message });
      }
      break;
    case "reset":
      resetState();
      port?.postMessage({ type: "reset", success: true });
      break;
    case "configure":
      CONFIG = { ...CONFIG, ...event.data.config };
      port?.postMessage({ type: "configured", success: true, config: CONFIG });
      break;
  }
}
async function handleEncryptedRequest(request) {
  try {
    await ensureInitialized();
    await checkKeyRotation();
    const url = new URL(request.url);
    const encryptedRequest = await encryptRequest(request);
    if (CONFIG.emitEncryptedPayloads) {
      const encryptedBody = new Uint8Array(await encryptedRequest.clone().arrayBuffer());
      notifyClients("encrypted-request", {
        path: url.pathname,
        size: encryptedBody.length,
        payload: bytesToHex2(encryptedBody.slice(0, 64)) + (encryptedBody.length > 64 ? "..." : "")
      });
    }
    const response = await fetch(encryptedRequest);
    if (!response.ok && response.status >= 500) {
      throw new Error(`Server error: ${response.status}`);
    }
    if (CONFIG.emitEncryptedPayloads) {
      const encryptedResponse = new Uint8Array(await response.clone().arrayBuffer());
      notifyClients("encrypted-response", {
        status: response.status,
        size: encryptedResponse.length,
        payload: bytesToHex2(encryptedResponse.slice(0, 64)) + (encryptedResponse.length > 64 ? "..." : "")
      });
    }
    return await decryptResponse(response);
  } catch (error) {
    notifyClients("error", { message: error.message, url: request.url });
    return new Response(JSON.stringify({ error: error.message }), {
      status: 502,
      headers: { "Content-Type": "application/json" }
    });
  }
}
function bytesToHex2(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}
async function ensureInitialized() {
  if (state.initialized) {
    return;
  }
  if (state.initPromise) {
    return state.initPromise;
  }
  state.initPromise = initializeSecureChannel();
  try {
    await state.initPromise;
  } finally {
    state.initPromise = null;
  }
}
async function initializeSecureChannel() {
  try {
    notifyClients("status", { stage: "requesting-attestation" });
    const nonce = crypto.getRandomValues(new Uint8Array(32));
    const encodedNonce = bytesToBase64(nonce);
    const response = await fetch(CONFIG.attestationEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ nonce: encodedNonce })
    });
    if (!response.ok) {
      throw new Error(`Attestation request failed: ${response.status}`);
    }
    const jsonResponse = await response.json();
    if (jsonResponse.error) {
      throw new Error(jsonResponse.error);
    }
    const attestationB64 = jsonResponse.document;
    if (!attestationB64) {
      throw new Error("No attestation document in response");
    }
    const attestationBytes = Uint8Array.from(atob(attestationB64), (c) => c.charCodeAt(0));
    notifyClients("status", { stage: "verifying-attestation" });
    const result = await verify(attestationBytes, { nonce });
    if (!result.verified) {
      throw new Error(`Attestation verification failed: ${result.error}`);
    }
    state.attestationResult = result;
    if (!result.userData?.verifying_key) {
      throw new Error("No verifying key in attestation user data");
    }
    state.verifyingKey = new Uint8Array(result.userData.verifying_key);
    notifyClients("status", { stage: "establishing-channel" });
    await performKeyExchange();
    state.initialized = true;
    state.error = null;
    state.lastKeyRotation = Date.now();
    notifyClients("initialized", {
      pcrs: result.pcrs,
      moduleId: result.moduleId
    });
  } catch (error) {
    state.error = error.message;
    notifyClients("error", { message: error.message, stage: "initialization" });
    throw error;
  }
}
async function performKeyExchange() {
  const ourKeyPair = await crypto.subtle.generateKey(
    { name: "X25519" },
    true,
    ["deriveBits"]
  );
  const ourPublicKeyRaw = await crypto.subtle.exportKey("raw", ourKeyPair.publicKey);
  const ourPublicKeyBytes = new Uint8Array(ourPublicKeyRaw);
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const response = await fetch(CONFIG.keyExchangeEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      public_key_bytes: Array.from(ourPublicKeyBytes),
      nonce: Array.from(nonce)
    })
  });
  if (!response.ok) {
    throw new Error(`Key exchange failed: ${response.status}`);
  }
  const data = await response.json();
  const theirPublicKeyBytes = new Uint8Array(data.public_key);
  const signature = new Uint8Array(data.signature);
  state.enclaveEncryptedSharedKey = new Uint8Array(data.enclave_encrypted_shared_key);
  const messageToVerify = new Uint8Array(nonce.length + theirPublicKeyBytes.length);
  messageToVerify.set(nonce, 0);
  messageToVerify.set(theirPublicKeyBytes, nonce.length);
  const verifyingKey = await crypto.subtle.importKey(
    "raw",
    state.verifyingKey,
    { name: "Ed25519" },
    false,
    ["verify"]
  );
  const signatureValid = await crypto.subtle.verify(
    { name: "Ed25519" },
    verifyingKey,
    signature,
    messageToVerify
  );
  if (!signatureValid) {
    throw new Error("Key exchange signature verification failed");
  }
  const theirPublicKey = await crypto.subtle.importKey(
    "raw",
    theirPublicKeyBytes,
    { name: "X25519" },
    false,
    []
  );
  const sharedSecret = await crypto.subtle.deriveBits(
    { name: "X25519", public: theirPublicKey },
    ourKeyPair.privateKey,
    256
  );
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    sharedSecret,
    { name: "HKDF" },
    false,
    ["deriveKey"]
  );
  state.sessionKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: new TextEncoder().encode("key") },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
async function checkKeyRotation() {
  if (!state.lastKeyRotation) return;
  const elapsed = Date.now() - state.lastKeyRotation;
  if (elapsed >= CONFIG.keyRotationInterval) {
    await rotateSessionKey();
  }
}
async function rotateSessionKey() {
  if (!state.initialized || !state.verifyingKey) {
    throw new Error("Cannot rotate key: not initialized");
  }
  notifyClients("status", { stage: "rotating-key" });
  await performKeyExchange();
  state.lastKeyRotation = Date.now();
  notifyClients("key-rotated", { timestamp: state.lastKeyRotation });
}
async function encryptRequest(request) {
  const url = new URL(request.url);
  const body = await request.arrayBuffer();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = encode({
    method: request.method,
    path: url.pathname + url.search,
    headers: Object.fromEntries(request.headers),
    body: body.byteLength > 0 ? new Uint8Array(body) : null
  });
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    state.sessionKey,
    plaintext
  );
  const encryptedBody = new Uint8Array(iv.length + ciphertext.byteLength);
  encryptedBody.set(iv, 0);
  encryptedBody.set(new Uint8Array(ciphertext), iv.length);
  return new Request(url.href, {
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
      "X-E2P-Key": btoa(String.fromCharCode(...state.enclaveEncryptedSharedKey)),
      "X-E2P-Original-Method": request.method
    },
    body: encryptedBody
  });
}
async function decryptResponse(response) {
  const encrypted = new Uint8Array(await response.arrayBuffer());
  if (encrypted.length < 12) {
    throw new Error("Invalid encrypted response: too short");
  }
  const iv = encrypted.slice(0, 12);
  const ciphertext = encrypted.slice(12);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    state.sessionKey,
    ciphertext
  );
  const decoded = decode(new Uint8Array(plaintext));
  const bodyBytes = decoded.body instanceof Uint8Array ? decoded.body : new Uint8Array(0);
  return new Response(bodyBytes, {
    status: decoded.status || 200,
    headers: decoded.headers || {}
  });
}
function resetState() {
  state = {
    sessionKey: null,
    verifyingKey: null,
    enclaveEncryptedSharedKey: null,
    attestationResult: null,
    initialized: false,
    initPromise: null,
    lastKeyRotation: null,
    error: null
  };
}
async function notifyClients(type, data) {
  const allClients = await self.clients.matchAll({ type: "window" });
  for (const client of allClients) {
    client.postMessage({ type: `enclave:${type}`, ...data });
  }
}
