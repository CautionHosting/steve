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

// src/protocol-v2.js
var VERSION = 2;
var PROTOCOL_ID = "STEVE-E2P-V2";
var SESSION_ENDPOINT = "/e2p/v2/session";
var CONFIRM_ENDPOINT = "/e2p/v2/confirm";
var REQUEST_ENDPOINT = "/e2p/v2/request";
var encoder = new TextEncoder();
var MAGIC = encoder.encode("STEVE-E2P-V2\0");
var LABELS = {
  c2sKey: encoder.encode("steve-e2p-v2/c2s-key"),
  s2cKey: encoder.encode("steve-e2p-v2/s2c-key"),
  c2sIv: encoder.encode("steve-e2p-v2/c2s-iv"),
  s2cIv: encoder.encode("steve-e2p-v2/s2c-iv"),
  binder: encoder.encode("steve-e2p-v2/attestation-binder")
};
var Direction = Object.freeze({ CLIENT_TO_SERVER: 0, SERVER_TO_CLIENT: 1 });
var MessageType = Object.freeze({ CONFIRMATION: 0, APPLICATION: 1 });
var SequenceTracker = class {
  constructor() {
    this.next = 1n;
    this.pending = /* @__PURE__ */ new Set();
  }
  allocate() {
    const sequence = this.next;
    if (sequence > 0xffffffffffffffffn) throw new Error("session sequence exhausted");
    this.next += 1n;
    this.pending.add(sequence.toString());
    return sequence;
  }
  accept(expected, received) {
    const key = expected.toString();
    if (received !== expected || !this.pending.delete(key)) {
      throw new Error("unexpected v2 response sequence");
    }
  }
};
function concatBytes(...parts) {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}
function equalBytes(left, right) {
  if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array) || left.length !== right.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}
function buildTranscript(clientNonce, clientKey, serverKey, sessionId, contextHash) {
  requireLength("client nonce", clientNonce, 32);
  requireLength("client public key", clientKey, 32);
  requireLength("server public key", serverKey, 32);
  requireLength("session ID", sessionId, 16);
  requireLength("context hash", contextHash, 32);
  return concatBytes(MAGIC, clientNonce, clientKey, serverKey, sessionId, contextHash);
}
async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}
async function hashOrigin(origin) {
  return sha256(encoder.encode(origin));
}
async function deriveMaterial(sharedSecret, transcriptHash) {
  requireLength("X25519 shared secret", sharedSecret, 32);
  requireLength("transcript hash", transcriptHash, 32);
  const hkdfKey = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveBits"]);
  const derive = async (label, bits) => new Uint8Array(await crypto.subtle.deriveBits({
    name: "HKDF",
    hash: "SHA-256",
    salt: transcriptHash,
    info: label
  }, hkdfKey, bits));
  return {
    c2sKey: await derive(LABELS.c2sKey, 256),
    s2cKey: await derive(LABELS.s2cKey, 256),
    c2sIvPrefix: await derive(LABELS.c2sIv, 32),
    s2cIvPrefix: await derive(LABELS.s2cIv, 32),
    binder: await derive(LABELS.binder, 256)
  };
}
function sequenceBytes(sequence) {
  const value = BigInt(sequence);
  if (value < 0n || value > 0xffffffffffffffffn) {
    throw new Error("sequence is out of range");
  }
  const bytes = new Uint8Array(8);
  const view = new DataView(bytes.buffer);
  view.setBigUint64(0, value, false);
  return bytes;
}
function parseSequence(bytes) {
  requireLength("sequence", bytes, 8);
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(0, false);
}
function messageNonce(prefix, sequence) {
  requireLength("IV prefix", prefix, 4);
  return concatBytes(prefix, sequenceBytes(sequence));
}
function associatedData(messageType, direction, sessionId, sequence) {
  requireLength("session ID", sessionId, 16);
  return concatBytes(
    MAGIC,
    new Uint8Array([messageType, direction]),
    sessionId,
    sequenceBytes(sequence)
  );
}
async function seal(material, direction, messageType, sessionId, sequence, plaintext) {
  const keyBytes = direction === Direction.CLIENT_TO_SERVER ? material.c2sKey : material.s2cKey;
  const prefix = direction === Direction.CLIENT_TO_SERVER ? material.c2sIvPrefix : material.s2cIvPrefix;
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt({
    name: "AES-GCM",
    iv: messageNonce(prefix, sequence),
    additionalData: associatedData(messageType, direction, sessionId, sequence),
    tagLength: 128
  }, key, plaintext);
  return new Uint8Array(ciphertext);
}
async function open(material, direction, messageType, sessionId, sequence, ciphertext) {
  const keyBytes = direction === Direction.CLIENT_TO_SERVER ? material.c2sKey : material.s2cKey;
  const prefix = direction === Direction.CLIENT_TO_SERVER ? material.c2sIvPrefix : material.s2cIvPrefix;
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt({
    name: "AES-GCM",
    iv: messageNonce(prefix, sequence),
    additionalData: associatedData(messageType, direction, sessionId, sequence),
    tagLength: 128
  }, key, ciphertext);
  return new Uint8Array(plaintext);
}
function encodeSessionRequest(clientNonce, clientPublicKey, contextHash) {
  return encode({
    version: VERSION,
    client_nonce: clientNonce,
    client_public_key: clientPublicKey,
    context_hash: contextHash
  });
}
function decodeSessionResponse(bytes) {
  const response = decode(bytes);
  if (response.version !== VERSION) throw new Error("unsupported session response version");
  requireLength("session ID", response.session_id, 16);
  requireLength("server public key", response.server_public_key, 32);
  if (!(response.attestation_document instanceof Uint8Array)) {
    throw new Error("invalid attestation document");
  }
  if (!Number.isInteger(response.expires_in_seconds) || response.expires_in_seconds <= 0) {
    throw new Error("invalid pending-session expiry");
  }
  return response;
}
function encodeEnvelope(sessionId, sequence, ciphertext) {
  requireLength("session ID", sessionId, 16);
  return encode({
    version: VERSION,
    session_id: sessionId,
    sequence: sequenceBytes(sequence),
    ciphertext
  });
}
function decodeEnvelope(bytes) {
  const envelope = decode(bytes);
  if (envelope.version !== VERSION) throw new Error("unsupported envelope version");
  requireLength("session ID", envelope.session_id, 16);
  requireLength("sequence", envelope.sequence, 8);
  if (!(envelope.ciphertext instanceof Uint8Array)) throw new Error("invalid envelope ciphertext");
  return { ...envelope, sequenceValue: parseSequence(envelope.sequence) };
}
function verifyBinding(userData, sessionId, transcriptHash, binder) {
  if (!userData || userData.protocol !== PROTOCOL_ID) {
    throw new Error("attestation protocol binding mismatch");
  }
  const expected = {
    session_id: sessionId,
    transcript_hash: transcriptHash,
    binder
  };
  for (const [field, bytes] of Object.entries(expected)) {
    const actual = decodeBase64Url(userData[field]);
    if (!equalBytes(actual, bytes)) throw new Error(`attestation ${field} mismatch`);
  }
}
function validateAttestationResult(result, sessionId, transcriptHash, binder) {
  if (!result?.verified) {
    throw new Error(`Nitro attestation verification failed: ${result?.error || "unknown error"}`);
  }
  verifyBinding(result.userData, sessionId, transcriptHash, binder);
}
function decodeBase64Url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/u.test(value)) {
    throw new Error("invalid base64url value in attestation");
  }
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
function requireLength(name, value, length) {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new Error(`invalid ${name}`);
  }
}

// src/enclave-sw.js
var DEFAULT_BOOTSTRAP_PATHS = ["/", "/enclave-sw.js", "/register.js", "/attestation-widget.js"];
var ROTATION_INTERVAL_MS = 25 * 60 * 1e3;
var config = {
  passthroughPaths: DEFAULT_BOOTSTRAP_PATHS,
  excludePrefixes: ["/attestation", "/e2p/"],
  emitEncryptedPayloads: false
};
var state = freshState();
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(clients.claim()));
self.addEventListener("message", (event) => handleMessage(event));
self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin || isPassthrough(url.pathname)) {
    return;
  }
  event.respondWith(handleProtectedRequest(event.request));
});
async function handleMessage(event) {
  const { type } = event.data;
  const port = event.ports[0];
  try {
    switch (type) {
      case "get-status":
        port?.postMessage(statusMessage());
        break;
      case "initialize":
        await ensureSession();
        port?.postMessage({ type: "initialized", success: true });
        break;
      case "rotate-key":
        await rotateSession();
        port?.postMessage({ type: "key-rotated", success: true });
        break;
      case "reset":
        resetState();
        port?.postMessage({ type: "reset", success: true });
        break;
      case "configure":
        configure(event.data.config || {});
        port?.postMessage({ type: "configured", success: true, config });
        break;
      default:
        throw new Error("unknown service-worker command");
    }
  } catch (error) {
    port?.postMessage({ type, success: false, error: publicError(error) });
  }
}
async function handleProtectedRequest(request) {
  let session;
  try {
    session = await currentSession();
    const sequence = session.sequences.allocate();
    const url = new URL(request.url);
    const requestBody = new Uint8Array(await request.arrayBuffer());
    const plaintext = encode({
      method: request.method,
      path: url.pathname + url.search,
      headers: Object.fromEntries(request.headers),
      body: requestBody.length === 0 ? null : requestBody
    });
    const ciphertext = await seal(
      session.material,
      Direction.CLIENT_TO_SERVER,
      MessageType.APPLICATION,
      session.id,
      sequence,
      plaintext
    );
    const envelope = encodeEnvelope(session.id, sequence, ciphertext);
    if (config.emitEncryptedPayloads) {
      notifyClients("encrypted-request", { sequence: sequence.toString(), size: envelope.length });
    }
    const response = await protocolFetch(REQUEST_ENDPOINT, envelope);
    if (!response.ok) throw new Error(`v2 request rejected (${response.status})`);
    const responseBytes = new Uint8Array(await response.arrayBuffer());
    const responseEnvelope = decodeEnvelope(responseBytes);
    if (!equalBytes(responseEnvelope.session_id, session.id)) {
      throw new Error("unexpected v2 response envelope");
    }
    session.sequences.accept(sequence, responseEnvelope.sequenceValue);
    const responsePlaintext = await open(
      session.material,
      Direction.SERVER_TO_CLIENT,
      MessageType.APPLICATION,
      session.id,
      sequence,
      responseEnvelope.ciphertext
    );
    const decoded = decode(responsePlaintext);
    validateApplicationResponse(decoded);
    if (config.emitEncryptedPayloads) {
      notifyClients("encrypted-response", { sequence: sequence.toString(), size: responseBytes.length });
    }
    const body = decoded.body instanceof Uint8Array ? decoded.body : decoded.error ? new TextEncoder().encode(JSON.stringify({ error: decoded.error })) : null;
    return new Response(body, { status: decoded.status, headers: decoded.headers || {} });
  } catch (error) {
    if (!session || state.session === session) resetState(publicError(error));
    notifyClients("error", { message: publicError(error), url: request.url });
    return new Response(JSON.stringify({ error: "secure channel failed" }), {
      status: 502,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
    });
  }
}
async function currentSession() {
  const session = await ensureSession();
  if (Date.now() - session.createdAt >= ROTATION_INTERVAL_MS) {
    return rotateSession();
  }
  return session;
}
async function ensureSession() {
  if (state.session) return state.session;
  if (!state.sessionPromise) {
    state.sessionPromise = establishSession().then((session) => {
      state.session = session;
      state.error = null;
      return session;
    }).catch((error) => {
      state.error = publicError(error);
      throw error;
    }).finally(() => {
      state.sessionPromise = null;
    });
  }
  return state.sessionPromise;
}
async function rotateSession() {
  if (state.rotationPromise) return state.rotationPromise;
  notifyClients("status", { stage: "rotating-session" });
  state.rotationPromise = establishSession().then((session) => {
    state.session = session;
    state.error = null;
    notifyClients("key-rotated", { timestamp: session.createdAt });
    return session;
  }).finally(() => {
    state.rotationPromise = null;
  });
  return state.rotationPromise;
}
async function establishSession() {
  notifyClients("status", { stage: "creating-session" });
  const clientNonce = crypto.getRandomValues(new Uint8Array(32));
  const clientKeyPair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const clientPublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", clientKeyPair.publicKey));
  const contextHash = await hashOrigin(self.location.origin);
  const response = await protocolFetch(
    SESSION_ENDPOINT,
    encodeSessionRequest(clientNonce, clientPublicKey, contextHash)
  );
  if (!response.ok) throw new Error(`session creation rejected (${response.status})`);
  const sessionResponse = decodeSessionResponse(new Uint8Array(await response.arrayBuffer()));
  const transcript = buildTranscript(
    clientNonce,
    clientPublicKey,
    sessionResponse.server_public_key,
    sessionResponse.session_id,
    contextHash
  );
  const transcriptHash = await sha256(transcript);
  const serverPublicKey = await crypto.subtle.importKey(
    "raw",
    sessionResponse.server_public_key,
    { name: "X25519" },
    false,
    []
  );
  const sharedSecret = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "X25519", public: serverPublicKey },
    clientKeyPair.privateKey,
    256
  ));
  const material = await deriveMaterial(sharedSecret, transcriptHash);
  notifyClients("status", { stage: "verifying-session-attestation" });
  const attestation = await verify(sessionResponse.attestation_document, { nonce: clientNonce });
  validateAttestationResult(
    attestation,
    sessionResponse.session_id,
    transcriptHash,
    material.binder
  );
  const confirmationCiphertext = await seal(
    material,
    Direction.CLIENT_TO_SERVER,
    MessageType.CONFIRMATION,
    sessionResponse.session_id,
    0n,
    transcriptHash
  );
  const confirmationResponse = await protocolFetch(
    CONFIRM_ENDPOINT,
    encodeEnvelope(sessionResponse.session_id, 0n, confirmationCiphertext)
  );
  if (!confirmationResponse.ok) {
    throw new Error(`session confirmation rejected (${confirmationResponse.status})`);
  }
  const confirmationEnvelope = decodeEnvelope(
    new Uint8Array(await confirmationResponse.arrayBuffer())
  );
  if (confirmationEnvelope.sequenceValue !== 0n || !equalBytes(confirmationEnvelope.session_id, sessionResponse.session_id)) {
    throw new Error("unexpected confirmation response");
  }
  const confirmedHash = await open(
    material,
    Direction.SERVER_TO_CLIENT,
    MessageType.CONFIRMATION,
    sessionResponse.session_id,
    0n,
    confirmationEnvelope.ciphertext
  );
  if (!equalBytes(confirmedHash, transcriptHash)) throw new Error("session confirmation mismatch");
  const session = {
    id: sessionResponse.session_id,
    material,
    sequences: new SequenceTracker(),
    createdAt: Date.now(),
    attestation: {
      verified: true,
      pcrs: attestation.pcrs,
      moduleId: attestation.moduleId
    }
  };
  notifyClients("initialized", session.attestation);
  return session;
}
async function protocolFetch(path, body) {
  return fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/cbor" },
    body,
    cache: "no-store",
    credentials: "omit",
    redirect: "error"
  });
}
function validateApplicationResponse(response) {
  if (!response || !Number.isInteger(response.status) || response.status < 200 || response.status > 599) {
    throw new Error("invalid protected application response");
  }
  if (response.headers && (typeof response.headers !== "object" || Array.isArray(response.headers))) {
    throw new Error("invalid protected application headers");
  }
  if (response.body !== null && response.body !== void 0 && !(response.body instanceof Uint8Array)) {
    throw new Error("invalid protected application body");
  }
}
function isPassthrough(path) {
  return config.passthroughPaths.includes(path) || config.excludePrefixes.some((prefix) => path.startsWith(prefix));
}
function configure(update) {
  const allowed = ["passthroughPaths", "excludePrefixes", "emitEncryptedPayloads"];
  for (const key of Object.keys(update)) {
    if (!allowed.includes(key)) throw new Error(`unsupported configuration key: ${key}`);
  }
  if (update.passthroughPaths) validatePathList(update.passthroughPaths);
  if (update.excludePrefixes) validatePathList(update.excludePrefixes);
  config = { ...config, ...update };
}
function validatePathList(values) {
  if (!Array.isArray(values)) throw new Error("passthrough rules must be arrays");
  for (const value of values) {
    if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || value.includes("?") || value.includes("#")) {
      throw new Error(`invalid bootstrap rule: ${value}`);
    }
  }
}
function statusMessage() {
  return {
    type: "status",
    initialized: Boolean(state.session),
    error: state.error,
    attestation: state.session?.attestation || null,
    lastKeyRotation: state.session?.createdAt || null,
    protocolVersion: 2
  };
}
function freshState(error = null) {
  return { session: null, sessionPromise: null, rotationPromise: null, error };
}
function resetState(error = null) {
  state = freshState(error);
}
function publicError(error) {
  return error instanceof Error ? error.message : "secure channel error";
}
async function notifyClients(type, data) {
  const allClients = await self.clients.matchAll({ type: "window" });
  for (const client of allClients) client.postMessage({ type: `enclave:${type}`, ...data });
}
