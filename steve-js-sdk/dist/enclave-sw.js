// node_modules/tee-attestation-js/src/lib/cbor.js
var MAX_CBOR_BYTES = 32 * 1024 * 1024;
var MAX_CBOR_DEPTH = 32;
var MAX_CBOR_CONTAINER_ITEMS = 65536;
var MAX_CBOR_NODES = MAX_CBOR_CONTAINER_ITEMS * 4;
var textEncoder = new TextEncoder();
var textDecoder = new TextDecoder("utf-8", { fatal: true });
function encode(value) {
  const chunks = [];
  const activeContainers = /* @__PURE__ */ new WeakSet();
  let encodedLength = 0;
  function push(chunk) {
    if (!(chunk instanceof Uint8Array)) {
      chunk = new Uint8Array(chunk);
    }
    if (chunk.length > MAX_CBOR_BYTES - encodedLength) {
      throw new Error("CBOR output exceeds size limit");
    }
    chunks.push(chunk);
    encodedLength += chunk.length;
  }
  function encodeArgument(majorType, value2) {
    if (!Number.isSafeInteger(value2) || value2 < 0) {
      throw new Error("CBOR integer is out of range");
    }
    if (value2 < 24) {
      push(Uint8Array.of(majorType << 5 | value2));
    } else if (value2 < 256) {
      push(Uint8Array.of(majorType << 5 | 24, value2));
    } else if (value2 < 65536) {
      push(Uint8Array.of(
        majorType << 5 | 25,
        value2 >>> 8,
        value2 & 255
      ));
    } else if (value2 <= 4294967295) {
      push(Uint8Array.of(
        majorType << 5 | 26,
        value2 >>> 24 & 255,
        value2 >>> 16 & 255,
        value2 >>> 8 & 255,
        value2 & 255
      ));
    } else {
      const encoded = new Uint8Array(9);
      encoded[0] = majorType << 5 | 27;
      let remaining = BigInt(value2);
      for (let index = 8; index > 0; index -= 1) {
        encoded[index] = Number(remaining & 0xffn);
        remaining >>= 8n;
      }
      push(encoded);
    }
  }
  function encodeItem(item, depth) {
    if (depth > MAX_CBOR_DEPTH) {
      throw new Error("CBOR nesting exceeds depth limit");
    }
    if (item === null) {
      push(Uint8Array.of(246));
    } else if (item === void 0) {
      push(Uint8Array.of(247));
    } else if (typeof item === "boolean") {
      push(Uint8Array.of(item ? 245 : 244));
    } else if (typeof item === "number") {
      if (!Number.isSafeInteger(item)) {
        throw new Error("CBOR supports only safe integers");
      }
      if (item >= 0) {
        encodeArgument(0, item);
      } else {
        encodeArgument(1, -1 - item);
      }
    } else if (typeof item === "string") {
      const bytes = textEncoder.encode(item);
      encodeArgument(3, bytes.length);
      push(bytes);
    } else if (item instanceof Uint8Array) {
      encodeArgument(2, item.length);
      push(item);
    } else if (Array.isArray(item)) {
      if (item.length > MAX_CBOR_CONTAINER_ITEMS) {
        throw new Error("CBOR container exceeds item limit");
      }
      if (activeContainers.has(item)) {
        throw new Error("CBOR cannot encode cyclic values");
      }
      activeContainers.add(item);
      encodeArgument(4, item.length);
      for (const value2 of item) {
        encodeItem(value2, depth + 1);
      }
      activeContainers.delete(item);
    } else if (typeof item === "object") {
      const prototype = Object.getPrototypeOf(item);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new Error("CBOR supports only plain objects");
      }
      const keys = Object.keys(item);
      if (keys.length > MAX_CBOR_CONTAINER_ITEMS) {
        throw new Error("CBOR container exceeds item limit");
      }
      if (activeContainers.has(item)) {
        throw new Error("CBOR cannot encode cyclic values");
      }
      activeContainers.add(item);
      encodeArgument(5, keys.length);
      for (const key of keys) {
        encodeItem(key, depth + 1);
        encodeItem(item[key], depth + 1);
      }
      activeContainers.delete(item);
    } else {
      throw new Error(`unsupported CBOR value type: ${typeof item}`);
    }
  }
  encodeItem(value, 0);
  const output = new Uint8Array(encodedLength);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}
function decode(input, {
  allowedTags = [],
  requiredTag,
  allowIndefinite = false
} = {}) {
  const bytes = input instanceof Uint8Array ? input : ArrayBuffer.isView(input) ? new Uint8Array(input.buffer, input.byteOffset, input.byteLength) : input instanceof ArrayBuffer ? new Uint8Array(input) : null;
  if (!bytes) throw new TypeError("CBOR input must be bytes");
  if (bytes.length > MAX_CBOR_BYTES) {
    throw new Error("CBOR input exceeds size limit");
  }
  const acceptedTags = new Set(allowedTags);
  if (requiredTag !== void 0) acceptedTags.add(requiredTag);
  let decodedNodes = 0;
  let rootTag;
  let offset = 0;
  function requireBytes(length) {
    if (!Number.isSafeInteger(length) || length < 0 || length > MAX_CBOR_BYTES || length > bytes.length - offset) {
      throw new Error("truncated or oversized CBOR value");
    }
  }
  function readArgument(additionalInfo) {
    if (additionalInfo < 24) return additionalInfo;
    let width;
    let minimumValue;
    switch (additionalInfo) {
      case 24:
        width = 1;
        minimumValue = 24n;
        break;
      case 25:
        width = 2;
        minimumValue = 0x100n;
        break;
      case 26:
        width = 4;
        minimumValue = 0x10000n;
        break;
      case 27:
        width = 8;
        minimumValue = 0x100000000n;
        break;
      case 31:
        throw new Error("indefinite-length CBOR is not supported");
      default:
        throw new Error(`unsupported CBOR additional info: ${additionalInfo}`);
    }
    requireBytes(width);
    let value2 = 0n;
    for (let index = 0; index < width; index += 1) {
      value2 = value2 << 8n | BigInt(bytes[offset]);
      offset += 1;
    }
    if (value2 < minimumValue) {
      throw new Error("non-preferred CBOR argument encoding");
    }
    if (value2 > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error("CBOR integer exceeds safe integer range");
    }
    return Number(value2);
  }
  function claimMapProperty(keys, key) {
    if (typeof key !== "string" && typeof key !== "number") {
      throw new Error("CBOR map keys must be strings or integers");
    }
    const property = String(key);
    if (keys.has(property)) {
      throw new Error("duplicate CBOR map key");
    }
    keys.add(property);
    return property;
  }
  function defineMapEntry(result, property, value2) {
    Object.defineProperty(result, property, {
      configurable: true,
      enumerable: true,
      value: value2,
      writable: true
    });
  }
  function readIndefiniteString(majorType, depth) {
    const chunks = [];
    let decodedLength = 0;
    while (true) {
      requireBytes(1);
      if (bytes[offset] === 255) {
        offset += 1;
        break;
      }
      if (chunks.length >= MAX_CBOR_CONTAINER_ITEMS) {
        throw new Error("CBOR container exceeds item limit");
      }
      const chunkInitial = bytes[offset];
      const chunkMajorType = chunkInitial >> 5;
      const chunkAdditionalInfo = chunkInitial & 31;
      if (chunkMajorType !== majorType || chunkAdditionalInfo === 31) {
        throw new Error("invalid indefinite-length CBOR string chunk");
      }
      const chunk = read(depth + 1);
      decodedLength += majorType === 2 ? chunk.length : textEncoder.encode(chunk).length;
      if (decodedLength > MAX_CBOR_BYTES) {
        throw new Error("CBOR string exceeds size limit");
      }
      chunks.push(chunk);
    }
    if (majorType === 3) return chunks.join("");
    const result = new Uint8Array(decodedLength);
    let resultOffset = 0;
    for (const chunk of chunks) {
      result.set(chunk, resultOffset);
      resultOffset += chunk.length;
    }
    return result;
  }
  function readIndefiniteArray(depth) {
    const result = [];
    while (true) {
      requireBytes(1);
      if (bytes[offset] === 255) {
        offset += 1;
        return result;
      }
      if (result.length >= MAX_CBOR_CONTAINER_ITEMS) {
        throw new Error("CBOR container exceeds item limit");
      }
      result.push(read(depth + 1));
    }
  }
  function readIndefiniteMap(depth) {
    const result = {};
    const keys = /* @__PURE__ */ new Set();
    let itemCount = 0;
    while (true) {
      requireBytes(1);
      if (bytes[offset] === 255) {
        offset += 1;
        return result;
      }
      if (itemCount >= MAX_CBOR_CONTAINER_ITEMS) {
        throw new Error("CBOR container exceeds item limit");
      }
      const key = read(depth + 1);
      requireBytes(1);
      if (bytes[offset] === 255) {
        throw new Error("indefinite-length CBOR map has a dangling key");
      }
      const property = claimMapProperty(keys, key);
      defineMapEntry(result, property, read(depth + 1));
      itemCount += 1;
    }
  }
  function read(depth) {
    if (depth > MAX_CBOR_DEPTH) {
      throw new Error("CBOR nesting exceeds depth limit");
    }
    requireBytes(1);
    decodedNodes += 1;
    if (decodedNodes > MAX_CBOR_NODES) {
      throw new Error("CBOR exceeds node limit");
    }
    const initial = bytes[offset];
    offset += 1;
    const majorType = initial >> 5;
    const additionalInfo = initial & 31;
    if (majorType === 7) {
      switch (additionalInfo) {
        case 20:
          return false;
        case 21:
          return true;
        case 22:
          return null;
        case 23:
          return void 0;
        case 31:
          throw new Error("unexpected CBOR break marker");
        default:
          throw new Error(`unsupported CBOR simple value: ${additionalInfo}`);
      }
    }
    if (additionalInfo === 31) {
      if (!allowIndefinite) {
        throw new Error("indefinite-length CBOR is not supported");
      }
      switch (majorType) {
        case 2:
        case 3:
          return readIndefiniteString(majorType, depth);
        case 4:
          return readIndefiniteArray(depth);
        case 5:
          return readIndefiniteMap(depth);
        default:
          throw new Error(`invalid indefinite-length CBOR major type: ${majorType}`);
      }
    }
    const value2 = readArgument(additionalInfo);
    switch (majorType) {
      case 0:
        return value2;
      case 1: {
        const result = -1 - value2;
        if (!Number.isSafeInteger(result)) {
          throw new Error("CBOR integer exceeds safe integer range");
        }
        return result;
      }
      case 2: {
        requireBytes(value2);
        const result = bytes.slice(offset, offset + value2);
        offset += value2;
        return result;
      }
      case 3: {
        requireBytes(value2);
        const encoded = bytes.subarray(offset, offset + value2);
        offset += value2;
        try {
          return textDecoder.decode(encoded);
        } catch {
          throw new Error("invalid UTF-8 in CBOR text string");
        }
      }
      case 4: {
        if (value2 > MAX_CBOR_CONTAINER_ITEMS) {
          throw new Error("CBOR container exceeds item limit");
        }
        const result = [];
        for (let index = 0; index < value2; index += 1) {
          result.push(read(depth + 1));
        }
        return result;
      }
      case 5: {
        if (value2 > MAX_CBOR_CONTAINER_ITEMS) {
          throw new Error("CBOR container exceeds item limit");
        }
        const result = {};
        const keys = /* @__PURE__ */ new Set();
        for (let index = 0; index < value2; index += 1) {
          const key = read(depth + 1);
          const property = claimMapProperty(keys, key);
          defineMapEntry(result, property, read(depth + 1));
        }
        return result;
      }
      case 6:
        if (depth !== 0 || !acceptedTags.has(value2)) {
          throw new Error(`unsupported CBOR tag: ${value2}`);
        }
        rootTag = value2;
        return read(depth + 1);
      default:
        throw new Error(`unsupported CBOR major type: ${majorType}`);
    }
  }
  const value = read(0);
  if (requiredTag !== void 0 && rootTag !== requiredTag) {
    throw new Error(`required CBOR tag: ${requiredTag}`);
  }
  if (offset !== bytes.length) {
    throw new Error("trailing bytes after CBOR value");
  }
  return value;
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
var COSE_SIGN1_TAG = 18;
var NITRO_PROTECTED_HEADER = Uint8Array.of(161, 1, 56, 34);
function validateProtectedHeader(protectedHeader) {
  let decodedHeader;
  try {
    decodedHeader = decode(protectedHeader);
  } catch {
    throw new Error("Invalid COSE protected header");
  }
  if (!decodedHeader || Object.getPrototypeOf(decodedHeader) !== Object.prototype || Object.keys(decodedHeader).length !== 1 || decodedHeader[1] !== -35 || !arraysEqual(protectedHeader, NITRO_PROTECTED_HEADER)) {
    throw new Error("Invalid COSE protected header");
  }
}
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
  const coseSign1 = decode(document, { allowedTags: [COSE_SIGN1_TAG] });
  if (!Array.isArray(coseSign1) || coseSign1.length !== 4) {
    throw new Error("Invalid COSE Sign1 structure");
  }
  const [protectedHeader, unprotectedHeader, payload, signature] = coseSign1;
  if (!(protectedHeader instanceof Uint8Array) || !unprotectedHeader || Object.getPrototypeOf(unprotectedHeader) !== Object.prototype || Object.keys(unprotectedHeader).length !== 0 || !(payload instanceof Uint8Array) || !(signature instanceof Uint8Array)) {
    throw new Error("Invalid COSE Sign1 structure");
  }
  validateProtectedHeader(protectedHeader);
  const decodedPayload = decode(payload, { allowIndefinite: true });
  if (!decodedPayload || Object.getPrototypeOf(decodedPayload) !== Object.prototype) {
    throw new Error("Invalid Nitro attestation payload");
  }
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

// src/attestation-verifier.js
var ATTESTATION_PROFILE = Object.freeze({
  id: "aws-nitro",
  trustAnchor: "AWS Nitro root CA",
  synthetic: false
});
function verifyAttestation(document, options) {
  return verify(document, options);
}

// src/protocol-v2.js
var VERSION = 2;
var PROTOCOL_ID = "STEVE-E2P-V2";
var X25519_KEY_EXCHANGE = "X25519";
var XWING_KEY_EXCHANGE = "XWING-DRAFT10";
var DEFAULT_KEY_EXCHANGE = X25519_KEY_EXCHANGE;
var KEY_DERIVATION = "HKDF-SHA256";
var RECORD_PROTECTION = "AES-256-GCM";
var SESSION_ENDPOINT = "/e2p/v2/session";
var CONFIRM_ENDPOINT = "/e2p/v2/confirm";
var REQUEST_ENDPOINT = "/e2p/v2/request";
var MAX_ENVELOPE_BYTES = MAX_CBOR_BYTES;
var encoder = new TextEncoder();
var MAGIC = encoder.encode("STEVE-E2P-V2\0");
var KEY_MATERIAL_LENGTHS = Object.freeze({
  [X25519_KEY_EXCHANGE]: Object.freeze({ client: 32, server: 32 }),
  [XWING_KEY_EXCHANGE]: Object.freeze({ client: 1216, server: 1120 })
});
var REPLAY_WINDOW_SIZE = 64n;
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
    this.waiters = [];
    this.closedError = null;
  }
  async allocate() {
    while (!this.canAllocate()) {
      await new Promise((resolve, reject) => this.waiters.push({ resolve, reject }));
    }
    if (this.closedError) throw this.closedError;
    const sequence = this.next;
    if (sequence > 0xffffffffffffffffn) throw new Error("session sequence exhausted");
    this.next += 1n;
    this.pending.add(sequence);
    return sequence;
  }
  accept(expected, received) {
    if (this.closedError) throw this.closedError;
    if (received !== expected || !this.pending.delete(expected)) {
      throw new Error("unexpected v2 response sequence");
    }
    this.wakeWaiters();
  }
  retire(sequence) {
    if (this.closedError) return false;
    if (!this.pending.delete(sequence)) {
      throw new Error("unexpected v2 retired sequence");
    }
    this.wakeWaiters();
    return true;
  }
  close(error = new Error("session sequence tracker closed")) {
    if (this.closedError) return;
    this.closedError = error instanceof Error ? error : new Error(String(error));
    this.pending.clear();
    const waiters = this.waiters.splice(0);
    for (const waiter of waiters) waiter.reject(this.closedError);
  }
  canAllocate() {
    if (this.closedError) return true;
    const oldest = this.pending.values().next().value;
    return oldest === void 0 || this.next - oldest < REPLAY_WINDOW_SIZE;
  }
  wakeWaiters() {
    const waiters = this.waiters.splice(0);
    for (const waiter of waiters) waiter.resolve();
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
function buildTranscript(keyExchange, clientNonce, clientKeyMaterial, serverKeyMaterial, sessionId, contextHash) {
  requireKeyExchange(keyExchange);
  requireLength("client nonce", clientNonce, 32);
  requireKeyMaterial(keyExchange, "client", clientKeyMaterial);
  requireKeyMaterial(keyExchange, "server", serverKeyMaterial);
  requireLength("session ID", sessionId, 16);
  requireLength("context hash", contextHash, 32);
  return concatBytes(
    MAGIC,
    encoder.encode(keyExchange),
    new Uint8Array([0]),
    clientNonce,
    clientKeyMaterial,
    serverKeyMaterial,
    sessionId,
    contextHash
  );
}
async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}
async function hashOrigin(origin) {
  return sha256(encoder.encode(origin));
}
async function deriveMaterial(sharedSecret, transcriptHash) {
  requireLength("key-exchange shared secret", sharedSecret, 32);
  requireLength("transcript hash", transcriptHash, 32);
  let hkdfKey;
  try {
    hkdfKey = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveBits"]);
  } finally {
    sharedSecret.fill(0);
  }
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
function encodeSessionRequest(keyExchange, clientNonce, clientKeyMaterial, contextHash) {
  requireKeyExchange(keyExchange);
  requireLength("client nonce", clientNonce, 32);
  requireKeyMaterial(keyExchange, "client", clientKeyMaterial);
  requireLength("context hash", contextHash, 32);
  return encode({
    version: VERSION,
    key_exchange: keyExchange,
    client_nonce: clientNonce,
    client_key_material: clientKeyMaterial,
    context_hash: contextHash
  });
}
function decodeSessionResponse(bytes, expectedKeyExchange) {
  requireKeyExchange(expectedKeyExchange);
  const response = decode(bytes);
  if (response.version !== VERSION) throw new Error("unsupported session response version");
  if (response.key_exchange !== expectedKeyExchange) {
    throw new Error("session key exchange mismatch");
  }
  requireLength("session ID", response.session_id, 16);
  requireKeyMaterial(expectedKeyExchange, "server", response.server_key_material);
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
  let envelope;
  try {
    envelope = encode({
      version: VERSION,
      session_id: sessionId,
      sequence: sequenceBytes(sequence),
      ciphertext
    });
  } catch (error) {
    if (error?.message === "CBOR output exceeds size limit") {
      throw new Error("v2 envelope exceeds size limit", { cause: error });
    }
    throw error;
  }
  if (envelope.length > MAX_ENVELOPE_BYTES) {
    throw new Error("v2 envelope exceeds size limit");
  }
  return envelope;
}
function decodeEnvelope(bytes) {
  const envelope = decode(bytes);
  if (envelope.version !== VERSION) throw new Error("unsupported envelope version");
  requireLength("session ID", envelope.session_id, 16);
  requireLength("sequence", envelope.sequence, 8);
  if (!(envelope.ciphertext instanceof Uint8Array)) throw new Error("invalid envelope ciphertext");
  return { ...envelope, sequenceValue: parseSequence(envelope.sequence) };
}
function verifyBinding(userData, keyExchange, sessionId, transcriptHash, binder) {
  requireKeyExchange(keyExchange);
  if (!userData || userData.protocol !== PROTOCOL_ID || userData.key_exchange !== keyExchange) {
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
function validateAttestationResult(result, keyExchange, sessionId, transcriptHash, binder) {
  if (!result?.verified) {
    throw new Error(`Nitro attestation verification failed: ${result?.error || "unknown error"}`);
  }
  verifyBinding(result.userData, keyExchange, sessionId, transcriptHash, binder);
}
function encodeBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
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
function requireKeyExchange(keyExchange) {
  if (!Object.prototype.hasOwnProperty.call(KEY_MATERIAL_LENGTHS, keyExchange)) {
    throw new Error(`unsupported key exchange: ${keyExchange}`);
  }
}
function requireKeyMaterial(keyExchange, side, value) {
  requireLength(
    `${side} key material`,
    value,
    KEY_MATERIAL_LENGTHS[keyExchange][side]
  );
}

// wasm-pkg/steve_xwing_wasm.js
var wasm;
function addToExternrefTable0(obj) {
  const idx = wasm.__externref_table_alloc();
  wasm.__wbindgen_externrefs.set(idx, obj);
  return idx;
}
function getArrayU8FromWasm0(ptr, len) {
  ptr = ptr >>> 0;
  return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}
function getStringFromWasm0(ptr, len) {
  ptr = ptr >>> 0;
  return decodeText(ptr, len);
}
var cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
  if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
    cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
  }
  return cachedUint8ArrayMemory0;
}
function handleError(f, args) {
  try {
    return f.apply(this, args);
  } catch (e) {
    const idx = addToExternrefTable0(e);
    wasm.__wbindgen_exn_store(idx);
  }
}
function passArray8ToWasm0(arg, malloc) {
  const ptr = malloc(arg.length * 1, 1) >>> 0;
  getUint8ArrayMemory0().set(arg, ptr / 1);
  WASM_VECTOR_LEN = arg.length;
  return ptr;
}
function takeFromExternrefTable0(idx) {
  const value = wasm.__wbindgen_externrefs.get(idx);
  wasm.__externref_table_dealloc(idx);
  return value;
}
var cachedTextDecoder = new TextDecoder("utf-8", { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
var MAX_SAFARI_DECODE_BYTES = 2146435072;
var numBytesDecoded = 0;
function decodeText(ptr, len) {
  numBytesDecoded += len;
  if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
    cachedTextDecoder = new TextDecoder("utf-8", { ignoreBOM: true, fatal: true });
    cachedTextDecoder.decode();
    numBytesDecoded = len;
  }
  return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}
var WASM_VECTOR_LEN = 0;
var XWingClientFinalization = typeof FinalizationRegistry === "undefined" ? { register: () => {
}, unregister: () => {
} } : new FinalizationRegistry((ptr) => wasm.__wbg_xwingclient_free(ptr >>> 0, 1));
var XWingClient = class {
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    XWingClientFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_xwingclient_free(ptr, 0);
  }
  /**
   * Return only the public encapsulation key.
   * @returns {Uint8Array}
   */
  public_key() {
    const ret = wasm.xwingclient_public_key(this.__wbg_ptr);
    if (ret[3]) {
      throw takeFromExternrefTable0(ret[2]);
    }
    var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v1;
  }
  /**
   * Decapsulate once, destroy the private key, and return the shared secret.
   * @param {Uint8Array} ciphertext
   * @returns {Uint8Array}
   */
  decapsulate_and_destroy(ciphertext) {
    const ptr0 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.xwingclient_decapsulate_and_destroy(this.__wbg_ptr, ptr0, len0);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
  }
  /**
   * Generate a fresh X-Wing key pair using the browser's CSPRNG.
   */
  constructor() {
    const ret = wasm.xwingclient_new();
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    this.__wbg_ptr = ret[0] >>> 0;
    XWingClientFinalization.register(this, this.__wbg_ptr, this);
    return this;
  }
};
if (Symbol.dispose) XWingClient.prototype[Symbol.dispose] = XWingClient.prototype.free;
var EXPECTED_RESPONSE_TYPES = /* @__PURE__ */ new Set(["basic", "cors", "default"]);
async function __wbg_load(module, imports) {
  if (typeof Response === "function" && module instanceof Response) {
    if (typeof WebAssembly.instantiateStreaming === "function") {
      try {
        return await WebAssembly.instantiateStreaming(module, imports);
      } catch (e) {
        const validResponse = module.ok && EXPECTED_RESPONSE_TYPES.has(module.type);
        if (validResponse && module.headers.get("Content-Type") !== "application/wasm") {
          console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);
        } else {
          throw e;
        }
      }
    }
    const bytes = await module.arrayBuffer();
    return await WebAssembly.instantiate(bytes, imports);
  } else {
    const instance = await WebAssembly.instantiate(module, imports);
    if (instance instanceof WebAssembly.Instance) {
      return { instance, module };
    } else {
      return instance;
    }
  }
}
function __wbg_get_imports() {
  const imports = {};
  imports.wbg = {};
  imports.wbg.__wbg_Error_52673b7de5a0ca89 = function(arg0, arg1) {
    const ret = Error(getStringFromWasm0(arg0, arg1));
    return ret;
  };
  imports.wbg.__wbg___wbindgen_throw_dd24417ed36fc46e = function(arg0, arg1) {
    throw new Error(getStringFromWasm0(arg0, arg1));
  };
  imports.wbg.__wbg_getRandomValues_a8ddca022803a145 = function() {
    return handleError(function(arg0, arg1) {
      globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
    }, arguments);
  };
  imports.wbg.__wbg_new_from_slice_f9c22b9153b26992 = function(arg0, arg1) {
    const ret = new Uint8Array(getArrayU8FromWasm0(arg0, arg1));
    return ret;
  };
  imports.wbg.__wbindgen_init_externref_table = function() {
    const table = wasm.__wbindgen_externrefs;
    const offset = table.grow(4);
    table.set(0, void 0);
    table.set(offset + 0, void 0);
    table.set(offset + 1, null);
    table.set(offset + 2, true);
    table.set(offset + 3, false);
  };
  return imports;
}
function __wbg_finalize_init(instance, module) {
  wasm = instance.exports;
  __wbg_init.__wbindgen_wasm_module = module;
  cachedUint8ArrayMemory0 = null;
  wasm.__wbindgen_start();
  return wasm;
}
async function __wbg_init(module_or_path) {
  if (wasm !== void 0) return wasm;
  if (typeof module_or_path !== "undefined") {
    if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
      ({ module_or_path } = module_or_path);
    } else {
      console.warn("using deprecated parameters for the initialization function; pass a single object instead");
    }
  }
  if (typeof module_or_path === "undefined") {
    module_or_path = new URL("steve_xwing_wasm_bg.wasm", import.meta.url);
  }
  const imports = __wbg_get_imports();
  if (typeof module_or_path === "string" || typeof Request === "function" && module_or_path instanceof Request || typeof URL === "function" && module_or_path instanceof URL) {
    module_or_path = fetch(module_or_path);
  }
  const { instance, module } = await __wbg_load(await module_or_path, imports);
  return __wbg_finalize_init(instance, module);
}
var steve_xwing_wasm_default = __wbg_init;

// src/key-exchange.js
var XWING_WASM_PATH = "./xwing/steve_xwing_wasm_bg.wasm";
var XWING_WASM_SHA256 = false ? null : "802131b0e84424760f3e2e37bcee0c76fb029aa3480d7742b839f60508cc0912";
function createVerifiedXWingModuleLoader(initializer) {
  if (typeof initializer !== "function") {
    throw new TypeError("X-Wing module initializer must be a function");
  }
  let cached;
  return function loadModule() {
    if (!cached) {
      const attempt = Promise.resolve().then(initializer);
      const guarded = attempt.catch((error) => {
        if (cached === guarded) cached = void 0;
        throw error;
      });
      cached = guarded;
    }
    return cached;
  };
}
var loadVerifiedXWingModule = createVerifiedXWingModuleLoader(
  () => initializeVerifiedXWingModule({
    initialize: steve_xwing_wasm_default,
    XWingClient
  })
);
async function initializeVerifiedXWingModule({
  initialize,
  XWingClient: XWingClient2,
  fetchImpl = globalThis.fetch,
  expectedDigest = XWING_WASM_SHA256,
  wasmUrl = new URL(XWING_WASM_PATH, import.meta.url)
}) {
  if (typeof initialize !== "function" || typeof XWingClient2 !== "function") {
    throw new Error("invalid self-hosted X-Wing WASM bindings");
  }
  if (!/^[0-9a-f]{64}$/u.test(expectedDigest || "")) {
    throw new Error("X-Wing WASM build digest is unavailable");
  }
  const response = await fetchImpl(wasmUrl, {
    cache: "no-store",
    credentials: "same-origin",
    redirect: "error"
  });
  if (!response.ok) {
    throw new Error(`X-Wing WASM asset fetch failed with HTTP ${response.status}`);
  }
  const wasmBytes = new Uint8Array(await response.arrayBuffer());
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", wasmBytes));
  const actualDigest = Array.from(
    digest,
    (byte) => byte.toString(16).padStart(2, "0")
  ).join("");
  if (actualDigest !== expectedDigest) {
    throw new Error("X-Wing WASM asset integrity check failed");
  }
  await initialize({ module_or_path: wasmBytes });
  return { XWingClient: XWingClient2 };
}
async function createClientKeyExchange(keyExchange, xwingModuleLoader) {
  requireKeyExchange(keyExchange);
  if (keyExchange === X25519_KEY_EXCHANGE) return createX25519Client();
  if (keyExchange === XWING_KEY_EXCHANGE) {
    if (typeof xwingModuleLoader !== "function") {
      throw new Error("X-Wing WASM loader is unavailable");
    }
    return createXWingClient(xwingModuleLoader);
  }
  throw new Error(`unsupported key exchange: ${keyExchange}`);
}
async function createX25519Client() {
  let keyPair = await crypto.subtle.generateKey(
    { name: "X25519" },
    false,
    ["deriveBits"]
  );
  const publicKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", keyPair.publicKey)
  );
  let consumed = false;
  return {
    keyExchange: X25519_KEY_EXCHANGE,
    publicKey,
    async decapsulate(serverKeyMaterial) {
      if (consumed) throw new Error("X25519 client already consumed");
      consumed = true;
      const privateKey = keyPair.privateKey;
      keyPair = null;
      const serverPublicKey = await crypto.subtle.importKey(
        "raw",
        serverKeyMaterial,
        { name: "X25519" },
        false,
        []
      );
      return new Uint8Array(await crypto.subtle.deriveBits(
        { name: "X25519", public: serverPublicKey },
        privateKey,
        256
      ));
    },
    destroy() {
      consumed = true;
      keyPair = null;
    }
  };
}
async function createXWingClient(moduleLoader) {
  const module = await moduleLoader();
  if (typeof module?.XWingClient !== "function") {
    throw new Error("invalid self-hosted X-Wing WASM module");
  }
  const client = new module.XWingClient();
  const publicKey = client.public_key();
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 1216) {
    client.free?.();
    throw new Error("invalid X-Wing client key material");
  }
  let consumed = false;
  let freed = false;
  const destroy = () => {
    if (!freed) {
      freed = true;
      client.free?.();
    }
  };
  return {
    keyExchange: XWING_KEY_EXCHANGE,
    publicKey,
    async decapsulate(serverKeyMaterial) {
      if (consumed) throw new Error("X-Wing client already consumed");
      consumed = true;
      try {
        const sharedSecret = client.decapsulate_and_destroy(serverKeyMaterial);
        if (!(sharedSecret instanceof Uint8Array) || sharedSecret.length !== 32) {
          sharedSecret?.fill?.(0);
          throw new Error("invalid X-Wing shared secret");
        }
        return sharedSecret;
      } finally {
        destroy();
      }
    },
    destroy() {
      consumed = true;
      destroy();
    }
  };
}

// src/pcr-policy.js
var DATABASE_NAME = "steve-sdk-pcr-policy-v1";
var DATABASE_VERSION = 1;
var STORE_NAME = "state";
var TRUST_KEY_DOMAIN = "STEVE-E2P-V2-BROWSER-PCR-TOFU\0";
var PCR_HEX = /^[0-9a-f]{96}$/iu;
var PCR_NAME = /^PCR(0|[1-9][0-9]{0,2})$/u;
var ZERO_PCR = "0".repeat(96);
function normalizePcrPolicy(policy) {
  if (policy === null) return null;
  requireRecord(policy, "pcrPolicy");
  if (policy.mode === "pinned") {
    requireOnlyKeys(policy, ["mode", "profiles"], "pinned PCR policy");
    if (!Array.isArray(policy.profiles) || policy.profiles.length === 0) {
      throw new Error("pinned PCR policy requires at least one profile");
    }
    return {
      mode: "pinned",
      profiles: policy.profiles.map((profile, index) => normalizeProfile(
        profile,
        `pinned PCR profile ${index}`
      ))
    };
  }
  if (policy.mode === "tofu") {
    requireOnlyKeys(policy, ["mode", "additionalPcrIndices"], "TOFU PCR policy");
    const supplied = policy.additionalPcrIndices ?? [];
    if (!Array.isArray(supplied)) {
      throw new Error("additionalPcrIndices must be an array");
    }
    const indices = /* @__PURE__ */ new Set();
    for (const index of supplied) {
      if (!Number.isInteger(index) || index < 0 || index > 255) {
        throw new Error("additional PCR indices must be integers from 0 through 255");
      }
      if (index > 2) indices.add(index);
    }
    return {
      mode: "tofu",
      additionalPcrIndices: [...indices].sort((left, right) => left - right)
    };
  }
  throw new Error("pcrPolicy.mode must be exactly pinned or tofu");
}
function pcrPoliciesEqual(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}
function verifyPinnedPcrPolicy(policy, observed) {
  if (policy?.mode !== "pinned") throw new Error("pinned PCR policy required");
  requireRecord(observed, "attested PCRs");
  if (policy.profiles.some((profile) => profileMatches(profile, observed))) {
    return "pinned";
  }
  throw policyError(
    "PCR_POLICY_MISMATCH",
    "attested PCRs did not match one complete pinned profile"
  );
}
function selectTofuPcrs(policy, observed) {
  if (policy?.mode !== "tofu") throw new Error("TOFU PCR policy required");
  requireRecord(observed, "attested PCRs");
  const selected = {};
  for (const index of [0, 1, 2, ...policy.additionalPcrIndices]) {
    try {
      selected[`PCR${index}`] = normalizePcrValue(
        observed[`PCR${index}`],
        `attested PCR${index}`
      );
    } catch (cause) {
      throw policyError("ATTESTED_PCR_INVALID", cause.message);
    }
  }
  return selected;
}
async function pcrTrustKey(scope, enclaveOrigin, suite) {
  const normalizedScope = new URL(scope).href;
  const encoded = new TextEncoder().encode(
    `${TRUST_KEY_DOMAIN}${normalizedScope}\0${enclaveOrigin}\0${suite}`
  );
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", encoded));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
function exactPcrsMatch(existing, observed) {
  let normalized;
  try {
    normalized = normalizeProfile(existing, "stored PCR trust record");
  } catch {
    return false;
  }
  return JSON.stringify(normalized) === JSON.stringify(observed);
}
async function enforceTofuPcrPolicy(policy, observed, context, storage) {
  const selected = selectTofuPcrs(policy, observed);
  const key = await pcrTrustKey(context.scope, context.enclaveOrigin, context.suite);
  const record = await storage.loadOrInsert(key, selected);
  if (record?.status === "inserted") return "tofu-enrolled";
  if (record?.status === "existing" && exactPcrsMatch(record.pcrs, selected)) {
    return "tofu-matched";
  }
  throw policyError(
    "PCR_TRUST_MISMATCH",
    "attested PCRs did not match the enrolled TOFU record"
  );
}
function createBrowserPcrPolicyStorage(databaseFactory = globalThis.indexedDB) {
  const openDatabase = () => openPcrDatabase(databaseFactory);
  return {
    async isPolicyRequired(scope) {
      return Boolean(await readValue(openDatabase, markerKey(scope)));
    },
    async setPolicyRequired(scope, required) {
      await writeValue(openDatabase, markerKey(scope), required ? true : void 0);
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
              "readwrite",
              { durability: "strict" }
            );
          } catch (error) {
            reject(storageError(error));
            return;
          }
          const request = transaction.objectStore(STORE_NAME).get(`trust:${key}`);
          request.onsuccess = () => {
            if (request.result === void 0) {
              outcome = { status: "inserted" };
              transaction.objectStore(STORE_NAME).add(observed, `trust:${key}`);
            } else {
              outcome = { status: "existing", pcrs: request.result };
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
    return typeof value === "string" && PCR_HEX.test(value) && value.toLowerCase() !== ZERO_PCR && value.toLowerCase() === expected;
  });
}
function normalizePcrValue(value, label) {
  if (typeof value !== "string" || !PCR_HEX.test(value)) {
    throw new Error(`${label} must contain exactly 96 hexadecimal characters`);
  }
  const normalized = value.toLowerCase();
  if (normalized === ZERO_PCR) throw new Error(`${label} must be nonzero`);
  return normalized;
}
function requireRecord(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
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
      let transaction;
      try {
        transaction = database.transaction(STORE_NAME, "readonly");
      } catch (error) {
        reject(storageError(error));
        return;
      }
      const request = transaction.objectStore(STORE_NAME).get(key);
      let value;
      request.onsuccess = () => {
        value = request.result;
      };
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
          "readwrite",
          { durability: "strict" }
        );
      } catch (error) {
        reject(storageError(error));
        return;
      }
      const store = transaction.objectStore(STORE_NAME);
      if (value === void 0) store.delete(key);
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
  const error = new Error("PCR policy storage failed");
  error.code = "PCR_TRUST_STORAGE";
  error.stage = "pcr-trust";
  error.cause = cause;
  return error;
}
function policyError(code, message) {
  const error = new Error(message);
  error.code = code;
  error.stage = "pcr-policy";
  return error;
}

// src/enclave-sw.js
var DEFAULT_BOOTSTRAP_PATHS = [
  "/enclave-sw.js",
  "/register.js",
  "/attestation-widget.js",
  "/xwing/steve_xwing_wasm_bg.wasm"
];
var SCOPED_BOOTSTRAP_PATHS = [
  "enclave-sw.js",
  "register.js",
  "attestation-widget.js",
  "xwing/steve_xwing_wasm_bg.wasm"
];
var SAFE_BOOTSTRAP_METHODS = /* @__PURE__ */ new Set(["GET", "HEAD"]);
var ROTATION_INTERVAL_MS = 25 * 60 * 1e3;
var PROTOCOL_EXCLUDE_PREFIXES = ["/e2p/"];
var DEFAULT_REQUEST_TIMEOUT_MS = 30 * 1e3;
var MIN_REQUEST_TIMEOUT_MS = 1e3;
var MAX_REQUEST_TIMEOUT_MS = 5 * 60 * 1e3;
var SESSION_ESTABLISH_TIMEOUT_MS = 10 * 1e3;
var MAX_SESSION_RESPONSE_BYTES = 64 * 1024;
var MAX_CONFIRMATION_RESPONSE_BYTES = 4 * 1024;
var MAX_APPLICATION_RESPONSE_BYTES = 32 * 1024 * 1024 + 64 * 1024;
var SESSION_FATAL_HTTP_STATUSES = /* @__PURE__ */ new Set([400, 401, 409, 425]);
var REQUEST_LOCAL_HTTP_STATUSES = /* @__PURE__ */ new Set([403, 404, 408, 413, 429]);
var CONFIG_CACHE_NAME = "steve-sdk-config-v1";
var CONFIG_CACHE_PATH = ".steve-sdk/config-v1";
function defaultConfig() {
  return {
    enclaveOrigin: self.location.origin,
    passthroughPaths: [...DEFAULT_BOOTSTRAP_PATHS],
    excludePrefixes: ["/attestation", "/e2p/"],
    emitEncryptedPayloads: false,
    requestTimeoutMs: DEFAULT_REQUEST_TIMEOUT_MS,
    expectedKeyExchange: DEFAULT_KEY_EXCHANGE,
    pcrPolicy: null
  };
}
var config = defaultConfig();
var configRestoreError = null;
var configurationReady = false;
var configurationTail = Promise.resolve();
var configGeneration = 0;
var pcrStorage = false ? self.__STEVE_PCR_STORAGE_TEST__ : createBrowserPcrPolicyStorage();
var configReady = initializeConfig();
var state = freshState();
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(clients.claim()));
self.addEventListener("message", (event) => event.waitUntil(handleMessage(event)));
self.addEventListener("fetch", (event) => {
  event.respondWith(routeRequest(event.request));
});
async function handleMessage(event) {
  const { type } = event.data;
  const port = event.ports[0];
  try {
    await configReady;
    switch (type) {
      case "get-status":
        port?.postMessage(statusMessage());
        break;
      case "initialize":
        await ensureSession("explicit-initialize");
        port?.postMessage({ type: "initialized", success: true, status: statusMessage() });
        break;
      case "rotate-session":
      case "rotate-key":
        await rotateSession();
        port?.postMessage({ type: "session-rotated", success: true, status: statusMessage() });
        break;
      case "reset":
        resetState();
        port?.postMessage({ type: "reset", success: true, status: statusMessage() });
        break;
      case "configure": {
        await configureAndPersist(event.data.config || {});
        port?.postMessage({
          type: "configured",
          success: true,
          config,
          status: statusMessage()
        });
        break;
      }
      case "protected-send": {
        const result = await protectedSend(event.data.request);
        port?.postMessage({ type: "protected-response", success: true, ...result });
        break;
      }
      case "get-pcr-policy":
        await configurationTail;
        requireConfiguration();
        port?.postMessage({
          type: "pcr-policy",
          success: true,
          policy: clonePcrPolicy()
        });
        break;
      case "replace-pcr-policy": {
        await configureAndPersist({ pcrPolicy: event.data.policy });
        port?.postMessage({
          type: "pcr-policy-replaced",
          success: true,
          policy: clonePcrPolicy(),
          status: statusMessage()
        });
        break;
      }
      default:
        throw new Error("unknown service-worker command");
    }
  } catch (error) {
    port?.postMessage({
      type,
      success: false,
      error: errorDetails(error, commandStage(type))
    });
  }
}
async function protectedSend(input) {
  requireConfiguration();
  const requestConfig = config;
  const requestGeneration = configGeneration;
  const request = deserializeProtectedRequest(input, requestConfig);
  const result = await handleProtectedRequest(
    request,
    requestConfig,
    requestGeneration,
    true
  );
  return {
    status: result.response.status,
    headers: [...result.response.headers.entries()],
    body: new Uint8Array(await result.response.arrayBuffer()),
    sessionId: result.sessionId,
    exchange: result.exchange
  };
}
function deserializeProtectedRequest(input, activeConfig) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw sdkError("INVALID_REQUEST", "request", "protected request must be an object");
  }
  const path = input.path;
  if (typeof path !== "string" || !path.startsWith("/") || path.startsWith("//")) {
    throw sdkError("INVALID_REQUEST", "request", "protected request path must be relative");
  }
  const url = new URL(path, `${activeConfig.enclaveOrigin}/`);
  if (url.origin !== activeConfig.enclaveOrigin || url.hash) {
    throw sdkError("INVALID_REQUEST", "request", "protected request path must be relative");
  }
  if (!Array.isArray(input.headers) || input.headers.some((header) => !Array.isArray(header) || header.length !== 2 || typeof header[0] !== "string" || typeof header[1] !== "string")) {
    throw sdkError("INVALID_REQUEST", "request", "protected request headers are invalid");
  }
  const method = typeof input.method === "string" ? input.method.toUpperCase() : "GET";
  const body = input.body instanceof Uint8Array ? input.body : input.body instanceof ArrayBuffer ? new Uint8Array(input.body) : null;
  try {
    return new Request(url, {
      method,
      headers: input.headers,
      body: body?.length ? body : void 0,
      credentials: "omit",
      redirect: "error"
    });
  } catch (cause) {
    throw sdkError("INVALID_REQUEST", "request", "protected request is invalid", cause);
  }
}
async function routeRequest(request) {
  await configReady;
  await configurationTail;
  if (!configurationReady || configRestoreError) {
    if (fixedBootstrapDisposition(request, new URL(request.url)) === true) {
      return fetch(request);
    }
    return configurationFailureResponse();
  }
  const requestConfig = config;
  const requestGeneration = configGeneration;
  if (!shouldProtectRequest(request, requestConfig)) return fetch(request);
  return handleProtectedRequest(request, requestConfig, requestGeneration);
}
async function handleProtectedRequest(request, requestConfig = config, requestGeneration = configGeneration, returnDetails = false) {
  let session;
  let sequence;
  try {
    const url = new URL(request.url);
    const requestBody = new Uint8Array(await request.arrayBuffer());
    const plaintext = encode({
      method: request.method,
      path: url.pathname + url.search,
      headers: Object.fromEntries(request.headers),
      body: requestBody.length === 0 ? null : requestBody
    });
    session = await currentSession();
    if (requestGeneration !== configGeneration || session.configGeneration !== requestGeneration) {
      throw new Error("configuration changed before protected request");
    }
    sequence = await session.sequences.allocate();
    const protectedResponse = await withDeadline(
      requestConfig.requestTimeoutMs,
      request.signal,
      async (signal) => {
        throwIfAborted(signal);
        const ciphertext = await seal(
          session.material,
          Direction.CLIENT_TO_SERVER,
          MessageType.APPLICATION,
          session.id,
          sequence,
          plaintext
        );
        throwIfAborted(signal);
        const envelope = encodeEnvelope(session.id, sequence, ciphertext);
        if (requestConfig.emitEncryptedPayloads) {
          await notifyClients(
            "encrypted-request",
            encryptedPayloadTrace(session, sequence, envelope)
          );
        }
        const response = await protocolFetch(
          REQUEST_ENDPOINT,
          envelope,
          signal,
          session.enclaveOrigin
        );
        const outerStatus = response.status;
        if (!response.ok) {
          throw new ProtocolHttpError(outerStatus, "request", "v2 request");
        }
        const responseBytes = await readBoundedResponse(
          response,
          MAX_APPLICATION_RESPONSE_BYTES
        );
        throwIfAborted(signal);
        const responseEnvelope = decodeEnvelope(responseBytes);
        if (!equalBytes(responseEnvelope.session_id, session.id) || responseEnvelope.sequenceValue !== sequence) {
          throw new Error("unexpected v2 response envelope");
        }
        const responsePlaintext = await open(
          session.material,
          Direction.SERVER_TO_CLIENT,
          MessageType.APPLICATION,
          session.id,
          sequence,
          responseEnvelope.ciphertext
        );
        throwIfAborted(signal);
        const decoded = decode(responsePlaintext);
        validateApplicationResponse(decoded);
        const body = decoded.body instanceof Uint8Array ? decoded.body : decoded.error ? new TextEncoder().encode(JSON.stringify({ error: decoded.error })) : null;
        return {
          response: new Response(body, { status: decoded.status, headers: decoded.headers }),
          sequenceValue: responseEnvelope.sequenceValue,
          responseEnvelope: responseBytes,
          exchange: {
            protocolName: PROTOCOL_ID,
            protection: RECORD_PROTECTION,
            sessionId: encodeDiagnosticBytes(session.id),
            sequence: sequence.toString(),
            keyExchange: session.keyExchange,
            pcrTrust: session.attestation.pcrTrust,
            outerStatus,
            requestPlaintextBytes: plaintext.length,
            requestCiphertextBytes: ciphertext.length,
            requestEnvelopeBytes: envelope.length,
            responseEnvelopeBytes: responseBytes.length,
            responseCiphertextBytes: responseEnvelope.ciphertext.length,
            responsePlaintextBytes: responsePlaintext.length
          }
        };
      },
      "v2 request timed out",
      "request"
    );
    session.sequences.accept(sequence, protectedResponse.sequenceValue);
    if (requestConfig.emitEncryptedPayloads) {
      await notifyClients(
        "encrypted-response",
        encryptedPayloadTrace(session, sequence, protectedResponse.responseEnvelope)
      );
    }
    return returnDetails ? {
      response: protectedResponse.response,
      sessionId: encodeDiagnosticBytes(session.id),
      exchange: protectedResponse.exchange
    } : protectedResponse.response;
  } catch (error) {
    if (session && sequence !== void 0 && isRequestLocalFailure(error)) {
      session.sequences.retire(sequence);
    } else if (session) {
      session.sequences.close(new Error(publicError(error)));
    }
    if (session ? !isRequestLocalFailure(error) && state.session === session : !hasValidSession(state.session)) {
      resetState(publicError(error));
    }
    const requestUrl = new URL(request.url);
    notifyClients("error", {
      ...errorDetails(error, session ? "request" : "initialization"),
      operation: session ? "request" : "initialization",
      url: requestUrl.origin + requestUrl.pathname
    });
    if (returnDetails) throw error;
    return new Response(JSON.stringify({ error: "secure channel failed" }), {
      status: error instanceof ProtocolTimeoutError ? 504 : 502,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
    });
  }
}
async function currentSession() {
  const session = await ensureSession("protected-request");
  if (Date.now() - session.createdAt >= ROTATION_INTERVAL_MS) {
    return rotateSession();
  }
  return session;
}
var establishSessionFn = establishSession;
async function ensureSession(trigger = "protected-request") {
  requireConfiguration();
  if (state.session) return state.session;
  if (!state.sessionPromise) {
    const s = state;
    s.trigger = trigger;
    s.stage = "creating-session";
    s.sessionPromise = Promise.resolve().then(() => establishSessionFn(trigger, s)).then((session) => {
      if (state === s) {
        session.trigger = trigger;
        s.session = session;
        s.error = null;
        s.stage = null;
        notifyStatus();
        void notifyClients("initialized", {
          ...session.attestation,
          status: statusMessage()
        });
      }
      return session;
    }).catch((error) => {
      if (state === s) {
        s.error = publicError(error);
        s.stage = null;
      }
      throw error;
    }).finally(() => {
      if (state === s) {
        s.sessionPromise = null;
        notifyStatus();
      }
    });
    notifyStatus();
  }
  return state.sessionPromise;
}
async function rotateSession() {
  requireConfiguration();
  if (state.rotationPromise) return state.rotationPromise;
  const s = state;
  s.stage = "creating-session";
  s.rotationPromise = Promise.resolve().then(() => establishSessionFn("rotation", s));
  notifyStatus();
  let rotatedSession;
  try {
    rotatedSession = await s.rotationPromise;
    if (state === s) {
      rotatedSession.trigger = "rotation";
      s.session = rotatedSession;
      s.error = null;
      s.stage = null;
    }
    return rotatedSession;
  } finally {
    if (state === s) {
      s.rotationPromise = null;
      s.stage = null;
      notifyStatus();
      if (rotatedSession) {
        void notifyClients("key-rotated", {
          timestamp: rotatedSession.createdAt,
          status: statusMessage()
        });
      }
    }
  }
}
async function establishSession(_trigger, targetState) {
  return withDeadline(
    SESSION_ESTABLISH_TIMEOUT_MS,
    null,
    (signal) => establishSessionWithinDeadline(signal, targetState),
    "session establishment timed out",
    "initialization"
  );
}
async function establishSessionWithinDeadline(signal, targetState) {
  const sessionConfig = config;
  const sessionGeneration = configGeneration;
  const keyExchange = sessionConfig.expectedKeyExchange;
  updateStage(targetState, "creating-session");
  const clientNonce = crypto.getRandomValues(new Uint8Array(32));
  const clientKeyExchange = await createClientKeyExchange(
    keyExchange,
    loadVerifiedXWingModule
  );
  try {
    throwIfAborted(signal);
    const clientKeyMaterial = clientKeyExchange.publicKey;
    const contextHash = await hashOrigin(self.location.origin);
    throwIfAborted(signal);
    const response = await protocolFetch(
      SESSION_ENDPOINT,
      encodeSessionRequest(
        keyExchange,
        clientNonce,
        clientKeyMaterial,
        contextHash
      ),
      signal,
      sessionConfig.enclaveOrigin
    );
    if (!response.ok) {
      throw new ProtocolHttpError(response.status, "initialization", "session creation");
    }
    const sessionResponse = decodeSessionResponse(
      await readBoundedResponse(response, MAX_SESSION_RESPONSE_BYTES),
      keyExchange
    );
    throwIfAborted(signal);
    const transcript = buildTranscript(
      keyExchange,
      clientNonce,
      clientKeyMaterial,
      sessionResponse.server_key_material,
      sessionResponse.session_id,
      contextHash
    );
    const transcriptHash = await sha256(transcript);
    throwIfAborted(signal);
    const sharedSecret = await clientKeyExchange.decapsulate(
      sessionResponse.server_key_material
    );
    const material = await deriveMaterial(sharedSecret, transcriptHash);
    throwIfAborted(signal);
    updateStage(targetState, "verifying-attestation");
    let attestation;
    try {
      attestation = await verifyAttestation(
        sessionResponse.attestation_document,
        { nonce: clientNonce }
      );
      throwIfAborted(signal);
      validateAttestationResult(
        attestation,
        keyExchange,
        sessionResponse.session_id,
        transcriptHash,
        material.binder
      );
    } catch (cause) {
      if (cause?.code === "ABORTED") throw cause;
      throw sdkError(
        "ATTESTATION_INVALID",
        "attestation",
        publicError(cause),
        cause
      );
    }
    const pinnedTrust = sessionConfig.pcrPolicy?.mode === "pinned" ? verifyPinnedPcrPolicy(sessionConfig.pcrPolicy, attestation.pcrs) : null;
    updateStage(targetState, "confirming-session");
    const confirmationCiphertext = await seal(
      material,
      Direction.CLIENT_TO_SERVER,
      MessageType.CONFIRMATION,
      sessionResponse.session_id,
      0n,
      transcriptHash
    );
    throwIfAborted(signal);
    const confirmationResponse = await protocolFetch(
      CONFIRM_ENDPOINT,
      encodeEnvelope(sessionResponse.session_id, 0n, confirmationCiphertext),
      signal,
      sessionConfig.enclaveOrigin
    );
    if (!confirmationResponse.ok) {
      throw new ProtocolHttpError(
        confirmationResponse.status,
        "confirmation",
        "session confirmation"
      );
    }
    const confirmationEnvelope = decodeEnvelope(
      await readBoundedResponse(confirmationResponse, MAX_CONFIRMATION_RESPONSE_BYTES)
    );
    throwIfAborted(signal);
    if (confirmationEnvelope.sequenceValue !== 0n || !equalBytes(confirmationEnvelope.session_id, sessionResponse.session_id)) {
      throw sdkError(
        "CONFIRMATION_INVALID",
        "confirmation",
        "unexpected confirmation response"
      );
    }
    const confirmedHash = await open(
      material,
      Direction.SERVER_TO_CLIENT,
      MessageType.CONFIRMATION,
      sessionResponse.session_id,
      0n,
      confirmationEnvelope.ciphertext
    );
    throwIfAborted(signal);
    if (!equalBytes(confirmedHash, transcriptHash)) {
      throw sdkError(
        "CONFIRMATION_INVALID",
        "confirmation",
        "session confirmation mismatch"
      );
    }
    const pcrTrust = await finalizePcrTrust(
      sessionConfig,
      sessionGeneration,
      targetState,
      attestation.pcrs,
      pinnedTrust,
      signal
    );
    const session = {
      id: sessionResponse.session_id,
      keyExchange,
      material,
      sequences: new SequenceTracker(),
      createdAt: Date.now(),
      enclaveOrigin: sessionConfig.enclaveOrigin,
      configGeneration: sessionGeneration,
      transcriptHash,
      confirmation: "verified",
      attestation: {
        verified: true,
        profile: ATTESTATION_PROFILE.id,
        trustAnchor: ATTESTATION_PROFILE.trustAnchor,
        synthetic: ATTESTATION_PROFILE.synthetic,
        pcrs: attestation.pcrs,
        pcrTrust,
        moduleId: attestation.moduleId,
        checks: {
          certificateChain: "verified",
          nonceBinding: "verified",
          sessionBinding: "verified",
          keyConfirmation: "verified",
          expectedPcrPolicy: pcrTrust === "not-checked" ? "not-checked" : "verified"
        }
      }
    };
    return session;
  } finally {
    clientKeyExchange.destroy();
  }
}
async function finalizePcrTrust(sessionConfig, sessionGeneration, targetState, observedPcrs, pinnedTrust, signal) {
  return serializeConfiguration(async () => {
    throwIfAborted(signal);
    if (config !== sessionConfig || configGeneration !== sessionGeneration || state !== targetState) {
      throw new Error("configuration changed during session establishment");
    }
    if (!sessionConfig.pcrPolicy) return "not-checked";
    if (pinnedTrust) return pinnedTrust;
    const status = await enforceTofuPcrPolicy(
      sessionConfig.pcrPolicy,
      observedPcrs,
      {
        scope: serviceWorkerScope(),
        enclaveOrigin: sessionConfig.enclaveOrigin,
        suite: sessionConfig.expectedKeyExchange
      },
      pcrStorage
    );
    throwIfAborted(signal);
    return status;
  });
}
function clonePcrPolicy() {
  return config.pcrPolicy === null ? null : JSON.parse(JSON.stringify(config.pcrPolicy));
}
async function protocolFetch(path, body, signal, enclaveOrigin = config.enclaveOrigin) {
  const stage = path === REQUEST_ENDPOINT ? "request" : path === CONFIRM_ENDPOINT ? "confirmation" : "initialization";
  try {
    return await fetch(resolveProtocolUrl(path, enclaveOrigin), {
      method: "POST",
      headers: { "Content-Type": "application/cbor" },
      body,
      credentials: "omit",
      redirect: "error",
      signal
    });
  } catch (error) {
    if (signal?.aborted) throw new ProtocolAbortError(void 0, stage);
    throw new ProtocolTransportError(error, stage);
  }
}
function requireConfiguration() {
  if (!configurationReady || configRestoreError) {
    throw sdkError(
      "CONFIGURATION_UNAVAILABLE",
      "configuration",
      configRestoreError || "service worker configuration unavailable"
    );
  }
}
function configurationFailureResponse() {
  return new Response(JSON.stringify({ error: "secure channel unavailable" }), {
    status: 503,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
  });
}
async function readBoundedResponse(response, limit) {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null && /^[0-9]+$/u.test(declaredLength)) {
    const length = Number(declaredLength);
    if (!Number.isSafeInteger(length) || length > limit) {
      throw new Error("protocol response too large");
    }
  }
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value.byteLength > limit - total) {
        await reader.cancel().catch(() => {
        });
        throw new Error("protocol response too large");
      }
      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}
var ProtocolTimeoutError = class extends Error {
  constructor(message = "v2 operation timed out", stage = "request") {
    super(message);
    this.name = "ProtocolTimeoutError";
    this.code = "TIMEOUT";
    this.stage = stage;
  }
};
var ProtocolAbortError = class extends Error {
  constructor(message = "v2 request aborted", stage = "request") {
    super(message);
    this.name = "ProtocolAbortError";
    this.code = "ABORTED";
    this.stage = stage;
  }
};
var ProtocolTransportError = class extends Error {
  constructor(cause, stage = "transport") {
    super("v2 transport failed");
    this.name = "ProtocolTransportError";
    this.code = "TRANSPORT";
    this.stage = stage;
    this.cause = cause;
  }
};
var ProtocolHttpError = class extends Error {
  constructor(status, stage, operation = stage) {
    super(`${operation} rejected (${status})`);
    this.name = "ProtocolHttpError";
    this.code = "HTTP_STATUS";
    this.stage = stage;
    this.status = status;
    this.httpStatus = status;
  }
};
async function withDeadline(timeoutMs, externalSignal, operation, timeoutMessage, stage = "request") {
  const controller = new AbortController();
  let timedOut = false;
  let forwardAbort;
  const abortPromise = new Promise((_, reject) => {
    controller.signal.addEventListener("abort", () => {
      reject(timedOut ? new ProtocolTimeoutError(timeoutMessage, stage) : new ProtocolAbortError(void 0, stage));
    }, { once: true });
  });
  if (externalSignal) {
    forwardAbort = () => controller.abort(externalSignal.reason);
    if (externalSignal.aborted) {
      forwardAbort();
    } else {
      externalSignal.addEventListener("abort", forwardAbort, { once: true });
    }
  }
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  try {
    return await Promise.race([
      Promise.resolve().then(() => operation(controller.signal)),
      abortPromise
    ]);
  } finally {
    clearTimeout(timer);
    if (externalSignal && forwardAbort) {
      externalSignal.removeEventListener("abort", forwardAbort);
    }
  }
}
function throwIfAborted(signal) {
  if (signal.aborted) throw new ProtocolAbortError();
}
function isRequestLocalFailure(error) {
  if (error instanceof ProtocolTimeoutError || error instanceof ProtocolAbortError || error instanceof ProtocolTransportError) {
    return true;
  }
  if (!(error instanceof ProtocolHttpError)) return false;
  if (SESSION_FATAL_HTTP_STATUSES.has(error.status)) return false;
  return REQUEST_LOCAL_HTTP_STATUSES.has(error.status) || error.status >= 500 && error.status <= 599;
}
function resolveProtocolUrl(path, enclaveOrigin = config.enclaveOrigin) {
  return new URL(path, `${enclaveOrigin}/`).href;
}
function validateApplicationResponse(response) {
  if (!response || !Number.isInteger(response.status) || response.status < 200 || response.status > 599) {
    throw new Error("invalid protected application response");
  }
  if (!Array.isArray(response.headers) || response.headers.some((header) => !Array.isArray(header) || header.length !== 2 || typeof header[0] !== "string" || typeof header[1] !== "string")) {
    throw new Error("invalid protected application headers");
  }
  if (response.body !== null && response.body !== void 0 && !(response.body instanceof Uint8Array)) {
    throw new Error("invalid protected application body");
  }
}
function shouldProtectRequest(request, activeConfig = config) {
  const url = new URL(request.url);
  if (url.origin !== activeConfig.enclaveOrigin) return false;
  return !isPassthrough(request, url, activeConfig);
}
function isPassthrough(request, url, activeConfig = config) {
  const fixedBootstrap = fixedBootstrapDisposition(request, url);
  if (fixedBootstrap !== null) return fixedBootstrap;
  const localOrigin = url.origin === self.location.origin;
  const configuredPassthrough = activeConfig.passthroughPaths.includes(url.pathname);
  const localBootstrap = localOrigin && configuredPassthrough;
  return localBootstrap && SAFE_BOOTSTRAP_METHODS.has(request.method) || activeConfig.excludePrefixes.some((prefix) => url.pathname.startsWith(prefix));
}
function fixedBootstrapDisposition(request, url) {
  const localOrigin = url.origin === self.location.origin;
  const registrationScope = new URL(self.registration.scope);
  const bootstrapNavigation = localOrigin && (url.pathname === "/" || url.pathname === registrationScope.pathname) && request.method === "GET" && request.mode === "navigate" && request.destination === "document";
  if (bootstrapNavigation) return true;
  const bootstrapNavigationTarget = localOrigin && (url.pathname === "/" || url.pathname === registrationScope.pathname) && request.mode === "navigate" && request.destination === "document";
  if (bootstrapNavigationTarget) return false;
  const builtInBootstrap = localOrigin && (DEFAULT_BOOTSTRAP_PATHS.includes(url.pathname) || SCOPED_BOOTSTRAP_PATHS.some(
    (path) => new URL(path, registrationScope).pathname === url.pathname
  ));
  if (builtInBootstrap) return SAFE_BOOTSTRAP_METHODS.has(request.method);
  return null;
}
function configure(update) {
  const allowed = [
    "enclaveOrigin",
    "passthroughPaths",
    "excludePrefixes",
    "emitEncryptedPayloads",
    "requestTimeoutMs",
    "expectedKeyExchange",
    "pcrPolicy"
  ];
  for (const key of Object.keys(update)) {
    if (!allowed.includes(key)) throw new Error(`unsupported configuration key: ${key}`);
  }
  if ("passthroughPaths" in update) validatePathList(update.passthroughPaths);
  if ("excludePrefixes" in update) validatePathList(update.excludePrefixes);
  if ("requestTimeoutMs" in update) validateRequestTimeout(update.requestTimeoutMs);
  if ("expectedKeyExchange" in update) {
    requireKeyExchange(update.expectedKeyExchange);
  }
  let nextPolicy = config.pcrPolicy;
  if ("pcrPolicy" in update) {
    try {
      nextPolicy = normalizePcrPolicy(update.pcrPolicy);
    } catch (cause) {
      throw sdkError("PCR_POLICY_INVALID", "configuration", publicError(cause), cause);
    }
  }
  const next = { ...config, ...update, pcrPolicy: nextPolicy };
  if ("enclaveOrigin" in update) {
    next.enclaveOrigin = normalizeEnclaveOrigin(update.enclaveOrigin);
  }
  next.passthroughPaths = [
    .../* @__PURE__ */ new Set([...DEFAULT_BOOTSTRAP_PATHS, ...next.passthroughPaths])
  ];
  next.excludePrefixes = [
    .../* @__PURE__ */ new Set([...PROTOCOL_EXCLUDE_PREFIXES, ...next.excludePrefixes])
  ];
  const enclaveChanged = next.enclaveOrigin !== config.enclaveOrigin;
  const keyExchangeChanged = next.expectedKeyExchange !== config.expectedKeyExchange;
  const pcrPolicyChanged = !pcrPoliciesEqual(next.pcrPolicy, config.pcrPolicy);
  if (enclaveChanged || keyExchangeChanged || pcrPolicyChanged) {
    configGeneration += 1;
    resetState();
  }
  config = next;
}
async function initializeConfig() {
  configurationReady = false;
  try {
    await restoreConfig();
    configRestoreError = null;
  } catch (error) {
    configRestoreError = publicError(error);
  }
}
async function configureAndPersist(update) {
  return serializeConfiguration(() => configureAndPersistNow(update));
}
async function configureAndPersistNow(update) {
  const previous = config;
  let policyRequired;
  try {
    policyRequired = await pcrStorage.isPolicyRequired(serviceWorkerScope());
  } catch (error) {
    blockConfiguration(previous, error);
    throw error;
  }
  if (policyRequired && !previous.pcrPolicy && !("pcrPolicy" in update)) {
    const error = new Error("persisted PCR policy configuration is missing");
    blockConfiguration(previous, error);
    throw error;
  }
  configure(update);
  try {
    if (!policyRequired && config.pcrPolicy) {
      await pcrStorage.setPolicyRequired(serviceWorkerScope(), true);
    }
    await persistConfig();
    if (policyRequired && !config.pcrPolicy) {
      await pcrStorage.setPolicyRequired(serviceWorkerScope(), false);
    }
    configurationReady = true;
    configRestoreError = null;
  } catch (error) {
    blockConfiguration(previous, error);
    throw error;
  }
}
function blockConfiguration(previous, error) {
  config = previous;
  configurationReady = false;
  configRestoreError = publicError(error);
  resetState(configRestoreError);
}
function serializeConfiguration(operation) {
  const result = configurationTail.then(operation);
  configurationTail = result.catch(() => {
  });
  return result;
}
function configCacheKey() {
  if (typeof self.registration?.scope !== "string") {
    throw new Error("service worker scope unavailable");
  }
  return new URL(CONFIG_CACHE_PATH, self.registration.scope).href;
}
async function restoreConfig() {
  const policyRequired = await pcrStorage.isPolicyRequired(serviceWorkerScope());
  if (!self.caches) throw new Error("configuration storage unavailable");
  const cache = await self.caches.open(CONFIG_CACHE_NAME);
  const response = await cache.match(configCacheKey());
  if (!response) {
    if (policyRequired) throw new Error("persisted PCR policy configuration is missing");
    return;
  }
  configure(await response.json());
  if (policyRequired && !config.pcrPolicy) {
    throw new Error("persisted PCR policy configuration is missing");
  }
  if (config.pcrPolicy && !policyRequired) {
    await pcrStorage.setPolicyRequired(serviceWorkerScope(), true);
  }
  configurationReady = true;
}
async function persistConfig() {
  if (!self.caches) throw new Error("configuration storage unavailable");
  const cache = await self.caches.open(CONFIG_CACHE_NAME);
  await cache.put(
    configCacheKey(),
    new Response(JSON.stringify(config), {
      headers: { "Content-Type": "application/json" }
    })
  );
}
function serviceWorkerScope() {
  if (typeof self.registration?.scope !== "string") {
    throw new Error("service worker scope unavailable");
  }
  return new URL(self.registration.scope).href;
}
function normalizeEnclaveOrigin(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("enclaveOrigin must be an absolute HTTP(S) origin");
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error("enclaveOrigin must be an absolute HTTP(S) origin");
  }
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
    throw new Error("enclaveOrigin must be an absolute HTTP(S) origin");
  }
  return url.origin;
}
function validateRequestTimeout(value) {
  if (!Number.isInteger(value) || value < MIN_REQUEST_TIMEOUT_MS || value > MAX_REQUEST_TIMEOUT_MS) {
    throw new Error(
      `requestTimeoutMs must be an integer between ${MIN_REQUEST_TIMEOUT_MS} and ${MAX_REQUEST_TIMEOUT_MS}`
    );
  }
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
  const session = state.session;
  return {
    type: "status",
    state: lifecycleState(),
    stage: state.stage,
    initialized: Boolean(session),
    error: state.error || configRestoreError,
    protocol: {
      id: PROTOCOL_ID,
      version: VERSION,
      keyEstablishment: session?.keyExchange || config.expectedKeyExchange,
      keyDerivation: KEY_DERIVATION,
      recordProtection: RECORD_PROTECTION
    },
    session: session ? {
      id: encodeDiagnosticBytes(session.id),
      transcriptHash: encodeDiagnosticBytes(session.transcriptHash),
      establishedAt: session.createdAt,
      rotatesAt: session.createdAt + ROTATION_INTERVAL_MS,
      trigger: session.trigger || null,
      confirmation: session.confirmation || "verified"
    } : null,
    attestationVerifier: ATTESTATION_PROFILE,
    attestation: session?.attestation || null,
    lastKeyRotation: session?.createdAt || null,
    protocolVersion: VERSION
  };
}
function encodeDiagnosticBytes(value) {
  return value instanceof Uint8Array ? encodeBase64Url(value) : null;
}
function encryptedPayloadTrace(session, sequence, envelope) {
  return {
    endpoint: REQUEST_ENDPOINT,
    sessionId: encodeDiagnosticBytes(session.id),
    sequence: sequence.toString(),
    size: envelope.length,
    envelope: encodeBase64Url(envelope)
  };
}
function lifecycleState() {
  if (state.rotationPromise) return "rotating";
  if (state.session) return "ready";
  if (state.sessionPromise) return "establishing";
  if (state.error || configRestoreError) return "error";
  return "idle";
}
function hasValidSession(session) {
  return Boolean(session) && Date.now() - session.createdAt < ROTATION_INTERVAL_MS;
}
function freshState(error = null) {
  return {
    session: null,
    sessionPromise: null,
    rotationPromise: null,
    error,
    stage: null,
    trigger: null
  };
}
function resetState(error = null) {
  state.session?.sequences?.close(new Error(error || "secure channel reset"));
  state = freshState(error);
  notifyStatus();
}
function publicError(error) {
  return error instanceof Error ? error.message : "secure channel error";
}
function sdkError(code, stage, message, cause, httpStatus) {
  const error = new Error(message);
  error.code = code;
  error.stage = stage;
  if (cause !== void 0) error.cause = cause;
  if (httpStatus !== void 0) error.httpStatus = httpStatus;
  return error;
}
function errorDetails(error, fallbackStage = "internal") {
  const stage = typeof error?.stage === "string" ? error.stage : fallbackStage;
  const details = {
    code: typeof error?.code === "string" ? error.code : `${stage.replaceAll("-", "_").toUpperCase()}_FAILED`,
    stage,
    message: publicError(error)
  };
  const httpStatus = error?.httpStatus ?? error?.status;
  if (Number.isInteger(httpStatus)) details.httpStatus = httpStatus;
  return details;
}
function commandStage(type) {
  switch (type) {
    case "configure":
    case "get-pcr-policy":
    case "replace-pcr-policy":
      return "configuration";
    case "rotate-key":
    case "rotate-session":
      return "rotation";
    case "protected-send":
      return "request";
    case "initialize":
      return "initialization";
    default:
      return "service-worker";
  }
}
async function notifyClients(type, data) {
  const allClients = await self.clients.matchAll({ type: "window" });
  for (const client of allClients) client.postMessage({ ...data, type: `enclave:${type}` });
}
function notifyStatus() {
  void notifyClients("status", statusMessage());
}
function updateStage(targetState, stage) {
  if (state !== targetState) return;
  targetState.stage = stage;
  notifyStatus();
}
