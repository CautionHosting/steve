import { createReadStream } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import { createServer } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

const directory = path.dirname(fileURLToPath(import.meta.url));
const publicDirectory = path.join(directory, 'public');
const generatedDirectory = path.join(publicDirectory, 'generated');
const keyExchange = process.env.STEVE_KEY_EXCHANGE || 'X25519';
const uiOnly = process.env.STEVE_E2E_UI_ONLY === '1';
const supportedKeyExchanges = new Set(['X25519', 'XWING-DRAFT10']);
const profiles = new Set(['local', 'nitro']);
const maxEchoBytes = 1024 * 1024;
const maxDelayMs = 10_000;
const fixtureContract = Object.freeze({
  contract: 'steve-test-fixture/v1',
  capabilities: ['echo', 'unauthorized', 'delay', 'compressed'],
  max_echo_bytes: maxEchoBytes,
  max_delay_ms: maxDelayMs
});

if (!supportedKeyExchanges.has(keyExchange)) {
  throw new Error('STEVE_KEY_EXCHANGE must be exactly X25519 or XWING-DRAFT10');
}
if (!['0', '1'].includes(process.env.STEVE_E2E_UI_ONLY || '0')) {
  throw new Error('STEVE_E2E_UI_ONLY must be exactly 0 or 1');
}

const indexTemplate = await readFile(path.join(publicDirectory, 'index.html'), 'utf8');
for (const placeholder of [
  '__STEVE_PROFILE__',
  '__STEVE_KEY_EXCHANGE__',
  '__STEVE_DEFAULT_ORIGIN__',
  '__STEVE_REQUEST_TIMEOUT_MS__'
]) {
  if (!indexTemplate.includes(placeholder)) {
    throw new Error(`STEVE E2E index is missing ${placeholder}`);
  }
}

function renderIndex(profile, requestHostname) {
  const localOrigin = `http://${requestHostname}:49500`;
  return indexTemplate
    .replaceAll('__STEVE_PROFILE__', profile)
    .replaceAll('__STEVE_KEY_EXCHANGE__', keyExchange)
    .replaceAll('__STEVE_DEFAULT_ORIGIN__', localOrigin)
    .replaceAll('__STEVE_REQUEST_TIMEOUT_MS__', profile === 'local' ? '1000' : '3000');
}

function readBody(request, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let exceeded = false;
    request.on('data', chunk => {
      if (exceeded) return;
      size += chunk.length;
      if (size > limit) {
        exceeded = true;
        reject(Object.assign(new Error('request body too large'), { code: 'BODY_TOO_LARGE' }));
        request.resume();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => {
      if (!exceeded) resolve(Buffer.concat(chunks));
    });
    request.on('error', reject);
  });
}

function respond(response, status, body, contentType = 'text/plain; charset=utf-8', headers = {}) {
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(body);
  response.writeHead(status, {
    'Content-Type': contentType,
    'Content-Length': payload.length,
    'Cache-Control': 'no-store',
    ...headers
  });
  response.end(payload);
}

function logRequest(service, request, response) {
  const started = performance.now();
  response.once('finish', () => {
    const duration = (performance.now() - started).toFixed(1);
    console.log(
      `[${service}] ${request.method} ${request.url} -> ${response.statusCode} ${duration}ms`
    );
  });
}

const upstream = createServer(async (request, response) => {
  logRequest('upstream', request, response);
  const url = new URL(request.url, 'http://fixture:8083');

  if (request.method === 'GET' && url.pathname === '/health') {
    respond(response, 200, 'ok\n');
    return;
  }
  if (
    request.method === 'GET'
    && (url.pathname === '/' || url.pathname === '/index.html')
  ) {
    respond(response, 200, 'steve nitro test app\n');
    return;
  }
  if (
    request.method === 'GET'
    && url.pathname === '/.well-known/steve-test-fixture'
  ) {
    respond(
      response,
      200,
      JSON.stringify(fixtureContract),
      'application/json; charset=utf-8'
    );
    return;
  }
  if (request.method === 'GET' && url.pathname === '/unauthorized') {
    respond(response, 401, 'application unauthorized\n');
    return;
  }
  if (request.method === 'GET' && url.pathname === '/delay') {
    const rawDelay = url.searchParams.get('ms');
    const delay = Number(rawDelay);
    if (
      rawDelay === null
      || rawDelay === ''
      || !Number.isInteger(delay)
      || delay < 0
      || delay > maxDelayMs
    ) {
      respond(response, 400, `ms must be an integer between 0 and ${maxDelayMs}\n`);
      return;
    }
    await new Promise(resolve => setTimeout(resolve, delay));
    respond(response, 200, `delayed:${delay}`);
    return;
  }
  if (request.method === 'POST' && url.pathname === '/echo') {
    try {
      const body = await readBody(request, maxEchoBytes);
      respond(
        response,
        200,
        body,
        request.headers['content-type'] || 'application/octet-stream'
      );
    } catch (error) {
      if (error.code === 'BODY_TOO_LARGE') {
        respond(response, 413, 'echo body exceeds 1048576 bytes\n');
        return;
      }
      throw error;
    }
    return;
  }
  if (request.method === 'GET' && url.pathname === '/compressed') {
    const acceptEncoding = request.headers['accept-encoding'] || 'missing';
    const identity = acceptEncoding === 'identity';
    const body = identity
      ? Buffer.from('identity-through-steve')
      : gzipSync(Buffer.from('compressed-through-steve'));
    respond(
      response,
      200,
      body,
      'text/plain; charset=utf-8',
      {
        ...(!identity && { 'Content-Encoding': 'gzip' }),
        'X-Upstream-Accept-Encoding': acceptEncoding
      }
    );
    return;
  }

  respond(response, 404, 'not found\n');
});

function safeFile(root, relative) {
  const file = path.resolve(root, relative);
  if (file !== root && !file.startsWith(`${root}${path.sep}`)) return null;
  return file;
}

async function serveFile(response, file, serviceWorkerScope) {
  try {
    const info = await stat(file);
    if (!info.isFile()) throw new Error('not a file');
    const contentTypes = {
      '.html': 'text/html; charset=utf-8',
      '.js': 'text/javascript; charset=utf-8',
      '.wasm': 'application/wasm'
    };
    response.writeHead(200, {
      'Content-Type': contentTypes[path.extname(file)] || 'application/octet-stream',
      'Content-Length': info.size,
      'Cache-Control': 'no-store',
      ...(serviceWorkerScope ? { 'Service-Worker-Allowed': serviceWorkerScope } : {})
    });
    createReadStream(file).pipe(response);
  } catch {
    respond(response, 404, 'not found\n');
  }
}

const web = createServer(async (request, response) => {
  logRequest('web', request, response);
  const url = new URL(request.url, 'http://127.0.0.1:3000');
  if (url.pathname === '/__steve_e2e_health') {
    respond(response, 200, 'ok\n');
    return;
  }
  if (url.pathname === '/') {
    response.writeHead(302, {
      Location: '/local/',
      'Cache-Control': 'no-store'
    });
    response.end();
    return;
  }

  const segments = url.pathname.split('/').filter(Boolean);
  const profile = segments.shift();
  if (!profiles.has(profile)) {
    respond(response, 404, 'not found\n');
    return;
  }
  const profileRoot = `/${profile}/`;
  const relative = segments.join('/');

  if (relative === '' || relative === 'index.html') {
    const hostname = request.headers.host?.split(':')[0] || '127.0.0.1';
    respond(
      response,
      200,
      renderIndex(profile, hostname),
      'text/html; charset=utf-8'
    );
    return;
  }
  if (relative === 'attestation-widget.js') {
    await serveFile(
      response,
      path.join(publicDirectory, 'attestation-widget.js')
    );
    return;
  }

  const file = safeFile(path.join(generatedDirectory, profile), relative);
  if (!file) {
    respond(response, 404, 'not found\n');
    return;
  }
  await serveFile(
    response,
    file,
    relative === 'enclave-sw.js' ? profileRoot : undefined
  );
});

if (!uiOnly) {
  upstream.listen(8083, '0.0.0.0', () => {
    console.log('fixture upstream listening on 8083');
  });
}
web.listen(3000, '0.0.0.0', () => {
  console.log(`fixture web UI listening on 3000 (${uiOnly ? 'UI only' : 'with upstream'})`);
});
