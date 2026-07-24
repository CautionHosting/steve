import { createReadStream } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import { createServer } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const directory = path.dirname(fileURLToPath(import.meta.url));
const publicDirectory = path.join(directory, 'public');

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on('data', chunk => chunks.push(chunk));
    request.on('end', () => resolve(Buffer.concat(chunks)));
    request.on('error', reject);
  });
}

function respond(response, status, body, contentType = 'text/plain; charset=utf-8') {
  response.writeHead(status, {
    'Content-Type': contentType,
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store'
  });
  response.end(body);
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
  if (url.pathname === '/health') {
    respond(response, 200, 'ok');
    return;
  }
  if (url.pathname === '/unauthorized') {
    respond(response, 401, 'application unauthorized');
    return;
  }
  if (url.pathname === '/delay') {
    const delay = Math.min(Number(url.searchParams.get('ms')) || 0, 10_000);
    await new Promise(resolve => setTimeout(resolve, delay));
    respond(response, 200, `delayed:${delay}`);
    return;
  }
  if (url.pathname === '/echo') {
    const body = await readBody(request);
    respond(response, 200, body, request.headers['content-type'] || 'application/octet-stream');
    return;
  }
  respond(response, 404, 'not found');
});

const web = createServer(async (request, response) => {
  logRequest('web', request, response);
  const url = new URL(request.url, 'http://127.0.0.1:3000');
  const relative = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
  const file = path.resolve(publicDirectory, relative);
  if (!file.startsWith(`${publicDirectory}${path.sep}`) && file !== publicDirectory) {
    respond(response, 404, 'not found');
    return;
  }

  try {
    const info = await stat(file);
    if (!info.isFile()) throw new Error('not a file');
    const contentTypes = {
      '.html': 'text/html; charset=utf-8',
      '.js': 'text/javascript; charset=utf-8'
    };
    response.writeHead(200, {
      'Content-Type': contentTypes[path.extname(file)] || 'application/octet-stream',
      'Content-Length': info.size,
      'Cache-Control': 'no-store',
      ...(url.pathname === '/enclave-sw.js'
        ? { 'Service-Worker-Allowed': '/' }
        : {})
    });
    createReadStream(file).pipe(response);
  } catch {
    respond(response, 404, 'not found');
  }
});

upstream.listen(8083, '0.0.0.0', () => {
  console.log('fixture upstream listening on 8083');
});
web.listen(3000, '0.0.0.0', () => {
  console.log('fixture web UI listening on 3000');
});
