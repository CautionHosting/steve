import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { createServer } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const directory = path.dirname(fileURLToPath(import.meta.url));
const distDirectory = path.resolve(directory, '../../dist');
const host = '127.0.0.1';
const port = 3000;
const page = Buffer.from(`<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>STEVE Nitro E2E</title></head>
  <body>STEVE Nitro E2E</body>
</html>
`);

function respond(response, status, body, contentType = 'text/plain; charset=utf-8') {
  response.writeHead(status, {
    'Content-Type': contentType,
    'Content-Length': body.length,
    'Cache-Control': 'no-store'
  });
  response.end(body);
}

const server = createServer(async (request, response) => {
  const url = new URL(request.url, `http://${host}:${port}`);

  if (url.pathname === '/__steve_nitro_e2e_health') {
    respond(response, 200, Buffer.from('ok'));
    return;
  }
  if (url.pathname === '/' || url.pathname === '/index.html') {
    respond(response, 200, page, 'text/html; charset=utf-8');
    return;
  }

  const file = path.resolve(distDirectory, `.${url.pathname}`);
  if (!file.startsWith(`${distDirectory}${path.sep}`)) {
    respond(response, 404, Buffer.from('not found'));
    return;
  }

  try {
    const info = await stat(file);
    if (!info.isFile()) throw new Error('not a file');
    const contentTypes = {
      '.js': 'text/javascript; charset=utf-8',
      '.wasm': 'application/wasm'
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
    respond(response, 404, Buffer.from('not found'));
  }
});

server.listen(port, host);
