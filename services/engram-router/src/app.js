import http from 'node:http';
import { deriveProject } from './identity.js';

/**
 * @param {import('node:http').ServerResponse} res
 * @param {number} status
 * @param {unknown} body
 */
function sendJson(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(json);
}

/**
 * Byte-level reverse proxy to 127.0.0.1:<port> — no MCP/JSON-RPC awareness,
 * just streams the request/response through without buffering either side,
 * so Streamable HTTP's chunked/SSE bodies pass through untouched.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {number} port
 */
function proxyTo(req, res, port) {
  const proxyReq = http.request(
    { host: '127.0.0.1', port, path: req.url, method: req.method, headers: req.headers },
    (proxyRes) => {
      res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
      proxyRes.pipe(res);
    },
  );
  proxyReq.on('error', () => {
    if (!res.headersSent) {
      sendJson(res, 502, { error: 'bad_gateway' });
    } else {
      res.end();
    }
  });
  req.pipe(proxyReq);
}

/**
 * @param {{ getOrCreateChild: (identity: string) => Promise<{ port: number }> }} processManager
 * @returns {(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => void}
 */
export function createApp(processManager) {
  return function requestListener(req, res) {
    const project = deriveProject(req.headers);
    if (project === null) {
      sendJson(res, 401, { error: 'unauthenticated' });
      return;
    }

    processManager.getOrCreateChild(project).then(
      ({ port }) => proxyTo(req, res, port),
      (err) => sendJson(res, 503, { error: 'capacity', message: err.message }),
    );
  };
}

/**
 * @param {{ getOrCreateChild: (identity: string) => Promise<{ port: number }> }} processManager
 * @returns {import('node:http').Server}
 */
export function createServer(processManager) {
  return http.createServer(createApp(processManager));
}
