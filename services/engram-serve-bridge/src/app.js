import http from 'node:http';

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
 * Byte-level reverse proxy to 127.0.0.1:<port> — no protocol awareness,
 * just streams the request/response through without buffering either side.
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
 * @param {() => number} getBackendPort
 * @returns {(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => void}
 */
export function createApp(getBackendPort) {
  return function requestListener(req, res) {
    proxyTo(req, res, getBackendPort());
  };
}

/**
 * @param {() => number} getBackendPort
 * @returns {import('node:http').Server}
 */
export function createServer(getBackendPort) {
  return http.createServer(createApp(getBackendPort));
}
