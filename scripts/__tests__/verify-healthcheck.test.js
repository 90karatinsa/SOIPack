const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const { Agent, getGlobalDispatcher, setGlobalDispatcher } = require('undici');
const { once } = require('events');
const { verifyHealthcheck } = require('../verify-healthcheck');

const KEY_PATH = path.join(__dirname, '../../test/certs/localhost-key.pem');
const CERT_PATH = path.join(__dirname, '../../test/certs/localhost-cert.pem');

async function startHealthcheckServer({ key, cert, expectedToken }) {
  const server = https.createServer({ key, cert }, (req, res) => {
    const header = req.headers.authorization;

    if (header !== `Bearer ${expectedToken}`) {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ status: 'unauthorized' }));
      return;
    }

    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
  });

  server.listen(0, '127.0.0.1');
  await once(server, 'listening');

  const address = server.address();
  const url = `https://127.0.0.1:${address.port}/health`;

  return {
    url,
    close: () => new Promise((resolve) => server.close(resolve))
  };
}

describe('verifyHealthcheck', () => {
  const token = 'test-token';
  const key = fs.readFileSync(KEY_PATH, 'utf8');
  const cert = fs.readFileSync(CERT_PATH, 'utf8');

  test('trusts a provided CA bundle for self-signed certificates', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-healthcheck-'));
    const caPath = path.join(tempDir, 'ca.pem');
    fs.writeFileSync(caPath, cert);

    const server = await startHealthcheckServer({ key, cert, expectedToken: token });

    try {
      const body = await verifyHealthcheck({ url: server.url, token, caPath, requireCaExists: true });
      expect(body).toEqual({ status: 'ok' });
    } finally {
      await server.close();
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  test('throws when an explicit CA path is configured but missing', async () => {
    const missingPath = path.join(os.tmpdir(), `verify-healthcheck-missing-${Date.now()}.pem`);

    await expect(
      verifyHealthcheck({ url: 'https://localhost:1234/health', token, caPath: missingPath, requireCaExists: true })
    ).rejects.toThrow(`CA bundle not found at ${missingPath}`);
  });

  test('falls back to the default dispatcher when no CA bundle is supplied', async () => {
    const server = await startHealthcheckServer({ key, cert, expectedToken: token });
    const originalDispatcher = getGlobalDispatcher();
    const trustedDispatcher = new Agent({ connect: { ca: cert } });
    setGlobalDispatcher(trustedDispatcher);

    try {
      const body = await verifyHealthcheck({ url: server.url, token });
      expect(body).toEqual({ status: 'ok' });
    } finally {
      await server.close();
      setGlobalDispatcher(originalDispatcher);
      await trustedDispatcher.close();
    }
  });
});
