#!/usr/bin/env node
const fs = require('fs');
const https = require('https');
const { Agent: UndiciAgent, fetch: undiciFetch } = require('undici');

const DEFAULT_HEALTHCHECK_URL = 'https://localhost:3443/health';
const DEFAULT_CA_PATH = '/run/secrets/soipack-ca.crt';

async function verifyHealthcheck({
  url = DEFAULT_HEALTHCHECK_URL,
  token,
  caPath,
  requireCaExists = false
}) {
  if (!token) {
    throw new Error('SOIPACK_HEALTHCHECK_TOKEN must be set.');
  }

  const requestInit = {
    headers: { Authorization: `Bearer ${token}` }
  };

  let dispatcher;
  let httpsAgent;

  if (caPath) {
    if (!fs.existsSync(caPath)) {
      if (requireCaExists) {
        throw new Error(`CA bundle not found at ${caPath}`);
      }
    } else {
      const ca = fs.readFileSync(caPath);

      // Create explicit agents for both undici and legacy HTTPS clients.
      // Even though fetch uses undici internally, callers may re-use the
      // helper for custom integrations that rely on https.request.
      httpsAgent = new https.Agent({ ca });
      dispatcher = new UndiciAgent({ connect: { ca } });

      requestInit.dispatcher = dispatcher;
      requestInit.agent = httpsAgent;
    }
  }

  try {
    const response = await undiciFetch(url, requestInit);

    if (!response.ok) {
      throw new Error(`Healthcheck responded with status ${response.status}`);
    }

    return await response.json();
  } finally {
    if (dispatcher) {
      await dispatcher.close();
    }
    if (httpsAgent) {
      httpsAgent.destroy();
    }
  }
}

async function main() {
  const url = process.argv[2] ?? DEFAULT_HEALTHCHECK_URL;
  const token = process.env.SOIPACK_HEALTHCHECK_TOKEN;
  const envCaPathRaw = process.env.SOIPACK_HEALTHCHECK_CA_PATH;
  const envCaPath = envCaPathRaw && envCaPathRaw.trim() !== '' ? envCaPathRaw : undefined;
  const defaultCaPath = envCaPath
    ? undefined
    : fs.existsSync(DEFAULT_CA_PATH)
      ? DEFAULT_CA_PATH
      : undefined;
  const caPath = envCaPath ?? defaultCaPath;
  const requireCaExists = Boolean(envCaPath);

  try {
    const body = await verifyHealthcheck({ url, token, caPath, requireCaExists });
    console.log(JSON.stringify(body));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = { verifyHealthcheck };
