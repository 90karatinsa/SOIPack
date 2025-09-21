#!/usr/bin/env node
const fs = require('fs');

const url = process.argv[2] ?? 'https://localhost:3443/health';
const token = process.env.SOIPACK_HEALTHCHECK_TOKEN;
const caPath = process.env.SOIPACK_HEALTHCHECK_CA_PATH || '/run/secrets/soipack-ca.crt';

if (!token) {
  console.error('SOIPACK_HEALTHCHECK_TOKEN must be set.');
  process.exit(1);
}

if (!fs.existsSync(caPath)) {
  console.error(`CA bundle not found at ${caPath}`);
  process.exit(1);
}

process.env.NODE_EXTRA_CA_CERTS = caPath;

fetch(url, {
  headers: { Authorization: `Bearer ${token}` },
})
  .then((res) => {
    if (!res.ok) {
      throw new Error(`Healthcheck responded with status ${res.status}`);
    }
    return res.json();
  })
  .then((body) => {
    console.log(JSON.stringify(body));
  })
  .catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
