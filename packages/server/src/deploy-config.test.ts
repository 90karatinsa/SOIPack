import { readFileSync } from 'fs';
import { resolve } from 'path';

import { parse } from 'yaml';

describe('docker-compose deployment configuration', () => {
  it('defines required secrets and health check configuration', () => {
    const composePath = resolve(__dirname, '../../../docker-compose.yaml');
    const file = readFileSync(composePath, 'utf8');
    const compose = parse(file) as {
      services: Record<string, { environment?: Record<string, string>; volumes?: string[] }>;
    };

    const server = compose.services?.server;
    expect(server).toBeDefined();

    expect(server?.environment).toMatchObject({
      SOIPACK_SIGNING_KEY_PATH: '/run/secrets/soipack-signing.pem',
      SOIPACK_LICENSE_PUBLIC_KEY_PATH: '/run/secrets/soipack-license.pub',
      SOIPACK_HEALTHCHECK_TOKEN:
        '${SOIPACK_HEALTHCHECK_TOKEN:?SOIPACK_HEALTHCHECK_TOKEN tanımlanmalıdır}',
    });

    expect(server?.volumes).toEqual(
      expect.arrayContaining(['./secrets:/run/secrets:ro'])
    );
  });
});
