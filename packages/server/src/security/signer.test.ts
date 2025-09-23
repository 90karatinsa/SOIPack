import { readFileSync } from 'node:fs';
import path from 'node:path';

import { Manifest } from '@soipack/core';

import { signManifestBundle, verifyManifestSignatureDetailed } from './signer';

const DEV_CERT_BUNDLE_PATH = path.resolve(__dirname, '../../../../test/certs/dev.pem');

describe('server security signer re-export', () => {
  it('re-exports signing helpers from report package', () => {
    const manifest: Manifest = {
      files: [{ path: 'reports/index.html', sha256: 'f0'.repeat(32) }],
      createdAt: '2024-01-01T00:00:00.000Z',
      toolVersion: 'server-test',
    };

    const bundlePem = readFileSync(DEV_CERT_BUNDLE_PATH, 'utf8');
    const signature = signManifestBundle(manifest, { bundlePem }).signature;
    const verification = verifyManifestSignatureDetailed(manifest, signature);

    expect(verification.valid).toBe(true);
  });
});
