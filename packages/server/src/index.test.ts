import { createHash } from 'crypto';
import fs, { promises as fsPromises } from 'fs';
import https from 'https';
import type { AddressInfo } from 'net';
import os from 'os';
import path from 'path';
import { Writable } from 'stream';
import tls from 'tls';

import * as cli from '@soipack/cli';
import { Manifest, createSnapshotVersion } from '@soipack/core';
import { verifyManifestSignature } from '@soipack/packager';
import { generateKeyPair, SignJWT, exportJWK, type JWK, type JSONWebKeySet, type KeyLike } from 'jose';
import pino from 'pino';
import { Registry } from 'prom-client';
import request from 'supertest';
import { Agent, setGlobalDispatcher } from 'undici';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';


import type { FileScanner } from './scanner';

import { createHttpsServer, createServer, getServerLifecycle, type ServerConfig } from './index';

const DEV_CERT_BUNDLE_PATH = path.resolve(__dirname, '../../../test/certs/dev.pem');
const TEST_SIGNING_BUNDLE = fs.readFileSync(DEV_CERT_BUNDLE_PATH, 'utf8');
const CERTIFICATE_PATTERN = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/;
const TEST_SIGNING_CERTIFICATE = (() => {
  const match = TEST_SIGNING_BUNDLE.match(CERTIFICATE_PATTERN);
  if (!match) {
    throw new Error('Test sertifika demeti bulunamadı.');
  }
  return match[0];
})();

const LICENSE_PUBLIC_KEY_BASE64 = 'mXRQccwM4wyv+mmIQZjJWAqDDvD6wYn+c/DpB1w/x20=';

const buildSnapshotVersion = (fingerprint = 'cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe') =>
  createSnapshotVersion(fingerprint, { createdAt: '2024-06-19T12:34:56Z' });

const TEST_CA_CERT = `-----BEGIN CERTIFICATE-----
MIIDFTCCAf2gAwIBAgIUOrBbV6ZFBaLvne/UffpWm90JGXEwDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPU09JUGFjayBUZXN0IENBMB4XDTI1MDkyMTA5NTQ1N1oX
DTI2MDkyMTA5NTQ1N1owGjEYMBYGA1UEAwwPU09JUGFjayBUZXN0IENBMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwfgu4Ppytc9XVj9WLxJDzHeudFEv
JbIAI7kX0KheeDY2vZd8F1E4cwtc3sh9FDp4zOqS3Fz9T25cwsKeX7L7quazuIX0
UgXzM2BsWb94DOxgF9ZVSoLGPhHH2t5BuP5/xabnOEuNyT/IqSdVkZpjjVtLQRae
0hwDwhJZsbDUQGOM2yJBUEyyDUjouP5mUT5jHrdtLwioIGnp4IuH32O1EzrJ6nAG
kevZFi5uLLvw02nULm53trFSFy8xgXTGxtMZppbXWaWFH16ihbEBMWW9U7BAAdjw
El9jQTGF+88ist9vQ6AP70zyxGV4I9kcGGlJZSoy275ld6XZnN9zaUY9DQIDAQAB
o1MwUTAdBgNVHQ4EFgQUK/DFywnrjojGChaU81wZLdxFc30wHwYDVR0jBBgwFoAU
K/DFywnrjojGChaU81wZLdxFc30wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAR5Ur5Mddvckl8Ivh20qq8c/KcgJb9Lo2Thm9ShatsWa3Ra4/Lyhp
16XhrSoWzJZlsv1TcHE9gG07r5Jib93V/zJR3mt56k8uTstoeoIdTBC3en2Slpjl
/N+8vnRbe5EkpOKYlQdMTYskXQCmqH5za8xQw5v/6yUZ0GKy8N43cDF7PPF0sjgn
tBgOLs61YTU6Za6f+g2G+XlNnZzhjkqaLhcimSLzf/DCrquglvBjiWFdx0brVATi
sl10a+f47mqanJk0JQF2VHgOQEUXnCh9YrwmJqUOsJl1Txt7gs60ZqN9ryWczPyF
U+Nd/6z3RWIXJCA/Ue+xRDowhgI4yFISoA==
-----END CERTIFICATE-----`;

setGlobalDispatcher(
  new Agent({
    connect: {
      ca: TEST_CA_CERT,
    },
  }),
);

const TEST_SERVER_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDsphbJCknHw4kG
hOkj030GF8bjJ37bESelmyJIXX2G9GeipNPoDuqJYKxIuKyEphDWrHzm4S3sZRmg
KyDdY5dhVOd+w6rCw1FmcLOfoqaKAEE4GgXAuaZaKtUtynuePb7s81nRSRA82qnm
a2zZH3sBVZPB4suHMiOtdVLUj0o5cW5sXxuJfNb0U59zXD+Cd2KJ9/k/0W6UD0ck
/LQBWH2OTsgrq2D2ODiLJvbkmMo5B8AEfgtuZ98mfgJuEAAQPU6h6RjnIoCLnKlr
A+2wT3ns0U/wkIZLg2NGtpDck2b1NgYHtW3mcIh8rD0qQtBXMEtDw+ezxeDdD3vK
V8MEIbyZAgMBAAECggEAHFUmx3dVPcbf/BEz4gOPNYhpehcHkbYQNXw5OqmBzsNq
eH8sNT168EtsGRFOK1wAClmwowpM759rleDwAH2M2Vz7UdKemk6c62s9IDTOpFlT
NaKs82XuwB8ecorqabfKCO+6Pku1d1m1K3aLW8Pwe8iJhhYviK5Ute7k5bjJmc6L
SbsRh9xkIsmLVkQW6mClMd4RkownWWRSai7w7OpDxqNH1XaRYOWSZDZL6bkDZxLB
UEB7O7IcCLeXrAFjNHra7b82ZeKTUVu/sU1/+Adt6Kb3vmeS+85BsIxqTa3evB49
obBqq3xUnPz0u68PvmQTO4NnlUX4sdyuylEBq3vhoQKBgQD4TXyudkzRX+eo5+wJ
COyjwsZX6FSbg43qvPJG4VTJFk5zo44GqvbE1IYvstzmlSZRdC6j10p3e+6k098N
QanSNs8mrMJrUlGrwG7QWPxkqE1Fpz9TreNKTZ+8jmzwZVwJoaDw5aIoiDvVkYOs
Q6KAvkkoBMYBLbEZLYCITQxXeQKBgQDz/B4QG6LmYQAh5S0JeLyPO5BpiuIhD4/M
6SHedDSCDTy+RC5nvcfOi2drsD7ntimhQ95rYaUl9kpMg9oyIItS/uMDxAPqHCjK
473xIqLR/TPJUJhCA+n46mdgdzzaEKhjuJpqqX1ITWz5yqXAbrO2GjtKhR4ULauE
e6yhvOKmIQKBgFyJRDYgkHBXNZaVGDolwUsmg5SvWRi75l/dGs2fnGF0lrgx8/Q4
Ms8YBQoxtnGYlDc2/UrCKVZuMXnsG+xs1EUrd/gJ2kr02ssPZDzxbN52epXCxq8A
1vwSAb3btm3A2JQeUER20AAbBXGKUXAZpK4mPE1VuhUmWiHv+z7QuBDBAoGBAIAW
rhm6yIy2BAHHdRtx3Vw84xXlqc29g7sJ8ZP94csc8/TXip1ADvOqUANDJeMzySs2
nEA3pSIG6P6+ggCrATnzQm8pqvxvCCNr6L39dwlTKqrXuvd9YoohVWBZeQLql9yy
f67biEA7FakV8GrUM1i48MOwmxfw2gjVfM30gfDBAoGBAMZYUGLKO2QNX6RV2H49
ie03SVEAKZT8dCsrMaI4jb8cOy1wKA40QO+0/T3Yji7efYtmowPMpCeKJWkzC7z0
IdW4wEQFhOPiSvRM6JNbcWWzBovjIbo2U8PJ4FHQouTZRqGLG0CgPwSvpfNt2ZOe
MuHbT+pZKzPEWjAkdc2naxXX
-----END PRIVATE KEY-----`;

const TEST_SERVER_CERT = `-----BEGIN CERTIFICATE-----
MIICtTCCAZ0CFDYXYeMMS+SgDF+eusp4dBJ/BqVvMA0GCSqGSIb3DQEBCwUAMBox
GDAWBgNVBAMMD1NPSVBhY2sgVGVzdCBDQTAeFw0yNTA5MjEwOTU1MDRaFw0yNjA5
MjEwOTU1MDRaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAOymFskKScfDiQaE6SPTfQYXxuMnftsRJ6WbIkhdfYb0
Z6Kk0+gO6olgrEi4rISmENasfObhLexlGaArIN1jl2FU537DqsLDUWZws5+ipooA
QTgaBcC5ploq1S3Ke549vuzzWdFJEDzaqeZrbNkfewFVk8Hiy4cyI611UtSPSjlx
bmxfG4l81vRTn3NcP4J3Yon3+T/RbpQPRyT8tAFYfY5OyCurYPY4OIsm9uSYyjkH
wAR+C25n3yZ+Am4QABA9TqHpGOcigIucqWsD7bBPeezRT/CQhkuDY0a2kNyTZvU2
Bge1beZwiHysPSpC0FcwS0PD57PF4N0Pe8pXwwQhvJkCAwEAATANBgkqhkiG9w0B
AQsFAAOCAQEAR71+ZuU5zm3B6UGQD34QSkTE6iQyM2ZLgk8bVp1WXCLDt5UVRqyZ
jGATfGuFivyWSDy5ckPp7kw9DClOLSg5LBuprl97LxTNPyqOFmHD1WxxfTd8LWIo
kFYaLOx45k0pmCEt7T1hRl7g75uj/msBNIWRnSbjBYW5y2d22C6BlAARkCUDVbOx
ud24tNK+D+lODKlrfkQLSKmQ2wSL4sZ0+ZLUk6h92/qxS5gxpxBKhsJZ/grEchPk
hqneJkRzLDD5p22v0oxB4SsQrgksStxEM5cFBEKWD+BZeyoKwPL8NOfQoF80uYEo
ln1Jnl9pkw7o1qX2ygX2kc+Yp3VaOTJL3g==
-----END CERTIFICATE-----`;

const TEST_CLIENT_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCjMtGc+lMmO7Ve
zawGQycswlu/VdBz/AcqMGyqxRPiVUwKamtv0XGEoVFuQFr0hYffQvwJNkz45vwc
AAvSv2b/EcB71oYTTc4yy+ne0GcuIgW5FbRXtLaNKcp48uHQhIEv3YhwnfsIJEzC
yBJyvCmInar2JjXBC3fCYTEqfWY4FriqbNrjXL8rQT4hoJ7fixtqD+H5+nEQ3UXM
iAu/49133WK/4UG881UOvoQ19np6iOU8jXlYrljdUgzSJ9Yk9il43/SEL40pRygS
HSrUNDgFfwhaD6nFhuNpRP/Q9i6Ci0qMQeoC7y4+QpXXiMnRjwYyF+FBhJQwzCOk
OFvCsdKxAgMBAAECggEAImPR2IjGj1K7OkZQdwRdI7k0MLpiYiKMlvcb2xOLCGGN
k89PowFJcNe2q2s7z3W5B1Lb/gv3hebU3wiidS9YwqzIuT/gQn6dkkY2mvmjGI1a
U+GPPoEqC86v6DNUYwadG4tNFmAwF0vg8hXLj2p3vR5ueY7dOngSbT9iZzAEI5LN
adp7Ek4JVE1zPqNnoTdHfymGiH/mi7RDvYQ/8hldX99K0UGjoDqBRXs/nRkUg3cr
v/65pzgmBllHU9Tk1W77z66wgqiNAagRK/RNCa+Q4FDeiRlZpSyC27BQRjKVy/6k
Xa7mIN7fKKjwaj3Ms6MUHfu1606i6wxT+6iwkLL8vQKBgQDmAQFjv7xXiazL2ZBu
2xHUkmEWPCeBoCjtgCkfsrxyjCNrpXyfXM9oLWbRy5898Gdc2NAitaOVGbxkmNZZ
bPmuIAygvNulAVCT/nZFNKUzLcqBPvYmmD47py2Y8ETjIQyqEqRZLaBUX6rw7HFF
QujdpQvZVk/B3gl6VUnZD0KJrQKBgQC1pNkGWuNMLSFSX4Tb3LHzFGjR4tMweagd
vn+Vu3JTdAjrflE/Lp79/qdcxKryguqsXLSNxX31RYl0395m7VRpdwpsvv+33Q3S
g3LmpJ85RG3c7YwVtgmM3wnPcciu/gkll5lHJzHscDUljov4/4/NgWxCEaHl6wXk
8lO9yO6VlQKBgEMNk/wij6PtjSS4vrSyxRX1vrweuV2+9W+X52VIVEwIsuLVEenb
wtOaONl8xWXnShr1UmhsD86N/DBPpl3XuUqcKVJK/LW0FmuuyYgPewHanajkVBqY
U7xMVqy5jzuwDOMgIC2ncZBne4xVQghxIzZKwZOQ6BuawaSabLcNDdbZAoGARVOe
dTt5JxjOb/b+6T8pN8JhY0H0Irs7++Y6IbbCIrHVubOjZL7xdbWcwN5a9GYdFR3o
13c55MPee5n580S/g+UoOGsJhG49GUyMLRVFpADHAZw0bBDnQjnaL6+YzZkteoiK
uspt1nTZA/WM3MMFaoTsAadjKDJ0NHZ8maG31aUCgYEA1gAw02osTtWUOGP4sNXC
l0PUFAhpmYE1Lzw4KOTJkfDpdliiXcKVgmTJqt1SCwO3n06dDtTn0ZnOEDjscy1b
4QGMj7cDwgTIX0oazNZHqfShz9eWy52XZh8ROedo/DZJZOMWtQ/YT17VwJl8dXLy
OmRYUyFHmEjWjETI/3fBxYo=
-----END PRIVATE KEY-----`;

const TEST_CLIENT_CERT = `-----BEGIN CERTIFICATE-----
MIICsjCCAZoCFDYXYeMMS+SgDF+eusp4dBJ/BqVwMA0GCSqGSIb3DQEBCwUAMBox
GDAWBgNVBAMMD1NPSVBhY2sgVGVzdCBDQTAeFw0yNTA5MjEwOTU1MTBaFw0yNjA5
MjEwOTU1MTBaMBExDzANBgNVBAMMBmNsaWVudDCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAKMy0Zz6UyY7tV7NrAZDJyzCW79V0HP8ByowbKrFE+JVTApq
a2/RcYShUW5AWvSFh99C/Ak2TPjm/BwAC9K/Zv8RwHvWhhNNzjLL6d7QZy4iBbkV
tFe0to0pynjy4dCEgS/diHCd+wgkTMLIEnK8KYidqvYmNcELd8JhMSp9ZjgWuKps
2uNcvytBPiGgnt+LG2oP4fn6cRDdRcyIC7/j3XfdYr/hQbzzVQ6+hDX2enqI5TyN
eViuWN1SDNIn1iT2KXjf9IQvjSlHKBIdKtQ0OAV/CFoPqcWG42lE/9D2LoKLSoxB
6gLvLj5CldeIydGPBjIX4UGElDDMI6Q4W8Kx0rECAwEAATANBgkqhkiG9w0BAQsF
AAOCAQEAgMJ/lY9V7STQh4q8qaL6pACwpZjckIg3u2nRZ52UB1TcikgkOu4IIbr4
0h20sP5T7UXto4M8h8Zg2uLtA3jxL9G8V2sTIAGgz0Nyw8d9V1nWi5HR2moxW9R1
fvYlYqxN0YYwkV8l44kf8FwkIAXOAwrN1IAloe0XSEE2ObafGrzMaUuWRx7Rc1vB
TdnU4QWMvPvrFYb9or81QTPBDCQI9k8Xfb8PG5jz37fqVzTOXoW77/O9Nvfp+DVa
uge7kxuxKUyC7Ed7/uZ18cQzYoHE1Yj445O+0dWG4LRD/0+Vu8TPM74/Evxn340v
Z/bzenvXPNe+zu8uumrKWmwy+w3kTw==
-----END CERTIFICATE-----`;

const minimalExample = (...segments: string[]): string =>
  path.resolve(__dirname, '../../..', 'examples', 'minimal', ...segments);

const demoLicensePath = path.resolve(__dirname, '../../..', 'data', 'licenses', 'demo-license.key');

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const createDeferred = <T = void>() => {
  let resolve: (value: T | PromiseLike<T>) => void;
  let reject: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return {
    promise,
    resolve: resolve!,
    reject: reject!,
  };
};

type ComplianceRequirementInput = {
  id: string;
  status: 'covered' | 'partial' | 'missing';
  title?: string;
  evidenceIds: string[];
};

const buildCanonicalCompliancePayload = (
  matrix: {
    project?: string;
    level?: string;
    generatedAt?: string;
    requirements: ComplianceRequirementInput[];
    summary: { total: number; covered: number; partial: number; missing: number };
  },
  coverage: Partial<Record<'statements' | 'branches' | 'functions' | 'lines', number>>,
  metadata?: Record<string, unknown>,
) => {
  const canonicalRequirements = matrix.requirements.map((requirement) => {
    const evidenceIds = (requirement.evidenceIds ?? [])
      .map((value) => (typeof value === 'string' ? value.trim() : ''))
      .filter((value): value is string => value.length > 0);
    const canonical: Record<string, unknown> = {
      id: requirement.id.trim(),
      status: requirement.status,
      evidenceIds,
    };
    if (typeof requirement.title === 'string' && requirement.title.trim().length > 0) {
      canonical.title = requirement.title.trim();
    }
    return canonical;
  });

  const canonicalSummary = {
    total: Math.trunc(matrix.summary.total),
    covered: Math.trunc(matrix.summary.covered),
    partial: Math.trunc(matrix.summary.partial),
    missing: Math.trunc(matrix.summary.missing),
  };

  const canonicalCoverage: Record<string, number> = {};
  (['statements', 'branches', 'functions', 'lines'] as const).forEach((key) => {
    const value = coverage[key];
    if (value !== undefined && value !== null) {
      const numeric = Number(value);
      canonicalCoverage[key] = Math.round(numeric * 1000) / 1000;
    }
  });

  const canonicalMetadata: Record<string, unknown> = {};
  Object.entries(metadata ?? {}).forEach(([key, value]) => {
    if (value !== undefined) {
      canonicalMetadata[key] = value;
    }
  });

  return {
    matrix: {
      project: typeof matrix.project === 'string' ? matrix.project : undefined,
      level: typeof matrix.level === 'string' ? matrix.level : undefined,
      generatedAt: typeof matrix.generatedAt === 'string' ? matrix.generatedAt : undefined,
      requirements: canonicalRequirements,
      summary: canonicalSummary,
    },
    coverage: canonicalCoverage,
    metadata: canonicalMetadata,
  };
};

const waitForCondition = async (predicate: () => boolean | Promise<boolean>, timeoutMs = 5000): Promise<void> => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) {
      return;
    }
    await delay(10);
  }
  throw new Error('Condition was not met within the allotted time.');
};

const createLogCapture = () => {
  const entries: Array<Record<string, unknown>> = [];
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      const lines = chunk
        .toString()
        .split(/\n/u)
        .map((line: string) => line.trim())
        .filter((line: string) => line.length > 0);
      lines.forEach((line: string) => {
        try {
          entries.push(JSON.parse(line));
        } catch {
          // Ignore malformed log lines.
        }
      });
      callback();
    },
  });
  const logger = pino({ level: 'info', base: undefined }, stream);
  return { logger, entries };
};

const flushLogs = async () => new Promise((resolve) => setImmediate(resolve));

const waitForJobCompletion = async (
  app: ReturnType<typeof createServer>,
  token: string,
  jobId: string,
) => {
  let lastResponse: request.Response | undefined;
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const response = await request(app)
      .get(`/v1/jobs/${jobId}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    lastResponse = response;
    if (response.body.status === 'completed') {
      return response.body;
    }
    if (response.body.status === 'failed') {
      throw new Error(`Job ${jobId} failed: ${JSON.stringify(response.body.error)}`);
    }
    await delay(250);
  }
  throw new Error(`Job ${jobId} did not complete in time: ${JSON.stringify(lastResponse?.body)}`);
};

const waitForJobFailure = async (
  app: ReturnType<typeof createServer>,
  token: string,
  jobId: string,
) => {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const response = await request(app)
      .get(`/v1/jobs/${jobId}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    if (response.body.status === 'failed') {
      return response.body;
    }
    if (response.body.status === 'completed') {
      throw new Error(`Job ${jobId} unexpectedly completed.`);
    }
    await delay(250);
  }
  throw new Error(`Job ${jobId} did not fail in time.`);
};

jest.setTimeout(60000);

describe('@soipack/server REST API', () => {
  const tenantId = 'tenant-a';
  const issuer = 'https://auth.test';
  const audience = 'soipack-api';
  const tenantClaim = 'tenant';
  const requiredScope = 'soipack.api';
  const adminScope = 'soipack.admin';
  let token: string;
  let storageDir: string;
  let app: ReturnType<typeof createServer>;
  let signingKeyPath: string;
  let licensePublicKeyPath: string;
  let licenseHeader: string;
  let licenseExpiresAt: Date | undefined;
  let privateKey: KeyLike;
  let jwks: JSONWebKeySet;
  let baseConfig: ServerConfig;
  let metricsRegistry: Registry;
  let logEntries: Array<Record<string, unknown>>;

  const createAccessToken = async ({
    tenant = tenantId,
    subject = 'user-1',
    scope = `${requiredScope} ${adminScope}`,
    expiresIn = '2h',
  }: {
    tenant?: string;
    subject?: string;
    scope?: string | null;
    expiresIn?: string | number;
  } = {}): Promise<string> => {
    const payload: Record<string, unknown> = { [tenantClaim]: tenant };
    if (scope) {
      payload.scope = scope;
    }

    return new SignJWT(payload)
      .setProtectedHeader({ alg: 'RS256', kid: jwks.keys[0].kid })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject(subject)
      .setIssuedAt()
      .setExpirationTime(expiresIn)
      .sign(privateKey);
  };

  beforeAll(async () => {
    storageDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'soipack-server-test-'));
    signingKeyPath = path.join(storageDir, 'signing-key.pem');
    await fsPromises.writeFile(signingKeyPath, TEST_SIGNING_BUNDLE, 'utf8');
    licensePublicKeyPath = path.join(storageDir, 'license.pub');
    await fsPromises.writeFile(licensePublicKeyPath, LICENSE_PUBLIC_KEY_BASE64, 'utf8');
    const licenseContent = await fsPromises.readFile(demoLicensePath, 'utf8');
    licenseHeader = Buffer.from(licenseContent, 'utf8').toString('base64');
    const parsedLicense = JSON.parse(licenseContent) as { payload: string };
    const decodedPayload = JSON.parse(
      Buffer.from(parsedLicense.payload, 'base64').toString('utf8'),
    ) as { expiresAt?: string };
    licenseExpiresAt = decodedPayload.expiresAt ? new Date(decodedPayload.expiresAt) : undefined;

    const { publicKey, privateKey: generatedPrivateKey } = await generateKeyPair('RS256');
    privateKey = generatedPrivateKey;
    const publicJwk = (await exportJWK(publicKey)) as JWK;
    publicJwk.use = 'sig';
    publicJwk.alg = 'RS256';
    publicJwk.kid = 'test-key';
    jwks = { keys: [publicJwk] };

    const logCapture = createLogCapture();
    logEntries = logCapture.entries;
    metricsRegistry = new Registry();

    baseConfig = {
      auth: {
        issuer,
        audience,
        tenantClaim,
        jwks,
        requiredScopes: [requiredScope],
        adminScopes: [adminScope],
        clockToleranceSeconds: 0,
      },
      storageDir,
      signingKeyPath,
      licensePublicKeyPath,
      retention: {
        uploads: { maxAgeMs: 0 },
        analyses: { maxAgeMs: 0 },
        reports: { maxAgeMs: 0 },
        packages: { maxAgeMs: 0 },
      },
      logger: logCapture.logger,
      metricsRegistry,
      jsonBodyLimitBytes: 2 * 1024 * 1024,
      rateLimit: {
        global: { windowMs: 60_000, max: 5_000 },
        ip: { windowMs: 60_000, max: 1_000 },
        tenant: { windowMs: 60_000, max: 1_000 },
      },
      requireAdminClientCertificate: false,
    };

    app = createServer(baseConfig);

    token = await createAccessToken();
  });

  beforeEach(() => {
    metricsRegistry?.resetMetrics();
    if (logEntries) {
      logEntries.length = 0;
    }
  });

  afterAll(async () => {
    await fsPromises.rm(storageDir, { recursive: true, force: true });
  });

  it('rejects direct HTTP listen attempts', () => {
    expect(() => app.listen(0)).toThrow('SOIPack sunucusu yalnızca HTTPS ile başlatılabilir.');
  });

  it('rejects unauthorized requests', async () => {
    const response = await request(app).post('/v1/import').expect(401);
    expect(response.body.error.code).toBe('UNAUTHORIZED');
  });

  it('rejects authenticated requests without API key when keys are configured', async () => {
    process.env.SOIPACK_API_KEYS = 'demo-key:reader';
    const securedApp = createServer({ ...baseConfig, metricsRegistry: new Registry() });

    try {
      const response = await request(securedApp)
        .get('/evidence')
        .set('Authorization', `Bearer ${token}`)
        .expect(401);
      expect(response.body.error.code).toBe('UNAUTHORIZED');
    } finally {
      delete process.env.SOIPACK_API_KEYS;
    }
  });

  it('localizes error responses based on the Accept-Language header', async () => {
    const invalidJobId = 'not-a-valid-id';

    const englishResponse = await request(app)
      .get(`/v1/jobs/${invalidJobId}`)
      .set('Authorization', `Bearer ${token}`)
      .set('Accept-Language', 'en-US,en;q=0.9')
      .expect(400);
    expect(englishResponse.body.error.message).toBe('The identifier value is not valid.');

    const turkishResponse = await request(app)
      .get(`/v1/jobs/${invalidJobId}`)
      .set('Authorization', `Bearer ${token}`)
      .set('Accept-Language', 'tr-TR,tr;q=0.9')
      .expect(400);
    expect(turkishResponse.body.error.message).toBe('Kimlik değeri geçerli değil.');
  });

  it('allows access with a valid API key and matching role', async () => {
    process.env.SOIPACK_API_KEYS = 'ops=demo-key:reader|maintainer';
    const securedApp = createServer({ ...baseConfig, metricsRegistry: new Registry() });

    try {
      const response = await request(securedApp)
        .get('/evidence')
        .set('Authorization', `Bearer ${token}`)
        .set('x-api-key', 'demo-key')
        .expect(200);
      expect(Array.isArray(response.body.items)).toBe(true);
    } finally {
      delete process.env.SOIPACK_API_KEYS;
    }
  });

  it('throws when jwksUri is not HTTPS', () => {
    expect(() =>
      createServer({
        ...baseConfig,
        auth: {
          ...baseConfig.auth,
          jwks: undefined,
          jwksUri: 'http://invalid.test/jwks.json',
        },
        metricsRegistry: new Registry(),
      }),
    ).toThrow('jwksUri HTTPS protokolü kullanmalıdır.');
  });

  it('allows health checks without authorization when no token is configured', async () => {
    const response = await request(app).get('/health').expect(200);
    expect(response.body).toEqual({ status: 'ok' });
  });

  it('accepts health checks with the configured bearer token', async () => {
    const healthcheckToken = 'test-health-token';
    const serverWithToken = createServer({
      ...baseConfig,
      healthcheckToken,
      metricsRegistry: new Registry(),
    });
    const response = await request(serverWithToken)
      .get('/health')
      .set('Authorization', `Bearer ${healthcheckToken}`)
      .expect(200);
    expect(response.body).toEqual({ status: 'ok' });
  });

  it('sets helmet security headers on health responses', async () => {
    const response = await request(app).get('/health').expect(200);
    expect(response.headers['x-dns-prefetch-control']).toBe('off');
    expect(response.headers['x-content-type-options']).toBe('nosniff');
    expect(response.headers['x-frame-options']).toBe('SAMEORIGIN');
  });

  it('uploads evidence with SHA-256 validation', async () => {
    const payload = 'integration evidence sample';
    const buffer = Buffer.from(payload, 'utf8');
    const sha = createHash('sha256').update(buffer).digest('hex');

    const uploadResponse = await request(app)
      .post('/evidence/upload')
      .set('Authorization', `Bearer ${token}`)
      .send({
        filename: 'artifact.log',
        content: buffer.toString('base64'),
        metadata: { sha256: sha, size: buffer.length, description: 'test artifact' },
      })
      .expect(201);

    expect(uploadResponse.body).toMatchObject({
      filename: 'artifact.log',
      sha256: sha,
      size: buffer.length,
      metadata: expect.objectContaining({
        sha256: sha,
        size: buffer.length,
        description: 'test artifact',
      }),
    });
    expect(typeof uploadResponse.body.id).toBe('string');
    expect(uploadResponse.body.snapshotId).toMatch(/^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$/);
    expect(uploadResponse.body.snapshotVersion).toEqual(
      expect.objectContaining({ fingerprint: sha, isFrozen: false }),
    );

    const detail = await request(app)
      .get(`/evidence/${uploadResponse.body.id}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(detail.body.contentEncoding).toBe('base64');
    const decoded = Buffer.from(detail.body.content as string, 'base64').toString('utf8');
    expect(decoded).toBe(payload);
    expect(detail.body.snapshotId).toBe(uploadResponse.body.snapshotId);
    expect(detail.body.snapshotVersion.isFrozen).toBe(false);
  });

  it('persists evidence, compliance, and frozen snapshot versions across restarts', async () => {
    const persistentDir = await fsPromises.mkdtemp(path.join(storageDir, 'persistence-test-'));
    const restartConfig: ServerConfig = {
      ...baseConfig,
      storageDir: persistentDir,
      metricsRegistry: new Registry(),
    };
    const firstApp = createServer(restartConfig);
    const restartToken = await createAccessToken();

    const artifactBuffer = Buffer.from('persistent artifact payload', 'utf8');
    const artifactHash = createHash('sha256').update(artifactBuffer).digest('hex');

    const uploadResponse = await request(firstApp)
      .post('/evidence/upload')
      .set('Authorization', `Bearer ${restartToken}`)
      .send({
        filename: 'persist.log',
        content: artifactBuffer.toString('base64'),
        metadata: {
          sha256: artifactHash,
          size: artifactBuffer.length,
          description: 'persistence test artifact',
        },
      })
      .expect(201);

    const evidenceId = uploadResponse.body.id as string;
    expect(evidenceId).toBeDefined();

    const matrix = {
      project: 'Persistence Demo',
      level: 'A',
      generatedAt: '2024-09-21T10:00:00Z',
      requirements: [
        {
          id: 'REQ-1',
          status: 'covered' as const,
          title: 'Persist state',
          evidenceIds: [evidenceId],
        },
      ],
      summary: { total: 1, covered: 1, partial: 0, missing: 0 },
    };

    const coverageInput = { statements: 97.5, lines: 100 };
    const metadata = { reviewer: 'qa' };

    const canonicalPayload = buildCanonicalCompliancePayload(matrix, coverageInput, metadata);
    const complianceHash = createHash('sha256')
      .update(JSON.stringify(canonicalPayload))
      .digest('hex');

    const complianceResponse = await request(firstApp)
      .post('/compliance')
      .set('Authorization', `Bearer ${restartToken}`)
      .send({
        sha256: complianceHash,
        matrix,
        coverage: coverageInput,
        metadata,
      })
      .expect(201);

    expect(complianceResponse.body.sha256).toBe(complianceHash);

    const freezeResponse = await request(firstApp)
      .post('/v1/config/freeze')
      .set('Authorization', `Bearer ${restartToken}`)
      .expect(200);

    expect(freezeResponse.body.version.isFrozen).toBe(true);

    const restartedApp = createServer({ ...restartConfig, metricsRegistry: new Registry() });

    const evidenceList = await request(restartedApp)
      .get('/evidence')
      .set('Authorization', `Bearer ${restartToken}`)
      .expect(200);

    expect(evidenceList.body.items).toHaveLength(1);
    expect(evidenceList.body.items[0]).toMatchObject({ id: evidenceId, sha256: artifactHash });

    const complianceList = await request(restartedApp)
      .get('/compliance')
      .set('Authorization', `Bearer ${restartToken}`)
      .expect(200);

    expect(complianceList.body.items).toHaveLength(1);
    expect(complianceList.body.items[0].sha256).toBe(complianceHash);

    const freezeAfterRestart = await request(restartedApp)
      .post('/v1/config/freeze')
      .set('Authorization', `Bearer ${restartToken}`)
      .expect(200);

    expect(freezeAfterRestart.body.version).toEqual(freezeResponse.body.version);

    await fsPromises.rm(persistentDir, { recursive: true, force: true });
  });

  it('returns existing records when identical evidence is uploaded twice', async () => {
    const payload = 'duplicate evidence payload';
    const buffer = Buffer.from(payload, 'utf8');
    const sha = createHash('sha256').update(buffer).digest('hex');

    const first = await request(app)
      .post('/evidence/upload')
      .set('Authorization', `Bearer ${token}`)
      .send({ filename: 'duplicate.txt', content: buffer.toString('base64'), metadata: { sha256: sha } })
      .expect(201);

    const second = await request(app)
      .post('/evidence/upload')
      .set('Authorization', `Bearer ${token}`)
      .send({ filename: 'duplicate.txt', content: buffer.toString('base64'), metadata: { sha256: sha } })
      .expect(200);

    expect(second.body.id).toBe(first.body.id);
    expect(second.body.snapshotId).toBe(first.body.snapshotId);
  });

  it('rejects evidence uploads when the hash is incorrect', async () => {
    const buffer = Buffer.from('mismatched evidence', 'utf8');
    const wrongHash = createHash('sha256').update('different').digest('hex');

    const response = await request(app)
      .post('/evidence/upload')
      .set('Authorization', `Bearer ${token}`)
      .send({
        filename: 'broken.log',
        content: buffer.toString('base64'),
        metadata: { sha256: wrongHash, size: buffer.length },
      })
      .expect(400);

    expect(response.body.error.code).toBe('HASH_MISMATCH');
  });

  it('rejects evidence uploads after configuration freeze', async () => {
    const buffer = Buffer.from('freeze evidence', 'utf8');
    const sha = createHash('sha256').update(buffer).digest('hex');

    const freezeLog = createLogCapture();
    const freezeApp = createServer({ ...baseConfig, logger: freezeLog.logger, metricsRegistry: new Registry() });
    const freezeToken = await createAccessToken();

    await request(freezeApp)
      .post('/evidence/upload')
      .set('Authorization', `Bearer ${freezeToken}`)
      .send({ filename: 'frozen.log', content: buffer.toString('base64'), metadata: { sha256: sha } })
      .expect(201);

    const freezeResponse = await request(freezeApp)
      .post('/v1/config/freeze')
      .set('Authorization', `Bearer ${freezeToken}`)
      .expect(200);

    expect(freezeResponse.body.version).toEqual(
      expect.objectContaining({ isFrozen: true, id: expect.any(String) }),
    );

    const rejection = await request(freezeApp)
      .post('/evidence/upload')
      .set('Authorization', `Bearer ${freezeToken}`)
      .send({ filename: 'frozen-again.log', content: buffer.toString('base64'), metadata: { sha256: sha } })
      .expect(409);

    expect(rejection.body.error.code).toBe('CONFIG_FROZEN');
  });

  it('creates compliance records that reference stored evidence', async () => {
    const evidenceBuffer = Buffer.from('traceability report', 'utf8');
    const evidenceHash = createHash('sha256').update(evidenceBuffer).digest('hex');
    const evidenceUpload = await request(app)
      .post('/evidence/upload')
      .set('Authorization', `Bearer ${token}`)
      .send({
        filename: 'report.pdf',
        content: evidenceBuffer.toString('base64'),
        metadata: { sha256: evidenceHash, size: evidenceBuffer.length },
      })
      .expect(201);

    const matrix = {
      project: 'Demo Avionics',
      level: 'C',
      generatedAt: new Date().toISOString(),
      summary: { total: 1, covered: 1, partial: 0, missing: 0 },
      requirements: [
        {
          id: 'REQ-1',
          title: 'Autopilot engages',
          status: 'covered',
          evidenceIds: [evidenceUpload.body.id as string],
        },
      ],
    };

    const coverage = { statements: 96.5, branches: 88.2 };
    const metadata = { build: '2024.09.21' };
    const canonicalRequirements = matrix.requirements.map((entry) => {
      const normalizedEvidence = (entry.evidenceIds ?? [])
        .map((value) => (typeof value === 'string' ? value.trim() : ''))
        .filter((value) => value.length > 0);
      const normalized: Record<string, unknown> = {
        id: entry.id.trim(),
        status: entry.status,
        evidenceIds: normalizedEvidence,
      };
      if (typeof entry.title === 'string' && entry.title.trim().length > 0) {
        normalized.title = entry.title.trim();
      }
      return normalized;
    });

    const canonicalCoverage: Record<string, number> = {};
    (['statements', 'branches', 'functions', 'lines'] as const).forEach((key) => {
      const value = (coverage as Record<string, unknown>)[key];
      if (value !== undefined && value !== null) {
        const numeric = Number(value);
        canonicalCoverage[key] = Math.round(numeric * 1000) / 1000;
      }
    });

    const canonicalMetadata: Record<string, unknown> = {};
    Object.entries(metadata).forEach(([key, value]) => {
      if (value !== undefined) {
        canonicalMetadata[key] = value;
      }
    });

    const canonicalPayload = {
      matrix: {
        project: matrix.project,
        level: matrix.level,
        generatedAt: matrix.generatedAt,
        requirements: canonicalRequirements,
        summary: {
          total: Math.trunc(matrix.summary.total),
          covered: Math.trunc(matrix.summary.covered),
          partial: Math.trunc(matrix.summary.partial),
          missing: Math.trunc(matrix.summary.missing),
        },
      },
      coverage: canonicalCoverage,
      metadata: canonicalMetadata,
    };
    const complianceHash = createHash('sha256').update(JSON.stringify(canonicalPayload)).digest('hex');

    const complianceResponse = await request(app)
      .post('/compliance')
      .set('Authorization', `Bearer ${token}`)
      .send({ matrix, coverage, metadata, sha256: complianceHash });

    expect(complianceResponse.status).toBe(201);
    expect(complianceResponse.body).toMatchObject({
      sha256: complianceHash,
      matrix: expect.objectContaining({ project: 'Demo Avionics', summary: matrix.summary }),
    });

    const listResponse = await request(app)
      .get('/compliance')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(listResponse.body.items).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: complianceResponse.body.id,
          sha256: complianceHash,
          matrix: expect.objectContaining({
            requirements: [
              expect.objectContaining({
                id: 'REQ-1',
                evidenceIds: [evidenceUpload.body.id],
              }),
            ],
          }),
        }),
      ]),
    );

    const detailResponse = await request(app)
      .get(`/compliance/${complianceResponse.body.id}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(detailResponse.body.sha256).toBe(complianceHash);
  });

  it('rejects health checks without or with an invalid token', async () => {
    const healthcheckToken = 'test-health-token';
    const serverWithToken = createServer({
      ...baseConfig,
      healthcheckToken,
      metricsRegistry: new Registry(),
    });
    const missingResponse = await request(serverWithToken).get('/health').expect(401);
    expect(missingResponse.body.error.code).toBe('UNAUTHORIZED');
    const wrongResponse = await request(serverWithToken)
      .get('/health')
      .set('Authorization', 'Bearer wrong-token')
      .expect(401);
    expect(wrongResponse.body.error.code).toBe('UNAUTHORIZED');
  });

  it('applies security headers to responses', async () => {
    const health = await request(app).get('/health').expect(200);
    expect(health.headers['strict-transport-security']).toContain('max-age=31536000');
    expect(health.headers['strict-transport-security']).toContain('includeSubDomains');
    expect(health.headers['strict-transport-security']).toContain('preload');
    expect(health.headers['x-content-type-options']).toBe('nosniff');
    expect(health.headers['x-frame-options']).toBe('SAMEORIGIN');
    expect(health.headers['x-powered-by']).toBeUndefined();

    const jobs = await request(app)
      .get('/v1/jobs')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(jobs.headers['strict-transport-security']).toBe(health.headers['strict-transport-security']);
    expect(jobs.headers['x-content-type-options']).toBe('nosniff');
    expect(jobs.headers['x-frame-options']).toBe('SAMEORIGIN');
    expect(jobs.headers['x-powered-by']).toBeUndefined();
  });

  it('requires authorization for job and artifact endpoints', async () => {
    const jobList = await request(app).get('/v1/jobs').expect(401);
    expect(jobList.body.error.code).toBe('UNAUTHORIZED');

    const jobDetail = await request(app).get('/v1/jobs/test-job').expect(401);
    expect(jobDetail.body.error.code).toBe('UNAUTHORIZED');

    const manifestResponse = await request(app).get('/v1/manifests/abcd1234').expect(401);
    expect(manifestResponse.body.error.code).toBe('UNAUTHORIZED');

    const packageResponse = await request(app).get('/v1/packages/abcd1234').expect(401);
    expect(packageResponse.body.error.code).toBe('UNAUTHORIZED');

    const reportAsset = await request(app)
      .get('/v1/reports/abcd1234/compliance.html')
      .expect(401);
    expect(reportAsset.body.error.code).toBe('UNAUTHORIZED');
  });

  it('rejects tokens missing required scopes', async () => {
    const otherScopeToken = await createAccessToken({ scope: 'other.scope' });
    const response = await request(app)
      .get('/v1/jobs')
      .set('Authorization', `Bearer ${otherScopeToken}`)
      .expect(403);
    expect(response.body.error.code).toBe('INSUFFICIENT_SCOPE');
  });

  it('requires admin scope for privileged endpoints', async () => {
    const userToken = await createAccessToken({ scope: requiredScope });

    const cleanupForbidden = await request(app)
      .post('/v1/admin/cleanup')
      .set('Authorization', `Bearer ${userToken}`)
      .expect(403);
    expect(cleanupForbidden.body.error.code).toBe('INSUFFICIENT_SCOPE');

    const metricsForbidden = await request(app)
      .get('/metrics')
      .set('Authorization', `Bearer ${userToken}`)
      .expect(403);
    expect(metricsForbidden.body.error.code).toBe('INSUFFICIENT_SCOPE');

    const adminToken = await createAccessToken({ scope: `${requiredScope} ${adminScope}` });

    await request(app)
      .post('/v1/admin/cleanup')
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(200);

    await request(app)
      .get('/metrics')
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(200);
  });

  it('rejects expired tokens', async () => {
    const shortLivedToken = await createAccessToken({ expiresIn: '1s' });
    await delay(1600);
    const response = await request(app)
      .get('/v1/jobs')
      .set('Authorization', `Bearer ${shortLivedToken}`)
      .expect(401);
    expect(response.body.error.code).toBe('UNAUTHORIZED');
  });

  it('propagates JWKS fetch timeouts as service unavailable', async () => {
    const slowJwksServer = https.createServer({ key: TEST_SERVER_KEY, cert: TEST_SERVER_CERT }, (_req, res) => {
      setTimeout(() => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(jwks));
      }, 200);
    });

    const originalTlsSetting = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

    try {
      await new Promise<void>((resolve) => slowJwksServer.listen(0, resolve));
      const { port } = slowJwksServer.address() as AddressInfo;
      const remoteConfig: ServerConfig = {
        ...baseConfig,
        auth: {
          ...baseConfig.auth,
          jwks: undefined,
          jwksUri: `https://localhost:${port}/jwks.json`,
          remoteJwks: { timeoutMs: 50, maxRetries: 0, backoffMs: 10 },
        },
        metricsRegistry: new Registry(),
      };
      const remoteApp = createServer(remoteConfig);
      const response = await request(remoteApp)
        .get('/v1/jobs')
        .set('Authorization', `Bearer ${token}`)
        .expect(503);
      expect(response.body.error.code).toBe('JWKS_UNAVAILABLE');
    } finally {
      await new Promise<void>((resolve) => slowJwksServer.close(() => resolve()));
      if (originalTlsSetting === undefined) {
        delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
      } else {
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = originalTlsSetting;
      }
    }
  });

  it('requires a license token for import requests', async () => {
    const response = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .attach('reqif', minimalExample('spec.reqif'))
      .expect(401);

    expect(response.body.error.code).toBe('LICENSE_REQUIRED');
  });

  it('rejects invalid license tokens', async () => {
    const licenseJson = JSON.parse(Buffer.from(licenseHeader, 'base64').toString('utf8')) as {
      payload: string;
      signature: string;
    };
    const signatureBytes = Buffer.from(licenseJson.signature, 'base64');
    signatureBytes[0] ^= 0xff;
    licenseJson.signature = Buffer.from(signatureBytes).toString('base64');
    const tamperedHeader = Buffer.from(JSON.stringify(licenseJson), 'utf8').toString('base64');

    const response = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', tamperedHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .expect(402);

    expect(response.body.error.code).toBe('LICENSE_INVALID');
  });

  it('rejects oversized license headers before decoding', async () => {
    const limitedApp = createServer({
      ...baseConfig,
      licenseLimits: { maxBytes: 64, headerMaxBytes: 32 },
      metricsRegistry: new Registry(),
    });

    const oversizedHeader = Buffer.alloc(48, 1).toString('base64');
    const response = await request(limitedApp)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', oversizedHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .expect(413);

    expect(response.body.error.code).toBe('LICENSE_TOO_LARGE');
  });

  it('rejects oversized uploaded license files', async () => {
    const limitedApp = createServer({
      ...baseConfig,
      licenseLimits: { maxBytes: 32 },
      metricsRegistry: new Registry(),
    });

    const response = await request(limitedApp)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .attach('license', Buffer.alloc(128, 2), { filename: 'license.key' })
      .attach('reqif', minimalExample('spec.reqif'))
      .expect(413);

    expect(response.body.error.code).toBe('LICENSE_TOO_LARGE');
  });

  it('throttles repeated requests from the same IP', async () => {
    const throttledApp = createServer({
      ...baseConfig,
      rateLimit: {
        ip: { windowMs: 1000, max: 1 },
        tenant: baseConfig.rateLimit?.tenant,
      },
      metricsRegistry: new Registry(),
    });

    await request(throttledApp).get('/health').expect(200);
    const response = await request(throttledApp).get('/health').expect(429);
    expect(response.body.error.code).toBe('IP_RATE_LIMIT_EXCEEDED');
    expect(response.headers['retry-after']).toBeDefined();
  });

  it('enforces the global rate limiter for consecutive requests', async () => {
    const globallyLimitedApp = createServer({
      ...baseConfig,
      rateLimit: {
        global: { windowMs: 1000, max: 1 },
        ip: baseConfig.rateLimit?.ip,
        tenant: baseConfig.rateLimit?.tenant,
      },
      metricsRegistry: new Registry(),
    });

    await request(globallyLimitedApp).get('/health').expect(200);
    const response = await request(globallyLimitedApp).get('/health').expect(429);
    expect(response.body.error.code).toBe('GLOBAL_RATE_LIMIT_EXCEEDED');
    expect(response.headers['retry-after']).toBeDefined();
  });

  it('uses forwarded client IPs when trust proxy is enabled', async () => {
    const proxyLogCapture = createLogCapture();
    const proxyApp = createServer({
      ...baseConfig,
      logger: proxyLogCapture.logger,
      trustProxy: true,
      rateLimit: {
        ip: { windowMs: 1000, max: 1, maxEntries: 5 },
        tenant: baseConfig.rateLimit?.tenant,
      },
      metricsRegistry: new Registry(),
    });

    const firstIp = '203.0.113.10';
    const secondIp = '203.0.113.11';

    await request(proxyApp).get('/health').set('X-Forwarded-For', firstIp).expect(200);
    await request(proxyApp).get('/health').set('X-Forwarded-For', secondIp).expect(200);
    const limited = await request(proxyApp)
      .get('/health')
      .set('X-Forwarded-For', firstIp)
      .expect(429);
    expect(limited.body.error.code).toBe('IP_RATE_LIMIT_EXCEEDED');

    await flushLogs();
    const seenAddresses = proxyLogCapture.entries
      .filter((entry) => entry.event === 'http_request')
      .map((entry) => entry.remoteAddress);
    expect(seenAddresses).toContain(firstIp);
    expect(seenAddresses).toContain(secondIp);
  });

  it('evicts old rate limit entries when capacity is reached', async () => {
    const evictionApp = createServer({
      ...baseConfig,
      trustProxy: true,
      rateLimit: {
        ip: { windowMs: 10_000, max: 1, maxEntries: 3 },
        tenant: baseConfig.rateLimit?.tenant,
      },
      metricsRegistry: new Registry(),
    });

    const ips = ['198.51.100.1', '198.51.100.2', '198.51.100.3', '198.51.100.4'];
    for (const ip of ips) {
      await request(evictionApp).get('/health').set('X-Forwarded-For', ip).expect(200);
    }

    const reused = await request(evictionApp)
      .get('/health')
      .set('X-Forwarded-For', ips[0])
      .expect(200);
    expect(reused.body).toEqual({ status: 'ok' });
  });

  it('enforces per-tenant rate limits', async () => {
    const tenantLimitedApp = createServer({
      ...baseConfig,
      rateLimit: {
        ip: { windowMs: 60_000, max: 1_000 },
        tenant: { windowMs: 1000, max: 2 },
      },
      metricsRegistry: new Registry(),
    });

    const authHeader = { Authorization: `Bearer ${token}` };
    await request(tenantLimitedApp).get('/v1/jobs').set(authHeader).expect(200);
    await request(tenantLimitedApp).get('/v1/jobs').set(authHeader).expect(200);
    const response = await request(tenantLimitedApp).get('/v1/jobs').set(authHeader).expect(429);
    expect(response.body.error.code).toBe('TENANT_RATE_LIMIT_EXCEEDED');
  });

  it('rejects oversized JSON bodies', async () => {
    const limitedApp = createServer({
      ...baseConfig,
      jsonBodyLimitBytes: 32,
      metricsRegistry: new Registry(),
    });

    const payload = { importId: 'x'.repeat(64) };
    const response = await request(limitedApp)
      .post('/v1/analyze')
      .set('Authorization', `Bearer ${token}`)
      .set('Content-Type', 'application/json')
      .send(JSON.stringify(payload))
      .expect(413);
    expect(response.body.error.code).toBe('PAYLOAD_TOO_LARGE');
  });

  it('rejects cached licenses once they expire', async () => {
    if (!licenseExpiresAt) {
      throw new Error('Demo lisansının son kullanma tarihi yok.');
    }
    const beforeExpiry = new Date(licenseExpiresAt.getTime() - 60_000);
    const afterExpiry = new Date(licenseExpiresAt.getTime() + 1_000);

    jest.useFakeTimers({
      now: beforeExpiry,
      doNotFake: ['setTimeout', 'setInterval', 'setImmediate'],
    });
    try {
      const futureToken = await createAccessToken();
      const projectBase = `license-expiry-${Date.now()}`;
      const primeResponse = await request(app)
        .post('/v1/import')
        .set('Authorization', `Bearer ${futureToken}`)
        .set('X-SOIPACK-License', licenseHeader)
        .attach('reqif', minimalExample('spec.reqif'))
        .attach('junit', minimalExample('results.xml'))
        .attach('lcov', minimalExample('lcov.info'))
        .field('projectName', 'Expiry Cache Project')
        .field('projectVersion', projectBase)
        .expect((response) => {
          if (![200, 202].includes(response.status)) {
            throw new Error(`Unexpected status while priming license cache: ${response.status}`);
          }
        });

      if (primeResponse.status === 202) {
        expect(primeResponse.body.error).toBeUndefined();
      }

      jest.setSystemTime(afterExpiry);

      const expiredResponse = await request(app)
        .post('/v1/import')
        .set('Authorization', `Bearer ${futureToken}`)
        .set('X-SOIPACK-License', licenseHeader)
        .attach('reqif', minimalExample('spec.reqif'))
        .attach('junit', minimalExample('results.xml'))
        .attach('lcov', minimalExample('lcov.info'))
        .field('projectName', 'Expiry Cache Project')
        .field('projectVersion', `${projectBase}-retry`)
        .expect(402);

      expect(expiredResponse.body.error.code).toBe('LICENSE_INVALID');
      expect(expiredResponse.body.error.message).toBe('Lisans süresi dolmuş.');
    } finally {
      jest.useRealTimers();
    }
  });

  it('evicts least recently used licenses when cache bounds are exceeded', async () => {
    const verifySpy = jest.spyOn(cli, 'verifyLicenseFile');
    const runImportSpy = jest.spyOn(cli, 'runImport');
    verifySpy.mockImplementation(async (filePath) => {
      const content = await fsPromises.readFile(filePath);
      const hash = createHash('sha256').update(content).digest('hex');
      return {
        licenseId: hash,
        issuedTo: 'test-suite',
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        features: ['import', 'analyze', 'report', 'pack'],
      } as cli.LicensePayload;
    });
    runImportSpy.mockResolvedValue({
      warnings: [],
      workspacePath: path.join('out', 'workspace.json'),
      workspace: {} as cli.ImportWorkspace,
    });

    const cachingApp = createServer({
      ...baseConfig,
      licenseCache: { maxEntries: 2, maxAgeMs: 60_000 },
      metricsRegistry: new Registry(),
    });

    const submitImport = async (licenseValue: string, suffix: string) => {
      const response = await request(cachingApp)
        .post('/v1/import')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', Buffer.from(licenseValue).toString('base64'))
        .attach('reqif', minimalExample('spec.reqif'))
        .field('projectName', `Project-${suffix}`)
        .field('projectVersion', suffix)
        .expect((res) => {
          if (![200, 202].includes(res.status)) {
            throw new Error(`Unexpected status ${res.status}`);
          }
        });
      if (response.status === 202) {
        await waitForJobCompletion(cachingApp, token, response.body.id);
      }
    };

    try {
      await submitImport('license-a', 'one');
      expect(verifySpy).toHaveBeenCalledTimes(1);

      await submitImport('license-a', 'two');
      expect(verifySpy).toHaveBeenCalledTimes(1);

      await submitImport('license-b', 'three');
      expect(verifySpy).toHaveBeenCalledTimes(2);

      await submitImport('license-c', 'four');
      expect(verifySpy).toHaveBeenCalledTimes(3);

      await submitImport('license-a', 'five');
      expect(verifySpy).toHaveBeenCalledTimes(4);
    } finally {
      verifySpy.mockRestore();
      runImportSpy.mockRestore();
    }
  });

  it('rejects unauthorized TLS handshakes and legacy protocols when mutual TLS is required', async () => {
    const secureConfig: ServerConfig = {
      ...baseConfig,
      requireAdminClientCertificate: true,
      metricsRegistry: new Registry(),
    };
    const secureApp = createServer(secureConfig);
    const httpsServer = createHttpsServer(
      secureApp,
      {
        key: TEST_SERVER_KEY,
        cert: TEST_SERVER_CERT,
        clientCa: TEST_CA_CERT,
      },
      { requireClientCertificate: true },
    );

    await new Promise<void>((resolve) => httpsServer.listen(0, resolve));
    const { port } = httpsServer.address() as AddressInfo;
    const adminToken = await createAccessToken({ scope: `${requiredScope} ${adminScope}` });

    const attemptTlsConnection = (options: tls.ConnectionOptions) =>
      new Promise<void>((resolve, reject) => {
        const socket = tls.connect(
          {
            host: 'localhost',
            port,
            ca: TEST_CA_CERT,
            rejectUnauthorized: true,
            ...options,
          },
        );
        socket.once('secureConnect', () => {
          socket.end();
          resolve();
        });
        socket.once('error', (error) => {
          socket.destroy();
          reject(error);
        });
      });

    const expectRequestFailure = (options?: https.RequestOptions) =>
      new Promise<never>((_resolve, reject) => {
        const requestOptions: https.RequestOptions = {
          host: 'localhost',
          port,
          path: '/metrics',
          method: 'GET',
          headers: { Authorization: `Bearer ${adminToken}` },
          ca: TEST_CA_CERT,
          rejectUnauthorized: true,
          ...options,
        };
        const req = https.request(requestOptions, (res) => {
          reject(new Error(`unexpected response ${res.statusCode ?? 'unknown'}`));
        });
        req.on('error', (error) => reject(error));
        req.end();
      });

    await expect(expectRequestFailure()).rejects.toMatchObject({
      code: expect.stringMatching(/^(ERR_TLS_|ERR_SSL_|ECONNRESET$)/u),
    });

    await expect(
      expectRequestFailure({ key: TEST_SERVER_KEY, cert: TEST_CLIENT_CERT }),
    ).rejects.toMatchObject({
      code: expect.stringMatching(/^(ERR_TLS_|ERR_OSSL_)/u),
    });

    await expect(
      attemptTlsConnection({ secureProtocol: 'TLSv1_1_method' }),
    ).rejects.toMatchObject({
      code: expect.stringMatching(/^(ERR_TLS_|ERR_SSL_)/u),
    });

    const performAuthorizedRequest = () =>
      new Promise<{ status: number; body: string }>((resolve, reject) => {
        const requestOptions: https.RequestOptions = {
          host: 'localhost',
          port,
          path: '/metrics',
          method: 'GET',
          headers: { Authorization: `Bearer ${adminToken}` },
          ca: TEST_CA_CERT,
          rejectUnauthorized: true,
          key: TEST_CLIENT_KEY,
          cert: TEST_CLIENT_CERT,
        };
        const req = https.request(requestOptions, (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
          res.on('end', () => {
            resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') });
          });
        });
        req.on('error', reject);
        req.end();
      });

    const authorized = await performAuthorizedRequest();
    expect(authorized.status).toBe(200);

    await new Promise<void>((resolve) => httpsServer.close(() => resolve()));
  });

  it('requires a license token for analyze, report, and pack requests', async () => {
    const analyzeResponse = await request(app)
      .post('/v1/analyze')
      .set('Authorization', `Bearer ${token}`)
      .send({ importId: 'missing-import' })
      .expect(401);
    expect(analyzeResponse.body.error.code).toBe('LICENSE_REQUIRED');

    const reportResponse = await request(app)
      .post('/v1/report')
      .set('Authorization', `Bearer ${token}`)
      .send({ analysisId: 'missing-analysis' })
      .expect(401);
    expect(reportResponse.body.error.code).toBe('LICENSE_REQUIRED');

    const packResponse = await request(app)
      .post('/v1/pack')
      .set('Authorization', `Bearer ${token}`)
      .send({ reportId: 'missing-report' })
      .expect(401);
    expect(packResponse.body.error.code).toBe('LICENSE_REQUIRED');
  });

  it('enforces license feature entitlements for pipeline routes', async () => {
    const basePayload = {
      licenseId: 'feature-test',
      issuedTo: 'Feature Tester',
      issuedAt: new Date().toISOString(),
    };
    let currentFeatures: string[] = [];

    await jest.isolateModulesAsync(async () => {
      jest.doMock('@soipack/cli', () => {
        const actual = jest.requireActual('@soipack/cli');
        return {
          ...actual,
          verifyLicenseFile: jest.fn(async () => ({
            ...basePayload,
            features: currentFeatures.length ? [...currentFeatures] : undefined,
          })),
        };
      });

      const { createServer: createServerWithMock } = await import('./index');
      const featureApp = createServerWithMock({
        ...baseConfig,
        metricsRegistry: new Registry(),
      });

      const expectDenied = async (
        path: string,
        configure: (req: request.Test) => request.Test,
        feature: string,
      ) => {
        currentFeatures = [];
        const headerValue = Buffer.from(
          `feature-denied-${feature}-${Math.random().toString(36).slice(2)}`,
        ).toString('base64');
        const response = await configure(
          request(featureApp)
            .post(path)
            .set('Authorization', `Bearer ${token}`)
            .set('X-SOIPACK-License', headerValue),
        ).expect(403);
        expect(response.body.error.code).toBe('LICENSE_FEATURE_REQUIRED');
        expect(response.body.error.details).toEqual(expect.objectContaining({ requiredFeature: feature }));
      };

      await expectDenied(
        '/v1/import',
        (req) =>
          req
            .attach('reqif', minimalExample('spec.reqif'))
            .field('projectName', 'Feature Project')
            .field('projectVersion', '1.0.0'),
        'import',
      );
      await expectDenied(
        '/v1/analyze',
        (req) => req.send({ importId: 'aaaaaaaaaaaaaaaa' }),
        'analyze',
      );
      await expectDenied(
        '/v1/report',
        (req) => req.send({ analysisId: 'bbbbbbbbbbbbbbbb' }),
        'report',
      );
      await expectDenied(
        '/v1/pack',
        (req) => req.send({ reportId: 'cccccccccccccccc' }),
        'pack',
      );

      currentFeatures = ['import', 'analyze', 'report', 'pack'];
      const allowedHeader = Buffer.from(
        `feature-allowed-${Math.random().toString(36).slice(2)}`,
      ).toString('base64');

      const allowedImport = await request(featureApp)
        .post('/v1/import')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', allowedHeader)
        .attach('reqif', minimalExample('spec.reqif'))
        .field('projectName', 'Feature Project')
        .field('projectVersion', '1.0.1');
      expect([200, 202]).toContain(allowedImport.status);

      const allowedAnalyze = await request(featureApp)
        .post('/v1/analyze')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', Buffer.from(`feature-allowed-analyze-${Math.random()
            .toString(36)
            .slice(2)}`).toString('base64'))
        .send({ importId: 'aaaaaaaaaaaaaaaa' });
      expect(allowedAnalyze.status).toBe(404);

      const allowedReport = await request(featureApp)
        .post('/v1/report')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', Buffer.from(`feature-allowed-report-${Math.random()
            .toString(36)
            .slice(2)}`).toString('base64'))
        .send({ analysisId: 'bbbbbbbbbbbbbbbb' });
      expect(allowedReport.status).toBe(404);

      const allowedPack = await request(featureApp)
        .post('/v1/pack')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', Buffer.from(`feature-allowed-pack-${Math.random()
            .toString(36)
            .slice(2)}`).toString('base64'))
        .send({ reportId: 'cccccccccccccccc' });
      expect(allowedPack.status).toBe(404);
    });

    jest.resetModules();
    jest.dontMock('@soipack/cli');
  });

  it('enforces per-field size limits before queuing import jobs', async () => {
    const limitedStorageDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'soipack-limit-test-'));
    const limitedApp = createServer({
      ...baseConfig,
      storageDir: limitedStorageDir,
      maxUploadSizeBytes: 1024,
      uploadPolicies: {
        jira: { maxSizeBytes: 32, allowedMimeTypes: ['application/json'] },
      },
      metricsRegistry: new Registry(),
    });

    try {
      const response = await request(limitedApp)
        .post('/v1/import')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .attach('jira', Buffer.from('a'.repeat(64)), {
          filename: 'jira.json',
          contentType: 'application/json',
        })
        .expect(413);

      expect(response.body.error.code).toBe('FILE_TOO_LARGE');
      expect(response.body.error.details.limit).toBe(32);
    } finally {
      await fsPromises.rm(limitedStorageDir, { recursive: true, force: true });
    }
  });

  it('enforces the global upload size limit before processing files', async () => {
    const limitedStorageDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'soipack-global-limit-'));
    const limitedApp = createServer({
      ...baseConfig,
      storageDir: limitedStorageDir,
      maxUploadSizeBytes: 32,
      metricsRegistry: new Registry(),
    });

    try {
      const response = await request(limitedApp)
        .post('/v1/import')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .attach('reqif', Buffer.from('a'.repeat(128)), {
          filename: 'spec.reqif',
          contentType: 'application/xml',
        })
        .expect(500);

      expect(response.body.error.code).toBe('UNEXPECTED_ERROR');
      expect(response.body.error.details?.cause).toBe('File too large');
    } finally {
      await fsPromises.rm(limitedStorageDir, { recursive: true, force: true });
    }
  });

  it('rejects new jobs once the tenant queue limit is reached', async () => {
    const limitedRegistry = new Registry();
    const runImportSpy = jest.spyOn(cli, 'runImport');
    const importStarted = createDeferred<void>();
    const allowImportToFinish = createDeferred<void>();
    runImportSpy.mockImplementation(async () => {
      importStarted.resolve();
      await allowImportToFinish.promise;
      const workspace: cli.ImportWorkspace = {
        requirements: [],
        testResults: [],
        traceLinks: [],
        testToCodeMap: {},
        evidenceIndex: {},
        findings: [],
        builds: [],
        metadata: {
          generatedAt: new Date().toISOString(),
          warnings: [],
          inputs: {},
          version: buildSnapshotVersion(),
        },
      };
      return {
        workspace,
        workspacePath: 'workspace.json',
        warnings: [],
      } satisfies Awaited<ReturnType<typeof cli.runImport>>;
    });

    const limitedApp = createServer({
      ...baseConfig,
      metricsRegistry: limitedRegistry,
      maxQueuedJobsPerTenant: 1,
    });

    const projectVersion = `queue-limit-${Date.now()}`;

    try {
      const firstResponse = await request(limitedApp)
        .post('/v1/import')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .attach('reqif', minimalExample('spec.reqif'))
        .attach('junit', minimalExample('results.xml'))
        .attach('lcov', minimalExample('lcov.info'))
        .field('projectName', 'Queue Limit Demo')
        .field('projectVersion', projectVersion)
        .expect(202);

      await importStarted.promise;

      let metricSnapshot = await limitedRegistry.getSingleMetricAsString('soipack_job_queue_depth');
      expect(metricSnapshot).toContain(`soipack_job_queue_depth{tenantId="${tenantId}"} 1`);

      const secondResponse = await request(limitedApp)
        .post('/v1/import')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .attach('reqif', minimalExample('spec.reqif'))
        .attach('junit', minimalExample('results.xml'))
        .attach('lcov', minimalExample('lcov.info'))
        .field('projectName', 'Queue Limit Demo')
        .field('projectVersion', `${projectVersion}-retry`)
        .expect(429);

      expect(secondResponse.body.error.code).toBe('QUEUE_LIMIT_EXCEEDED');
      expect(secondResponse.body.error.details.limit).toBe(1);
      expect(secondResponse.body.error.details.scope).toBe('tenant');
      expect(runImportSpy).toHaveBeenCalledTimes(1);

      allowImportToFinish.resolve();

      await waitForJobCompletion(limitedApp, token, firstResponse.body.id);

      metricSnapshot = await limitedRegistry.getSingleMetricAsString('soipack_job_queue_depth');
      expect(metricSnapshot).toContain(`soipack_job_queue_depth{tenantId="${tenantId}"} 0`);
    } finally {
      allowImportToFinish.resolve();
      runImportSpy.mockRestore();
    }
  });

  it('runs jobs in parallel up to the configured worker concurrency and enforces the global queue limit', async () => {
    const concurrencyRegistry = new Registry();
    const runImportSpy = jest.spyOn(cli, 'runImport');
    const releaseDeferreds: Array<ReturnType<typeof createDeferred<void>>> = [];
    let running = 0;
    let maxRunning = 0;

    const buildImportResult = () => {
      const workspace: cli.ImportWorkspace = {
        requirements: [],
        testResults: [],
        traceLinks: [],
        testToCodeMap: {},
        evidenceIndex: {},
        findings: [],
        builds: [],
        metadata: {
          generatedAt: new Date().toISOString(),
          warnings: [],
          inputs: {},
          version: buildSnapshotVersion(),
        },
      };
      return {
        workspace,
        workspacePath: 'workspace.json',
        warnings: [],
      } satisfies Awaited<ReturnType<typeof cli.runImport>>;
    };

    runImportSpy.mockImplementation(() => {
      running += 1;
      maxRunning = Math.max(maxRunning, running);
      const deferred = createDeferred<void>();
      releaseDeferreds.push(deferred);
      return deferred.promise
        .then(() => buildImportResult())
        .finally(() => {
          running -= 1;
        });
    });

    const concurrencyApp = createServer({
      ...baseConfig,
      metricsRegistry: concurrencyRegistry,
      workerConcurrency: 2,
      maxQueuedJobsPerTenant: 5,
      maxQueuedJobsTotal: 3,
    });

    const projectVersion = `global-limit-${Date.now()}`;

    const firstRequest = request(concurrencyApp)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .attach('junit', minimalExample('results.xml'))
      .attach('lcov', minimalExample('lcov.info'))
      .field('projectName', 'Concurrency Demo')
      .field('projectVersion', `${projectVersion}-1`)
      .expect(202);

    const secondRequest = request(concurrencyApp)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .attach('junit', minimalExample('results.xml'))
      .attach('lcov', minimalExample('lcov.info'))
      .field('projectName', 'Concurrency Demo')
      .field('projectVersion', `${projectVersion}-2`)
      .expect(202);

    const thirdRequest = request(concurrencyApp)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .attach('junit', minimalExample('results.xml'))
      .attach('lcov', minimalExample('lcov.info'))
      .field('projectName', 'Concurrency Demo')
      .field('projectVersion', `${projectVersion}-3`)
      .expect(202);

    const [firstQueued, secondQueued, thirdQueued] = await Promise.all([
      firstRequest,
      secondRequest,
      thirdRequest,
    ]);

    try {
      await waitForCondition(async () => {
        const response = await request(concurrencyApp)
          .get('/v1/jobs')
          .set('Authorization', `Bearer ${token}`)
          .set('X-SOIPACK-License', licenseHeader)
          .expect(200);
        const jobs = response.body.jobs as Array<{ status: string }>;
        const running = jobs.filter((job) => job.status === 'running').length;
        return jobs.length >= 3 && running >= 2;
      });
      await waitForCondition(() => releaseDeferreds.length >= 2);
      expect(runImportSpy.mock.calls.length).toBeGreaterThanOrEqual(2);
      expect(releaseDeferreds.length).toBeGreaterThanOrEqual(2);

      let metricSnapshot = await concurrencyRegistry.getSingleMetricAsString('soipack_job_queue_total');
      expect(metricSnapshot).toContain('soipack_job_queue_total 3');

      const overflowResponse = await request(concurrencyApp)
        .post('/v1/import')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .attach('reqif', minimalExample('spec.reqif'))
        .attach('junit', minimalExample('results.xml'))
        .attach('lcov', minimalExample('lcov.info'))
        .field('projectName', 'Concurrency Demo')
        .field('projectVersion', `${projectVersion}-overflow`)
        .expect(429);

      expect(overflowResponse.body.error.code).toBe('QUEUE_LIMIT_EXCEEDED');
      expect(overflowResponse.body.error.details.limit).toBe(3);
      expect(overflowResponse.body.error.details.scope).toBe('global');

      const releaseNext = async () => {
        const next = releaseDeferreds.shift();
        if (next) {
          next.resolve();
          await delay(0);
        }
      };

      await releaseNext();
      await waitForCondition(async () => {
        const response = await request(concurrencyApp)
          .get('/v1/jobs')
          .set('Authorization', `Bearer ${token}`)
          .set('X-SOIPACK-License', licenseHeader)
          .expect(200);
        const jobs = response.body.jobs as Array<{ status: string }>;
        const running = jobs.filter((job) => job.status === 'running').length;
        const completed = jobs.filter((job) => job.status === 'completed').length;
        return running >= 2 && completed >= 1;
      });
      await waitForCondition(() => releaseDeferreds.length >= 2);
      await releaseNext();
      await waitForCondition(() => releaseDeferreds.length === 1);
      await releaseNext();

      await Promise.all([
        waitForJobCompletion(concurrencyApp, token, firstQueued.body.id),
        waitForJobCompletion(concurrencyApp, token, secondQueued.body.id),
        waitForJobCompletion(concurrencyApp, token, thirdQueued.body.id),
      ]);

      expect(maxRunning).toBe(2);
      expect(running).toBe(0);

      metricSnapshot = await concurrencyRegistry.getSingleMetricAsString('soipack_job_queue_total');
      expect(metricSnapshot).toContain('soipack_job_queue_total 0');
    } finally {
      while (releaseDeferreds.length > 0) {
        const deferred = releaseDeferreds.shift();
        deferred?.resolve();
      }
      runImportSpy.mockRestore();
    }
  });

  it('resolves lifecycle waitForIdle only after running jobs finish', async () => {
    const runImportSpy = jest.spyOn(cli, 'runImport');
    const jobStarted = createDeferred<void>();
    const allowCompletion = createDeferred<void>();
    runImportSpy.mockImplementation(async () => {
      jobStarted.resolve();
      await allowCompletion.promise;
      const workspace: cli.ImportWorkspace = {
        requirements: [],
        testResults: [],
        traceLinks: [],
        testToCodeMap: {},
        evidenceIndex: {},
        findings: [],
        builds: [],
        metadata: {
          generatedAt: new Date().toISOString(),
          warnings: [],
          inputs: {},
          version: buildSnapshotVersion(),
        },
      };
      return {
        workspace,
        workspacePath: 'workspace.json',
        warnings: [],
      } satisfies Awaited<ReturnType<typeof cli.runImport>>;
    });

    const idleApp = createServer({
      ...baseConfig,
      metricsRegistry: new Registry(),
    });
    const projectVersion = `idle-${Date.now()}`;

    try {
      const response = await request(idleApp)
        .post('/v1/import')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .attach('reqif', minimalExample('spec.reqif'))
        .attach('junit', minimalExample('results.xml'))
        .attach('lcov', minimalExample('lcov.info'))
        .field('projectName', 'Idle Wait Demo')
        .field('projectVersion', projectVersion)
        .expect(202);

      await jobStarted.promise;

      const lifecycle = getServerLifecycle(idleApp);
      const waitPromise = lifecycle.waitForIdle().then(() => true);

      await new Promise((resolve) => setTimeout(resolve, 100));
      await expect(Promise.race([waitPromise, Promise.resolve(false)])).resolves.toBe(false);

      allowCompletion.resolve();
      await waitPromise;

      await waitForJobCompletion(idleApp, token, response.body.id);
    } finally {
      allowCompletion.resolve();
      runImportSpy.mockRestore();
    }
  });

  it('rejects malicious uploads flagged by the scanning service', async () => {
    const scanningStorageDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'soipack-scan-test-'));
    const scanningScanner: FileScanner = {
      async scan(target) {
        if (target.field === 'jira') {
          return { clean: false, threat: 'EICAR-Test-File', engine: 'ClamAV' };
        }
        return { clean: true };
      },
    };
    const scanningApp = createServer({
      ...baseConfig,
      storageDir: scanningStorageDir,
      scanner: scanningScanner,
      metricsRegistry: new Registry(),
    });

    try {
      const response = await request(scanningApp)
        .post('/v1/import')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .attach('jira', Buffer.from('dummy content'), {
          filename: 'bad.zip',
          contentType: 'application/zip',
        })
        .expect(422);

      expect(response.body.error.code).toBe('FILE_SCAN_FAILED');
      expect(response.body.error.details.threat).toBe('EICAR-Test-File');
      expect(response.body.error.details.field).toBe('jira');
    } finally {
      await fsPromises.rm(scanningStorageDir, { recursive: true, force: true });
    }
  });

  it('rejects malformed import and pipeline payloads', async () => {
    const noFilesResponse = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .field('projectName', 'No Files Project')
      .expect(400);
    expect(noFilesResponse.body.error.code).toBe('NO_INPUT_FILES');

    const invalidAnalyze = await request(app)
      .post('/v1/analyze')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({})
      .expect(400);
    expect(invalidAnalyze.body.error.code).toBe('INVALID_REQUEST');

    const invalidReport = await request(app)
      .post('/v1/report')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({})
      .expect(400);
    expect(invalidReport.body.error.code).toBe('INVALID_REQUEST');

    const invalidPack = await request(app)
      .post('/v1/pack')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({})
      .expect(400);
    expect(invalidPack.body.error.code).toBe('INVALID_REQUEST');
  });

  it('rejects invalid job identifiers provided by clients', async () => {
    const invalidParamIds = ['../evil', '..%2Fevil', 'abc%2Fdef'];
    for (const invalidId of invalidParamIds) {
      const response = await request(app)
        .get(`/v1/jobs/${invalidId}`)
        .set('Authorization', `Bearer ${token}`)
        .expect(400);
      expect(response.body.error.code).toBe('INVALID_REQUEST');
    }

    const cancelResponse = await request(app)
      .post('/v1/jobs/..%2Fevil/cancel')
      .set('Authorization', `Bearer ${token}`)
      .expect(400);
    expect(cancelResponse.body.error.code).toBe('INVALID_REQUEST');

    const deleteResponse = await request(app)
      .delete('/v1/jobs/abc%2Fdef')
      .set('Authorization', `Bearer ${token}`)
      .expect(400);
    expect(deleteResponse.body.error.code).toBe('INVALID_REQUEST');

    for (const invalidId of ['../evil', 'abc/def', '..%2Fevil', 'abc%2Fdef']) {
      const analyzeResponse = await request(app)
        .post('/v1/analyze')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .send({ importId: invalidId })
        .expect(400);
      expect(analyzeResponse.body.error.code).toBe('INVALID_REQUEST');

      const reportResponse = await request(app)
        .post('/v1/report')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .send({ analysisId: invalidId })
        .expect(400);
      expect(reportResponse.body.error.code).toBe('INVALID_REQUEST');

      const packResponse = await request(app)
        .post('/v1/pack')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .send({ reportId: invalidId })
        .expect(400);
      expect(packResponse.body.error.code).toBe('INVALID_REQUEST');
    }

    for (const invalidId of ['../evil', 'abc%2Fdef']) {
      const packageResponse = await request(app)
        .get(`/v1/packages/${invalidId}`)
        .set('Authorization', `Bearer ${token}`)
        .expect(400);
      expect(packageResponse.body.error.code).toBe('INVALID_REQUEST');
    }
  });

  it('prevents path traversal when serving report assets', async () => {
    const importResponse = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .attach('junit', minimalExample('results.xml'))
      .attach('lcov', minimalExample('lcov.info'))
      .field('projectName', 'Traversal Project')
      .field('projectVersion', '1.0.0')
      .expect(202);

    const importJob = await waitForJobCompletion(app, token, importResponse.body.id);

    const analyzeResponse = await request(app)
      .post('/v1/analyze')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ importId: importJob.id })
      .expect(202);
    const analyzeJob = await waitForJobCompletion(app, token, analyzeResponse.body.id);

    const reportResponse = await request(app)
      .post('/v1/report')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ analysisId: analyzeJob.id })
      .expect(202);
    await waitForJobCompletion(app, token, reportResponse.body.id);

    const traversalAttempt = await request(app)
      .get(`/v1/reports/${reportResponse.body.id}/../secrets.txt`)
      .set('Authorization', `Bearer ${token}`)
      .expect(400);

    expect(traversalAttempt.body.error.code).toBe('INVALID_PATH');
  });

  it('deduplicates concurrent import submissions targeting the same payload', async () => {
    const projectVersion = `concurrent-${Date.now()}`;

    const submitImport = () =>
      request(app)
        .post('/v1/import')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .attach('reqif', minimalExample('spec.reqif'))
        .attach('junit', minimalExample('results.xml'))
        .attach('lcov', minimalExample('lcov.info'))
        .field('projectName', 'Concurrent Project')
        .field('projectVersion', projectVersion);

    const [firstResponse, secondResponse, thirdResponse] = await Promise.all([
      submitImport(),
      submitImport(),
      submitImport(),
    ]);

    expect(firstResponse.body.id).toHaveLength(16);
    expect([200, 202]).toContain(firstResponse.status);
    if (firstResponse.status === 200) {
      expect(firstResponse.body.reused).toBe(false);
      expect(firstResponse.body.status).toBe('completed');
    }

    const ids = new Set([firstResponse.body.id, secondResponse.body.id, thirdResponse.body.id]);
    expect(ids.size).toBe(1);

    [secondResponse, thirdResponse].forEach((response) => {
      expect([200, 202]).toContain(response.status);
      if (response.status === 202) {
        expect(response.body.reused === undefined || response.body.reused === false).toBe(true);
        expect(response.body.status === 'queued' || response.body.status === 'running').toBe(true);
      } else {
        expect(response.body.reused).toBe(true);
      }
    });

    const jobId = firstResponse.body.id;
    const job = await waitForJobCompletion(app, token, jobId);
    expect(job.status).toBe('completed');

    const reuseResponse = await submitImport().expect(200);
    expect(reuseResponse.body.id).toBe(jobId);
    expect(reuseResponse.body.reused).toBe(true);
    expect(reuseResponse.body.result.outputs.workspace).toBe(job.result.outputs.workspace);
  });

  it('processes pipeline jobs asynchronously with idempotent reuse', async () => {
    const importResponse = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .attach('junit', minimalExample('results.xml'))
      .attach('lcov', minimalExample('lcov.info'))
      .field('projectName', 'Minimal Project')
      .field('projectVersion', '1.0.0')
      .expect(202);

    expect(importResponse.body.id).toHaveLength(16);
    expect(importResponse.body.kind).toBe('import');
    expect(['queued', 'running']).toContain(importResponse.body.status);
    expect(importResponse.body.result).toBeUndefined();

    const importJob = await waitForJobCompletion(app, token, importResponse.body.id);
    expect(importJob.hash).toMatch(/^[a-f0-9]{64}$/u);
    expect(new Date(importJob.createdAt).getTime()).not.toBeNaN();
    expect(new Date(importJob.updatedAt).getTime()).not.toBeNaN();
    expect(importJob.result.outputs.workspace).toMatch(/^workspaces\//);
    expect(Array.isArray(importJob.result.warnings)).toBe(true);

    const uploadDir = path.join(storageDir, 'uploads', tenantId, importResponse.body.id);
    await expect(fsPromises.access(uploadDir, fs.constants.F_OK)).rejects.toThrow();

    const importList = await request(app)
      .get('/v1/jobs')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    const importSummary = importList.body.jobs.find(
      (job: { id: string }) => job.id === importResponse.body.id,
    );
    expect(importSummary).toBeDefined();
    expect(importSummary.hash).toBe(importJob.hash);
    expect(new Date(importSummary.createdAt).getTime()).not.toBeNaN();
    expect(new Date(importSummary.updatedAt).getTime()).not.toBeNaN();

    const importReuse = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .attach('junit', minimalExample('results.xml'))
      .attach('lcov', minimalExample('lcov.info'))
      .field('projectName', 'Minimal Project')
      .field('projectVersion', '1.0.0')
      .expect(200);

    expect(importReuse.body.id).toBe(importResponse.body.id);
    expect(importReuse.body.reused).toBe(true);
    expect(importReuse.body.result.outputs.workspace).toBe(importJob.result.outputs.workspace);

    const analyzeQueued = await request(app)
      .post('/v1/analyze')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ importId: importResponse.body.id })
      .expect(202);

    expect(analyzeQueued.body.kind).toBe('analyze');
    expect(analyzeQueued.body.result).toBeUndefined();

    const analyzeJob = await waitForJobCompletion(app, token, analyzeQueued.body.id);
    expect(analyzeJob.result.outputs.snapshot).toMatch(/^analyses\//);
    expect(typeof analyzeJob.result.exitCode).toBe('number');

    const analyzeDetails = await request(app)
      .get(`/v1/jobs/${analyzeQueued.body.id}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(analyzeDetails.body.hash).toBe(analyzeJob.hash);
    expect(analyzeDetails.body.result.outputs.directory).toBe(analyzeJob.result.outputs.directory);

    const analyzeReuse = await request(app)
      .post('/v1/analyze')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ importId: importResponse.body.id })
      .expect(200);
    expect(analyzeReuse.body.reused).toBe(true);
    expect(analyzeReuse.body.id).toBe(analyzeQueued.body.id);

    const reportQueued = await request(app)
      .post('/v1/report')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ analysisId: analyzeQueued.body.id })
      .expect(202);

    const reportJob = await waitForJobCompletion(app, token, reportQueued.body.id);
    expect(reportJob.result.outputs.complianceHtml).toMatch(/^reports\//);

    const otherTenantToken = await createAccessToken({ tenant: 'tenant-b' });
    const crossTenantJob = await request(app)
      .get(`/v1/jobs/${importResponse.body.id}`)
      .set('Authorization', `Bearer ${otherTenantToken}`)
      .expect(404);
    expect(crossTenantJob.body.error.code).toBe('JOB_NOT_FOUND');

    const reportReuse = await request(app)
      .post('/v1/report')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ analysisId: analyzeQueued.body.id })
      .expect(200);
    expect(reportReuse.body.reused).toBe(true);
    expect(reportReuse.body.id).toBe(reportQueued.body.id);

    const packQueued = await request(app)
      .post('/v1/pack')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ reportId: reportQueued.body.id })
      .expect(202);

    const packJob = await waitForJobCompletion(app, token, packQueued.body.id);
    expect(packJob.result.outputs.archive).toMatch(/^packages\//);
    expect(packJob.result.manifestId).toHaveLength(12);

    const packDetails = await request(app)
      .get(`/v1/jobs/${packQueued.body.id}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(packDetails.body.result.outputs.archive).toBe(packJob.result.outputs.archive);
    expect(packDetails.body.result.manifestId).toBe(packJob.result.manifestId);

    const packReuse = await request(app)
      .post('/v1/pack')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ reportId: reportQueued.body.id })
      .expect(200);
    expect(packReuse.body.reused).toBe(true);
    expect(packReuse.body.id).toBe(packQueued.body.id);

    const archivePath = path.resolve(storageDir, packJob.result.outputs.archive);
    await expect(fsPromises.access(archivePath, fs.constants.F_OK)).resolves.toBeUndefined();

    const manifestPath = path.resolve(storageDir, packJob.result.outputs.manifest);
    const manifestDir = path.dirname(manifestPath);
    const signaturePath = path.join(manifestDir, 'manifest.sig');
    const manifest = JSON.parse(await fsPromises.readFile(manifestPath, 'utf8')) as Manifest;
    const signature = (await fsPromises.readFile(signaturePath, 'utf8')).trim();
    expect(verifyManifestSignature(manifest, signature, TEST_SIGNING_CERTIFICATE)).toBe(true);

    const packFilter = await request(app)
      .get('/v1/jobs')
      .query({ kind: 'pack' })
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(packFilter.body.jobs.some((job: { id: string }) => job.id === packQueued.body.id)).toBe(true);
    expect(packFilter.body.jobs.every((job: { kind: string }) => job.kind === 'pack')).toBe(true);

    const completedFilter = await request(app)
      .get('/v1/jobs')
      .query({ status: 'completed' })
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(completedFilter.body.jobs.every((job: { status: string }) => job.status === 'completed')).toBe(true);

    const combinedFilter = await request(app)
      .get('/v1/jobs')
      .query({ kind: 'pack', status: 'completed' })
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(combinedFilter.body.jobs).toHaveLength(1);
    expect(combinedFilter.body.jobs[0].id).toBe(packQueued.body.id);

    const manifestResponse = await request(app)
      .get(`/v1/manifests/${packJob.result.manifestId}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(manifestResponse.body.manifestId).toBe(packJob.result.manifestId);
    expect(manifestResponse.body.jobId).toBe(packQueued.body.id);
    expect(manifestResponse.body.manifest).toEqual(manifest);

    const manifestForbidden = await request(app)
      .get(`/v1/manifests/${packJob.result.manifestId}`)
      .set('Authorization', `Bearer ${otherTenantToken}`)
      .expect(404);
    expect(manifestForbidden.body.error.code).toBe('MANIFEST_NOT_FOUND');

    const packageDownload = await request(app)
      .get(`/v1/packages/${packQueued.body.id}/archive`)
      .set('Authorization', `Bearer ${token}`)
      .buffer(true)
      .parse((res, callback) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => callback(null, Buffer.concat(chunks)));
      })
      .expect('Content-Type', /zip|octet-stream/)
      .expect(200);
    expect(packageDownload.headers['content-disposition']).toContain('.zip');
    expect(Buffer.isBuffer(packageDownload.body)).toBe(true);
    expect((packageDownload.body as Buffer).length).toBeGreaterThan(0);

    const manifestDownload = await request(app)
      .get(`/v1/packages/${packQueued.body.id}/manifest`)
      .set('Authorization', `Bearer ${token}`)
      .buffer(true)
      .parse((res, callback) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
        res.on('end', () => callback(null, Buffer.concat(chunks)));
      })
      .expect('Content-Type', /application\/json/)
      .expect(200);
    expect(manifestDownload.headers['content-disposition']).toContain('.json');
    const downloadedManifest = JSON.parse((manifestDownload.body as Buffer).toString('utf8')) as Manifest;
    expect(downloadedManifest).toEqual(manifest);

    const packageForbidden = await request(app)
      .get(`/v1/packages/${packQueued.body.id}/archive`)
      .set('Authorization', `Bearer ${otherTenantToken}`)
      .expect(404);
    expect(packageForbidden.body.error.code).toBe('PACKAGE_NOT_FOUND');

    const manifestForbiddenDownload = await request(app)
      .get(`/v1/packages/${packQueued.body.id}/manifest`)
      .set('Authorization', `Bearer ${otherTenantToken}`)
      .expect(404);
    expect(manifestForbiddenDownload.body.error.code).toBe('PACKAGE_NOT_FOUND');

    const reportAsset = await request(app)
      .get(`/v1/reports/${reportQueued.body.id}/compliance.html`)
      .set('Authorization', `Bearer ${token}`)
      .expect('Content-Type', /html/)
      .expect(200);

    expect(reportAsset.text).toContain('<html');

    const reportDetails = await request(app)
      .get(`/v1/jobs/${reportQueued.body.id}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(reportDetails.body.result.outputs.complianceHtml).toBe(
      reportJob.result.outputs.complianceHtml,
    );

    const forbiddenAsset = await request(app)
      .get(`/v1/reports/${reportQueued.body.id}/compliance.html`)
      .set('Authorization', `Bearer ${otherTenantToken}`)
      .expect(404);
    expect(forbiddenAsset.body.error.code).toBe('NOT_FOUND');

    const cleanupResponse = await request(app)
      .post('/v1/admin/cleanup')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(cleanupResponse.body.status).toBe('ok');
    expect(Array.isArray(cleanupResponse.body.summary)).toBe(true);
    const summaryByTarget = Object.fromEntries(
      cleanupResponse.body.summary.map((entry: { target: string }) => [entry.target, entry]),
    );

    (['uploads', 'analyses', 'reports', 'packages'] as const).forEach((target) => {
      expect(summaryByTarget[target]).toMatchObject({
        configured: true,
        retained: 0,
        skipped: 0,
      });
      expect(summaryByTarget[target].removed).toBeGreaterThanOrEqual(1);
    });

    await expect(fsPromises.access(uploadDir, fs.constants.F_OK)).rejects.toThrow();
    await expect(
      fsPromises.access(
        path.join(storageDir, 'workspaces', tenantId, importResponse.body.id),
        fs.constants.F_OK,
      ),
    ).rejects.toThrow();
    await expect(
      fsPromises.access(
        path.join(storageDir, 'analyses', tenantId, analyzeQueued.body.id),
        fs.constants.F_OK,
      ),
    ).rejects.toThrow();
    await expect(
      fsPromises.access(path.join(storageDir, 'reports', tenantId, reportQueued.body.id), fs.constants.F_OK),
    ).rejects.toThrow();
    await expect(
      fsPromises.access(path.join(storageDir, 'packages', tenantId, packQueued.body.id), fs.constants.F_OK),
    ).rejects.toThrow();

    await request(app)
      .get(`/v1/manifests/${packJob.result.manifestId}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(404);

    await request(app)
      .get(`/v1/packages/${packQueued.body.id}/archive`)
      .set('Authorization', `Bearer ${token}`)
      .expect(404);

    await request(app)
      .get(`/v1/packages/${packQueued.body.id}/manifest`)
      .set('Authorization', `Bearer ${token}`)
      .expect(404);
  });

  it('rejects pack jobs with unsafe package names', async () => {
    const unsafeTenant = `tenant-unsafe-${Date.now()}`;
    const unsafeToken = await createAccessToken({ tenant: unsafeTenant });

    const importResponse = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${unsafeToken}`)
      .set('X-SOIPACK-License', licenseHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .attach('junit', minimalExample('results.xml'))
      .attach('lcov', minimalExample('lcov.info'))
      .field('projectName', 'Unsafe Package Project')
      .field('projectVersion', '1.0.0')
      .expect(202);

    await waitForJobCompletion(app, unsafeToken, importResponse.body.id);

    const analyzeResponse = await request(app)
      .post('/v1/analyze')
      .set('Authorization', `Bearer ${unsafeToken}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ importId: importResponse.body.id })
      .expect(202);

    await waitForJobCompletion(app, unsafeToken, analyzeResponse.body.id);

    const reportResponse = await request(app)
      .post('/v1/report')
      .set('Authorization', `Bearer ${unsafeToken}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ analysisId: analyzeResponse.body.id })
      .expect(202);

    await waitForJobCompletion(app, unsafeToken, reportResponse.body.id);

    const invalidResponse = await request(app)
      .post('/v1/pack')
      .set('Authorization', `Bearer ${unsafeToken}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ reportId: reportResponse.body.id, packageName: '../../../escape-from-pack.zip' })
      .expect(400);

    expect(invalidResponse.body.error.code).toBe('INVALID_REQUEST');
    expect(invalidResponse.body.error.message).toContain('packageName');

    const tenantPackagesDir = path.join(storageDir, 'packages', unsafeTenant);
    await expect(fsPromises.access(tenantPackagesDir, fs.constants.F_OK)).rejects.toThrow();

    const escapePath = path.join(storageDir, 'escape-from-pack.zip');
    await expect(fsPromises.access(escapePath, fs.constants.F_OK)).rejects.toThrow();
  });

  it('supports cancelling queued jobs and deleting finished jobs', async () => {
    const originalRunImport = cli.runImport;
    const runImportSpy = jest.spyOn(cli, 'runImport');
    const firstImportGate = createDeferred<void>();
    runImportSpy.mockImplementationOnce(async (options) => {
      await firstImportGate.promise;
      return originalRunImport(options);
    });

    try {
      const firstImport = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .attach('junit', minimalExample('results.xml'))
      .attach('lcov', minimalExample('lcov.info'))
      .field('projectName', 'Queued Project')
      .field('projectVersion', '1.0.0')
      .expect(202);

      let firstJobRunning = false;
      for (let attempt = 0; attempt < 20; attempt += 1) {
        const statusResponse = await request(app)
          .get(`/v1/jobs/${firstImport.body.id}`)
          .set('Authorization', `Bearer ${token}`)
          .expect(200);
        if (statusResponse.body.status === 'running') {
          firstJobRunning = true;
          break;
        }
        await delay(50);
      }
      expect(firstJobRunning).toBe(true);

      const secondImport = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .attach('junit', minimalExample('results.xml'))
      .attach('lcov', minimalExample('lcov.info'))
      .field('projectName', 'Queued Project')
      .field('projectVersion', '2.0.0')
      .expect(202);

      expect(secondImport.body.status).toBe('queued');
      expect(secondImport.body.id).not.toBe(firstImport.body.id);

      const cancelResponse = await request(app)
      .post(`/v1/jobs/${secondImport.body.id}/cancel`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
      expect(cancelResponse.body.status).toBe('cancelled');

      await request(app)
      .get(`/v1/jobs/${secondImport.body.id}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(404);
      const cancelledWorkspace = path.join(storageDir, 'workspaces', tenantId, secondImport.body.id);
      await expect(fsPromises.access(cancelledWorkspace, fs.constants.F_OK)).rejects.toThrow();
      const cancelledUploads = path.join(storageDir, 'uploads', tenantId, secondImport.body.id);
      await expect(fsPromises.access(cancelledUploads, fs.constants.F_OK)).rejects.toThrow();

      firstImportGate.resolve();

      await waitForJobCompletion(app, token, firstImport.body.id);

      const deleteResponse = await request(app)
      .delete(`/v1/jobs/${firstImport.body.id}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
      expect(deleteResponse.body.status).toBe('deleted');

      await request(app)
      .get(`/v1/jobs/${firstImport.body.id}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(404);
      const deletedWorkspace = path.join(storageDir, 'workspaces', tenantId, firstImport.body.id);
      await expect(fsPromises.access(deletedWorkspace, fs.constants.F_OK)).rejects.toThrow();
      const deletedUploads = path.join(storageDir, 'uploads', tenantId, firstImport.body.id);
      await expect(fsPromises.access(deletedUploads, fs.constants.F_OK)).rejects.toThrow();
    } finally {
      firstImportGate.resolve();
      runImportSpy.mockRestore();
    }
  });

  it('emits structured logs and metrics for successful jobs', async () => {
    const projectVersion = `1.0.${Date.now()}`;
    const importResponse = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .attach('junit', minimalExample('results.xml'))
      .attach('lcov', minimalExample('lcov.info'))
      .field('projectName', 'Observability Project')
      .field('projectVersion', projectVersion)
      .expect(202);

    const importId: string = importResponse.body.id;
    await waitForJobCompletion(app, token, importId);

    const reuseResponse = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .attach('junit', minimalExample('results.xml'))
      .attach('lcov', minimalExample('lcov.info'))
      .field('projectName', 'Observability Project')
      .field('projectVersion', projectVersion)
      .expect(200);

    expect(reuseResponse.body.reused).toBe(true);

    await flushLogs();

    const creationLog = logEntries.find(
      (entry) => entry.event === 'job_created' && entry.jobId === importId,
    ) as Record<string, unknown> | undefined;
    expect(creationLog).toMatchObject({ tenantId, kind: 'import' });

    const completionLog = logEntries.find(
      (entry) => entry.event === 'job_completed' && entry.jobId === importId,
    ) as Record<string, unknown> | undefined;
    expect(completionLog).toBeDefined();
    expect(typeof completionLog?.durationMs).toBe('number');

    const reuseLog = logEntries.find(
      (entry) => entry.event === 'job_reused' && entry.jobId === importId,
    ) as Record<string, unknown> | undefined;
    expect(reuseLog).toMatchObject({ tenantId, kind: 'import', status: 'completed' });

    const metricsResponse = await request(app)
      .get('/metrics')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    const metricsLines = metricsResponse.text.split('\n');

    const durationLine = metricsLines.find((line) =>
      line.startsWith(
        `soipack_job_duration_seconds_count{tenantId="${tenantId}",kind="import",status="completed"}`,
      ),
    );
    expect(durationLine).toBeDefined();
    const durationCount = Number(durationLine?.split(' ').pop());
    expect(Number.isFinite(durationCount)).toBe(true);
    expect(durationCount).toBeGreaterThanOrEqual(1);

    const queueLine = metricsLines.find((line) =>
      line.startsWith(`soipack_job_queue_depth{tenantId="${tenantId}"}`),
    );
    expect(queueLine).toBe(`soipack_job_queue_depth{tenantId="${tenantId}"} 0`);

    const errorLine = metricsLines.find((line) =>
      line.startsWith(`soipack_job_errors_total{tenantId="${tenantId}",kind="import"`),
    );
    if (errorLine) {
      expect(errorLine.endsWith(' 0')).toBe(true);
    }
  });

  it('emits metrics and logs when a job fails', async () => {
    const failingStorageDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'soipack-fail-test-'));
    const failingSigningKeyPath = path.join(failingStorageDir, 'signing-key.pem');
    await fsPromises.writeFile(failingSigningKeyPath, TEST_SIGNING_BUNDLE, 'utf8');

    const failingLogCapture = createLogCapture();
    const failingRegistry = new Registry();

    const failingApp = createServer({
      ...baseConfig,
      storageDir: failingStorageDir,
      signingKeyPath: failingSigningKeyPath,
      logger: failingLogCapture.logger,
      metricsRegistry: failingRegistry,
    });

    try {
      const importResponse = await request(failingApp)
        .post('/v1/import')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .attach('reqif', minimalExample('spec.reqif'))
        .attach('junit', minimalExample('results.xml'))
        .attach('lcov', minimalExample('lcov.info'))
        .field('projectName', 'Failing Project')
        .field('projectVersion', '1.0.0')
        .expect(202);
      const importId: string = importResponse.body.id;
      await waitForJobCompletion(failingApp, token, importId);

      const analyzeResponse = await request(failingApp)
        .post('/v1/analyze')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .send({ importId })
        .expect(202);
      const analyzeId: string = analyzeResponse.body.id;
      await waitForJobCompletion(failingApp, token, analyzeId);

      const reportResponse = await request(failingApp)
        .post('/v1/report')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .send({ analysisId: analyzeId })
        .expect(202);
      const reportId: string = reportResponse.body.id;
      await waitForJobCompletion(failingApp, token, reportId);

      await fsPromises.rm(failingSigningKeyPath);

      const packResponse = await request(failingApp)
        .post('/v1/pack')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .send({ reportId })
        .expect(202);

      const failedJob = await waitForJobFailure(failingApp, token, packResponse.body.id);
      expect(failedJob.status).toBe('failed');

      await flushLogs();

      const packCreationLog = failingLogCapture.entries.find(
        (entry) => entry.event === 'job_created' && entry.jobId === packResponse.body.id,
      ) as Record<string, unknown> | undefined;
      expect(packCreationLog).toMatchObject({ tenantId, kind: 'pack' });

      const failureLog = failingLogCapture.entries.find(
        (entry) => entry.event === 'job_failed' && entry.jobId === packResponse.body.id,
      ) as Record<string, unknown> | undefined;
      expect(failureLog).toMatchObject({ tenantId, kind: 'pack' });
      expect((failureLog?.error as { code?: string } | undefined)?.code).toBe('PIPELINE_ERROR');

      const metricsResponse = await request(failingApp)
        .get('/metrics')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);
      const metricsLines = metricsResponse.text.split('\n');

      const failureDurationLine = metricsLines.find((line) =>
        line.startsWith(
          `soipack_job_duration_seconds_count{tenantId="${tenantId}",kind="pack",status="failed"}`,
        ),
      );
      expect(failureDurationLine).toBe(
        `soipack_job_duration_seconds_count{tenantId="${tenantId}",kind="pack",status="failed"} 1`,
      );

      const errorLine = metricsLines.find((line) =>
        line.startsWith(
          `soipack_job_errors_total{tenantId="${tenantId}",kind="pack",code="PIPELINE_ERROR"}`,
        ),
      );
      expect(errorLine).toBe(
        `soipack_job_errors_total{tenantId="${tenantId}",kind="pack",code="PIPELINE_ERROR"} 1`,
      );

      const queueDepthLine = metricsLines.find((line) =>
        line.startsWith(`soipack_job_queue_depth{tenantId="${tenantId}"}`),
      );
      expect(queueDepthLine).toBe(`soipack_job_queue_depth{tenantId="${tenantId}"} 0`);
    } finally {
      await fsPromises.rm(failingStorageDir, { recursive: true, force: true });
    }
  });
  it('runs retention sweeps on a schedule', async () => {
    const storageDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'soipack-retention-'));
    let retentionApp: ReturnType<typeof createServer> | undefined;
    try {
      retentionApp = createServer({
        ...baseConfig,
        storageDir,
        retention: { uploads: { maxAgeMs: 0 } },
        retentionScheduler: { intervalMs: 50 },
        metricsRegistry: new Registry(),
      });

      const tenantId = 'ret-scheduler';
      const jobId = 'aaaaaaaaaaaaaaaa';
      const workspaceDir = path.join(storageDir, 'workspaces', tenantId, jobId);
      const uploadDir = path.join(storageDir, 'uploads', tenantId, jobId);
      await fsPromises.mkdir(workspaceDir, { recursive: true });
      await fsPromises.mkdir(uploadDir, { recursive: true });
      const metadata = {
        tenantId,
        id: jobId,
        hash: 'hash',
        kind: 'import' as const,
        createdAt: new Date(Date.now() - 86_400_000).toISOString(),
        directory: workspaceDir,
        params: {},
        license: {
          hash: 'license-hash',
          licenseId: 'scheduled',
          issuedTo: 'tenant',
          issuedAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
          features: [],
        },
        warnings: [],
        outputs: { workspacePath: path.join(workspaceDir, 'workspace.json') },
      };
      await fsPromises.writeFile(path.join(workspaceDir, 'job.json'), JSON.stringify(metadata));

      await delay(200);

      await expect(fsPromises.access(workspaceDir)).rejects.toThrow();
      await expect(fsPromises.access(uploadDir)).rejects.toThrow();
    } finally {
      if (retentionApp) {
        await getServerLifecycle(retentionApp).shutdown();
      }
      await fsPromises.rm(storageDir, { recursive: true, force: true });
    }
  });

  it('logs HTTP requests with correlation identifiers and updates metrics', async () => {
    const logCapture = createLogCapture();
    const metricsRegistry = new Registry();
    const loggingApp = createServer({
      ...baseConfig,
      logger: logCapture.logger,
      metricsRegistry,
    });

    await request(loggingApp).get('/health').expect(200);
    await flushLogs();

    const httpLog = logCapture.entries.find(
      (entry) => entry.event === 'http_request' && entry.route === '/health',
    );
    expect(httpLog).toBeDefined();
    expect(typeof httpLog?.requestId).toBe('string');
    expect((httpLog?.requestId as string).length).toBeGreaterThanOrEqual(16);
    expect(httpLog?.status).toBe(200);
    expect(httpLog?.durationMs).toBeGreaterThanOrEqual(0);

    const metricsText = await metricsRegistry.metrics();
    expect(metricsText).toContain('soipack_http_requests_total');
    expect(metricsText).toContain('soipack_http_request_duration_seconds');
  });

  it('adopts completed jobs after a restart without rerunning pipelines', async () => {
    const runImportSpy = jest.spyOn(cli, 'runImport');
    runImportSpy.mockResolvedValue({
      workspace: {
        requirements: [],
        testResults: [],
        traceLinks: [],
        testToCodeMap: {},
        evidenceIndex: {},
        findings: [],
        builds: [],
        metadata: {
          generatedAt: new Date().toISOString(),
          warnings: [],
          inputs: {},
          version: buildSnapshotVersion(),
        },
      },
      workspacePath: 'workspace.json',
      warnings: [],
    } satisfies Awaited<ReturnType<typeof cli.runImport>>);

    const importResponse = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .attach('junit', minimalExample('results.xml'))
      .attach('lcov', minimalExample('lcov.info'))
      .field('projectName', 'Restart Demo')
      .field('projectVersion', `restart-${Date.now()}`)
      .expect(202);

    const importJob = await waitForJobCompletion(app, token, importResponse.body.id);
    expect(importJob.status).toBe('completed');

    const initialRuns = runImportSpy.mock.calls.length;

    const restartRegistry = new Registry();
    const restartApp = createServer({
      ...baseConfig,
      metricsRegistry: restartRegistry,
    });

    const adoptedResponse = await request(restartApp)
      .get(`/v1/jobs/${importResponse.body.id}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(adoptedResponse.body.status).toBe('completed');
    expect(adoptedResponse.body.id).toBe(importResponse.body.id);
    expect(runImportSpy.mock.calls.length).toBe(initialRuns);

    runImportSpy.mockRestore();
  });
});

