import { createHash } from 'crypto';
import { generateKeyPairSync, sign as signMessage } from 'crypto';
import fs, { promises as fsPromises } from 'fs';
import https from 'https';
import type { AddressInfo } from 'net';
import os from 'os';
import path from 'path';
import { Writable } from 'stream';
import tls from 'tls';
import EventSource from 'eventsource';

import * as cli from '@soipack/cli';
import { fetchJiraChangeRequests, type JiraChangeRequest } from '@soipack/adapters';
import {
  LedgerEntry,
  Manifest,
  createSnapshotVersion,
  deserializeLedgerProof,
  verifyLedgerProof,
} from '@soipack/core';
import type { RiskProfile } from '@soipack/engine';
import { verifyManifestSignature } from '@soipack/packager';
import { loadDefaultSphincsPlusKeyPair } from '@soipack/packager/security/pqc';
import { generateKeyPair, SignJWT, exportJWK, type JWK, type JSONWebKeySet, type KeyLike } from 'jose';
import pino from 'pino';
import { Registry } from 'prom-client';
import request from 'supertest';
import { Agent, setGlobalDispatcher } from 'undici';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';


import type { DatabaseManager } from './database';
import type { JobKind, JobStatus } from './queue';
import type { FileScanner } from './scanner';
import type { UserRole } from './middleware/auth';

import {
  createHttpsServer,
  createServer,
  getServerLifecycle,
  __clearChangeRequestCacheForTesting,
  __clearComplianceSummaryCacheForTesting,
  type ServerConfig,
} from './index';
import type { AppendAuditLogInput, AuditLogQueryOptions } from './audit';

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

jest.mock('@soipack/adapters', () => {
  const actual = jest.requireActual<typeof import('@soipack/adapters')>('@soipack/adapters');
  return {
    ...actual,
    fetchJiraChangeRequests: jest.fn(),
  };
});

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

const mockedFetchJiraChangeRequests =
  fetchJiraChangeRequests as jest.MockedFunction<typeof fetchJiraChangeRequests>;

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
  let cmsBundlePath: string;
  let licenseHeader: string;
  let licenseExpiresAt: Date | undefined;
  let privateKey: KeyLike;
  let jwks: JSONWebKeySet;
  let baseConfig: ServerConfig;
  let databaseStub: DatabaseStub;
  let metricsRegistry: Registry;
  let logEntries: Array<Record<string, unknown>>;
  let auditLogMock: AuditLogStoreMock;
  type StubJobRow = {
    id: string;
    tenantId: string;
    kind: JobKind;
    status: JobStatus;
    hash: string;
    payload?: unknown;
    result?: unknown;
    error?: { statusCode: number; code: string; message: string; details?: unknown };
    createdAt: Date;
    updatedAt: Date;
  };

  type StubRbacUser = {
    id: string;
    tenantId: string;
    email: string;
    displayName?: string | null;
    secretHash: string;
    createdAt: Date;
    updatedAt: Date;
  };

  type StubRbacRole = {
    id: string;
    tenantId: string;
    name: string;
    description?: string | null;
    createdAt: Date;
  };

  type StubRbacApiKey = {
    id: string;
    tenantId: string;
    label?: string | null;
    secretHash: string;
    fingerprint: string;
    createdAt: Date;
    lastUsedAt?: Date | null;
  };

  type StubReview = {
    id: string;
    tenantId: string;
    jobId?: string | null;
    reviewer?: string | null;
    decision: string;
    notes?: string | null;
    metadata: Record<string, unknown>;
    createdAt: Date;
    updatedAt: Date;
  };

  type StubWorkspaceDocument = {
    id: string;
    tenantId: string;
    workspaceId: string;
    kind: string;
    title: string;
    latestRevisionId?: string | null;
    latestRevisionHash?: string | null;
    createdAt: Date;
    updatedAt: Date;
  };

  type StubWorkspaceRevision = {
    id: string;
    documentId: string;
    tenantId: string;
    workspaceId: string;
    revision: number;
    hash: string;
    content: unknown;
    authorId: string;
    createdAt: Date;
  };

  type StubWorkspaceComment = {
    id: string;
    documentId: string;
    revisionId: string;
    tenantId: string;
    workspaceId: string;
    authorId: string;
    body: string;
    createdAt: Date;
  };

  type StubWorkspaceSignoff = {
    id: string;
    documentId: string;
    revisionId: string;
    tenantId: string;
    workspaceId: string;
    revisionHash: string;
    status: 'pending' | 'approved';
    requestedBy: string;
    requestedFor: string;
    signerId?: string | null;
    signerPublicKey?: string | null;
    signature?: string | null;
    signedAt?: Date | null;
    createdAt: Date;
    updatedAt: Date;
  };

  type DatabaseStub = {
    manager: DatabaseManager;
    pool: { query: jest.Mock<Promise<{ rows: unknown[]; rowCount: number }>, [string, unknown[]?]> };
    rows: Map<string, StubJobRow>;
    reviews: Map<string, StubReview>;
    rbacUsers: Map<string, StubRbacUser>;
    rbacRoles: Map<string, StubRbacRole>;
    rbacUserRoles: Set<string>;
    rbacApiKeys: Map<string, StubRbacApiKey>;
    workspaceDocuments: Map<string, StubWorkspaceDocument>;
    workspaceRevisions: Map<string, StubWorkspaceRevision>;
    workspaceComments: Map<string, StubWorkspaceComment>;
    workspaceSignoffs: Map<string, StubWorkspaceSignoff>;
    reset: () => void;
    seedDefaults: () => void;
    ensureUser: (tenantId: string, userId: string, roles?: UserRole[], options?: { email?: string }) => void;
    failNext: (error: Error) => void;
  };

  const parseJson = (value: unknown): unknown => {
    if (value === null || value === undefined) {
      return undefined;
    }
    if (typeof value === 'string') {
      try {
        return JSON.parse(value);
      } catch {
        return undefined;
      }
    }
    return value;
  };

  const createDatabaseStub = (): DatabaseStub => {
    const rows = new Map<string, StubJobRow>();
    const reviews = new Map<string, StubReview>();
    const rbacUsers = new Map<string, StubRbacUser>();
    const rbacRoles = new Map<string, StubRbacRole>();
    const rbacUserRoles = new Set<string>();
    const rbacApiKeys = new Map<string, StubRbacApiKey>();
    const workspaceDocuments = new Map<string, StubWorkspaceDocument>();
    const workspaceRevisions = new Map<string, StubWorkspaceRevision>();
    const workspaceComments = new Map<string, StubWorkspaceComment>();
    const workspaceSignoffs = new Map<string, StubWorkspaceSignoff>();
    let failNextError: Error | undefined;

    const toDbRow = (row: StubJobRow): Record<string, unknown> => ({
      id: row.id,
      tenant_id: row.tenantId,
      kind: row.kind,
      status: row.status,
      hash: row.hash,
      payload: row.payload ?? null,
      result: row.result ?? null,
      error: row.error ?? null,
      created_at: row.createdAt,
      updated_at: row.updatedAt,
    });

    const userKey = (tenantId: string, userId: string) => `${tenantId}:${userId}`;
    const reviewKey = (tenantId: string, reviewId: string) => `${tenantId}:${reviewId}`;
    const roleKey = (tenantId: string, roleId: string) => `${tenantId}:${roleId}`;
    const apiKeyKey = (tenantId: string, apiKeyId: string) => `${tenantId}:${apiKeyId}`;
    const userRoleKey = (tenantId: string, userId: string, roleId: string) => `${tenantId}:${userId}:${roleId}`;
    const workspaceDocumentKey = (tenantId: string, workspaceId: string, documentId: string) =>
      `${tenantId}:${workspaceId}:${documentId}`;
    const workspaceRevisionKey = (tenantId: string, workspaceId: string, revisionId: string) =>
      `${tenantId}:${workspaceId}:${revisionId}`;
    const workspaceSignoffKey = (tenantId: string, workspaceId: string, signoffId: string) =>
      `${tenantId}:${workspaceId}:${signoffId}`;

    const mapUserRow = (user: StubRbacUser): Record<string, unknown> => ({
      id: user.id,
      tenant_id: user.tenantId,
      email: user.email,
      display_name: user.displayName ?? null,
      created_at: user.createdAt,
      updated_at: user.updatedAt,
    });

    const mapRoleRow = (role: StubRbacRole): Record<string, unknown> => ({
      id: role.id,
      tenant_id: role.tenantId,
      name: role.name,
      description: role.description ?? null,
      created_at: role.createdAt,
    });

    const mapApiKeyRow = (key: StubRbacApiKey): Record<string, unknown> => ({
      id: key.id,
      tenant_id: key.tenantId,
      label: key.label ?? null,
      fingerprint: key.fingerprint,
      created_at: key.createdAt,
      last_used_at: key.lastUsedAt ?? null,
    });

    const mapReviewRow = (review: StubReview): Record<string, unknown> => ({
      id: review.id,
      tenant_id: review.tenantId,
      job_id: review.jobId ?? null,
      reviewer: review.reviewer ?? null,
      decision: review.decision,
      notes: review.notes ?? null,
      metadata: review.metadata,
      created_at: review.createdAt,
      updated_at: review.updatedAt,
    });

    const mapWorkspaceDocumentRow = (document: StubWorkspaceDocument): Record<string, unknown> => ({
      id: document.id,
      tenant_id: document.tenantId,
      workspace_id: document.workspaceId,
      kind: document.kind,
      title: document.title,
      latest_revision_id: document.latestRevisionId ?? null,
      latest_revision_hash: document.latestRevisionHash ?? null,
      created_at: document.createdAt,
      updated_at: document.updatedAt,
    });

    const mapWorkspaceRevisionRow = (revision: StubWorkspaceRevision): Record<string, unknown> => ({
      id: revision.id,
      document_id: revision.documentId,
      tenant_id: revision.tenantId,
      workspace_id: revision.workspaceId,
      revision: revision.revision,
      hash: revision.hash,
      content: revision.content,
      author_id: revision.authorId,
      created_at: revision.createdAt,
    });

    const mapWorkspaceCommentRow = (comment: StubWorkspaceComment): Record<string, unknown> => ({
      id: comment.id,
      document_id: comment.documentId,
      revision_id: comment.revisionId,
      tenant_id: comment.tenantId,
      workspace_id: comment.workspaceId,
      author_id: comment.authorId,
      body: comment.body,
      created_at: comment.createdAt,
    });

    const mapWorkspaceSignoffRow = (signoff: StubWorkspaceSignoff): Record<string, unknown> => ({
      id: signoff.id,
      document_id: signoff.documentId,
      revision_id: signoff.revisionId,
      tenant_id: signoff.tenantId,
      workspace_id: signoff.workspaceId,
      revision_hash: signoff.revisionHash,
      status: signoff.status,
      requested_by: signoff.requestedBy,
      requested_for: signoff.requestedFor,
      signer_id: signoff.signerId ?? null,
      signer_public_key: signoff.signerPublicKey ?? null,
      signature: signoff.signature ?? null,
      signed_at: signoff.signedAt ?? null,
      created_at: signoff.createdAt,
      updated_at: signoff.updatedAt,
    });

    const ensureRoleRecord = (
      tenantId: string,
      name: string,
      description?: string | null,
      id?: string,
      createdAt?: Date,
    ): StubRbacRole => {
      const roleId = id ?? `role-${name}`;
      const key = roleKey(tenantId, roleId);
      const existing = rbacRoles.get(key);
      if (existing) {
        if (description !== undefined) {
          existing.description = description;
        }
        return existing;
      }
      const record: StubRbacRole = {
        id: roleId,
        tenantId,
        name,
        description: description ?? null,
        createdAt: createdAt ?? new Date(),
      };
      rbacRoles.set(key, record);
      return record;
    };

    const ensureUserRecord = (
      tenantId: string,
      userId: string,
      roles: UserRole[] = ['reader'],
      options?: { email?: string },
    ) => {
      const key = userKey(tenantId, userId);
      if (!rbacUsers.has(key)) {
        const now = new Date();
        rbacUsers.set(key, {
          id: userId,
          tenantId,
          email: options?.email ?? `${userId}@example.com`,
          displayName: options?.email ?? userId,
          secretHash: 'seed-secret-hash',
          createdAt: now,
          updatedAt: now,
        });
      }
      for (const entry of [...rbacUserRoles]) {
        if (entry.startsWith(`${tenantId}:${userId}:`)) {
          rbacUserRoles.delete(entry);
        }
      }
      roles.forEach((roleName) => {
        const role = ensureRoleRecord(tenantId, roleName, `${roleName} role`, `role-${roleName}`);
        rbacUserRoles.add(userRoleKey(tenantId, userId, role.id));
      });
    };

    const query = jest.fn(async (text: string, parameters?: unknown[]) => {
      if (failNextError) {
        const error = failNextError;
        failNextError = undefined;
        throw error;
      }
      const params = parameters ?? [];
      const normalized = text.replace(/\s+/g, ' ').trim().toLowerCase();

      if (normalized === 'select 1') {
        return { rows: [{ '?': 1 }], rowCount: 1 };
      }

      if (normalized.startsWith('select id, tenant_id, kind, status, hash, payload, result, error, created_at, updated_at from jobs order by created_at asc')) {
        const ordered = [...rows.values()].sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
        return { rows: ordered.map(toDbRow), rowCount: ordered.length };
      }

      if (normalized.startsWith('select id, tenant_id, kind, status, hash')) {
        if (normalized.includes('where id = $1 and tenant_id = $2 limit 1')) {
          const [scopedId, tenantId] = params as [string, string];
          const row = rows.get(scopedId);
          if (!row || row.tenantId !== tenantId) {
            return { rows: [], rowCount: 0 };
          }
          return { rows: [toDbRow(row)], rowCount: 1 };
        }
        if (normalized.includes('where tenant_id = $1 order by created_at desc')) {
          const [tenantId] = params as [string];
          const filtered = [...rows.values()]
            .filter((row) => row.tenantId === tenantId)
            .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
          return { rows: filtered.map(toDbRow), rowCount: filtered.length };
        }
      }

      if (normalized.startsWith('select id, tenant_id, job_id, reviewer, decision, notes, metadata, created_at, updated_at from reviews where tenant_id = $1 and id = $2 limit 1')) {
        const [tenantIdParam, reviewIdParam] = params as [string, string];
        const record = reviews.get(reviewKey(tenantIdParam, reviewIdParam));
        if (!record) {
          return { rows: [], rowCount: 0 };
        }
        return { rows: [mapReviewRow(record)], rowCount: 1 };
      }

      if (normalized.startsWith('insert into reviews')) {
        const [id, tenantIdParam, jobId, reviewer, decision, notes, metadataRaw, createdAtRaw] = params as [
          string,
          string,
          string | null,
          string | null,
          string,
          string | null,
          unknown,
          string,
        ];
        const createdAt = new Date(createdAtRaw);
        const metadataValue = parseJson(metadataRaw) as Record<string, unknown> | undefined;
        const record: StubReview = {
          id,
          tenantId: tenantIdParam,
          jobId: jobId ?? null,
          reviewer: reviewer ?? null,
          decision,
          notes: notes ?? null,
          metadata: metadataValue ?? {},
          createdAt,
          updatedAt: new Date(createdAtRaw),
        };
        reviews.set(reviewKey(tenantIdParam, id), record);
        return { rows: [mapReviewRow(record)], rowCount: 1 };
      }

      if (normalized.startsWith('update reviews set reviewer = $3, decision = $4, notes = $5, metadata = $6::jsonb, updated_at = $7 where tenant_id = $1 and id = $2 and metadata->>\'lockhash\' = $8 returning')) {
        const [tenantIdParam, reviewIdParam, reviewer, decision, notes, metadataRaw, updatedAtRaw, expectedHash] = params as [
          string,
          string,
          string | null,
          string,
          string | null,
          unknown,
          string,
          string,
        ];
        const key = reviewKey(tenantIdParam, reviewIdParam);
        const record = reviews.get(key);
        if (!record) {
          return { rows: [], rowCount: 0 };
        }
        const currentLock = String(
          ((record.metadata as { lockHash?: unknown }).lockHash ?? '') as string,
        );
        if (currentLock !== expectedHash) {
          return { rows: [], rowCount: 0 };
        }
        record.reviewer = reviewer ?? record.reviewer ?? null;
        record.decision = decision;
        record.notes = notes ?? null;
        const metadataValue = parseJson(metadataRaw) as Record<string, unknown> | undefined;
        record.metadata = metadataValue ?? {};
        record.updatedAt = new Date(updatedAtRaw);
        reviews.set(key, record);
        return { rows: [mapReviewRow(record)], rowCount: 1 };
      }

      if (normalized.startsWith('insert into jobs')) {
        const [id, tenantId, kind, status, hash, payloadRaw, resultRaw, errorRaw, createdAtRaw, updatedAtRaw] =
          params as [
            string,
            string,
            JobKind,
            JobStatus,
            string,
            unknown,
            unknown,
            unknown,
            string,
            string,
          ];
        if (rows.has(id)) {
          return { rows: [], rowCount: 0 };
        }
        const payload = parseJson(payloadRaw);
        const result = parseJson(resultRaw);
        const error = parseJson(errorRaw) as StubJobRow['error'];
        const createdAt = new Date(createdAtRaw);
        const updatedAt = new Date(updatedAtRaw);
        rows.set(id, {
          id,
          tenantId,
          kind,
          status,
          hash,
          payload: payload ?? undefined,
          result: result ?? undefined,
          error: error ?? undefined,
          createdAt,
          updatedAt,
        });
        return { rows: [], rowCount: 1 };
      }

      if (normalized.startsWith('update jobs set status = $1, updated_at = $2, error = null where id = $3 and tenant_id = $4')) {
        const [status, updatedAtRaw, scopedId] = params as [JobStatus, string, string, string];
        const row = rows.get(scopedId);
        if (row) {
          row.status = status;
          row.updatedAt = new Date(updatedAtRaw);
          delete row.error;
        }
        return { rows: [], rowCount: row ? 1 : 0 };
      }

      if (normalized.startsWith('update jobs set status = $1, updated_at = $2, result = $3, error = null where id = $4 and tenant_id = $5')) {
        const [status, updatedAtRaw, resultRaw, scopedId] = params as [JobStatus, string, unknown, string, string];
        const row = rows.get(scopedId);
        if (row) {
          row.status = status;
          row.updatedAt = new Date(updatedAtRaw);
          row.result = parseJson(resultRaw) ?? undefined;
          delete row.error;
        }
        return { rows: [], rowCount: row ? 1 : 0 };
      }

      if (normalized.startsWith('update jobs set status = $1, updated_at = $2, error = $3 where id = $4 and tenant_id = $5')) {
        const [status, updatedAtRaw, errorRaw, scopedId] = params as [JobStatus, string, unknown, string, string];
        const row = rows.get(scopedId);
        if (row) {
          row.status = status;
          row.updatedAt = new Date(updatedAtRaw);
          row.error = parseJson(errorRaw) as StubJobRow['error'];
        }
        return { rows: [], rowCount: row ? 1 : 0 };
      }

      if (normalized.startsWith('update jobs set status = $1, updated_at = $2 where id = $3 and tenant_id = $4')) {
        const [status, updatedAtRaw, scopedId] = params as [JobStatus, string, string, string];
        const row = rows.get(scopedId);
        if (row) {
          row.status = status;
          row.updatedAt = new Date(updatedAtRaw);
        }
        return { rows: [], rowCount: row ? 1 : 0 };
      }

      if (normalized.startsWith('delete from jobs where id = $1 and tenant_id = $2')) {
        const [scopedId] = params as [string, string];
        const existed = rows.delete(scopedId);
        return { rows: [], rowCount: existed ? 1 : 0 };
      }

      if (normalized.startsWith('select count(*)::int as count from jobs where tenant_id = $1 and status in ($2, $3)')) {
        const [tenantId, firstStatus, secondStatus] = params as [string, JobStatus, JobStatus];
        const count = [...rows.values()].filter(
          (row) => row.tenantId === tenantId && (row.status === firstStatus || row.status === secondStatus),
        ).length;
        return { rows: [{ count }], rowCount: 1 };
      }

      if (normalized.startsWith('select count(*)::int as count from jobs where status in ($1, $2)')) {
        const [firstStatus, secondStatus] = params as [JobStatus, JobStatus];
        const count = [...rows.values()].filter(
          (row) => row.status === firstStatus || row.status === secondStatus,
        ).length;
        return { rows: [{ count }], rowCount: 1 };
      }

      if (
        normalized.startsWith(
          'select id, tenant_id, workspace_id, kind, title, latest_revision_id, latest_revision_hash, created_at, updated_at from workspace_documents',
        )
      ) {
        const [tenantIdParam, workspaceIdParam, documentIdParam] = params as [string, string, string];
        const record = workspaceDocuments.get(
          workspaceDocumentKey(tenantIdParam, workspaceIdParam, documentIdParam),
        );
        if (!record) {
          return { rows: [], rowCount: 0 };
        }
        return { rows: [mapWorkspaceDocumentRow(record)], rowCount: 1 };
      }

      if (normalized.startsWith('insert into workspace_documents')) {
        const [
          id,
          tenantIdParam,
          workspaceIdParam,
          kind,
          title,
          latestRevisionId,
          latestRevisionHash,
          createdAtRaw,
          updatedAtRaw,
        ] = params as [string, string, string, string, string, string | null, string | null, string, string];
        workspaceDocuments.set(workspaceDocumentKey(tenantIdParam, workspaceIdParam, id), {
          id,
          tenantId: tenantIdParam,
          workspaceId: workspaceIdParam,
          kind,
          title,
          latestRevisionId: latestRevisionId ?? null,
          latestRevisionHash: latestRevisionHash ?? null,
          createdAt: new Date(createdAtRaw),
          updatedAt: new Date(updatedAtRaw),
        });
        return { rows: [], rowCount: 1 };
      }

      if (
        normalized.startsWith(
          'update workspace_documents set title = $4, latest_revision_id = $5, latest_revision_hash = $6, updated_at = $7 where tenant_id = $1 and workspace_id = $2 and id = $3',
        )
      ) {
        const [tenantIdParam, workspaceIdParam, documentIdParam, title, latestRevisionId, latestRevisionHash, updatedAtRaw] =
          params as [string, string, string, string, string | null, string | null, string];
        const key = workspaceDocumentKey(tenantIdParam, workspaceIdParam, documentIdParam);
        const record = workspaceDocuments.get(key);
        if (!record) {
          return { rows: [], rowCount: 0 };
        }
        record.title = title;
        record.latestRevisionId = latestRevisionId ?? null;
        record.latestRevisionHash = latestRevisionHash ?? null;
        record.updatedAt = new Date(updatedAtRaw);
        workspaceDocuments.set(key, record);
        return { rows: [], rowCount: 1 };
      }

      if (normalized.startsWith('insert into workspace_document_revisions')) {
        const [
          id,
          documentIdParam,
          tenantIdParam,
          workspaceIdParam,
          revision,
          hash,
          contentRaw,
          authorId,
          createdAtRaw,
        ] = params as [string, string, string, string, number, string, unknown, string, string];
        workspaceRevisions.set(workspaceRevisionKey(tenantIdParam, workspaceIdParam, id), {
          id,
          documentId: documentIdParam,
          tenantId: tenantIdParam,
          workspaceId: workspaceIdParam,
          revision,
          hash,
          content: parseJson(contentRaw) ?? null,
          authorId,
          createdAt: new Date(createdAtRaw),
        });
        return { rows: [], rowCount: 1 };
      }

      if (
        normalized.startsWith(
          'select id, document_id, tenant_id, workspace_id, revision, hash, content, author_id, created_at from workspace_document_revisions where tenant_id = $1 and workspace_id = $2 and id = $3 limit 1',
        )
      ) {
        const [tenantIdParam, workspaceIdParam, revisionIdParam] = params as [string, string, string];
        const record = workspaceRevisions.get(workspaceRevisionKey(tenantIdParam, workspaceIdParam, revisionIdParam));
        if (!record) {
          return { rows: [], rowCount: 0 };
        }
        return { rows: [mapWorkspaceRevisionRow(record)], rowCount: 1 };
      }

      if (
        normalized.startsWith(
          'select id, document_id, tenant_id, workspace_id, revision, hash, content, author_id, created_at from workspace_document_revisions where tenant_id = $1 and workspace_id = $2 and document_id = $3 and hash = $4 limit 1',
        )
      ) {
        const [tenantIdParam, workspaceIdParam, documentIdParam, hash] = params as [string, string, string, string];
        const record = [...workspaceRevisions.values()].find(
          (revision) =>
            revision.tenantId === tenantIdParam &&
            revision.workspaceId === workspaceIdParam &&
            revision.documentId === documentIdParam &&
            revision.hash === hash,
        );
        if (!record) {
          return { rows: [], rowCount: 0 };
        }
        return { rows: [mapWorkspaceRevisionRow(record)], rowCount: 1 };
      }

      if (
        normalized.startsWith(
          'select id, document_id, revision_id, tenant_id, workspace_id, author_id, body, created_at from workspace_document_comments where tenant_id = $1 and workspace_id = $2 and document_id = $3',
        )
      ) {
        const [tenantIdParam, workspaceIdParam, documentIdParam] = params as [string, string, string];
        let limitParamIndex = 3;
        let createdAfter: Date | undefined;
        let cursorId: string | undefined;
        if (normalized.includes('and (created_at > $4 or (created_at = $4 and id > $5))')) {
          const createdRaw = params[3] as string;
          const idRaw = params[4] as string;
          createdAfter = new Date(createdRaw);
          cursorId = idRaw;
          limitParamIndex = 5;
        }
        const limitParam = Number(params[limitParamIndex] ?? Number.MAX_SAFE_INTEGER);
        const comments = [...workspaceComments.values()]
          .filter(
            (comment) =>
              comment.tenantId === tenantIdParam &&
              comment.workspaceId === workspaceIdParam &&
              comment.documentId === documentIdParam,
          )
          .sort((a, b) => {
            const delta = a.createdAt.getTime() - b.createdAt.getTime();
            if (delta !== 0) {
              return delta;
            }
            return a.id.localeCompare(b.id);
          })
          .filter((comment) => {
            if (!createdAfter || !cursorId) {
              return true;
            }
            const diff = comment.createdAt.getTime() - createdAfter.getTime();
            if (diff > 0) {
              return true;
            }
            if (diff < 0) {
              return false;
            }
            return comment.id > cursorId;
          })
          .slice(0, limitParam);

        return { rows: comments.map(mapWorkspaceCommentRow), rowCount: comments.length };
      }

      if (normalized.startsWith('insert into workspace_document_comments')) {
        const [
          id,
          documentIdParam,
          revisionIdParam,
          tenantIdParam,
          workspaceIdParam,
          authorId,
          body,
          createdAtRaw,
        ] = params as [string, string, string, string, string, string, string, string];
        workspaceComments.set(id, {
          id,
          documentId: documentIdParam,
          revisionId: revisionIdParam,
          tenantId: tenantIdParam,
          workspaceId: workspaceIdParam,
          authorId,
          body,
          createdAt: new Date(createdAtRaw),
        });
        return { rows: [], rowCount: 1 };
      }

      if (normalized.startsWith('insert into workspace_signoffs')) {
        const [
          id,
          documentIdParam,
          revisionIdParam,
          tenantIdParam,
          workspaceIdParam,
          revisionHash,
          status,
          requestedBy,
          requestedFor,
          createdAtRaw,
        ] = params as [string, string, string, string, string, string, string, string, string, string];
        const createdAt = new Date(createdAtRaw);
        workspaceSignoffs.set(workspaceSignoffKey(tenantIdParam, workspaceIdParam, id), {
          id,
          documentId: documentIdParam,
          revisionId: revisionIdParam,
          tenantId: tenantIdParam,
          workspaceId: workspaceIdParam,
          revisionHash,
          status: status as 'pending' | 'approved',
          requestedBy,
          requestedFor,
          createdAt,
          updatedAt: createdAt,
        });
        return { rows: [], rowCount: 1 };
      }

      if (
        normalized.startsWith(
          'select id, document_id, revision_id, tenant_id, workspace_id, revision_hash, status, requested_by, requested_for, signer_id, signer_public_key, signature, signed_at, created_at, updated_at from workspace_signoffs where tenant_id = $1 and workspace_id = $2 and id = $3 limit 1',
        )
      ) {
        const [tenantIdParam, workspaceIdParam, signoffIdParam] = params as [string, string, string];
        const record = workspaceSignoffs.get(workspaceSignoffKey(tenantIdParam, workspaceIdParam, signoffIdParam));
        if (!record) {
          return { rows: [], rowCount: 0 };
        }
        return { rows: [mapWorkspaceSignoffRow(record)], rowCount: 1 };
      }

      if (
        normalized.startsWith(
          'select id, document_id, revision_id, tenant_id, workspace_id, revision_hash, status, requested_by, requested_for, signer_id, signer_public_key, signature, signed_at, created_at, updated_at from workspace_signoffs where tenant_id = $1 and workspace_id = $2 and document_id = $3 order by created_at asc, id asc',
        )
      ) {
        const [tenantIdParam, workspaceIdParam, documentIdParam] = params as [string, string, string];
        const results = [...workspaceSignoffs.values()]
          .filter(
            (record) =>
              record.tenantId === tenantIdParam &&
              record.workspaceId === workspaceIdParam &&
              record.documentId === documentIdParam,
          )
          .sort((a, b) => {
            const delta = a.createdAt.getTime() - b.createdAt.getTime();
            if (delta !== 0) {
              return delta;
            }
            return a.id.localeCompare(b.id);
          })
          .map(mapWorkspaceSignoffRow);
        return { rows: results, rowCount: results.length };
      }

      if (
        normalized.startsWith(
          "update workspace_signoffs set status = $4, signer_id = $5, signer_public_key = $6, signature = $7, signed_at = $8, updated_at = $9 where tenant_id = $1 and workspace_id = $2 and id = $3 and status = 'pending'",
        )
      ) {
        const [tenantIdParam, workspaceIdParam, signoffIdParam, status, signerId, signerPublicKey, signature, signedAtRaw, updatedAtRaw] =
          params as [string, string, string, string, string, string, string, string, string];
        const key = workspaceSignoffKey(tenantIdParam, workspaceIdParam, signoffIdParam);
        const record = workspaceSignoffs.get(key);
        if (!record || record.status !== 'pending') {
          return { rows: [], rowCount: 0 };
        }
        record.status = status as 'pending' | 'approved';
        record.signerId = signerId;
        record.signerPublicKey = signerPublicKey;
        record.signature = signature;
        record.signedAt = new Date(signedAtRaw);
        record.updatedAt = new Date(updatedAtRaw);
        workspaceSignoffs.set(key, record);
        return { rows: [], rowCount: 1 };
      }

      if (normalized.startsWith('insert into rbac_users')) {
        const [id, tenantIdParam, email, displayNameRaw, secretHash, createdAtRaw, updatedAtRaw] = params as [
          string,
          string,
          string,
          string | null,
          string,
          string | Date,
          string | Date | undefined,
        ];
        const createdAtSource = createdAtRaw ?? new Date();
        const updatedAtSource = updatedAtRaw ?? createdAtRaw ?? createdAtSource;
        const key = userKey(tenantIdParam, id);
        const existing = rbacUsers.get(key);
        const createdAt =
          existing?.createdAt ?? (createdAtSource instanceof Date ? createdAtSource : new Date(createdAtSource));
        const updatedAt = updatedAtSource instanceof Date ? updatedAtSource : new Date(updatedAtSource);
        const normalizedUpdatedAt = Number.isNaN(updatedAt.getTime()) ? new Date(createdAt.getTime()) : updatedAt;
        const record: StubRbacUser = {
          id,
          tenantId: tenantIdParam,
          email,
          displayName: displayNameRaw ?? null,
          secretHash,
          createdAt,
          updatedAt: normalizedUpdatedAt,
        };
        rbacUsers.set(key, record);
        return { rows: [mapUserRow(record)], rowCount: 1 };
      }

      if (normalized.startsWith('select id, tenant_id, email, display_name, created_at, updated_at from rbac_users where tenant_id = $1 order by created_at asc')) {
        const [tenantIdParam] = params as [string];
        const items = [...rbacUsers.values()]
          .filter((user) => user.tenantId === tenantIdParam)
          .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime())
          .map(mapUserRow);
        return { rows: items, rowCount: items.length };
      }

      if (normalized.startsWith('select id, tenant_id, email, display_name, created_at, updated_at from rbac_users where tenant_id = $1 and id = $2 limit 1')) {
        const [tenantIdParam, userIdParam] = params as [string, string];
        const record = rbacUsers.get(userKey(tenantIdParam, userIdParam));
        if (!record) {
          return { rows: [], rowCount: 0 };
        }
        return { rows: [mapUserRow(record)], rowCount: 1 };
      }

      if (normalized.startsWith('update rbac_users set secret_hash = $1, updated_at = $2 where tenant_id = $3 and id = $4')) {
        const [secretHash, updatedAtRaw, tenantIdParam, userIdParam] = params as [string, string, string, string];
        const key = userKey(tenantIdParam, userIdParam);
        const record = rbacUsers.get(key);
        if (record) {
          record.secretHash = secretHash;
          record.updatedAt = new Date(updatedAtRaw);
        }
        return { rows: [], rowCount: record ? 1 : 0 };
      }

      if (normalized.startsWith('select secret_hash from rbac_users where tenant_id = $1 and id = $2 limit 1')) {
        const [tenantIdParam, userIdParam] = params as [string, string];
        const record = rbacUsers.get(userKey(tenantIdParam, userIdParam));
        if (!record) {
          return { rows: [], rowCount: 0 };
        }
        return { rows: [{ secret_hash: record.secretHash }], rowCount: 1 };
      }

      if (normalized.startsWith('update rbac_users set display_name = $1, updated_at = $2 where tenant_id = $3 and id = $4')) {
        const [displayNameRaw, updatedAtRaw, tenantIdParam, userIdParam] = params as [
          string | null,
          string,
          string,
          string,
        ];
        const key = userKey(tenantIdParam, userIdParam);
        const record = rbacUsers.get(key);
        if (record) {
          record.displayName = displayNameRaw ?? null;
          record.updatedAt = new Date(updatedAtRaw);
        }
        return { rows: [], rowCount: record ? 1 : 0 };
      }

      if (normalized.startsWith('delete from rbac_users where tenant_id = $1 and id = $2')) {
        const [tenantIdParam, userIdParam] = params as [string, string];
        const key = userKey(tenantIdParam, userIdParam);
        const existed = rbacUsers.delete(key);
        [...rbacUserRoles].forEach((assignment) => {
          if (assignment.startsWith(`${tenantIdParam}:${userIdParam}:`)) {
            rbacUserRoles.delete(assignment);
          }
        });
        return { rows: [], rowCount: existed ? 1 : 0 };
      }

      if (normalized.startsWith('insert into rbac_roles')) {
        const [id, tenantIdParam, name, descriptionRaw, createdAtRaw] = params as [
          string,
          string,
          string,
          string | null,
          string,
        ];
        const record = ensureRoleRecord(tenantIdParam, name, descriptionRaw, id, new Date(createdAtRaw));
        return { rows: [mapRoleRow(record)], rowCount: 1 };
      }

      if (normalized.startsWith('select id, tenant_id, name, description, created_at from rbac_roles where tenant_id = $1 order by created_at asc')) {
        const [tenantIdParam] = params as [string];
        const items = [...rbacRoles.values()]
          .filter((role) => role.tenantId === tenantIdParam)
          .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime())
          .map(mapRoleRow);
        return { rows: items, rowCount: items.length };
      }

      if (normalized.startsWith('delete from rbac_roles where tenant_id = $1 and id = $2')) {
        const [tenantIdParam, roleIdParam] = params as [string, string];
        const existed = rbacRoles.delete(roleKey(tenantIdParam, roleIdParam));
        [...rbacUserRoles].forEach((assignment) => {
          if (assignment.endsWith(`:${roleIdParam}`) && assignment.startsWith(`${tenantIdParam}:`)) {
            rbacUserRoles.delete(assignment);
          }
        });
        return { rows: [], rowCount: existed ? 1 : 0 };
      }

      if (normalized.startsWith('insert into rbac_user_roles')) {
        const [tenantIdParam, userIdParam, roleIdParam] = params as [string, string, string, string];
        const assignmentKey = userRoleKey(tenantIdParam, userIdParam, roleIdParam);
        rbacUserRoles.add(assignmentKey);
        return { rows: [], rowCount: 1 };
      }

      if (normalized.startsWith('select r.id, r.tenant_id, r.name, r.description, r.created_at from rbac_roles r join rbac_user_roles ur')) {
        const [tenantIdParam, userIdParam] = params as [string, string];
        const roleIds = [...rbacUserRoles]
          .filter((assignment) => assignment.startsWith(`${tenantIdParam}:${userIdParam}:`))
          .map((assignment) => assignment.split(':')[2]);
        const roles = roleIds
          .map((roleId) => rbacRoles.get(roleKey(tenantIdParam, roleId)))
          .filter((role): role is StubRbacRole => role !== undefined)
          .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime())
          .map(mapRoleRow);
        return { rows: roles, rowCount: roles.length };
      }

      if (normalized.startsWith('delete from rbac_user_roles where tenant_id = $1 and user_id = $2 and role_id = $3')) {
        const [tenantIdParam, userIdParam, roleIdParam] = params as [string, string, string];
        const assignmentKey = userRoleKey(tenantIdParam, userIdParam, roleIdParam);
        const existed = rbacUserRoles.delete(assignmentKey);
        return { rows: [], rowCount: existed ? 1 : 0 };
      }

      if (normalized.startsWith('delete from rbac_user_roles where tenant_id = $1 and role_id = $2')) {
        const [tenantIdParam, roleIdParam] = params as [string, string];
        let count = 0;
        [...rbacUserRoles].forEach((assignment) => {
          if (assignment.startsWith(`${tenantIdParam}:`) && assignment.endsWith(`:${roleIdParam}`)) {
            rbacUserRoles.delete(assignment);
            count += 1;
          }
        });
        return { rows: [], rowCount: count };
      }

      if (normalized.startsWith('delete from rbac_user_roles where tenant_id = $1 and user_id = $2')) {
        const [tenantIdParam, userIdParam] = params as [string, string];
        let count = 0;
        [...rbacUserRoles].forEach((assignment) => {
          if (assignment.startsWith(`${tenantIdParam}:${userIdParam}:`)) {
            rbacUserRoles.delete(assignment);
            count += 1;
          }
        });
        return { rows: [], rowCount: count };
      }

      if (normalized.startsWith('insert into rbac_api_keys')) {
        const [id, tenantIdParam, labelRaw, secretHash, fingerprint, createdAtRaw] = params as [
          string,
          string,
          string | null,
          string,
          string,
          string,
          unknown,
        ];
        const key = apiKeyKey(tenantIdParam, id);
        const existing = rbacApiKeys.get(key);
        const record: StubRbacApiKey = {
          id,
          tenantId: tenantIdParam,
          label: labelRaw ?? null,
          secretHash,
          fingerprint,
          createdAt: existing?.createdAt ?? new Date(createdAtRaw),
          lastUsedAt: existing?.lastUsedAt ?? null,
        };
        rbacApiKeys.set(key, record);
        return { rows: [mapApiKeyRow(record)], rowCount: 1 };
      }

      if (normalized.startsWith('select id, tenant_id, label, fingerprint, created_at, last_used_at from rbac_api_keys where tenant_id = $1 order by created_at asc')) {
        const [tenantIdParam] = params as [string];
        const items = [...rbacApiKeys.values()]
          .filter((key) => key.tenantId === tenantIdParam)
          .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime())
          .map(mapApiKeyRow);
        return { rows: items, rowCount: items.length };
      }

      if (normalized.startsWith('select secret_hash from rbac_api_keys where tenant_id = $1 and id = $2 limit 1')) {
        const [tenantIdParam, apiKeyId] = params as [string, string];
        const record = rbacApiKeys.get(apiKeyKey(tenantIdParam, apiKeyId));
        if (!record) {
          return { rows: [], rowCount: 0 };
        }
        return { rows: [{ secret_hash: record.secretHash }], rowCount: 1 };
      }

      if (normalized.startsWith('delete from rbac_api_keys where tenant_id = $1 and id = $2')) {
        const [tenantIdParam, apiKeyId] = params as [string, string];
        const existed = rbacApiKeys.delete(apiKeyKey(tenantIdParam, apiKeyId));
        return { rows: [], rowCount: existed ? 1 : 0 };
      }

      throw new Error(`Unsupported query: ${text}`);
    });

    const pool = { query };
    const manager = {
      initialize: jest.fn().mockResolvedValue(undefined),
      close: jest.fn().mockResolvedValue(undefined),
      getPool: jest.fn(() => pool),
    } as unknown as DatabaseManager;

    const seedDefaults = () => {
      rbacUsers.clear();
      rbacRoles.clear();
      rbacUserRoles.clear();
      rbacApiKeys.clear();
      reviews.clear();
      workspaceDocuments.clear();
      workspaceRevisions.clear();
      workspaceComments.clear();
      workspaceSignoffs.clear();
      ensureRoleRecord(tenantId, 'admin', 'Administrator', 'role-admin');
      ensureRoleRecord(tenantId, 'maintainer', 'Maintainer', 'role-maintainer');
      ensureRoleRecord(tenantId, 'reader', 'Reader', 'role-reader');
      ensureUserRecord(tenantId, 'user-1', ['admin']);
    };

    return {
      manager,
      pool,
      rows,
      reviews,
      rbacUsers,
      rbacRoles,
      rbacUserRoles,
      rbacApiKeys,
      workspaceDocuments,
      workspaceRevisions,
      workspaceComments,
      workspaceSignoffs,
      reset: () => {
        rows.clear();
        reviews.clear();
        rbacUsers.clear();
        rbacRoles.clear();
        rbacUserRoles.clear();
        rbacApiKeys.clear();
        workspaceDocuments.clear();
        workspaceRevisions.clear();
        workspaceComments.clear();
        workspaceSignoffs.clear();
        query.mockClear();
        failNextError = undefined;
      },
      seedDefaults,
      ensureUser: ensureUserRecord,
      failNext: (error: Error) => {
        failNextError = error;
      },
    };
  };

  type AuditLogStoreMock = {
    store: {
      append: jest.Mock<
        Promise<{
          id: string;
          tenantId: string;
          actor: string;
          action: string;
          target?: string;
          payload?: unknown;
          createdAt: Date;
        }>,
        [AppendAuditLogInput]
      >;
      query: jest.Mock<
        Promise<{
          items: Array<{
            id: string;
            tenantId: string;
            actor: string;
            action: string;
            target?: string;
            payload?: unknown;
            createdAt: Date;
          }>;
          hasMore: boolean;
          nextOffset?: number;
        }>,
        [AuditLogQueryOptions]
      >;
    };
    appended: AppendAuditLogInput[];
    reset: () => void;
  };

  const createAuditLogStoreMock = (): AuditLogStoreMock => {
    const appended: AppendAuditLogInput[] = [];
    const append = jest.fn(async (input: AppendAuditLogInput) => {
      appended.push(input);
      return {
        id: input.id ?? `audit-${appended.length}`,
        tenantId: input.tenantId,
        actor: input.actor,
        action: input.action,
        target: input.target,
        payload: input.payload,
        createdAt: input.createdAt ? new Date(input.createdAt) : new Date(),
      };
    });
    const query = jest.fn(async (options: AuditLogQueryOptions) => {
      const filtered = appended.filter(
        (entry) =>
          entry.tenantId === options.tenantId &&
          (!options.actor || entry.actor === options.actor) &&
          (!options.action || entry.action === options.action) &&
          (!options.target || entry.target === options.target),
      );
      return {
        items: filtered.map((entry, index) => ({
          id: entry.id ?? `audit-query-${index}`,
          tenantId: entry.tenantId,
          actor: entry.actor,
          action: entry.action,
          target: entry.target,
          payload: entry.payload,
          createdAt: entry.createdAt ? new Date(entry.createdAt) : new Date(),
        })),
        hasMore: false,
        nextOffset: undefined,
      };
    });
    return {
      store: { append, query },
      appended,
      reset: () => {
        appended.length = 0;
        append.mockClear();
        query.mockClear();
      },
    };
  };

  const createAccessToken = async ({
    tenant = tenantId,
    subject = 'user-1',
    scope = `${requiredScope} ${adminScope}`,
    expiresIn = '2h',
    roles = ['admin'],
  }: {
    tenant?: string;
    subject?: string;
    scope?: string | null;
    expiresIn?: string | number;
    roles?: UserRole[];
  } = {}): Promise<string> => {
    const payload: Record<string, unknown> = { [tenantClaim]: tenant };
    if (scope) {
      payload.scope = scope;
    }

    if (databaseStub) {
      databaseStub.ensureUser(tenant, subject, roles);
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

  afterEach(() => {
    __clearComplianceSummaryCacheForTesting();
  });

  beforeAll(async () => {
    storageDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'soipack-server-test-'));
    signingKeyPath = path.join(storageDir, 'signing-key.pem');
    await fsPromises.writeFile(signingKeyPath, TEST_SIGNING_BUNDLE, 'utf8');
    licensePublicKeyPath = path.join(storageDir, 'license.pub');
    await fsPromises.writeFile(licensePublicKeyPath, LICENSE_PUBLIC_KEY_BASE64, 'utf8');
    cmsBundlePath = path.join(storageDir, 'cms-bundle.pem');
    await fsPromises.copyFile(
      path.resolve(__dirname, '../../../test/certs/cms-test.pem'),
      cmsBundlePath,
    );
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

    databaseStub = createDatabaseStub();
    databaseStub.seedDefaults();
    auditLogMock = createAuditLogStoreMock();

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
      database: databaseStub.manager,
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
      auditLogStore: auditLogMock.store,
      cmsSigning: { bundlePath: cmsBundlePath },
    };

    app = createServer(baseConfig);

    token = await createAccessToken();
  });

  beforeEach(() => {
    metricsRegistry?.resetMetrics();
    if (logEntries) {
      logEntries.length = 0;
    }
    databaseStub.reset();
    databaseStub.seedDefaults();
    auditLogMock.reset();
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
    expect(response.headers['content-security-policy']).toContain("default-src 'self'");
    expect(response.headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(response.headers['referrer-policy']).toBe('no-referrer');
    expect(response.headers['cross-origin-embedder-policy']).toBe('require-corp');
    expect(response.headers['cross-origin-opener-policy']).toBe('same-origin');
    expect(response.headers['cross-origin-resource-policy']).toBe('same-origin');
    expect(response.headers['permissions-policy']).toContain('accelerometer=()');
    expect(response.headers['permissions-policy']).toContain('geolocation=()');
    expect(response.headers['x-permitted-cross-domain-policies']).toBe('none');
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

  it('serves a cached compliance summary for the latest record', async () => {
    const token = await createAccessToken();

    const emptySummary = await request(app)
      .get('/v1/compliance/summary')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(emptySummary.body.latest).toBeNull();
    expect(typeof emptySummary.body.computedAt).toBe('string');

    const matrix = {
      project: 'Summary Demo',
      level: 'B',
      generatedAt: '2024-10-01T08:00:00Z',
      requirements: [
        { id: 'REQ-100', status: 'covered' as const, evidenceIds: [] },
        { id: 'REQ-200', status: 'partial' as const, evidenceIds: [] },
        { id: 'REQ-300', status: 'missing' as const, evidenceIds: [] },
      ],
      summary: { total: 3, covered: 1, partial: 1, missing: 1 },
    };

    const coverage = { statements: 82.5, functions: 61.25 };
    const canonicalPayload = buildCanonicalCompliancePayload(matrix, coverage, { release: '2024.10' });
    const complianceHash = createHash('sha256').update(JSON.stringify(canonicalPayload)).digest('hex');

    const complianceResponse = await request(app)
      .post('/compliance')
      .set('Authorization', `Bearer ${token}`)
      .send({
        sha256: complianceHash,
        matrix,
        coverage,
        metadata: { release: '2024.10' },
      })
      .expect(201);

    const summaryResponse = await request(app)
      .get('/v1/compliance/summary')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(summaryResponse.headers['cache-control']).toBe('private, max-age=60');
    expect(summaryResponse.body.latest).toMatchObject({
      id: complianceResponse.body.id,
      project: 'Summary Demo',
      level: 'B',
      summary: matrix.summary,
      coverage: expect.objectContaining({ statements: 82.5, functions: 61.25 }),
      gaps: {
        missingIds: ['REQ-300'],
        partialIds: ['REQ-200'],
        openObjectiveCount: 2,
      },
    });

    const cachedResponse = await request(app)
      .get('/v1/compliance/summary')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(cachedResponse.body.computedAt).toBe(summaryResponse.body.computedAt);
    expect(cachedResponse.body.latest).toEqual(summaryResponse.body.latest);
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

  it('preserves tenant evidence data when atomic rename fails', async () => {
    const atomicDir = await fsPromises.mkdtemp(path.join(storageDir, 'atomic-evidence-'));
    const atomicApp = createServer({ ...baseConfig, storageDir: atomicDir, metricsRegistry: new Registry() });
    const atomicToken = await createAccessToken();
    let renameSpy: jest.SpiedFunction<typeof fsPromises.rename> | undefined;

    try {
      const initialBuffer = Buffer.from('initial atomic evidence', 'utf8');
      const initialHash = createHash('sha256').update(initialBuffer).digest('hex');
      await request(atomicApp)
        .post('/evidence/upload')
        .set('Authorization', `Bearer ${atomicToken}`)
        .send({
          filename: 'initial.log',
          content: initialBuffer.toString('base64'),
          metadata: { sha256: initialHash, size: initialBuffer.length },
        })
        .expect(201);

      const evidencePath = path.join(atomicDir, 'tenants', tenantId, 'evidence.json');
      const originalContent = await fsPromises.readFile(evidencePath, 'utf8');

      const renameOriginal = fsPromises.rename.bind(fsPromises);
      let shouldFail = true;
      renameSpy = jest.spyOn(fsPromises, 'rename').mockImplementation(async (from, to) => {
        if (shouldFail && to === evidencePath) {
          shouldFail = false;
          throw Object.assign(new Error('rename failed'), { code: 'EPERM' });
        }
        return renameOriginal(from, to);
      });

      const failingBuffer = Buffer.from('failing atomic evidence', 'utf8');
      const failingHash = createHash('sha256').update(failingBuffer).digest('hex');
      await request(atomicApp)
        .post('/evidence/upload')
        .set('Authorization', `Bearer ${atomicToken}`)
        .send({
          filename: 'failing.log',
          content: failingBuffer.toString('base64'),
          metadata: { sha256: failingHash, size: failingBuffer.length },
        })
        .expect(500);

      const afterFailureContent = await fsPromises.readFile(evidencePath, 'utf8');
      expect(afterFailureContent).toBe(originalContent);

      renameSpy.mockRestore();
      renameSpy = undefined;

      const successBuffer = Buffer.from('successful atomic evidence', 'utf8');
      const successHash = createHash('sha256').update(successBuffer).digest('hex');
      const successResponse = await request(atomicApp)
        .post('/evidence/upload')
        .set('Authorization', `Bearer ${atomicToken}`)
        .send({
          filename: 'success.log',
          content: successBuffer.toString('base64'),
          metadata: { sha256: successHash, size: successBuffer.length },
        })
        .expect(201);

      expect(successResponse.body.sha256).toBe(successHash);

      const records = JSON.parse(await fsPromises.readFile(evidencePath, 'utf8')) as Array<{ sha256: string }>;
      expect(records).toHaveLength(2);
      expect(records[1].sha256).toBe(successHash);
    } finally {
      renameSpy?.mockRestore();
      await fsPromises.rm(atomicDir, { recursive: true, force: true });
    }
  });

  it('preserves tenant compliance data when atomic rename fails', async () => {
    const atomicDir = await fsPromises.mkdtemp(path.join(storageDir, 'atomic-compliance-'));
    const atomicApp = createServer({ ...baseConfig, storageDir: atomicDir, metricsRegistry: new Registry() });
    const atomicToken = await createAccessToken();
    let renameSpy: jest.SpiedFunction<typeof fsPromises.rename> | undefined;

    try {
      const evidenceBuffer = Buffer.from('compliance evidence', 'utf8');
      const evidenceHash = createHash('sha256').update(evidenceBuffer).digest('hex');
      const evidenceUpload = await request(atomicApp)
        .post('/evidence/upload')
        .set('Authorization', `Bearer ${atomicToken}`)
        .send({
          filename: 'compliance.log',
          content: evidenceBuffer.toString('base64'),
          metadata: { sha256: evidenceHash, size: evidenceBuffer.length },
        })
        .expect(201);

      const initialMatrix = {
        project: 'Atomic Compliance',
        level: 'B',
        generatedAt: '2024-10-01T12:00:00Z',
        requirements: [
          { id: 'REQ-A', status: 'covered' as const, evidenceIds: [evidenceUpload.body.id as string] },
        ],
        summary: { total: 1, covered: 1, partial: 0, missing: 0 },
      };
      const initialCoverage = { statements: 95.5 };
      const initialMetadata = { reviewer: 'qa' };
      const initialPayload = buildCanonicalCompliancePayload(initialMatrix, initialCoverage, initialMetadata);
      const initialHash = createHash('sha256').update(JSON.stringify(initialPayload)).digest('hex');

      await request(atomicApp)
        .post('/compliance')
        .set('Authorization', `Bearer ${atomicToken}`)
        .send({ matrix: initialMatrix, coverage: initialCoverage, metadata: initialMetadata, sha256: initialHash })
        .expect(201);

      const compliancePath = path.join(atomicDir, 'tenants', tenantId, 'compliance.json');
      const originalContent = await fsPromises.readFile(compliancePath, 'utf8');

      const renameOriginal = fsPromises.rename.bind(fsPromises);
      let shouldFail = true;
      renameSpy = jest.spyOn(fsPromises, 'rename').mockImplementation(async (from, to) => {
        if (shouldFail && to === compliancePath) {
          shouldFail = false;
          throw Object.assign(new Error('rename failed'), { code: 'EACCES' });
        }
        return renameOriginal(from, to);
      });

      const nextMatrix = {
        project: 'Atomic Compliance',
        level: 'B',
        generatedAt: '2024-10-02T12:00:00Z',
        requirements: [
          { id: 'REQ-B', status: 'covered' as const, evidenceIds: [evidenceUpload.body.id as string] },
        ],
        summary: { total: 1, covered: 1, partial: 0, missing: 0 },
      };
      const nextCoverage = { statements: 96.2 };
      const nextMetadata = { reviewer: 'qa', notes: 'daily update' };
      const nextPayload = buildCanonicalCompliancePayload(nextMatrix, nextCoverage, nextMetadata);
      const nextHash = createHash('sha256').update(JSON.stringify(nextPayload)).digest('hex');

      await request(atomicApp)
        .post('/compliance')
        .set('Authorization', `Bearer ${atomicToken}`)
        .send({ matrix: nextMatrix, coverage: nextCoverage, metadata: nextMetadata, sha256: nextHash })
        .expect(500);

      const afterFailureContent = await fsPromises.readFile(compliancePath, 'utf8');
      expect(afterFailureContent).toBe(originalContent);

      renameSpy.mockRestore();
      renameSpy = undefined;

      const finalMatrix = {
        project: 'Atomic Compliance',
        level: 'B',
        generatedAt: '2024-10-03T12:00:00Z',
        requirements: [
          { id: 'REQ-C', status: 'covered' as const, evidenceIds: [evidenceUpload.body.id as string] },
        ],
        summary: { total: 1, covered: 1, partial: 0, missing: 0 },
      };
      const finalCoverage = { statements: 97.1 };
      const finalMetadata = { reviewer: 'qa', notes: 'finalized' };
      const finalPayload = buildCanonicalCompliancePayload(finalMatrix, finalCoverage, finalMetadata);
      const finalHash = createHash('sha256').update(JSON.stringify(finalPayload)).digest('hex');

      const successResponse = await request(atomicApp)
        .post('/compliance')
        .set('Authorization', `Bearer ${atomicToken}`)
        .send({ matrix: finalMatrix, coverage: finalCoverage, metadata: finalMetadata, sha256: finalHash })
        .expect(201);

      expect(successResponse.body.sha256).toBe(finalHash);

      const records = JSON.parse(await fsPromises.readFile(compliancePath, 'utf8')) as Array<{ sha256: string }>;
      expect(records).toHaveLength(2);
      expect(records[1].sha256).toBe(finalHash);
    } finally {
      renameSpy?.mockRestore();
      await fsPromises.rm(atomicDir, { recursive: true, force: true });
    }
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
    expect(health.headers['content-security-policy']).toContain("default-src 'self'");
    expect(health.headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(health.headers['referrer-policy']).toBe('no-referrer');
    expect(health.headers['cross-origin-embedder-policy']).toBe('require-corp');
    expect(health.headers['cross-origin-opener-policy']).toBe('same-origin');
    expect(health.headers['cross-origin-resource-policy']).toBe('same-origin');
    expect(health.headers['permissions-policy']).toContain('accelerometer=()');
    expect(health.headers['permissions-policy']).toContain('geolocation=()');
    expect(health.headers['x-permitted-cross-domain-policies']).toBe('none');
    expect(health.headers['x-powered-by']).toBeUndefined();

    const jobs = await request(app)
      .get('/v1/jobs')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(jobs.headers['strict-transport-security']).toBe(health.headers['strict-transport-security']);
    expect(jobs.headers['x-content-type-options']).toBe('nosniff');
    expect(jobs.headers['x-frame-options']).toBe('SAMEORIGIN');
    expect(jobs.headers['content-security-policy']).toBe(health.headers['content-security-policy']);
    expect(jobs.headers['referrer-policy']).toBe('no-referrer');
    expect(jobs.headers['cross-origin-embedder-policy']).toBe('require-corp');
    expect(jobs.headers['cross-origin-opener-policy']).toBe('same-origin');
    expect(jobs.headers['cross-origin-resource-policy']).toBe('same-origin');
    expect(jobs.headers['permissions-policy']).toBe(health.headers['permissions-policy']);
    expect(jobs.headers['x-permitted-cross-domain-policies']).toBe('none');
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

  it('allows administrators to manage RBAC roles and users', async () => {
    const adminToken = await createAccessToken({ roles: ['admin'] });

    const roleResponse = await request(app)
      .post('/v1/admin/roles')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ id: 'role-auditor', name: 'auditor', description: 'Reviews compliance reports' })
      .expect(201);

    expect(roleResponse.body.role).toMatchObject({ id: 'role-auditor', name: 'auditor' });

    const roleList = await request(app)
      .get('/v1/admin/roles')
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(200);

    expect(roleList.body.items.map((item: { id: string }) => item.id)).toContain('role-auditor');

    const userResponse = await request(app)
      .post('/v1/admin/users')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        id: 'user-auditor',
        email: 'auditor@example.com',
        secret: 'Str0ngSecret!',
        displayName: 'Auditor',
        roleIds: ['role-auditor'],
      })
      .expect(201);

    expect(userResponse.body.user.email).toBe('auditor@example.com');
    expect(userResponse.body.user.roles).toHaveLength(1);

    const userId = userResponse.body.user.id as string;

    const userDetail = await request(app)
      .get(`/v1/admin/users/${userId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(200);

    expect(userDetail.body.user.roles.map((role: { id: string }) => role.id)).toEqual(['role-auditor']);

    const updateResponse = await request(app)
      .put(`/v1/admin/users/${userId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        displayName: 'Lead Auditor',
        secret: 'An0therSecret!',
        roleIds: ['role-admin'],
      })
      .expect(200);

    expect(updateResponse.body.user.displayName).toBe('Lead Auditor');
    expect(updateResponse.body.user.roles.map((role: { id: string }) => role.id)).toEqual(['role-admin']);

    await request(app)
      .delete(`/v1/admin/users/${userId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(204);

    await request(app)
      .delete('/v1/admin/roles/role-auditor')
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(204);

    const actions = auditLogMock.appended.map((entry) => entry.action);
    expect(actions).toEqual(expect.arrayContaining(['admin.user.created', 'admin.user.updated', 'admin.role.created']));
  });

  it('enforces role boundaries for admin endpoints', async () => {
    const maintainerToken = await createAccessToken({ roles: ['maintainer'], subject: 'user-maintainer' });
    const readerToken = await createAccessToken({ roles: ['reader'], subject: 'user-reader' });

    await request(app)
      .get('/v1/admin/users')
      .set('Authorization', `Bearer ${maintainerToken}`)
      .expect(200);

    const maintainerCreate = await request(app)
      .post('/v1/admin/users')
      .set('Authorization', `Bearer ${maintainerToken}`)
      .send({ email: 'denied@example.com', secret: 'Secret123!', roleIds: [] })
      .expect(403);

    expect(maintainerCreate.body.error.code).toBe('FORBIDDEN_ROLE');

    const readerList = await request(app)
      .get('/v1/admin/users')
      .set('Authorization', `Bearer ${readerToken}`)
      .expect(403);

    expect(readerList.body.error.code).toBe('FORBIDDEN_ROLE');
  });

  it('manages API keys with audit logging and rotation', async () => {
    const adminToken = await createAccessToken({ roles: ['admin'] });

    const createResponse = await request(app)
      .post('/v1/admin/api-keys')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ label: 'CI', roles: ['maintainer'], permissions: ['jobs:read'] })
      .expect(201);

    expect(createResponse.body.secret).toBeDefined();
    expect(createResponse.body.apiKey.roles).toEqual(['maintainer']);

    const keyId = createResponse.body.apiKey.id as string;

    const listResponse = await request(app)
      .get('/v1/admin/api-keys')
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(200);
    expect(listResponse.body.items.some((item: { id: string }) => item.id === keyId)).toBe(true);

    const rotateResponse = await request(app)
      .put(`/v1/admin/api-keys/${keyId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ secret: 'rotated-secret', roles: ['admin'], permissions: [] })
      .expect(200);

    expect(rotateResponse.body.apiKey.roles).toEqual(['admin']);
    expect(rotateResponse.body.secret).toBe('rotated-secret');

    await request(app)
      .delete(`/v1/admin/api-keys/${keyId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(204);

    const deletedList = await request(app)
      .get('/v1/admin/api-keys')
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(200);
    expect(deletedList.body.items.some((item: { id: string }) => item.id === keyId)).toBe(false);
  });

  it('rejects user creation with unknown role identifiers', async () => {
    const adminToken = await createAccessToken({ roles: ['admin'] });

    const invalidResponse = await request(app)
      .post('/v1/admin/users')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ email: 'invalid@example.com', secret: 'Secret123!', roleIds: ['role-missing'] })
      .expect(400);

    expect(invalidResponse.body.error.code).toBe('ROLE_NOT_FOUND');
  });

  it('reports storage provider health with database latency metrics', async () => {
    const response = await request(app)
      .get('/v1/admin/storage/health')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(response.body.provider).toBe('FileSystemStorage');
    expect(response.body.status).toBe('ok');
    expect(response.body.database).toEqual({
      latencyMs: expect.any(Number),
    });
    expect(response.body.database.latencyMs).toBeGreaterThanOrEqual(0);
  });

  it('returns an error response when the database health check fails', async () => {
    databaseStub.failNext(new Error('db down'));

    const response = await request(app)
      .get('/v1/admin/storage/health')
      .set('Authorization', `Bearer ${token}`)
      .expect(500);

    expect(response.body.error.code).toBe('STORAGE_HEALTH_FAILED');
    expect(response.body.error.message).toBe('Depolama sağlığı doğrulanamadı.');
    expect(response.body.error.details).toMatchObject({
      provider: 'FileSystemStorage',
      reason: 'db down',
      databaseLatencyMs: expect.any(Number),
    });
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

  it('prevents unassigned users from approving reviews', async () => {
    const importId = 'cafebabecafebabe';
    const ownerToken = await createAccessToken({ scope: requiredScope, roles: ['maintainer'], subject: 'review-owner' });

    const createResponse = await request(app)
      .post('/v1/reviews')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ target: { kind: 'analyze', reference: importId }, approvers: ['qa-approver'] })
      .expect(201);

    const reviewId = createResponse.body.review.id as string;
    const submitResponse = await request(app)
      .patch(`/v1/reviews/${reviewId}`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ action: 'submit', expectedHash: createResponse.body.review.hash })
      .expect(200);

    const intruderToken = await createAccessToken({ scope: requiredScope, roles: ['maintainer'], subject: 'intruder' });
    const approvalAttempt = await request(app)
      .patch(`/v1/reviews/${reviewId}`)
      .set('Authorization', `Bearer ${intruderToken}`)
      .send({ action: 'approve', expectedHash: submitResponse.body.review.hash })
      .expect(403);

    expect(approvalAttempt.body.error.code).toBe('REVIEW_FORBIDDEN');
  });

  it('requires approved reviews for analyze jobs when admin scope is absent', async () => {
    const importId = 'deadbeefcafebabe';
    const workspaceDir = path.join(storageDir, 'workspaces', tenantId, importId);
    await fsPromises.mkdir(workspaceDir, { recursive: true });
    await fsPromises.writeFile(
      path.join(workspaceDir, 'workspace.json'),
      JSON.stringify({
        metadata: {
          targetLevel: 'C',
          project: { name: 'Review Demo', version: '1.0.0' },
        },
      }),
      'utf8',
    );

    const ownerToken = await createAccessToken({ scope: requiredScope, roles: ['maintainer'], subject: 'review-owner' });
    const createResponse = await request(app)
      .post('/v1/reviews')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ target: { kind: 'analyze', reference: importId }, approvers: ['qa-approver'] })
      .expect(201);

    const reviewId = createResponse.body.review.id as string;
    const submitResponse = await request(app)
      .patch(`/v1/reviews/${reviewId}`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ action: 'submit', expectedHash: createResponse.body.review.hash })
      .expect(200);

    const runnerToken = await createAccessToken({ scope: requiredScope, roles: ['maintainer'], subject: 'pipeline-runner' });
    const reviewerToken = await createAccessToken({ scope: requiredScope, roles: ['maintainer'], subject: 'qa-approver' });

    const blockedAnalyze = await request(app)
      .post('/v1/analyze')
      .set('Authorization', `Bearer ${runnerToken}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ importId, reviewId })
      .expect(409);
    expect(blockedAnalyze.body.error.code).toBe('REVIEW_NOT_APPROVED');

    const approveResponse = await request(app)
      .patch(`/v1/reviews/${reviewId}`)
      .set('Authorization', `Bearer ${reviewerToken}`)
      .send({ action: 'approve', expectedHash: submitResponse.body.review.hash })
      .expect(200);

    const runAnalyzeSpy = jest.spyOn(cli, 'runAnalyze');
    runAnalyzeSpy.mockResolvedValue({ exitCode: 0 } as unknown as Awaited<ReturnType<typeof cli.runAnalyze>>);

    try {
      const analyzeResponse = await request(app)
        .post('/v1/analyze')
        .set('Authorization', `Bearer ${runnerToken}`)
        .set('X-SOIPACK-License', licenseHeader)
        .send({ importId, reviewId })
        .expect(202);
      expect(analyzeResponse.body.id).toMatch(/^[a-f0-9]{16}$/);
    } finally {
      runAnalyzeSpy.mockRestore();
    }

    // ensure review hash updated after approval to avoid lint warnings
    expect(typeof approveResponse.body.review.hash).toBe('string');
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

  it('passes design, defect, and tool artifacts through to import jobs', async () => {
    const runImportSpy = jest.spyOn(cli, 'runImport');
    let capturedOptions: cli.ImportOptions | undefined;
    runImportSpy.mockImplementation(async (options) => {
      capturedOptions = options;
      const workspace: cli.ImportWorkspace = {
        requirements: [],
        testResults: [],
        traceLinks: [],
        testToCodeMap: {},
        evidenceIndex: {},
        findings: [],
        builds: [],
        designs: [],
        metadata: {
          generatedAt: new Date().toISOString(),
          warnings: [],
          inputs: {},
          version: buildSnapshotVersion(),
        },
      };
      return {
        warnings: [],
        workspace,
        workspacePath: path.join(options.output, 'workspace.json'),
      } satisfies Awaited<ReturnType<typeof cli.runImport>>;
    });

    const projectVersion = `artifacts-${Date.now()}`;

    try {
      const response = await request(app)
        .post('/v1/import')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .attach('reqif', minimalExample('spec.reqif'))
        .attach('jiraDefects', Buffer.from('defect-a'), {
          filename: 'defects-1.csv',
          contentType: 'text/csv',
        })
        .attach('jiraDefects', Buffer.from('defect-b'), {
          filename: 'defects-2.csv',
          contentType: 'text/csv',
        })
        .attach('designCsv', Buffer.from('id,title\n1,Design\n'), {
          filename: 'designs.csv',
          contentType: 'text/csv',
        })
        .attach('polyspace', Buffer.from('polyspace-data'), {
          filename: 'polyspace.zip',
          contentType: 'application/zip',
        })
        .attach('ldra', Buffer.from('ldra-data'), {
          filename: 'ldra.zip',
          contentType: 'application/zip',
        })
        .attach('vectorcast', Buffer.from('vectorcast-data'), {
          filename: 'vectorcast.zip',
          contentType: 'application/zip',
        })
        .attach('qaLogs', Buffer.from('qa-log-1'), {
          filename: 'qa-1.log',
          contentType: 'text/plain',
        })
        .attach('qaLogs', Buffer.from('qa-log-2'), {
          filename: 'qa-2.log',
          contentType: 'text/plain',
        })
        .field('projectName', 'Artifact Demo')
        .field('projectVersion', projectVersion)
        .field('independentSources', JSON.stringify(['source-a', 'source-b']))
        .field('independentArtifacts', JSON.stringify(['artifact-a']))
        .expect(202);

      expect(response.body.id).toMatch(/^[a-f0-9]{16}$/);

      const jobId = response.body.id as string;
      const job = await waitForJobCompletion(app, token, jobId);
      expect(job.status).toBe('completed');

      expect(runImportSpy).toHaveBeenCalledTimes(1);
      expect(capturedOptions).toBeDefined();

      const expectedUploadBase = path.join(storageDir, 'uploads', tenantId, jobId);
      expect(capturedOptions?.designCsv).toBe(
        path.join(expectedUploadBase, 'designCsv', 'designs.csv'),
      );
      expect(capturedOptions?.jiraDefects).toEqual([
        path.join(expectedUploadBase, 'jiraDefects', 'defects-1.csv'),
        path.join(expectedUploadBase, 'jiraDefects', 'defects-2.csv'),
      ]);
      expect(capturedOptions?.polyspace).toBe(
        path.join(expectedUploadBase, 'polyspace', 'polyspace.zip'),
      );
      expect(capturedOptions?.ldra).toBe(path.join(expectedUploadBase, 'ldra', 'ldra.zip'));
      expect(capturedOptions?.vectorcast).toBe(
        path.join(expectedUploadBase, 'vectorcast', 'vectorcast.zip'),
      );
      expect(capturedOptions?.qaLogs).toEqual([
        path.join(expectedUploadBase, 'qaLogs', 'qa-1.log'),
        path.join(expectedUploadBase, 'qaLogs', 'qa-2.log'),
      ]);
      expect(capturedOptions?.independentSources).toEqual(['source-a', 'source-b']);
      expect(capturedOptions?.independentArtifacts).toEqual(['artifact-a']);

      const metadataPath = path.join(storageDir, 'workspaces', tenantId, jobId, 'job.json');
      const metadataContent = await fsPromises.readFile(metadataPath, 'utf8');
      const metadata = JSON.parse(metadataContent) as {
        params: {
          files?: Record<string, string[]>;
          independentSources?: string[] | null;
          independentArtifacts?: string[] | null;
        };
      };

      expect(metadata.params.files?.designCsv).toEqual(['designs.csv']);
      expect(metadata.params.files?.jiraDefects).toEqual(['defects-1.csv', 'defects-2.csv']);
      expect(metadata.params.files?.polyspace).toEqual(['polyspace.zip']);
      expect(metadata.params.files?.ldra).toEqual(['ldra.zip']);
      expect(metadata.params.files?.vectorcast).toEqual(['vectorcast.zip']);
      expect(metadata.params.files?.qaLogs).toEqual(['qa-1.log', 'qa-2.log']);
      expect(metadata.params.independentSources).toEqual(['source-a', 'source-b']);
      expect(metadata.params.independentArtifacts).toEqual(['artifact-a']);
    } finally {
      runImportSpy.mockRestore();
    }
  });

  it('rejects invalid independence declarations for import jobs', async () => {
    const invalidSources = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .field('independentSources', '{"not":"array"}')
      .expect(400);

    expect(invalidSources.body.error.code).toBe('INVALID_REQUEST');

    const invalidArtifacts = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .field('independentArtifacts', JSON.stringify(['', 'artifact']))
      .expect(400);

    expect(invalidArtifacts.body.error.code).toBe('INVALID_REQUEST');
  });

  it('passes plan configuration uploads and overrides to report jobs', async () => {
    const runReportSpy = jest.spyOn(cli, 'runReport');
    let capturedOptions: cli.ReportOptions | undefined;
    type ReportResult = Awaited<ReturnType<typeof cli.runReport>>;
    runReportSpy.mockImplementation(async (options) => {
      capturedOptions = options;
      const summary = {
        generatedAt: new Date().toISOString(),
        programName: 'Plan Config Project',
        level: 'DAL-B',
        author: 'QA Lead',
        tools: [
          {
            id: 'tool-1',
            name: 'Trace Analyzer',
            version: '1.0.0',
            category: 'verification' as const,
            tql: 'TQL-001',
            outputs: ['Tool Qualification Plan', 'Tool Assessment Report'],
            pendingActivities: 1,
          },
        ],
      };
      const toolQualificationDir = path.join(options.output, 'tool-qualification');
      const result: ReportResult = {
        complianceHtml: path.join(options.output, 'compliance.html'),
        complianceJson: path.join(options.output, 'compliance.json'),
        complianceCsv: path.join(options.output, 'compliance.csv'),
        traceHtml: path.join(options.output, 'trace.html'),
        gapsHtml: path.join(options.output, 'gaps.html'),
        traceCsv: path.join(options.output, 'traces.csv'),
        plans: {} as ReportResult['plans'],
        warnings: [] as ReportResult['warnings'],
        toolQualification: {
          tqp: path.join(toolQualificationDir, 'trace-analyzer-plan.md'),
          tar: path.join(toolQualificationDir, 'trace-analyzer-report.md'),
          summary,
        },
      };
      return result;
    });

    const planConfigBuffer = Buffer.from(JSON.stringify({ plan: 'demo' }), 'utf8');
    const overrides = { include: ['goal-1'], exclude: ['goal-2'] };

    try {
      const importResponse = await request(app)
        .post('/v1/import')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .attach('reqif', minimalExample('spec.reqif'))
        .attach('junit', minimalExample('results.xml'))
        .attach('lcov', minimalExample('lcov.info'))
        .field('projectName', 'Plan Config Project')
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
        .field('analysisId', analyzeJob.id)
        .field('planOverrides', JSON.stringify(overrides))
        .attach('planConfig', planConfigBuffer, {
          filename: 'plan.json',
          contentType: 'application/json',
        })
        .expect(202);

      const reportJob = await waitForJobCompletion(app, token, reportResponse.body.id);

      expect(runReportSpy).toHaveBeenCalledTimes(1);
      expect(capturedOptions).toBeDefined();

      const toolQualificationOutputs = reportJob.result.outputs.toolQualification;
      expect(toolQualificationOutputs).toBeDefined();
      expect(toolQualificationOutputs?.summary).toEqual({
        generatedAt: expect.any(String),
        programName: 'Plan Config Project',
        level: 'DAL-B',
        author: 'QA Lead',
        tools: [
          expect.objectContaining({
            id: 'tool-1',
            name: 'Trace Analyzer',
            category: 'verification',
            pendingActivities: 1,
          }),
        ],
      });
      expect(toolQualificationOutputs?.tqpHref).toBe('tool-qualification/trace-analyzer-plan.md');
      expect(toolQualificationOutputs?.tarHref).toBe('tool-qualification/trace-analyzer-report.md');
      expect(toolQualificationOutputs?.tqp.replace(/\\/g, '/').endsWith(
        `/tool-qualification/trace-analyzer-plan.md`,
      )).toBe(true);
      expect(toolQualificationOutputs?.tar.replace(/\\/g, '/').endsWith(
        `/tool-qualification/trace-analyzer-report.md`,
      )).toBe(true);

      const expectedUploadBase = path.join(storageDir, 'uploads', tenantId, reportJob.id);
      expect(capturedOptions?.planConfig).toBe(
        path.join(expectedUploadBase, 'planConfig', 'plan.json'),
      );
      expect(capturedOptions?.planOverrides).toEqual(overrides);

      const metadataPath = path.join(storageDir, 'reports', tenantId, reportJob.id, 'job.json');
      const metadataContent = await fsPromises.readFile(metadataPath, 'utf8');
      const metadata = JSON.parse(metadataContent) as {
        params: { planConfig?: string | null; planOverrides?: Record<string, unknown> | null };
        outputs: {
          toolQualification?: {
            summary: {
              generatedAt: string;
              programName?: string | null;
              level?: string | null;
              author?: string | null;
              tools: Array<{ id: string }>;
            };
            tqpHref: string;
            tarHref: string;
          };
        };
      };

      expect(metadata.params.planConfig).toBe('plan.json');
      expect(metadata.params.planOverrides).toEqual(overrides);
      expect(metadata.outputs.toolQualification?.tqpHref).toBe(
        'tool-qualification/trace-analyzer-plan.md',
      );
      expect(metadata.outputs.toolQualification?.tarHref).toBe(
        'tool-qualification/trace-analyzer-report.md',
      );
      expect(metadata.outputs.toolQualification?.summary.tools[0]?.id).toBe('tool-1');
    } finally {
      runReportSpy.mockRestore();
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
        designs: [],
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
        designs: [],
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
        designs: [],
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
    expect(reportJob.result.outputs.complianceCsv).toMatch(/^reports\//);

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

    const lifecycle = getServerLifecycle(app);
    const publishLedgerSpy = jest.spyOn(lifecycle.events, 'publishLedgerEntry');
    const publishProofSpy = jest.spyOn(lifecycle.events, 'publishManifestProof');

    const postQuantumMaterial = loadDefaultSphincsPlusKeyPair();
    const postQuantumRequest = {
      algorithm: postQuantumMaterial.algorithm,
      privateKey: postQuantumMaterial.privateKey,
      publicKey: postQuantumMaterial.publicKey,
    };

    const packQueued = await request(app)
      .post('/v1/pack')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ reportId: reportQueued.body.id, postQuantum: postQuantumRequest })
      .expect(202);

    const packJob = await waitForJobCompletion(app, token, packQueued.body.id);
    expect(packJob.result.outputs.archive).toMatch(/^packages\//);
    expect(packJob.result.manifestId).toHaveLength(12);
    expect(packJob.result.manifestDigest).toHaveLength(64);
    expect(packJob.result.outputs.ledger).toMatch(/^packages\//);
    expect(packJob.result.cmsSignature).toBeDefined();
    const cmsMetadata = packJob.result.cmsSignature!;
    expect(cmsMetadata.path).toMatch(/^packages\//);
    expect(cmsMetadata.sha256).toMatch(/^[0-9a-f]{64}$/i);
    expect(typeof cmsMetadata.der).toBe('string');
    expect(cmsMetadata.der.length).toBeGreaterThan(0);
    expect(cmsMetadata.digestAlgorithm).toBe('SHA-256');
    expect(cmsMetadata.verified).toBe(true);
    expect(cmsMetadata.digestVerified).toBe(true);
    expect(cmsMetadata.signerSerialNumber).toEqual(expect.any(String));
    expect(packJob.result.postQuantumSignature).toEqual(
      expect.objectContaining({
        algorithm: postQuantumMaterial.algorithm,
        publicKey: postQuantumMaterial.publicKey,
        signature: expect.any(String),
      }),
    );
    expect(packJob.result.postQuantumSignature?.signature.length).toBeGreaterThan(0);

    const ledgerAbsolutePath = path.resolve(storageDir, packJob.result.outputs.ledger!);
    const ledgerContent = JSON.parse(await fsPromises.readFile(ledgerAbsolutePath, 'utf8')) as {
      root: string;
      entries: Array<{ manifestDigest: string }>;
    };
    expect(packJob.result.ledgerRoot).toBe(ledgerContent.root);
    expect(ledgerContent.entries[0]?.manifestDigest).toBe(packJob.result.manifestDigest);

    expect(publishLedgerSpy).toHaveBeenCalledWith(
      tenantId,
      expect.objectContaining({ ledgerRoot: packJob.result.ledgerRoot }),
      expect.objectContaining({ id: expect.stringContaining(packQueued.body.id) }),
    );
    expect(publishProofSpy).toHaveBeenCalledWith(
      tenantId,
      expect.objectContaining({
        manifestId: packJob.result.manifestId,
        files: expect.arrayContaining([expect.objectContaining({ hasProof: true, verified: true })]),
      }),
      expect.objectContaining({ id: expect.stringContaining(packQueued.body.id) }),
    );

    const packDetails = await request(app)
      .get(`/v1/jobs/${packQueued.body.id}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(packDetails.body.result.outputs.archive).toBe(packJob.result.outputs.archive);
    expect(packDetails.body.result.manifestId).toBe(packJob.result.manifestId);
    expect(packDetails.body.result.manifestDigest).toBe(packJob.result.manifestDigest);
    expect(packDetails.body.result.outputs.ledger).toBe(packJob.result.outputs.ledger);
    expect(packDetails.body.result.cmsSignature).toMatchObject({
      path: cmsMetadata.path,
      sha256: cmsMetadata.sha256,
      der: cmsMetadata.der,
    });
    expect(packDetails.body.result.postQuantumSignature).toEqual(
      expect.objectContaining({
        algorithm: postQuantumMaterial.algorithm,
        publicKey: postQuantumMaterial.publicKey,
      }),
    );

    const packReuse = await request(app)
      .post('/v1/pack')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ reportId: reportQueued.body.id, postQuantum: postQuantumRequest })
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
    expect(manifest.merkle).toMatchObject({ algorithm: 'ledger-merkle-v1' });
    expect(manifest.merkle?.root).toMatch(/^[0-9a-f]{64}$/i);
    manifest.files.forEach((file) => {
      expect(file.proof?.algorithm).toBe('ledger-merkle-v1');
      expect(file.proof?.merkleRoot).toBe(manifest.merkle?.root);
      if (file.proof && manifest.merkle?.root) {
        const parsedProof = deserializeLedgerProof(file.proof.proof);
        expect(verifyLedgerProof(parsedProof, { expectedMerkleRoot: manifest.merkle.root })).toBe(
          manifest.merkle.root,
        );
      }
    });
    const cmsPath = path.resolve(storageDir, cmsMetadata.path);
    const cmsContent = await fsPromises.readFile(cmsPath, 'utf8');
    const expectedDer = cmsContent
      .replace(/-----BEGIN PKCS7-----/g, '')
      .replace(/-----END PKCS7-----/g, '')
      .replace(/\s+/g, '');
    expect(cmsMetadata.der).toBe(expectedDer);
    const expectedSha256 = createHash('sha256').update(cmsContent, 'utf8').digest('hex');
    expect(cmsMetadata.sha256).toBe(expectedSha256);
    expect(cmsMetadata.signerSubject).toEqual(expect.stringContaining('SOIPack CMS Test'));
    expect(cmsMetadata.signatureAlgorithm).toEqual(expect.any(String));

    const packageLedgerCopy = JSON.parse(
      await fsPromises.readFile(path.join(manifestDir, 'ledger.json'), 'utf8'),
    ) as { root: string };
    expect(packageLedgerCopy.root).toBe(packJob.result.ledgerRoot);

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
    expect(manifestResponse.body.cmsSignature).toMatchObject({
      path: cmsMetadata.path,
      sha256: cmsMetadata.sha256,
      der: cmsMetadata.der,
    });

    const proofsResponse = await request(app)
      .get(`/v1/manifests/${packJob.result.manifestId}/proofs`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(proofsResponse.body.merkle).toMatchObject({ root: manifest.merkle?.root });
    const listedProof = proofsResponse.body.files.find(
      (entry: { path: string }) => entry.path === manifest.files[0].path,
    );
    expect(listedProof).toMatchObject({ verified: true });
    expect(listedProof.proof).toEqual(manifest.files[0].proof);

    const encodedPath = encodeURIComponent(manifest.files[0].path);
    const proofResponse = await request(app)
      .get(`/v1/manifests/${packJob.result.manifestId}/proofs/${encodedPath}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(proofResponse.body.proof).toEqual(manifest.files[0].proof);
    expect(proofResponse.body.verified).toBe(true);
    expect(proofResponse.body.merkle).toMatchObject({ root: manifest.merkle?.root });

    const manifestForbidden = await request(app)
      .get(`/v1/manifests/${packJob.result.manifestId}`)
      .set('Authorization', `Bearer ${otherTenantToken}`)
      .expect(404);
    expect(manifestForbidden.body.error.code).toBe('MANIFEST_NOT_FOUND');

    await request(app)
      .get(`/v1/manifests/${packJob.result.manifestId}/proofs`)
      .set('Authorization', `Bearer ${otherTenantToken}`)
      .expect(404);

    await request(app)
      .get(`/v1/manifests/${packJob.result.manifestId}/proofs/${encodedPath}`)
      .set('Authorization', `Bearer ${otherTenantToken}`)
      .expect(404);

    publishLedgerSpy.mockRestore();
    publishProofSpy.mockRestore();

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

    const cmsDownload = await request(app)
      .get(`/v1/packages/${packQueued.body.id}/manifest.cms`)
      .set('Authorization', `Bearer ${token}`)
      .buffer(true)
      .parse((res, callback) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
        res.on('end', () => callback(null, Buffer.concat(chunks)));
      })
      .expect('Content-Type', /pkcs7|application\/pkcs7-signature/)
      .expect(200);
    expect(cmsDownload.headers['content-disposition']).toContain('.cms');
    expect((cmsDownload.body as Buffer).toString('utf8')).toBe(cmsContent);

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

    const cmsForbiddenDownload = await request(app)
      .get(`/v1/packages/${packQueued.body.id}/manifest.cms`)
      .set('Authorization', `Bearer ${otherTenantToken}`)
      .expect(404);
    expect(cmsForbiddenDownload.body.error.code).toBe('PACKAGE_NOT_FOUND');

    const reportAsset = await request(app)
      .get(`/v1/reports/${reportQueued.body.id}/compliance.html`)
      .set('Authorization', `Bearer ${token}`)
      .expect('Content-Type', /html/)
      .expect(200);

    expect(reportAsset.text).toContain('<html');

    const reportCsv = await request(app)
      .get(`/v1/reports/${reportQueued.body.id}/compliance.csv`)
      .set('Authorization', `Bearer ${token}`)
      .expect('Content-Type', /csv/)
      .expect(200);
    expect(reportCsv.text).toContain('Objective ID');

    const reportDetails = await request(app)
      .get(`/v1/jobs/${reportQueued.body.id}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(reportDetails.body.result.outputs.complianceHtml).toBe(
      reportJob.result.outputs.complianceHtml,
    );
    expect(reportDetails.body.result.outputs.complianceCsv).toBe(
      reportJob.result.outputs.complianceCsv,
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
      });
      expect(summaryByTarget[target].skipped).toBeGreaterThanOrEqual(0);
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

  it('stageRouting routes stage-scoped report and pack outputs into dedicated directories', async () => {
    const importResponse = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .attach('junit', minimalExample('results.xml'))
      .attach('lcov', minimalExample('lcov.info'))
      .field('projectName', 'Stage Routing Project')
      .field('projectVersion', '2.0.0')
      .expect(202);

    const importJob = await waitForJobCompletion(app, token, importResponse.body.id);

    const analyzeResponse = await request(app)
      .post('/v1/analyze')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ importId: importJob.id })
      .expect(202);
    const analyzeJob = await waitForJobCompletion(app, token, analyzeResponse.body.id);

    const soiStage = 'SOI-3';

    const reportResponse = await request(app)
      .post('/v1/report')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ analysisId: analyzeJob.id, soiStage })
      .expect(202);
    const reportJob = await waitForJobCompletion(app, token, reportResponse.body.id);

    const expectedReportDir = `reports/${tenantId}/${soiStage}/${reportResponse.body.id}`;
    expect(reportJob.result.outputs.directory).toBe(expectedReportDir);
    expect(reportJob.result.outputs.complianceHtml.startsWith(`${expectedReportDir}/`)).toBe(true);
    expect(reportJob.result.outputs.complianceCsv.startsWith(`${expectedReportDir}/`)).toBe(true);

    const reportMetadata = JSON.parse(
      await fsPromises.readFile(path.resolve(storageDir, expectedReportDir, 'job.json'), 'utf8'),
    ) as { params?: { soiStage?: string | null } };
    expect(reportMetadata.params?.soiStage).toBe(soiStage);

    const packResponse = await request(app)
      .post('/v1/pack')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ reportId: reportResponse.body.id, soiStage })
      .expect(202);
    const packJob = await waitForJobCompletion(app, token, packResponse.body.id);

    const expectedPackDir = `packages/${tenantId}/${soiStage}/${packResponse.body.id}`;
    expect(packJob.result.outputs.directory).toBe(expectedPackDir);
    expect(packJob.result.outputs.archive.startsWith(`${expectedPackDir}/`)).toBe(true);

    const packMetadata = JSON.parse(
      await fsPromises.readFile(path.resolve(storageDir, expectedPackDir, 'job.json'), 'utf8'),
    ) as { params?: { soiStage?: string | null } };
    expect(packMetadata.params?.soiStage).toBe(soiStage);
  });

  it('fails pack jobs when CMS signature verification fails', async () => {
    const tamperedContent = '-----BEGIN PKCS7-----\nINVALID-CMS\n-----END PKCS7-----\n';
    const originalRunPack = cli.runPack;
    const runPackSpy = jest.spyOn(cli, 'runPack').mockImplementation(async (options) => {
      const result = await originalRunPack(options);
      if (result.cmsSignaturePath) {
        await fsPromises.writeFile(result.cmsSignaturePath, tamperedContent, 'utf8');
        const tamperedSha = createHash('sha256').update(tamperedContent, 'utf8').digest('hex');
        result.cmsSignatureSha256 = tamperedSha;
      }
      return result;
    });

    try {
      const importResponse = await request(app)
        .post('/v1/import')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .attach('reqif', minimalExample('spec.reqif'))
        .attach('junit', minimalExample('results.xml'))
        .attach('lcov', minimalExample('lcov.info'))
        .field('projectName', 'CMS Failure Demo')
        .field('projectVersion', `cms-failure-${Date.now()}`)
        .expect(202);

      await waitForJobCompletion(app, token, importResponse.body.id);

      const analyzeResponse = await request(app)
        .post('/v1/analyze')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .send({ importId: importResponse.body.id })
        .expect(202);

      await waitForJobCompletion(app, token, analyzeResponse.body.id);

      const reportResponse = await request(app)
        .post('/v1/report')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .send({ analysisId: analyzeResponse.body.id })
        .expect(202);

      await waitForJobCompletion(app, token, reportResponse.body.id);

      const packResponse = await request(app)
        .post('/v1/pack')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .send({ reportId: reportResponse.body.id })
        .expect(202);

      const failedJob = await waitForJobFailure(app, token, packResponse.body.id);
      expect(failedJob.error?.code).toBe('PIPELINE_ERROR');
      expect(failedJob.error?.message).toContain('Paket oluşturma işlemi başarısız oldu.');
    } finally {
      runPackSpy.mockRestore();
    }
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
        designs: [],
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

    const scopedId = `${tenantId}:${importResponse.body.id}`;
    expect(databaseStub.rows.get(scopedId)?.status).toBe('completed');

    const initialRuns = runImportSpy.mock.calls.length;

    databaseStub.pool.query.mockClear();
    const restartRegistry = new Registry();
    const restartApp = createServer({
      ...baseConfig,
      metricsRegistry: restartRegistry,
    });

    await waitForCondition(() =>
      databaseStub.pool.query.mock.calls.some(
        ([sql]) => typeof sql === 'string' && sql.toLowerCase().includes('order by created_at asc'),
      ),
    );

    const adoptedResponse = await request(restartApp)
      .get(`/v1/jobs/${importResponse.body.id}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(adoptedResponse.body.status).toBe('completed');
    expect(adoptedResponse.body.id).toBe(importResponse.body.id);
    expect(runImportSpy.mock.calls.length).toBe(initialRuns);
    expect(databaseStub.rows.get(scopedId)?.status).toBe('completed');

    runImportSpy.mockRestore();
  });

  it('emits audit logs for import job lifecycle and license actions', async () => {
    const runImportSpy = jest.spyOn(cli, 'runImport');
    runImportSpy.mockResolvedValue({
      warnings: [],
      workspacePath: path.join('out', 'workspace.json'),
      workspace: {} as cli.ImportWorkspace,
    } satisfies Awaited<ReturnType<typeof cli.runImport>>);

    const projectVersion = `audit-${Date.now()}`;
    const response = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .attach('junit', minimalExample('results.xml'))
      .attach('lcov', minimalExample('lcov.info'))
      .field('projectName', 'Audit Demo')
      .field('projectVersion', projectVersion)
      .expect(202);

    const jobId = response.body.id as string;
    await waitForJobCompletion(app, token, jobId);
    runImportSpy.mockRestore();

    const actions = auditLogMock.store.append.mock.calls.map(([entry]) => entry.action);
    expect(actions).toEqual(
      expect.arrayContaining(['job.created', 'job.started', 'job.completed', 'license.attached']),
    );
    const creationEntry = auditLogMock.store.append.mock.calls.find(
      ([entry]) => entry.action === 'job.created',
    )?.[0];
    expect(creationEntry).toMatchObject({
      tenantId,
      actor: 'user-1',
      target: `job:${jobId}`,
      payload: expect.objectContaining({ kind: 'import' }),
    });
  });

  it('returns audit log entries filtered by actor via the API', async () => {
    const timestamp = new Date('2024-07-01T12:00:00Z');
    auditLogMock.store.query.mockResolvedValueOnce({
      items: [
        {
          id: 'entry-1',
          tenantId,
          actor: 'user-1',
          action: 'job.created',
          target: 'job:abcd1234',
          payload: { kind: 'import' },
          createdAt: timestamp,
        },
      ],
      hasMore: false,
      nextOffset: undefined,
    });

    const response = await request(app)
      .get('/api/audit-logs?actor=user-1')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(auditLogMock.store.query).toHaveBeenCalledWith(
      expect.objectContaining({ tenantId, actor: 'user-1' }),
    );
    expect(response.body.items).toEqual([
      expect.objectContaining({
        id: 'entry-1',
        actor: 'user-1',
        action: 'job.created',
        target: 'job:abcd1234',
      }),
    ]);
    expect(typeof response.body.items[0].createdAt).toBe('string');
  });

  describe('Change request proxy', () => {
    const originalBaseUrl = process.env.JIRA_BASE_URL;
    const originalToken = process.env.JIRA_TOKEN;
    const originalProject = process.env.JIRA_PROJECT_KEY;
    let projectCounter = 0;

    const nextProjectKey = (): string => {
      projectCounter += 1;
      return `CR-${projectCounter}`;
    };

    beforeAll(() => {
      process.env.JIRA_BASE_URL = 'https://jira.example.com';
      process.env.JIRA_TOKEN = 'jira-token';
    });

    afterAll(() => {
      if (originalBaseUrl === undefined) {
        delete process.env.JIRA_BASE_URL;
      } else {
        process.env.JIRA_BASE_URL = originalBaseUrl;
      }
      if (originalToken === undefined) {
        delete process.env.JIRA_TOKEN;
      } else {
        process.env.JIRA_TOKEN = originalToken;
      }
      if (originalProject === undefined) {
        delete process.env.JIRA_PROJECT_KEY;
      } else {
        process.env.JIRA_PROJECT_KEY = originalProject;
      }
    });

    beforeEach(() => {
      mockedFetchJiraChangeRequests.mockReset();
      projectCounter = 0;
      __clearChangeRequestCacheForTesting();
    });

    it('rejects requests without reader permissions', async () => {
      const projectKey = nextProjectKey();
      const unauthorizedToken = await createAccessToken({ roles: [], scope: requiredScope });

      await request(app)
        .get('/v1/change-requests')
        .query({ projectKey })
        .set('Authorization', `Bearer ${unauthorizedToken}`)
        .expect(403);

      expect(mockedFetchJiraChangeRequests).not.toHaveBeenCalled();
    });

    it('returns change requests with caching and ETag support', async () => {
      const readerToken = await createAccessToken({ roles: ['reader'], scope: requiredScope });
      const projectKey = nextProjectKey();
      mockedFetchJiraChangeRequests.mockResolvedValue([
        {
          id: '1001',
          key: 'CR-1',
          summary: 'Update autopilot logic',
          status: 'In Progress',
          statusCategory: 'In Progress',
          assignee: 'Alex Pilot',
          updatedAt: '2024-09-03T10:00:00Z',
          priority: 'High',
          issueType: 'Change Request',
          url: 'https://jira.example.com/browse/CR-1',
          transitions: [{ id: '1', name: 'Submit', toStatus: 'Ready for Review' }],
          attachments: [
            {
              id: 'att-1',
              filename: 'impact.pdf',
              url: 'https://jira.example.com/secure/attachment/att-1',
            },
          ],
        },
      ] satisfies JiraChangeRequest[]);

      const firstResponse = await request(app)
        .get('/v1/change-requests')
        .query({ projectKey })
        .set('Authorization', `Bearer ${readerToken}`)
        .expect(200);

      expect(firstResponse.body.items).toHaveLength(1);
      expect(firstResponse.body.items[0].key).toBe('CR-1');
      expect(firstResponse.headers['cache-control']).toBe('private, max-age=300');
      const etag = firstResponse.headers.etag as string;
      expect(typeof etag).toBe('string');

      mockedFetchJiraChangeRequests.mockClear();

      await request(app)
        .get('/v1/change-requests')
        .query({ projectKey })
        .set('Authorization', `Bearer ${readerToken}`)
        .set('If-None-Match', etag)
        .expect(304);

      expect(mockedFetchJiraChangeRequests).not.toHaveBeenCalled();

      const secondResponse = await request(app)
        .get('/v1/change-requests')
        .query({ projectKey })
        .set('Authorization', `Bearer ${readerToken}`)
        .expect(200);

      expect(secondResponse.body.items[0].summary).toContain('autopilot');
      expect(mockedFetchJiraChangeRequests).not.toHaveBeenCalled();
    });

    it('returns 502 when the Jira adapter throws an error', async () => {
      const readerToken = await createAccessToken({ roles: ['reader'] });
      const projectKey = nextProjectKey();
      mockedFetchJiraChangeRequests.mockRejectedValue(new Error('boom'));

      const response = await request(app)
        .get('/v1/change-requests')
        .query({ projectKey })
        .set('Authorization', `Bearer ${readerToken}`)
        .expect(502);

      expect(response.body.error.code).toBe('JIRA_FETCH_FAILED');
    });

    it('returns 503 when Jira configuration is missing', async () => {
      const readerToken = await createAccessToken({ roles: ['reader'] });
      const projectKey = nextProjectKey();
      const backupBaseUrl = process.env.JIRA_BASE_URL;
      delete process.env.JIRA_BASE_URL;

      const response = await request(app)
        .get('/v1/change-requests')
        .query({ projectKey })
        .set('Authorization', `Bearer ${readerToken}`)
        .expect(503);

      expect(response.body.error.code).toBe('UPSTREAM_UNAVAILABLE');
      process.env.JIRA_BASE_URL = backupBaseUrl ?? 'https://jira.example.com';
    });
  });

  describe('workspace collaboration endpoints', () => {
    const workspaceId = 'ws-main';
    const documentId = 'requirements';

    const baseDocumentBody = {
      kind: 'requirements',
      title: 'System Requirements',
      content: [
        {
          id: 'REQ-1',
          title: 'The system shall start safely.',
          status: 'draft',
          tags: ['safety'],
        },
      ],
    };

    it('rejects document edits from reader role', async () => {
      const readerToken = await createAccessToken({ roles: ['reader'] });
      const response = await request(app)
        .put(`/v1/workspaces/${workspaceId}/documents/${documentId}`)
        .set('Authorization', `Bearer ${readerToken}`)
        .send(baseDocumentBody)
        .expect(403);
      expect(response.body.error.code).toBe('FORBIDDEN_ROLE');
    });

    it('allows maintainers to update documents, comment, and request signoffs', async () => {
      const maintainerToken = await createAccessToken({ roles: ['maintainer'] });

      const editResponse = await request(app)
        .put(`/v1/workspaces/${workspaceId}/documents/${documentId}`)
        .set('Authorization', `Bearer ${maintainerToken}`)
        .send(baseDocumentBody)
        .expect(200);

      const revisionHash: string = editResponse.body.document.revision.hash;

      const commentResponse = await request(app)
        .post(`/v1/workspaces/${workspaceId}/documents/${documentId}/comments`)
        .set('Authorization', `Bearer ${maintainerToken}`)
        .send({ body: 'Looks good to me', revisionHash })
        .expect(201);
      expect(commentResponse.body.comment.body).toBe('Looks good to me');

      const signoffResponse = await request(app)
        .post(`/v1/workspaces/${workspaceId}/signoffs`)
        .set('Authorization', `Bearer ${maintainerToken}`)
        .send({ documentId, revisionHash, requestedFor: 'user-1' })
        .expect(201);

      expect(signoffResponse.body.signoff.status).toBe('pending');

      await request(app)
        .patch(`/v1/workspaces/${workspaceId}/signoffs/${signoffResponse.body.signoff.id}`)
        .set('Authorization', `Bearer ${maintainerToken}`)
        .send({
          action: 'approve',
          expectedRevisionHash: revisionHash,
          publicKey: Buffer.alloc(32, 1).toString('base64'),
          signature: Buffer.alloc(64, 2).toString('base64'),
          signedAt: new Date().toISOString(),
        })
        .expect(400);
    });

    it('allows admins to approve signoffs with valid Ed25519 signatures', async () => {
      const maintainerToken = await createAccessToken({ roles: ['maintainer'] });
      const adminToken = await createAccessToken({ roles: ['admin'] });
      const altDocumentId = `${documentId}-b`;

      const editResponse = await request(app)
        .put(`/v1/workspaces/${workspaceId}/documents/${altDocumentId}`)
        .set('Authorization', `Bearer ${maintainerToken}`)
        .send(baseDocumentBody)
        .expect(200);

      const revisionHash: string = editResponse.body.document.revision.hash;
      const signoffResponse = await request(app)
        .post(`/v1/workspaces/${workspaceId}/signoffs`)
        .set('Authorization', `Bearer ${maintainerToken}`)
        .send({ documentId: altDocumentId, revisionHash, requestedFor: 'approver-2' })
        .expect(201);

      const { publicKey, privateKey } = generateKeyPairSync('ed25519');
      const exported = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
      const rawPublicKey = exported.slice(exported.length - 32);
      const signedAt = new Date().toISOString();
      const payload = Buffer.from(
        `${tenantId}:${workspaceId}:${altDocumentId}:${revisionHash}:${signedAt}`,
        'utf8',
      );
      const signature = signMessage(null, payload, privateKey);

      const approveResponse = await request(app)
        .patch(`/v1/workspaces/${workspaceId}/signoffs/${signoffResponse.body.signoff.id}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          action: 'approve',
          expectedRevisionHash: revisionHash,
          publicKey: rawPublicKey.toString('base64'),
          signature: signature.toString('base64'),
          signedAt,
        })
        .expect(200);

      expect(approveResponse.body.signoff.status).toBe('approved');
      expect(approveResponse.body.signoff.signerId).toBe('user-1');
    });

    describe('Workspace document thread', () => {
      it('returns document thread data for authorized readers', async () => {
        const maintainerToken = await createAccessToken({
          subject: 'workspace-admin',
          roles: ['admin'],
        });
        const readerToken = await createAccessToken({
          subject: 'workspace-reader',
          roles: ['reader'],
          scope: requiredScope,
        });

        const editResponse = await request(app)
          .put(`/v1/workspaces/${workspaceId}/documents/${documentId}`)
          .set('Authorization', `Bearer ${maintainerToken}`)
          .send(baseDocumentBody)
          .expect(200);

        const revisionHash: string = editResponse.body.document.revision.hash;

        await request(app)
          .post(`/v1/workspaces/${workspaceId}/documents/${documentId}/comments`)
          .set('Authorization', `Bearer ${maintainerToken}`)
          .send({ body: 'Thread comment', revisionHash })
          .expect(201);

        await request(app)
          .post(`/v1/workspaces/${workspaceId}/signoffs`)
          .set('Authorization', `Bearer ${maintainerToken}`)
          .send({ documentId, revisionHash, requestedFor: 'approver-1' })
          .expect(201);

        const response = await request(app)
          .get(`/v1/workspaces/${workspaceId}/documents/${documentId}`)
          .set('Authorization', `Bearer ${readerToken}`)
          .expect(200);

        expect(response.headers.etag).toBe(`"${revisionHash}"`);
        expect(response.body.document.id).toBe(documentId);
        expect(response.body.comments).toHaveLength(1);
        expect(response.body.comments[0].body).toBe('Thread comment');
        expect(response.body.signoffs).toHaveLength(1);
        expect(response.body.nextCursor).toBeNull();
      });

      it('rejects access without reader permissions', async () => {
        const maintainerToken = await createAccessToken({
          subject: 'workspace-admin',
          roles: ['admin'],
        });
        const unauthorizedToken = await createAccessToken({
          subject: 'workspace-guest',
          roles: [],
          scope: null,
        });

        await request(app)
          .put(`/v1/workspaces/${workspaceId}/documents/${documentId}`)
          .set('Authorization', `Bearer ${maintainerToken}`)
          .send(baseDocumentBody)
          .expect(200);

        const response = await request(app)
          .get(`/v1/workspaces/${workspaceId}/documents/${documentId}`)
          .set('Authorization', `Bearer ${unauthorizedToken}`)
          .expect(403);

        expect(response.body.error.code).toBe('INSUFFICIENT_SCOPE');
      });

      it('returns 404 when the document does not exist', async () => {
        const readerToken = await createAccessToken({ roles: ['reader'] });

        const response = await request(app)
          .get(`/v1/workspaces/${workspaceId}/documents/missing-document`)
          .set('Authorization', `Bearer ${readerToken}`)
          .expect(404);

        expect(response.body.error.code).toBe('NOT_FOUND');
      });

      it('supports ETag based cache validation after updates', async () => {
        const maintainerToken = await createAccessToken({
          subject: 'workspace-admin',
          roles: ['admin'],
        });
        const readerToken = await createAccessToken({
          subject: 'workspace-reader',
          roles: ['reader'],
          scope: requiredScope,
        });

        const initialResponse = await request(app)
          .put(`/v1/workspaces/${workspaceId}/documents/${documentId}`)
          .set('Authorization', `Bearer ${maintainerToken}`)
          .send(baseDocumentBody)
          .expect(200);

        const initialHash: string = initialResponse.body.document.revision.hash;

        const firstFetch = await request(app)
          .get(`/v1/workspaces/${workspaceId}/documents/${documentId}`)
          .set('Authorization', `Bearer ${readerToken}`)
          .expect(200);

        const updatedBody = {
          ...baseDocumentBody,
          title: 'Updated Requirements',
          content: [
            {
              ...baseDocumentBody.content[0],
              status: 'approved',
            },
          ],
          expectedHash: initialHash,
        };

        const updateResponse = await request(app)
          .put(`/v1/workspaces/${workspaceId}/documents/${documentId}`)
          .set('Authorization', `Bearer ${maintainerToken}`)
          .send(updatedBody)
          .expect(200);

        const updatedHash: string = updateResponse.body.document.revision.hash;

        const staleResponse = await request(app)
          .get(`/v1/workspaces/${workspaceId}/documents/${documentId}`)
          .set('Authorization', `Bearer ${readerToken}`)
          .set('If-None-Match', firstFetch.headers.etag as string)
          .expect(200);

        expect(staleResponse.headers.etag).toBe(`"${updatedHash}"`);

        await request(app)
          .get(`/v1/workspaces/${workspaceId}/documents/${documentId}`)
          .set('Authorization', `Bearer ${readerToken}`)
          .set('If-None-Match', `"${updatedHash}"`)
          .expect(304);
      });
    });
  });

  it('streams compliance events over SSE with tenant isolation', async () => {
    const streamingApp = createServer({ ...baseConfig, metricsRegistry: new Registry() });
    const httpsServer = createHttpsServer(streamingApp, {
      key: TEST_SERVER_KEY,
      cert: TEST_SERVER_CERT,
    });

    await new Promise<void>((resolve) => httpsServer.listen(0, resolve));
    const { port } = httpsServer.address() as AddressInfo;

    const readerToken = await createAccessToken({ roles: ['reader'] });

    const url = `https://localhost:${port}/v1/stream/compliance`;
    const riskMessages: unknown[] = [];

    const source = new EventSource(url, {
      headers: { Authorization: `Bearer ${readerToken}` },
    } as EventSource.EventSourceInitDict);

    const opened = new Promise<void>((resolve, reject) => {
      source.onopen = () => resolve();
      source.onerror = (error: unknown) => reject(error);
    });

    const riskPromise = new Promise<Record<string, unknown>>((resolve) => {
      source.addEventListener('riskProfile', (event: MessageEvent) => {
        const payload = JSON.parse(event.data as string) as Record<string, unknown>;
        riskMessages.push(payload);
        resolve(payload);
      });
    });

    const ledgerPromise = new Promise<Record<string, unknown>>((resolve) => {
      source.addEventListener('ledgerEntry', (event: MessageEvent) => {
        const payload = JSON.parse(event.data as string) as Record<string, unknown>;
        resolve(payload);
      });
    });

    const queuePromise = new Promise<Record<string, unknown>>((resolve) => {
      source.addEventListener('queueState', (event: MessageEvent) => {
        const payload = JSON.parse(event.data as string) as Record<string, unknown>;
        resolve(payload);
      });
    });

    const proofPromise = new Promise<Record<string, unknown>>((resolve) => {
      source.addEventListener('manifestProof', (event: MessageEvent) => {
        const payload = JSON.parse(event.data as string) as Record<string, unknown>;
        resolve(payload);
      });
    });

    await opened;

    const lifecycle = getServerLifecycle(streamingApp);
    const profile = {
      score: 37,
      classification: 'moderate',
      breakdown: [
        { factor: 'coverage', contribution: 12, weight: 40, details: 'Coverage tracking' },
      ],
      missingSignals: ['testing'],
    } as RiskProfile;

    lifecycle.events.publishRiskProfile(tenantId, profile, {
      id: 'risk-stream',
      emittedAt: '2024-09-01T10:00:00Z',
    });

    const ledgerEntry: LedgerEntry = {
      index: 5,
      snapshotId: '20240901T095000Z-feedface',
      manifestDigest: 'e'.repeat(64),
      timestamp: '2024-09-01T09:50:00Z',
      evidence: [],
      merkleRoot: 'f'.repeat(64),
      previousRoot: '1'.repeat(64),
      ledgerRoot: '2'.repeat(64),
    };
    lifecycle.events.publishLedgerEntry(tenantId, ledgerEntry, { id: 'ledger-stream' });

    const jobTime = new Date('2024-09-01T10:05:00Z');
    lifecycle.events.publishQueueState(
      tenantId,
      [
        {
          id: 'job-stream',
          kind: 'analyze',
          hash: 'hash-stream',
          status: 'running',
          createdAt: jobTime,
          updatedAt: jobTime,
        },
      ],
      { id: 'queue-stream' },
    );

    lifecycle.events.publishManifestProof(
      tenantId,
      {
        manifestId: 'manifest-stream',
        jobId: 'job-stream',
        merkle: {
          algorithm: 'ledger-merkle-v1',
          root: 'd'.repeat(64),
          manifestDigest: 'c'.repeat(64),
          snapshotId: 'snap-stream',
        },
        files: [
          { path: 'reports/output.txt', sha256: 'e'.repeat(64), hasProof: true, verified: true },
        ],
      },
      { id: 'manifest-proof-stream' },
    );

    const [riskData, ledgerData, queueData, proofData] = await Promise.all([
      riskPromise,
      ledgerPromise,
      queuePromise,
      proofPromise,
    ]);

    expect(riskData.profile).toMatchObject({ score: 37, classification: 'moderate' });
    expect(ledgerData.entry).toMatchObject({ ledgerRoot: ledgerEntry.ledgerRoot });
    expect(queueData.jobs).toHaveLength(1);
    expect(queueData.counts).toMatchObject({ running: 1 });
    expect(proofData.files).toEqual(
      expect.arrayContaining([expect.objectContaining({ hasProof: true, verified: true })]),
    );

    lifecycle.events.publishRiskProfile('tenant-b', profile, { id: 'risk-other' });
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(riskMessages).toHaveLength(1);

    source.close();
    await new Promise<void>((resolve) => httpsServer.close(() => resolve()));
    await lifecycle.shutdown();
  });

  it('uses database counts to update queue metrics', async () => {
    databaseStub.pool.query.mockClear();

    const importResponse = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .attach('junit', minimalExample('results.xml'))
      .attach('lcov', minimalExample('lcov.info'))
      .field('projectName', 'Metrics Demo')
      .field('projectVersion', `metrics-${Date.now()}`)
      .expect(202);

    await waitForJobCompletion(app, token, importResponse.body.id);

    const countQueries = databaseStub.pool.query.mock.calls.filter(
      ([sql]) => typeof sql === 'string' && sql.toLowerCase().includes('select count(*'),
    );
    expect(countQueries.length).toBeGreaterThan(0);
  });

  it('propagates database errors when listing jobs fails', async () => {
    databaseStub.failNext(new Error('db failure'));

    const response = await request(app)
      .get('/v1/jobs')
      .set('Authorization', `Bearer ${token}`)
      .expect(500);

    expect(response.body.error.code).toBe('UNEXPECTED_ERROR');
  });
});

