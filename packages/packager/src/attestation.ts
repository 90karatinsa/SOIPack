import { createHash, createPrivateKey, createPublicKey, sign as signData } from 'crypto';

import type { ManifestFileEntry, ManifestMerkleSummary } from '@soipack/core';

import type { LedgerAwareManifest } from './index';
import type { ManifestSignatureBundle } from './security/signer';

const base64UrlEncode = (input: Buffer | string): string => {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
  return buffer
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
};

const base64UrlDecode = (value: string): Buffer => {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padding = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  return Buffer.from(`${normalized}${padding}`, 'base64');
};

const canonicalize = (value: unknown): unknown => {
  if (Array.isArray(value)) {
    return value.map((entry) => canonicalize(entry));
  }

  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entryValue]) => entryValue !== undefined)
      .map(([key, entryValue]) => [key, canonicalize(entryValue)] as const)
      .sort(([a], [b]) => a.localeCompare(b));

    return entries.reduce<Record<string, unknown>>((acc, [key, entryValue]) => {
      acc[key] = entryValue;
      return acc;
    }, {});
  }

  return value;
};

const pruneUndefined = <T>(value: T): T => {
  if (Array.isArray(value)) {
    return value.map((entry) => pruneUndefined(entry)).filter((entry) => entry !== undefined) as T;
  }

  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>);
    const result: Record<string, unknown> = {};

    entries.forEach(([key, entryValue]) => {
      const normalized = pruneUndefined(entryValue);
      if (normalized !== undefined) {
        result[key] = normalized;
      }
    });

    return result as T;
  }

  return value;
};

const computeSha256Hex = (value: Buffer | string): string =>
  createHash('sha256').update(value).digest('hex');

const computeKeyId = (publicKeyPem: string): string => computeSha256Hex(publicKeyPem);

export interface ProvenanceDigest {
  algorithm: 'sha256';
  digest: string;
}

export interface ProvenanceSubject {
  name: string;
  digest: { sha256: string };
}

export interface ProvenanceResourceDescriptor {
  uri?: string;
  name?: string;
  digest?: { sha256: string };
  mediaType?: string;
  annotations?: Record<string, string>;
  content?: unknown;
}

export interface ProvenancePredicate {
  buildDefinition: {
    buildType: string;
    externalParameters: Record<string, unknown>;
    resolvedDependencies: ProvenanceResourceDescriptor[];
  };
  runDetails: {
    builder: { id: string };
    metadata: Record<string, unknown>;
    byproducts: ProvenanceResourceDescriptor[];
  };
}

export interface InTotoStatement {
  _type: 'https://in-toto.io/Statement/v0.1';
  subject: ProvenanceSubject[];
  predicateType: 'https://slsa.dev/provenance/v1';
  predicate: ProvenancePredicate;
}

export interface AttestationSignatureRecord {
  algorithm: 'EdDSA';
  keyId?: string;
  publicKey: string;
  protectedHeader: Record<string, unknown>;
  protected: string;
  signature: string;
  jws: string;
}

export interface AttestationDocument {
  statement: InTotoStatement;
  statementDigest: ProvenanceDigest;
  signatures: AttestationSignatureRecord[];
}

export interface AttestationSigningOptions {
  keyId?: string;
  privateKeyPem?: string;
  publicKeyPem?: string;
  protectedHeader?: Record<string, unknown>;
  externalSigner?: (
    input: {
      signingInput: string;
      payload: string;
      header: Readonly<Record<string, unknown>>;
    },
  ) => Promise<string | Buffer | { signature: string | Buffer; publicKeyPem?: string }> | string | Buffer | {
    signature: string | Buffer;
    publicKeyPem?: string;
  };
}

export interface AttestationGenerationOptions {
  manifest: LedgerAwareManifest;
  manifestDigest: string;
  sbom: { path: string; algorithm: 'sha256'; digest: string };
  files: Array<{ path: string; sha256: string }>;
  packageName: string;
  manifestSignature: ManifestSignatureBundle;
  builderId?: string;
  invocationId?: string;
  environment?: Record<string, unknown>;
  signing: AttestationSigningOptions;
}

export interface AttestationGenerationResult {
  document: AttestationDocument;
  payload: string;
  signature: AttestationSignatureRecord;
}

const normalizeManifestFile = (file: ManifestFileEntry): { path: string; sha256: string } => ({
  path: file.path,
  sha256: file.sha256,
});

const resolvePublicKeyPem = (options: AttestationSigningOptions): string | undefined => {
  if (options.publicKeyPem) {
    return options.publicKeyPem;
  }

  if (!options.privateKeyPem) {
    return undefined;
  }

  const key = createPrivateKey(options.privateKeyPem);
  return createPublicKey(key).export({ format: 'pem', type: 'spki' }).toString();
};

const normalizeHeader = (header: Record<string, unknown>): Record<string, unknown> =>
  canonicalize(pruneUndefined(header)) as Record<string, unknown>;

const serializeCanonicalJson = (value: unknown): string => JSON.stringify(canonicalize(pruneUndefined(value)));

const buildSignatureMetadata = (
  manifestSignature: ManifestSignatureBundle,
): Record<string, unknown> => {
  const metadata: Record<string, unknown> = {
    digest: manifestSignature.manifestDigest.hash,
    certificateSha256: computeSha256Hex(manifestSignature.certificate),
    ledgerRoot: manifestSignature.ledgerRoot ?? null,
    previousLedgerRoot: manifestSignature.previousLedgerRoot ?? null,
  };

  if (manifestSignature.hardware) {
    metadata.hardware = manifestSignature.hardware;
  }

  if (manifestSignature.postQuantumSignature) {
    metadata.postQuantum = manifestSignature.postQuantumSignature;
  }

  if (manifestSignature.cmsSignature) {
    const cmsBuffer = Buffer.from(manifestSignature.cmsSignature.der, 'base64');
    metadata.cms = {
      digest: computeSha256Hex(cmsBuffer),
      digestAlgorithm: manifestSignature.cmsSignature.digestAlgorithm,
    };
  }

  return metadata;
};

const buildResolvedDependencies = (
  files: Array<{ path: string; sha256: string }>,
): ProvenanceResourceDescriptor[] =>
  files
    .map((file) => ({
      uri: `file:${file.path}`,
      digest: { sha256: file.sha256 },
    }))
    .sort((a, b) => (a.uri ?? '').localeCompare(b.uri ?? ''));

const buildByproducts = (
  manifestSignature: ManifestSignatureBundle,
): ProvenanceResourceDescriptor[] => {
  const base: ProvenanceResourceDescriptor = {
    name: 'manifest-signature',
    uri: 'urn:soipack:manifest-signature',
    digest: { sha256: computeSha256Hex(manifestSignature.signature) },
    mediaType: 'application/jose+json',
  };

  const byproducts: ProvenanceResourceDescriptor[] = [base];

  if (manifestSignature.cmsSignature) {
    byproducts.push({
      name: 'manifest-cms-signature',
      uri: 'urn:soipack:manifest-cms-signature',
      digest: { sha256: computeSha256Hex(Buffer.from(manifestSignature.cmsSignature.der, 'base64')) },
      mediaType: 'application/pkcs7-mime',
    });
  }

  if (manifestSignature.postQuantumSignature) {
    byproducts.push({
      name: 'manifest-post-quantum-signature',
      uri: 'urn:soipack:manifest-post-quantum-signature',
      digest: { sha256: computeSha256Hex(manifestSignature.postQuantumSignature.signature) },
      mediaType: 'application/octet-stream',
      annotations: {
        algorithm: manifestSignature.postQuantumSignature.algorithm,
      },
    });
  }

  return byproducts;
};

const buildStatement = (
  manifest: LedgerAwareManifest,
  manifestDigest: string,
  files: Array<{ path: string; sha256: string }>,
  sbom: { path: string; algorithm: 'sha256'; digest: string },
  packageName: string,
  manifestSignature: ManifestSignatureBundle,
  builderId: string,
  invocationId?: string,
  environment?: Record<string, unknown>,
): InTotoStatement => {
  const subjects: ProvenanceSubject[] = [
    { name: 'manifest.json', digest: { sha256: manifestDigest } },
    { name: 'manifest.sig', digest: { sha256: computeSha256Hex(manifestSignature.signature) } },
    { name: sbom.path, digest: { sha256: sbom.digest } },
  ];

  if (manifestSignature.cmsSignature) {
    subjects.push({
      name: 'manifest.cms',
      digest: { sha256: computeSha256Hex(Buffer.from(manifestSignature.cmsSignature.der, 'base64')) },
    });
  }

  const dependencies = buildResolvedDependencies(files);

  const metadata: Record<string, unknown> = {
    manifestCreatedAt: manifest.createdAt,
    manifestDigest,
    toolVersion: manifest.toolVersion,
    packageName,
    manifestStage: manifest.stage ?? null,
    ledgerRoot: manifest.ledger?.root ?? null,
    previousLedgerRoot: manifest.ledger?.previousRoot ?? null,
    merkleRoot: (manifest.merkle as ManifestMerkleSummary | undefined)?.root ?? null,
    merkleSnapshot: (manifest.merkle as ManifestMerkleSummary | undefined)?.snapshotId ?? null,
    sbomDigest: sbom.digest,
    signature: buildSignatureMetadata(manifestSignature),
  };

  if (invocationId) {
    metadata.invocationId = invocationId;
  }

  if (environment && Object.keys(environment).length > 0) {
    metadata.environment = environment;
  }

  const aggregate = createHash('sha256');
  dependencies.forEach((dependency) => {
    aggregate.update(`${dependency.uri ?? ''}:${dependency.digest?.sha256 ?? ''}\n`);
  });
  metadata.inputsDigest = aggregate.digest('hex');

  const externalParameters: Record<string, unknown> = {
    packageName,
    stage: manifest.stage ?? null,
    ledger: manifest.ledger ?? null,
    sbom,
  };

  const statement: InTotoStatement = {
    _type: 'https://in-toto.io/Statement/v0.1',
    subject: subjects.sort((a, b) => a.name.localeCompare(b.name)),
    predicateType: 'https://slsa.dev/provenance/v1',
    predicate: {
      buildDefinition: {
        buildType: 'https://soipack.dev/attestations/packager/v1',
        externalParameters,
        resolvedDependencies: dependencies,
      },
      runDetails: {
        builder: { id: builderId },
        metadata,
        byproducts: buildByproducts(manifestSignature),
      },
    },
  };

  return statement;
};

export const generateAttestation = async (
  options: AttestationGenerationOptions,
): Promise<AttestationGenerationResult> => {
  const builderId = options.builderId ?? 'https://soipack.dev/tools/packager';
  const manifest = options.manifest;
  const files = options.files.length > 0 ? options.files : manifest.files.map(normalizeManifestFile);

  const statement = buildStatement(
    manifest,
    options.manifestDigest,
    files,
    options.sbom,
    options.packageName,
    options.manifestSignature,
    builderId,
    options.invocationId,
    options.environment,
  );

  const payload = serializeCanonicalJson(statement);
  const statementDigest: ProvenanceDigest = {
    algorithm: 'sha256',
    digest: computeSha256Hex(payload),
  };

  const baseHeader: Record<string, unknown> = {
    alg: 'EdDSA',
    typ: 'application/vnd.in-toto+json',
  };

  const initialPublicKey = resolvePublicKeyPem(options.signing) ?? options.manifestSignature.certificate;
  const keyId = options.signing.keyId ?? (initialPublicKey ? computeKeyId(initialPublicKey) : undefined);

  if (keyId) {
    baseHeader.kid = keyId;
  }

  const header = normalizeHeader({ ...baseHeader, ...options.signing.protectedHeader });
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(payload);
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  let signatureBuffer: Buffer;
  let publicKeyPem = initialPublicKey;

  if (options.signing.externalSigner) {
    const result = await options.signing.externalSigner({
      signingInput,
      payload,
      header,
    });

    if (typeof result === 'string' || Buffer.isBuffer(result)) {
      signatureBuffer = Buffer.isBuffer(result) ? result : base64UrlDecode(result);
    } else {
      const { signature, publicKeyPem: providedPublicKey } = result;
      signatureBuffer = Buffer.isBuffer(signature) ? signature : base64UrlDecode(signature);
      if (providedPublicKey) {
        publicKeyPem = providedPublicKey;
      }
    }
  } else if (options.signing.privateKeyPem) {
    const privateKey = createPrivateKey(options.signing.privateKeyPem);
    signatureBuffer = signData(null, Buffer.from(signingInput, 'utf8'), privateKey);
  } else {
    throw new Error('Attestation imzası için özel anahtar veya dış imzalayıcı belirtilmelidir.');
  }

  if (!publicKeyPem && options.signing.privateKeyPem) {
    publicKeyPem = createPublicKey(createPrivateKey(options.signing.privateKeyPem))
      .export({ format: 'pem', type: 'spki' })
      .toString();
  }

  if (!publicKeyPem) {
    throw new Error('Attestation imzası için açık anahtar belirlenemedi.');
  }

  const encodedSignature = base64UrlEncode(signatureBuffer);
  const jws = `${encodedHeader}.${encodedPayload}.${encodedSignature}`;

  const signature: AttestationSignatureRecord = {
    algorithm: 'EdDSA',
    keyId,
    publicKey: publicKeyPem,
    protectedHeader: header,
    protected: encodedHeader,
    signature: encodedSignature,
    jws,
  };

  const document: AttestationDocument = {
    statement,
    statementDigest,
    signatures: [signature],
  };

  return { document, payload, signature };
};

export const serializeAttestationDocument = (document: AttestationDocument): string =>
  JSON.stringify(canonicalize(pruneUndefined(document)), null, 2);
