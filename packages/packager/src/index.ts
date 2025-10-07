import { createHash, randomUUID } from 'crypto';
import { promises as fsPromises, createReadStream, createWriteStream } from 'fs';
import path from 'path';
import { finished } from 'stream/promises';

import {
  Manifest,
  ManifestMerkleProof,
  ManifestMerkleSummary,
  SoiStage,
  appendEntry,
  createLedger,
  generateLedgerProof,
  serializeLedgerProof,
} from '@soipack/core';
import { ZipFile } from 'yazl';

import {
  CmsSigningOptions,
  ManifestSignatureBundle,
  SecuritySignerOptions,
  VerificationOptions,
  VerificationResult,
  signManifestWithSecuritySigner,
  verifyManifestSignatureWithSecuritySigner,
  computeManifestDigestHex,
} from './security/signer';

const { readdir, stat, readFile, mkdir } = fsPromises;

interface FileForPackaging {
  absolutePath: string;
  manifestPath: string;
  sha256: string;
}

const normalizeToPosix = (value: string): string => value.replace(/\\/g, '/');

const joinPosix = (...segments: string[]): string => normalizeToPosix(path.join(...segments));

const resolveCmsOptions = (
  cms?: CmsSigningOptions | false,
): CmsSigningOptions | false | undefined => {
  if (cms === undefined) {
    return undefined;
  }

  if (cms === false) {
    return false;
  }

  const resolved: CmsSigningOptions = { ...cms };

  if (cms.bundlePath) {
    resolved.bundlePath = path.resolve(cms.bundlePath);
  }

  if (cms.certificatePath) {
    resolved.certificatePath = path.resolve(cms.certificatePath);
  }

  if (cms.privateKeyPath) {
    resolved.privateKeyPath = path.resolve(cms.privateKeyPath);
  }

  if (cms.chainPath) {
    resolved.chainPath = path.resolve(cms.chainPath);
  }

  return resolved;
};

export interface ManifestLedgerMetadata {
  ledger?: {
    root: string | null;
    previousRoot?: string | null;
  } | null;
}

export interface ManifestMerkleMetadata {
  merkle?: ManifestMerkleSummary;
}

export interface ManifestStageMetadata {
  stage?: SoiStage | null;
}

export interface ManifestSbomMetadata {
  sbom?: {
    path: string;
    algorithm: 'sha256';
    digest: string;
  } | null;
}

export type LedgerAwareManifest = Manifest &
  ManifestLedgerMetadata &
  ManifestMerkleMetadata &
  ManifestStageMetadata &
  ManifestSbomMetadata;

const MANIFEST_PROOF_SNAPSHOT_ID = 'manifest-files';

const buildManifestSnapshotId = (digest: string, stage?: SoiStage | null): string =>
  stage ? `manifest:${stage}:${digest}` : `manifest:${digest}`;

const buildManifestEvidenceSnapshotId = (stage?: SoiStage | null): string =>
  stage ? `${MANIFEST_PROOF_SNAPSHOT_ID}:${stage}` : MANIFEST_PROOF_SNAPSHOT_ID;

const computeManifestProofs = (
  manifest: Manifest,
): { summary: ManifestMerkleSummary; proofs: Map<string, ManifestMerkleProof> } => {
  const digest = computeManifestDigestHex(manifest);
  const stage = (manifest as LedgerAwareManifest).stage ?? null;
  const ledger = appendEntry(createLedger(), {
    snapshotId: buildManifestSnapshotId(digest, stage),
    manifestDigest: digest,
    timestamp: manifest.createdAt,
    evidence: manifest.files.map((file) => ({
      snapshotId: buildManifestEvidenceSnapshotId(stage),
      path: file.path,
      hash: file.sha256,
    })),
  });
  const entry = ledger.entries[ledger.entries.length - 1];

  const summary: ManifestMerkleSummary = {
    algorithm: 'ledger-merkle-v1',
    root: entry.merkleRoot,
    manifestDigest: digest,
    snapshotId: entry.snapshotId,
  };

  const proofs = new Map<string, ManifestMerkleProof>();

  manifest.files.forEach((file) => {
    const proof = generateLedgerProof(entry, {
      type: 'evidence',
      snapshotId: MANIFEST_PROOF_SNAPSHOT_ID,
      path: file.path,
      hash: file.sha256,
    });
    proofs.set(file.path, {
      algorithm: 'ledger-merkle-v1',
      merkleRoot: entry.merkleRoot,
      proof: serializeLedgerProof(proof),
    });
  });

  return { summary, proofs };
};

const canonicalizeManifest = (manifest: LedgerAwareManifest): LedgerAwareManifest => {
  const ledgerMetadata = manifest.ledger
    ? {
        root: manifest.ledger.root ?? null,
        previousRoot:
          manifest.ledger.previousRoot === undefined
            ? null
            : manifest.ledger.previousRoot,
      }
    : manifest.ledger === null
      ? null
      : undefined;

  const canonical: LedgerAwareManifest = {
    files: [...manifest.files]
      .map((file) => ({ path: file.path, sha256: file.sha256 }))
      .sort((a, b) => a.path.localeCompare(b.path)),
    createdAt: manifest.createdAt,
    toolVersion: manifest.toolVersion,
  };

  if (manifest.stage !== undefined) {
    canonical.stage = manifest.stage ?? null;
  }

  if (ledgerMetadata !== undefined) {
    canonical.ledger = ledgerMetadata;
  }

  if (manifest.sbom !== undefined) {
    canonical.sbom =
      manifest.sbom === null
        ? null
        : {
            path: manifest.sbom.path,
            algorithm: 'sha256',
            digest: manifest.sbom.digest,
          };
  }

  return canonical;
};

const hashFile = async (filePath: string): Promise<string> => {
  const hash = createHash('sha256');
  const stream = createReadStream(filePath);
  stream.on('data', (chunk) => hash.update(chunk));
  await finished(stream);
  return hash.digest('hex');
};

const listFilesRecursively = async (root: string): Promise<string[]> => {
  const entries = await readdir(root, { withFileTypes: true });
  entries.sort((a, b) => a.name.localeCompare(b.name));

  const files: string[] = [];

  for (const entry of entries) {
    const fullPath = path.join(root, entry.name);

    if (entry.isDirectory()) {
      files.push(...(await listFilesRecursively(fullPath)));
    } else if (entry.isFile()) {
      files.push(fullPath);
    }
  }

  return files;
};

const collectDirectoryEntries = async (
  directory: string,
  prefix: string,
): Promise<Array<{ absolutePath: string; manifestPath: string }>> => {
  const absolute = path.resolve(directory);
  const stats = await stat(absolute);

  if (!stats.isDirectory()) {
    throw new Error(`Expected directory at path: ${directory}`);
  }

  const files = await listFilesRecursively(absolute);
  return files.map((file) => {
    const relativePath = path.relative(absolute, file);
    const normalizedRelative = normalizeToPosix(relativePath);
    const manifestPath = prefix
      ? joinPosix(prefix, normalizedRelative)
      : normalizeToPosix(normalizedRelative);

    return {
      absolutePath: file,
      manifestPath,
    };
  });
};

const deriveEvidencePrefixes = (evidenceDirs: string[], stage?: SoiStage | null): string[] => {
  const counts = new Map<string, number>();

  evidenceDirs.forEach((dir) => {
    const base = path.basename(path.resolve(dir));
    counts.set(base, (counts.get(base) ?? 0) + 1);
  });

  return evidenceDirs.map((dir, index) => {
    const base = path.basename(path.resolve(dir));
    const occurrences = counts.get(base) ?? 1;
    const suffix = occurrences > 1 ? `-${index + 1}` : '';
    const evidenceRoot = stage ? joinPosix('evidence', stage) : 'evidence';
    return joinPosix(evidenceRoot, `${base}${suffix}`);
  });
};

export interface ManifestLedgerOptions {
  root: string | null;
  previousRoot?: string | null;
}

export interface ManifestBuildOptions {
  reportDir: string;
  evidenceDirs?: string[];
  toolVersion: string;
  now?: Date;
  ledger?: ManifestLedgerOptions | null;
  stage?: SoiStage | null;
}

export interface ManifestBuildResult {
  manifest: LedgerAwareManifest;
  files: FileForPackaging[];
}

export const buildManifest = async ({
  reportDir,
  evidenceDirs = [],
  toolVersion,
  now,
  ledger,
  stage,
}: ManifestBuildOptions): Promise<ManifestBuildResult> => {
  const timestamp = now ?? new Date();
  const reportPrefix = stage ? joinPosix('reports', stage) : 'reports';
  const reportEntries = await collectDirectoryEntries(reportDir, reportPrefix);
  const evidencePrefixes = deriveEvidencePrefixes(evidenceDirs, stage);

  const evidenceEntries: Array<{ absolutePath: string; manifestPath: string }> = [];

  for (let i = 0; i < evidenceDirs.length; i += 1) {
    const prefix = evidencePrefixes[i];
    const dirEntries = await collectDirectoryEntries(evidenceDirs[i], prefix);
    evidenceEntries.push(...dirEntries);
  }

  const combinedEntries = [...reportEntries, ...evidenceEntries];
  combinedEntries.sort((a, b) => a.manifestPath.localeCompare(b.manifestPath));

  const files: FileForPackaging[] = [];

  for (const entry of combinedEntries) {
    const sha256 = await hashFile(entry.absolutePath);
    files.push({ ...entry, sha256 });
  }

  const manifestBase = canonicalizeManifest({
    files: files.map((file) => ({ path: file.manifestPath, sha256: file.sha256 })),
    createdAt: timestamp.toISOString(),
    toolVersion,
    stage: stage ?? null,
    ledger: ledger
      ? {
          root: ledger.root,
          previousRoot: ledger.previousRoot ?? null,
        }
      : ledger === null
        ? null
        : undefined,
  });

  const { summary, proofs } = computeManifestProofs(manifestBase);

  const manifest: LedgerAwareManifest = {
    ...manifestBase,
    merkle: summary,
    files: manifestBase.files.map((file) => {
      const proof = proofs.get(file.path);
      return proof ? { ...file, proof } : file;
    }),
  };

  return { manifest, files };
};

export const signManifest = (
  manifest: Manifest,
  privateKeyPemOrOptions: string | SecuritySignerOptions,
): string => {
  const options: SecuritySignerOptions =
    typeof privateKeyPemOrOptions === 'string'
      ? { privateKeyPem: privateKeyPemOrOptions }
      : privateKeyPemOrOptions;
  const bundle = signManifestWithSecuritySigner(manifest, options);
  return bundle.signature;
};

export const signManifestBundle = (
  manifest: Manifest,
  options?: SecuritySignerOptions,
): ManifestSignatureBundle => signManifestWithSecuritySigner(manifest, options);

export const verifyManifestSignature = (
  manifest: Manifest,
  signature: string,
  publicKeyOrOptions: string | VerificationOptions,
): boolean => {
  const options: VerificationOptions =
    typeof publicKeyOrOptions === 'string'
      ? publicKeyOrOptions.includes('BEGIN CERTIFICATE')
        ? { certificatePem: publicKeyOrOptions }
        : { publicKeyPem: publicKeyOrOptions }
      : publicKeyOrOptions;
  const result = verifyManifestSignatureWithSecuritySigner(manifest, signature, options);
  return result.valid;
};

export const verifyManifestSignatureDetailed = (
  manifest: Manifest,
  signature: string,
  options?: VerificationOptions,
): VerificationResult => verifyManifestSignatureWithSecuritySigner(manifest, signature, options);

const formatTimestamp = (date: Date): string => {
  const year = date.getUTCFullYear();
  const month = `${date.getUTCMonth() + 1}`.padStart(2, '0');
  const day = `${date.getUTCDate()}`.padStart(2, '0');
  const hours = `${date.getUTCHours()}`.padStart(2, '0');
  const minutes = `${date.getUTCMinutes()}`.padStart(2, '0');
  return `${year}${month}${day}_${hours}${minutes}`;
};

export interface PackageCreationOptions {
  reportDir: string;
  evidenceDirs?: string[];
  outputDir?: string;
  toolVersion: string;
  credentialsPath: string;
  now?: Date;
  packageName?: string;
  ledger?: ManifestLedgerOptions | null;
  stage?: SoiStage | null;
  cms?: CmsSigningOptions | false;
}

export interface PackageCreationResult {
  manifest: LedgerAwareManifest;
  signature: string;
  outputPath: string;
  sbom: {
    path: string;
    algorithm: 'sha256';
    digest: string;
    content: string;
  };
  cmsSignature?: {
    path: string;
    algorithm: 'sha256';
    digest: string;
    der: string;
    pem: string;
    certificates: string[];
    digestAlgorithm: string;
  };
}

interface SpdxFileEntry {
  SPDXID: string;
  fileName: string;
  checksums: Array<{ algorithm: 'SHA256'; checksumValue: string }>;
}

interface SpdxDocument {
  spdxVersion: 'SPDX-2.3';
  dataLicense: 'CC0-1.0';
  SPDXID: 'SPDXRef-DOCUMENT';
  name: string;
  documentNamespace: string;
  creationInfo: {
    created: string;
    creators: string[];
  };
  packages: Array<{
    SPDXID: string;
    name: string;
    downloadLocation: 'NOASSERTION';
    filesAnalyzed: boolean;
    hasFiles: string[];
    licenseConcluded: 'NOASSERTION';
    licenseDeclared: 'NOASSERTION';
    originator: string;
  }>;
  files: SpdxFileEntry[];
  relationships: Array<{
    spdxElementId: string;
    relationshipType: 'DESCRIBES' | 'CONTAINS';
    relatedSpdxElement: string;
  }>;
}

const SBOM_FILENAME = 'sbom.spdx.json';

const generateSpdxSbom = ({
  files,
  toolVersion,
  timestamp,
  packageLabel,
}: {
  files: FileForPackaging[];
  toolVersion: string;
  timestamp: Date;
  packageLabel: string;
}): SpdxDocument => {
  const fileEntries: SpdxFileEntry[] = files.map((file, index) => ({
    SPDXID: `SPDXRef-File-${index + 1}`,
    fileName: file.manifestPath,
    checksums: [
      {
        algorithm: 'SHA256',
        checksumValue: file.sha256,
      },
    ],
  }));

  const packageId = 'SPDXRef-Package-SOIPack';

  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: packageLabel,
    documentNamespace: `urn:uuid:${randomUUID()}`,
    creationInfo: {
      created: timestamp.toISOString(),
      creators: [`Tool: SOIPack Packager ${toolVersion}`],
    },
    packages: [
      {
        SPDXID: packageId,
        name: packageLabel,
        downloadLocation: 'NOASSERTION',
        filesAnalyzed: true,
        hasFiles: fileEntries.map((entry) => entry.SPDXID),
        licenseConcluded: 'NOASSERTION',
        licenseDeclared: 'NOASSERTION',
        originator: 'Organization: SOIPack',
      },
    ],
    files: fileEntries,
    relationships: [
      {
        spdxElementId: 'SPDXRef-DOCUMENT',
        relationshipType: 'DESCRIBES',
        relatedSpdxElement: packageId,
      },
      ...fileEntries.map((entry) => ({
        spdxElementId: packageId,
        relationshipType: 'CONTAINS' as const,
        relatedSpdxElement: entry.SPDXID,
      })),
    ],
  };
};

export const createSoiDataPack = async ({
  reportDir,
  evidenceDirs = [],
  outputDir,
  toolVersion,
  credentialsPath,
  now,
  packageName,
  ledger,
  stage,
  cms,
}: PackageCreationOptions): Promise<PackageCreationResult> => {
  const timestamp = now ?? new Date();
  const resolvedReportDir = path.resolve(reportDir);
  const defaultOutputDir = path.dirname(resolvedReportDir);
  const targetOutputDir = path.resolve(outputDir ?? defaultOutputDir);

  await mkdir(targetOutputDir, { recursive: true });

  const { manifest: baseManifest, files } = await buildManifest({
    reportDir: resolvedReportDir,
    evidenceDirs: evidenceDirs.map((dir) => path.resolve(dir)),
    toolVersion,
    now: timestamp,
    ledger,
    stage,
  });

  const packageLabel = packageName ?? `soi-pack-${formatTimestamp(timestamp)}.zip`;
  const sbomDocument = generateSpdxSbom({
    files,
    toolVersion,
    timestamp,
    packageLabel,
  });
  const serializedSbom = JSON.stringify(sbomDocument, null, 2);
  const sbomDigest = createHash('sha256').update(serializedSbom, 'utf8').digest('hex');
  const sbomMetadata = {
    path: SBOM_FILENAME,
    algorithm: 'sha256' as const,
    digest: sbomDigest,
  };

  const manifestForSigning: LedgerAwareManifest = {
    createdAt: baseManifest.createdAt,
    toolVersion: baseManifest.toolVersion,
    files: baseManifest.files.map((file) => ({ path: file.path, sha256: file.sha256 })),
    stage: baseManifest.stage,
    ledger: baseManifest.ledger,
    sbom: sbomMetadata,
  };

  const { summary, proofs } = computeManifestProofs(manifestForSigning);

  const manifestWithSbom: LedgerAwareManifest = {
    ...manifestForSigning,
    merkle: summary,
    files: manifestForSigning.files.map((file) => {
      const proof = proofs.get(file.path);
      return proof ? { ...file, proof } : file;
    }),
  };

  const credentialsPem = await readFile(path.resolve(credentialsPath), 'utf8');
  const ledgerForSigning =
    ledger && ledger.root
      ? {
          root: ledger.root,
          previousRoot: ledger.previousRoot ?? null,
        }
      : undefined;
  const resolvedCmsOptions = resolveCmsOptions(cms);
  const signingOptions: SecuritySignerOptions = {
    bundlePem: credentialsPem,
    ledger: ledgerForSigning,
  };
  if (resolvedCmsOptions !== undefined) {
    signingOptions.cms = resolvedCmsOptions;
  }
  const bundle = signManifestBundle(manifestWithSbom, signingOptions);
  const signature = bundle.signature;
  const verification = verifyManifestSignatureDetailed(manifestWithSbom, signature, {
    expectedLedgerRoot: ledger?.root ?? null,
    expectedPreviousLedgerRoot: ledger?.previousRoot ?? null,
    requireLedgerProof: Boolean(ledgerForSigning),
  });
  if (!verification.valid) {
    const reason = verification.reason ?? 'bilinmeyen';
    throw new Error(`Manifest imzası doğrulanamadı: ${reason}`);
  }

  if (manifestWithSbom.ledger) {
    const manifestLedgerRoot = manifestWithSbom.ledger.root ?? null;
    const manifestPrevious = manifestWithSbom.ledger.previousRoot ?? null;
    if (verification.ledgerRoot !== manifestLedgerRoot) {
      throw new Error('Manifest ledger kökü imza bağlamıyla eşleşmiyor.');
    }
    if (verification.previousLedgerRoot !== manifestPrevious) {
      throw new Error('Manifest ledger önceki kökü imza bağlamıyla eşleşmiyor.');
    }
  }

  const finalName = packageLabel;
  const outputPath = path.join(targetOutputDir, finalName);

  const zipFile = new ZipFile();
  const outputStream = createWriteStream(outputPath);
  const streamCompleted = finished(outputStream);

  zipFile.outputStream.pipe(outputStream);

  for (const file of files) {
    zipFile.addFile(file.absolutePath, file.manifestPath);
  }

  zipFile.addBuffer(Buffer.from(JSON.stringify(manifestWithSbom, null, 2), 'utf8'), 'manifest.json');
  zipFile.addBuffer(Buffer.from(signature, 'utf8'), 'manifest.sig');
  let cmsSignatureMetadata: PackageCreationResult['cmsSignature'];
  if (bundle.cmsSignature) {
    const cmsBuffer = Buffer.from(bundle.cmsSignature.der, 'base64');
    const cmsDigest = createHash('sha256').update(cmsBuffer).digest('hex');
    zipFile.addBuffer(cmsBuffer, 'manifest.cms');
    cmsSignatureMetadata = {
      path: 'manifest.cms',
      algorithm: 'sha256',
      digest: cmsDigest,
      der: bundle.cmsSignature.der,
      pem: bundle.cmsSignature.pem,
      certificates: bundle.cmsSignature.certificates,
      digestAlgorithm: bundle.cmsSignature.digestAlgorithm,
    };
  }
  zipFile.addBuffer(Buffer.from(serializedSbom, 'utf8'), SBOM_FILENAME);

  zipFile.end();
  await streamCompleted;

  return {
    manifest: manifestWithSbom,
    signature,
    outputPath,
    sbom: { ...sbomMetadata, content: serializedSbom },
    cmsSignature: cmsSignatureMetadata,
  };
};

export type {
  CmsSigningOptions,
  ManifestDigest,
  ManifestSignatureBundle,
  SecuritySignerOptions,
  VerificationFailureReason,
  VerificationOptions,
  VerificationResult,
} from './security/signer';

export {
  assertValidManifestSignature,
  computeManifestDigestHex,
  signManifestWithSecuritySigner,
  verifyManifestSignatureWithSecuritySigner,
} from './security/signer';
