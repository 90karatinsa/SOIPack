import { Manifest } from '@soipack/core';
import { createHash, sign, verify } from 'crypto';
import { promises as fsPromises, createReadStream, createWriteStream } from 'fs';
import path from 'path';
import { ZipFile } from 'yazl';
import { finished } from 'stream/promises';

const { readdir, stat, readFile, mkdir } = fsPromises;

interface FileForPackaging {
  absolutePath: string;
  manifestPath: string;
  sha256: string;
}

const normalizeToPosix = (value: string): string => value.replace(/\\/g, '/');

const joinPosix = (...segments: string[]): string => normalizeToPosix(path.join(...segments));

const canonicalizeManifest = (manifest: Manifest): Manifest => ({
  files: [...manifest.files]
    .map((file) => ({ path: file.path, sha256: file.sha256 }))
    .sort((a, b) => a.path.localeCompare(b.path)),
  createdAt: manifest.createdAt,
  toolVersion: manifest.toolVersion,
});

const base64UrlEncode = (input: Buffer | string): string => {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
  return buffer
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
};

const base64UrlDecode = (input: string): Buffer => {
  const padding = input.length % 4 === 0 ? '' : '='.repeat(4 - (input.length % 4));
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/') + padding;
  return Buffer.from(normalized, 'base64');
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

const deriveEvidencePrefixes = (evidenceDirs: string[]): string[] => {
  const counts = new Map<string, number>();

  evidenceDirs.forEach((dir) => {
    const base = path.basename(path.resolve(dir));
    counts.set(base, (counts.get(base) ?? 0) + 1);
  });

  return evidenceDirs.map((dir, index) => {
    const base = path.basename(path.resolve(dir));
    const occurrences = counts.get(base) ?? 1;
    const suffix = occurrences > 1 ? `-${index + 1}` : '';
    return joinPosix('evidence', `${base}${suffix}`);
  });
};

export interface ManifestBuildOptions {
  reportDir: string;
  evidenceDirs?: string[];
  toolVersion: string;
  now?: Date;
}

export interface ManifestBuildResult {
  manifest: Manifest;
  files: FileForPackaging[];
}

export const buildManifest = async ({
  reportDir,
  evidenceDirs = [],
  toolVersion,
  now,
}: ManifestBuildOptions): Promise<ManifestBuildResult> => {
  const timestamp = now ?? new Date();
  const reportEntries = await collectDirectoryEntries(reportDir, 'reports');
  const evidencePrefixes = deriveEvidencePrefixes(evidenceDirs);

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

  const manifest = canonicalizeManifest({
    files: files.map((file) => ({ path: file.manifestPath, sha256: file.sha256 })),
    createdAt: timestamp.toISOString(),
    toolVersion,
  });

  return { manifest, files };
};

export const signManifest = (manifest: Manifest, privateKeyPem: string): string => {
  const canonical = canonicalizeManifest(manifest);
  const headerJson = JSON.stringify({ alg: 'EdDSA', typ: 'SOIManifest' });
  const payloadJson = JSON.stringify(canonical);
  const encodedHeader = base64UrlEncode(headerJson);
  const encodedPayload = base64UrlEncode(payloadJson);
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = sign(null, Buffer.from(signingInput, 'utf8'), privateKeyPem);
  const encodedSignature = base64UrlEncode(signature);
  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
};

export const verifyManifestSignature = (
  manifest: Manifest,
  signature: string,
  publicKeyPem: string,
): boolean => {
  const segments = signature.split('.');
  if (segments.length !== 3) {
    return false;
  }

  const [encodedHeader, encodedPayload, encodedSignature] = segments;
  try {
    const header = JSON.parse(base64UrlDecode(encodedHeader).toString('utf8')) as { alg?: string };
    if (header.alg !== 'EdDSA') {
      return false;
    }

    const payloadBuffer = base64UrlDecode(encodedPayload);
    const payloadManifest = canonicalizeManifest(JSON.parse(payloadBuffer.toString('utf8')) as Manifest);
    const providedManifest = canonicalizeManifest(manifest);

    if (JSON.stringify(payloadManifest) !== JSON.stringify(providedManifest)) {
      return false;
    }

    return verify(null, Buffer.from(`${encodedHeader}.${encodedPayload}`, 'utf8'), publicKeyPem, base64UrlDecode(encodedSignature));
  } catch (error) {
    return false;
  }
};

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
  privateKeyPath: string;
  now?: Date;
  packageName?: string;
}

export interface PackageCreationResult {
  manifest: Manifest;
  signature: string;
  outputPath: string;
}

export const createSoiDataPack = async ({
  reportDir,
  evidenceDirs = [],
  outputDir,
  toolVersion,
  privateKeyPath,
  now,
  packageName,
}: PackageCreationOptions): Promise<PackageCreationResult> => {
  const timestamp = now ?? new Date();
  const resolvedReportDir = path.resolve(reportDir);
  const defaultOutputDir = path.dirname(resolvedReportDir);
  const targetOutputDir = path.resolve(outputDir ?? defaultOutputDir);

  await mkdir(targetOutputDir, { recursive: true });

  const { manifest, files } = await buildManifest({
    reportDir: resolvedReportDir,
    evidenceDirs: evidenceDirs.map((dir) => path.resolve(dir)),
    toolVersion,
    now: timestamp,
  });

  const privateKeyPem = await readFile(path.resolve(privateKeyPath), 'utf8');
  const signature = signManifest(manifest, privateKeyPem);

  const finalName = packageName ?? `soi-pack-${formatTimestamp(timestamp)}.zip`;
  const outputPath = path.join(targetOutputDir, finalName);

  const zipFile = new ZipFile();
  const outputStream = createWriteStream(outputPath);
  const streamCompleted = finished(outputStream);

  zipFile.outputStream.pipe(outputStream);

  for (const file of files) {
    zipFile.addFile(file.absolutePath, file.manifestPath);
  }

  zipFile.addBuffer(Buffer.from(JSON.stringify(manifest, null, 2), 'utf8'), 'manifest.json');
  zipFile.addBuffer(Buffer.from(signature, 'utf8'), 'manifest.sig');

  zipFile.end();
  await streamCompleted;

  return { manifest, signature, outputPath };
};
