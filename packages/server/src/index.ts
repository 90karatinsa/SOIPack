import { createHash } from 'crypto';
import fs, { promises as fsPromises } from 'fs';
import path from 'path';

import {
  AnalyzeOptions,
  ImportOptions,
  ImportWorkspace,
  PackOptions,
  ReportOptions,
  runAnalyze,
  runImport,
  runPack,
  runReport,
} from '@soipack/cli';
import { CertificationLevel } from '@soipack/core';
import express, { Express, NextFunction, Request, Response } from 'express';
import multer from 'multer';

import { HttpError } from './errors';
import { JobDetails, JobQueue, JobSummary } from './queue';

type FileMap = Record<string, Express.Multer.File[]>;

type PersistableFile = Pick<Express.Multer.File, 'originalname' | 'buffer'>;

type UploadedFileMap = Record<string, PersistableFile[]>;

interface HashEntry {
  key: string;
  value: string;
}

interface BaseJobMetadata {
  id: string;
  hash: string;
  kind: 'import' | 'analyze' | 'report' | 'pack';
  createdAt: string;
  directory: string;
  params: Record<string, unknown>;
}

interface ImportJobMetadata extends BaseJobMetadata {
  kind: 'import';
  warnings: string[];
  outputs: {
    workspacePath: string;
  };
}

interface AnalyzeJobMetadata extends BaseJobMetadata {
  kind: 'analyze';
  exitCode: number;
  outputs: {
    snapshotPath: string;
    tracePath: string;
    analysisPath: string;
  };
}

interface ReportJobMetadata extends BaseJobMetadata {
  kind: 'report';
  outputs: {
    directory: string;
    complianceHtml: string;
    complianceJson: string;
    traceHtml: string;
    gapsHtml: string;
    analysisPath: string;
    snapshotPath: string;
    tracesPath: string;
  };
}

interface PackJobMetadata extends BaseJobMetadata {
  kind: 'pack';
  outputs: {
    manifestPath: string;
    archivePath: string;
    manifestId: string;
  };
}

type JobMetadata = ImportJobMetadata | AnalyzeJobMetadata | ReportJobMetadata | PackJobMetadata;

interface ImportJobResult {
  warnings: string[];
  outputs: {
    directory: string;
    workspace: string;
  };
}

interface AnalyzeJobResult {
  exitCode: number;
  outputs: {
    directory: string;
    snapshot: string;
    traces: string;
    analysis: string;
  };
}

interface ReportJobResult {
  outputs: {
    directory: string;
    complianceHtml: string;
    complianceJson: string;
    traceHtml: string;
    gapsHtml: string;
    analysis: string;
    snapshot: string;
    traces: string;
  };
}

interface PackJobResult {
  manifestId: string;
  outputs: {
    directory: string;
    manifest: string;
    archive: string;
  };
}

const METADATA_FILE = 'job.json';

const ensureDirectory = async (target: string): Promise<void> => {
  await fsPromises.mkdir(target, { recursive: true });
};

const removeDirectory = async (target: string): Promise<void> => {
  await fsPromises.rm(target, { recursive: true, force: true });
};

const fileExists = async (target: string): Promise<boolean> => {
  try {
    await fsPromises.access(target, fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
};

const readJsonFile = async <T>(filePath: string): Promise<T> => {
  const content = await fsPromises.readFile(filePath, 'utf8');
  return JSON.parse(content) as T;
};

const writeJsonFile = async (filePath: string, data: unknown): Promise<void> => {
  const serialized = `${JSON.stringify(data, null, 2)}\n`;
  await fsPromises.writeFile(filePath, serialized, 'utf8');
};

const sanitizeFileName = (fileName: string, fallback: string): string => {
  const baseName = path.basename(fileName || fallback);
  const normalized = baseName.replace(/[^a-zA-Z0-9._-]/g, '_');
  return normalized || fallback;
};

const getFieldValue = (value: unknown): string | undefined => {
  if (Array.isArray(value)) {
    const [first] = value;
    return first !== undefined ? String(first) : undefined;
  }
  if (value === undefined || value === null) {
    return undefined;
  }
  return String(value);
};

const computeHash = (entries: HashEntry[]): string => {
  const sorted = [...entries].sort((a, b) => a.key.localeCompare(b.key));
  const hash = createHash('sha256');
  sorted.forEach((entry) => {
    hash.update(entry.key);
    hash.update('\0');
    hash.update(entry.value);
    hash.update('\0');
  });
  return hash.digest('hex');
};

const createJobId = (hash: string): string => hash.slice(0, 16);

const asCertificationLevel = (value: string | undefined): CertificationLevel | undefined => {
  if (!value) {
    return undefined;
  }
  const upper = value.trim().toUpperCase();
  if (['A', 'B', 'C', 'D', 'E'].includes(upper)) {
    return upper as CertificationLevel;
  }
  throw new HttpError(400, 'INVALID_LEVEL', 'Geçersiz seviye değeri. Geçerli değerler A-E aralığındadır.');
};

const persistUploadedFiles = async (
  fileMap: UploadedFileMap,
  baseDir: string,
): Promise<Record<string, string[]>> => {
  const entries = Object.entries(fileMap);
  const result: Record<string, string[]> = {};

  for (const [field, files] of entries) {
    for (const [index, file] of files.entries()) {
      const targetDir = path.join(baseDir, field);
      await ensureDirectory(targetDir);
      const safeName = sanitizeFileName(file.originalname, `${field}-${index}`);
      const targetPath = path.join(targetDir, safeName);
      await fsPromises.writeFile(targetPath, file.buffer);
      if (!result[field]) {
        result[field] = [];
      }
      result[field].push(targetPath);
    }
  }

  return result;
};

const toRelativePath = (baseDir: string, target: string): string => {
  const resolvedBase = path.resolve(baseDir);
  const resolvedTarget = path.resolve(target);
  const relative = path.relative(resolvedBase, resolvedTarget);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new HttpError(500, 'PATH_OUT_OF_ROOT', 'Dosya yolu sunucu depolama alanının dışında.');
  }
  return relative.split(path.sep).join('/');
};

const assertDirectoryExists = async (directory: string, kind: string): Promise<void> => {
  if (!(await fileExists(directory))) {
    throw new HttpError(404, 'NOT_FOUND', `${kind} bulunamadı.`);
  }
};

const convertFileMap = (fileMap: FileMap): UploadedFileMap => {
  const result: UploadedFileMap = {};
  Object.entries(fileMap).forEach(([field, files]) => {
    result[field] = files.map((file) => ({
      originalname: file.originalname,
      buffer: Buffer.from(file.buffer),
    }));
  });
  return result;
};

export interface ServerConfig {
  token: string;
  storageDir: string;
  signingKeyPath: string;
  maxUploadSizeBytes?: number;
}

interface PipelineDirectories {
  base: string;
  uploads: string;
  workspaces: string;
  analyses: string;
  reports: string;
  packages: string;
}

const createDirectories = (baseDir: string): PipelineDirectories => {
  const directories: PipelineDirectories = {
    base: baseDir,
    uploads: path.join(baseDir, 'uploads'),
    workspaces: path.join(baseDir, 'workspaces'),
    analyses: path.join(baseDir, 'analyses'),
    reports: path.join(baseDir, 'reports'),
    packages: path.join(baseDir, 'packages'),
  };
  Object.values(directories).forEach((directory) => {
    fs.mkdirSync(directory, { recursive: true });
  });
  return directories;
};

const readJobMetadata = async <T extends JobMetadata>(directory: string): Promise<T> => {
  const metadataPath = path.join(directory, METADATA_FILE);
  return readJsonFile<T>(metadataPath);
};

const writeJobMetadata = async (directory: string, metadata: JobMetadata): Promise<void> => {
  const metadataPath = path.join(directory, METADATA_FILE);
  await writeJsonFile(metadataPath, metadata);
};

const createPipelineError = (error: unknown, message: string): HttpError => {
  if (error instanceof HttpError) {
    return error;
  }
  const description = error instanceof Error ? error.message : String(error);
  return new HttpError(500, 'PIPELINE_ERROR', message, { cause: description });
};

const toImportResult = (
  directories: PipelineDirectories,
  metadata: ImportJobMetadata,
): ImportJobResult => ({
  warnings: metadata.warnings,
  outputs: {
    directory: toRelativePath(directories.base, metadata.directory),
    workspace: toRelativePath(directories.base, metadata.outputs.workspacePath),
  },
});

const toAnalyzeResult = (
  directories: PipelineDirectories,
  metadata: AnalyzeJobMetadata,
): AnalyzeJobResult => ({
  exitCode: metadata.exitCode,
  outputs: {
    directory: toRelativePath(directories.base, metadata.directory),
    snapshot: toRelativePath(directories.base, metadata.outputs.snapshotPath),
    traces: toRelativePath(directories.base, metadata.outputs.tracePath),
    analysis: toRelativePath(directories.base, metadata.outputs.analysisPath),
  },
});

const toReportResult = (
  directories: PipelineDirectories,
  metadata: ReportJobMetadata,
): ReportJobResult => ({
  outputs: {
    directory: toRelativePath(directories.base, metadata.directory),
    complianceHtml: toRelativePath(directories.base, metadata.outputs.complianceHtml),
    complianceJson: toRelativePath(directories.base, metadata.outputs.complianceJson),
    traceHtml: toRelativePath(directories.base, metadata.outputs.traceHtml),
    gapsHtml: toRelativePath(directories.base, metadata.outputs.gapsHtml),
    analysis: toRelativePath(directories.base, metadata.outputs.analysisPath),
    snapshot: toRelativePath(directories.base, metadata.outputs.snapshotPath),
    traces: toRelativePath(directories.base, metadata.outputs.tracesPath),
  },
});

const toPackResult = (
  directories: PipelineDirectories,
  metadata: PackJobMetadata,
): PackJobResult => ({
  manifestId: metadata.outputs.manifestId,
  outputs: {
    directory: toRelativePath(directories.base, metadata.directory),
    manifest: toRelativePath(directories.base, metadata.outputs.manifestPath),
    archive: toRelativePath(directories.base, metadata.outputs.archivePath),
  },
});

const serializeJobSummary = (summary: JobSummary) => ({
  id: summary.id,
  kind: summary.kind,
  hash: summary.hash,
  status: summary.status,
  createdAt: summary.createdAt.toISOString(),
  updatedAt: summary.updatedAt.toISOString(),
});

const serializeJobDetails = <T>(job: JobDetails<T>) => ({
  ...serializeJobSummary(job),
  result: job.result ?? undefined,
  error: job.error ?? undefined,
});

const respondWithJob = <T>(res: Response, job: JobDetails<T>, options?: { reused?: boolean }): void => {
  const payload = {
    ...serializeJobDetails(job),
    ...(options?.reused !== undefined ? { reused: options.reused } : {}),
  };
  const statusCode =
    job.status === 'completed'
      ? 200
      : job.status === 'failed'
      ? job.error?.statusCode ?? 500
      : 202;
  res.status(statusCode).json(payload);
};

const adoptJobFromMetadata = (
  directories: PipelineDirectories,
  queue: JobQueue,
  metadata: JobMetadata,
): JobDetails<unknown> => {
  switch (metadata.kind) {
    case 'import':
      return queue.adoptCompleted<ImportJobResult>({
        id: metadata.id,
        kind: metadata.kind,
        hash: metadata.hash,
        createdAt: metadata.createdAt,
        updatedAt: metadata.createdAt,
        result: toImportResult(directories, metadata),
      });
    case 'analyze':
      return queue.adoptCompleted<AnalyzeJobResult>({
        id: metadata.id,
        kind: metadata.kind,
        hash: metadata.hash,
        createdAt: metadata.createdAt,
        updatedAt: metadata.createdAt,
        result: toAnalyzeResult(directories, metadata),
      });
    case 'report':
      return queue.adoptCompleted<ReportJobResult>({
        id: metadata.id,
        kind: metadata.kind,
        hash: metadata.hash,
        createdAt: metadata.createdAt,
        updatedAt: metadata.createdAt,
        result: toReportResult(directories, metadata),
      });
    case 'pack':
      return queue.adoptCompleted<PackJobResult>({
        id: metadata.id,
        kind: metadata.kind,
        hash: metadata.hash,
        createdAt: metadata.createdAt,
        updatedAt: metadata.createdAt,
        result: toPackResult(directories, metadata),
      });
    default:
      throw new HttpError(500, 'UNKNOWN_JOB_KIND', `Bilinmeyen iş türü: ${(metadata as JobMetadata).kind}`);
  }
};

const locateJobMetadata = async (
  directories: PipelineDirectories,
  queue: JobQueue,
  jobId: string,
): Promise<JobDetails<unknown> | undefined> => {
  const locations: Array<{ dir: string; kind: JobMetadata['kind'] }> = [
    { dir: directories.workspaces, kind: 'import' },
    { dir: directories.analyses, kind: 'analyze' },
    { dir: directories.reports, kind: 'report' },
    { dir: directories.packages, kind: 'pack' },
  ];

  for (const location of locations) {
    const candidateDir = path.join(location.dir, jobId);
    const metadataPath = path.join(candidateDir, METADATA_FILE);
    if (await fileExists(metadataPath)) {
      const metadata = await readJobMetadata<JobMetadata>(candidateDir);
      return adoptJobFromMetadata(directories, queue, metadata);
    }
  }

  return undefined;
};

const createAsyncHandler = <T extends Request>(
  handler: (req: T, res: Response) => Promise<void>,
) =>
  async (req: T, res: Response, next: NextFunction): Promise<void> => {
    try {
      await handler(req, res);
    } catch (error) {
      next(error);
    }
  };

const createAuthMiddleware = (token: string) => {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const header = req.get('authorization');
    if (!header || !header.startsWith('Bearer ')) {
      next(new HttpError(401, 'UNAUTHORIZED', 'Bearer kimlik doğrulaması gerekiyor.'));
      return;
    }
    const provided = header.slice('Bearer '.length).trim();
    if (provided !== token) {
      next(new HttpError(401, 'UNAUTHORIZED', 'Geçersiz kimlik doğrulama belirteci.'));
      return;
    }
    next();
  };
};

export const createServer = (config: ServerConfig): Express => {
  const directories = createDirectories(path.resolve(config.storageDir));
  const signingKeyPath = path.resolve(config.signingKeyPath);
  const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
      fileSize: config.maxUploadSizeBytes ?? 25 * 1024 * 1024,
    },
  });

  const app = express();
  app.use(express.json());

  const requireAuth = createAuthMiddleware(config.token);
  const queue = new JobQueue();

  app.get(
    '/health',
    createAsyncHandler(async (_req, res) => {
      res.json({ status: 'ok' });
    }),
  );

  app.get(
    '/v1/jobs',
    requireAuth,
    createAsyncHandler(async (_req, res) => {
      const jobs = queue.list().map(serializeJobSummary);
      res.json({ jobs });
    }),
  );

  app.get(
    '/v1/jobs/:id',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { id } = req.params as { id?: string };
      if (!id) {
        throw new HttpError(400, 'INVALID_REQUEST', 'İş kimliği belirtilmelidir.');
      }
      const job = queue.get(id) ?? (await locateJobMetadata(directories, queue, id));
      if (!job) {
        throw new HttpError(404, 'JOB_NOT_FOUND', 'İstenen iş bulunamadı.');
      }
      res.json(serializeJobDetails(job));
    }),
  );

  const importFields = upload.fields([
    { name: 'jira', maxCount: 1 },
    { name: 'reqif', maxCount: 1 },
    { name: 'junit', maxCount: 1 },
    { name: 'lcov', maxCount: 1 },
    { name: 'cobertura', maxCount: 1 },
    { name: 'git', maxCount: 1 },
    { name: 'objectives', maxCount: 1 },
  ]);

  app.post(
    '/v1/import',
    requireAuth,
    importFields,
    createAsyncHandler(async (req, res) => {
      const fileMap = (req.files as FileMap) ?? {};
      const body = req.body as Record<string, unknown>;

      const availableFiles = Object.values(fileMap).reduce((sum, files) => sum + files.length, 0);
      if (availableFiles === 0) {
        throw new HttpError(400, 'NO_INPUT_FILES', 'En az bir veri dosyası yüklenmelidir.');
      }

      const stringFields: Record<string, string> = {};
      ['projectName', 'projectVersion', 'level'].forEach((field) => {
        const value = getFieldValue(body[field]);
        if (value !== undefined) {
          stringFields[field] = value;
        }
      });

      const hashEntries: HashEntry[] = [];
      Object.entries(stringFields).forEach(([key, value]) => {
        hashEntries.push({ key: `field:${key}`, value });
      });
      Object.entries(fileMap).forEach(([field, files]) => {
        files.forEach((file, index) => {
          const fileHash = createHash('sha256').update(file.buffer).digest('hex');
          hashEntries.push({ key: `file:${field}:${index}`, value: fileHash });
        });
      });

      const hash = computeHash(hashEntries);
      const importId = createJobId(hash);
      const workspaceDir = path.join(directories.workspaces, importId);
      const metadataPath = path.join(workspaceDir, METADATA_FILE);

      const existingJob = queue.get<ImportJobResult>(importId);
      if (existingJob) {
        respondWithJob(res, existingJob, { reused: existingJob.status === 'completed' });
        return;
      }

      if (await fileExists(metadataPath)) {
        const metadata = await readJobMetadata<ImportJobMetadata>(workspaceDir);
        const adopted = adoptJobFromMetadata(directories, queue, metadata) as JobDetails<ImportJobResult>;
        respondWithJob(res, adopted, { reused: true });
        return;
      }

      const uploadsDir = path.join(workspaceDir, 'inputs');
      const uploadedFiles = convertFileMap(fileMap);
      const level = asCertificationLevel(stringFields.level);

      const job = queue.enqueue<ImportJobResult>({
        id: importId,
        kind: 'import',
        hash,
        run: async () => {
          await ensureDirectory(workspaceDir);
          await ensureDirectory(uploadsDir);

          try {
            const persisted = await persistUploadedFiles(uploadedFiles, uploadsDir);
            const importOptions: ImportOptions = {
              output: workspaceDir,
              jira: persisted.jira?.[0],
              reqif: persisted.reqif?.[0],
              junit: persisted.junit?.[0],
              lcov: persisted.lcov?.[0],
              cobertura: persisted.cobertura?.[0],
              git: persisted.git?.[0],
              objectives: persisted.objectives?.[0],
              level,
              projectName: stringFields.projectName,
              projectVersion: stringFields.projectVersion,
            };

            const result = await runImport(importOptions);
            const metadata: ImportJobMetadata = {
              id: importId,
              hash,
              kind: 'import',
              createdAt: new Date().toISOString(),
              directory: workspaceDir,
              params: {
                level: level ?? null,
                projectName: stringFields.projectName ?? null,
                projectVersion: stringFields.projectVersion ?? null,
                files: Object.fromEntries(
                  Object.entries(persisted).map(([key, values]) => [key, values.map((value) => path.basename(value))]),
                ),
              },
              warnings: result.warnings,
              outputs: {
                workspacePath: path.join(workspaceDir, 'workspace.json'),
              },
            };

            await writeJobMetadata(workspaceDir, metadata);

            return toImportResult(directories, metadata);
          } catch (error) {
            await removeDirectory(workspaceDir);
            throw createPipelineError(error, 'Import işlemi sırasında bir hata oluştu.');
          }
        },
      });

      respondWithJob(res, job);
    }),
  );

  app.post(
    '/v1/analyze',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const body = req.body as {
        importId?: string;
        level?: string;
        projectName?: string;
        projectVersion?: string;
      };

      if (!body.importId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'importId alanı zorunludur.');
      }

      const workspaceDir = path.join(directories.workspaces, body.importId);
      await assertDirectoryExists(workspaceDir, 'Çalışma alanı');

      const workspace = await readJsonFile<ImportWorkspace>(path.join(workspaceDir, 'workspace.json'));
      const effectiveLevel = asCertificationLevel(body.level) ?? workspace.metadata.targetLevel ?? 'C';
      const effectiveProjectName = body.projectName ?? workspace.metadata.project?.name;
      const effectiveProjectVersion = body.projectVersion ?? workspace.metadata.project?.version;

      const fallbackObjectivesPath = path.resolve('data', 'objectives', 'do178c_objectives.min.json');
      const objectivesPathRaw = workspace.metadata.objectivesPath ?? fallbackObjectivesPath;
      const objectivesPath = path.resolve(objectivesPathRaw);

      const hash = computeHash(
        [
          { key: 'importId', value: body.importId },
          { key: 'level', value: effectiveLevel },
          { key: 'projectName', value: effectiveProjectName ?? '' },
          { key: 'projectVersion', value: effectiveProjectVersion ?? '' },
          { key: 'objectives', value: objectivesPath },
        ].filter((entry) => entry.value !== undefined) as HashEntry[],
      );
      const analyzeId = createJobId(hash);
      const analysisDir = path.join(directories.analyses, analyzeId);
      const metadataPath = path.join(analysisDir, METADATA_FILE);

      const existingJob = queue.get<AnalyzeJobResult>(analyzeId);
      if (existingJob) {
        respondWithJob(res, existingJob, { reused: existingJob.status === 'completed' });
        return;
      }

      if (await fileExists(metadataPath)) {
        const metadata = await readJobMetadata<AnalyzeJobMetadata>(analysisDir);
        const adopted = adoptJobFromMetadata(directories, queue, metadata) as JobDetails<AnalyzeJobResult>;
        respondWithJob(res, adopted, { reused: true });
        return;
      }

      const job = queue.enqueue<AnalyzeJobResult>({
        id: analyzeId,
        kind: 'analyze',
        hash,
        run: async () => {
          await ensureDirectory(analysisDir);
          try {
            const analyzeOptions: AnalyzeOptions = {
              input: workspaceDir,
              output: analysisDir,
              level: effectiveLevel,
              objectives: workspace.metadata.objectivesPath ?? undefined,
              projectName: effectiveProjectName,
              projectVersion: effectiveProjectVersion,
            };
            const result = await runAnalyze(analyzeOptions);

            const metadata: AnalyzeJobMetadata = {
              id: analyzeId,
              hash,
              kind: 'analyze',
              createdAt: new Date().toISOString(),
              directory: analysisDir,
              params: {
                importId: body.importId,
                level: effectiveLevel,
                projectName: effectiveProjectName ?? null,
                projectVersion: effectiveProjectVersion ?? null,
                objectivesPath,
              },
              exitCode: result.exitCode,
              outputs: {
                snapshotPath: path.join(analysisDir, 'snapshot.json'),
                tracePath: path.join(analysisDir, 'traces.json'),
                analysisPath: path.join(analysisDir, 'analysis.json'),
              },
            };

            await writeJobMetadata(analysisDir, metadata);

            return toAnalyzeResult(directories, metadata);
          } catch (error) {
            await removeDirectory(analysisDir);
            throw createPipelineError(error, 'Analiz işlemi başarısız oldu.');
          }
        },
      });

      respondWithJob(res, job);
    }),
  );

  app.post(
    '/v1/report',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const body = req.body as { analysisId?: string; manifestId?: string };
      if (!body.analysisId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'analysisId alanı zorunludur.');
      }

      const analysisDir = path.join(directories.analyses, body.analysisId);
      await assertDirectoryExists(analysisDir, 'Analiz çıktısı');

      const hashEntries: HashEntry[] = [{ key: 'analysisId', value: body.analysisId }];
      if (body.manifestId) {
        hashEntries.push({ key: 'manifestId', value: body.manifestId });
      }
      const hash = computeHash(hashEntries);
      const reportId = createJobId(hash);
      const reportDir = path.join(directories.reports, reportId);
      const metadataPath = path.join(reportDir, METADATA_FILE);

      const existingJob = queue.get<ReportJobResult>(reportId);
      if (existingJob) {
        respondWithJob(res, existingJob, { reused: existingJob.status === 'completed' });
        return;
      }

      if (await fileExists(metadataPath)) {
        const metadata = await readJobMetadata<ReportJobMetadata>(reportDir);
        const adopted = adoptJobFromMetadata(directories, queue, metadata) as JobDetails<ReportJobResult>;
        respondWithJob(res, adopted, { reused: true });
        return;
      }

      const job = queue.enqueue<ReportJobResult>({
        id: reportId,
        kind: 'report',
        hash,
        run: async () => {
          await ensureDirectory(reportDir);
          try {
            const reportOptions: ReportOptions = {
              input: analysisDir,
              output: reportDir,
              manifestId: body.manifestId,
            };
            const result = await runReport(reportOptions);

            const metadata: ReportJobMetadata = {
              id: reportId,
              hash,
              kind: 'report',
              createdAt: new Date().toISOString(),
              directory: reportDir,
              params: {
                analysisId: body.analysisId,
                manifestId: body.manifestId ?? null,
              },
              outputs: {
                directory: reportDir,
                complianceHtml: result.complianceHtml,
                complianceJson: result.complianceJson,
                traceHtml: result.traceHtml,
                gapsHtml: result.gapsHtml,
                analysisPath: path.join(reportDir, 'analysis.json'),
                snapshotPath: path.join(reportDir, 'snapshot.json'),
                tracesPath: path.join(reportDir, 'traces.json'),
              },
            };

            await writeJobMetadata(reportDir, metadata);

            return toReportResult(directories, metadata);
          } catch (error) {
            await removeDirectory(reportDir);
            throw createPipelineError(error, 'Rapor oluşturma işlemi başarısız oldu.');
          }
        },
      });

      respondWithJob(res, job);
    }),
  );

  app.post(
    '/v1/pack',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const body = req.body as { reportId?: string; packageName?: string };
      if (!body.reportId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'reportId alanı zorunludur.');
      }

      const reportDir = path.join(directories.reports, body.reportId);
      await assertDirectoryExists(reportDir, 'Rapor çıktısı');

      const hashEntries: HashEntry[] = [
        { key: 'reportId', value: body.reportId },
        { key: 'packageName', value: body.packageName ?? '' },
      ];
      const hash = computeHash(hashEntries);
      const packId = createJobId(hash);
      const packageDir = path.join(directories.packages, packId);
      const metadataPath = path.join(packageDir, METADATA_FILE);

      const existingJob = queue.get<PackJobResult>(packId);
      if (existingJob) {
        respondWithJob(res, existingJob, { reused: existingJob.status === 'completed' });
        return;
      }

      if (await fileExists(metadataPath)) {
        const metadata = await readJobMetadata<PackJobMetadata>(packageDir);
        const adopted = adoptJobFromMetadata(directories, queue, metadata) as JobDetails<PackJobResult>;
        respondWithJob(res, adopted, { reused: true });
        return;
      }

      const job = queue.enqueue<PackJobResult>({
        id: packId,
        kind: 'pack',
        hash,
        run: async () => {
          await ensureDirectory(packageDir);
          try {
            const signingKey = await fsPromises.readFile(signingKeyPath, 'utf8');
            const packOptions: PackOptions = {
              input: reportDir,
              output: packageDir,
              packageName: body.packageName,
              signingKey,
            };
            const result = await runPack(packOptions);

            const metadata: PackJobMetadata = {
              id: packId,
              hash,
              kind: 'pack',
              createdAt: new Date().toISOString(),
              directory: packageDir,
              params: {
                reportId: body.reportId,
                packageName: body.packageName ?? null,
              },
              outputs: {
                manifestPath: result.manifestPath,
                archivePath: result.archivePath,
                manifestId: result.manifestId,
              },
            };

            await writeJobMetadata(packageDir, metadata);

            return toPackResult(directories, metadata);
          } catch (error) {
            await removeDirectory(packageDir);
            throw createPipelineError(error, 'Paket oluşturma işlemi başarısız oldu.');
          }
        },
      });

      respondWithJob(res, job);
    }),
  );

  app.get(
    '/v1/reports/:id/:asset(*)',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { id, asset } = req.params as { id?: string; asset?: string };
      if (!id || !asset) {
        throw new HttpError(400, 'INVALID_REQUEST', 'Rapor kimliği ve dosya yolu belirtilmelidir.');
      }

      const reportDir = path.join(directories.reports, id);
      await assertDirectoryExists(reportDir, 'Rapor çıktısı');

      const metadataPath = path.join(reportDir, METADATA_FILE);
      if (!(await fileExists(metadataPath))) {
        throw new HttpError(404, 'NOT_FOUND', 'İstenen rapor bulunamadı.');
      }

      const safeAsset = asset.replace(/^\/+/, '');
      const targetPath = path.resolve(reportDir, safeAsset);
      const relative = path.relative(reportDir, targetPath);
      if (relative.startsWith('..') || path.isAbsolute(relative)) {
        throw new HttpError(400, 'INVALID_PATH', 'İstenen dosya yolu izin verilen dizin dışında.');
      }

      if (!(await fileExists(targetPath))) {
        throw new HttpError(404, 'NOT_FOUND', 'Rapor dosyası bulunamadı.');
      }

      await new Promise<void>((resolve, reject) => {
        res.sendFile(targetPath, (error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        });
      });
    }),
  );

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const normalized = error instanceof HttpError ? error : new HttpError(500, 'UNEXPECTED_ERROR', 'Beklenmeyen bir sunucu hatası oluştu.', {
      cause: error instanceof Error ? error.message : String(error),
    });
    res.status(normalized.statusCode).json({
      error: {
        code: normalized.code,
        message: normalized.message,
        details: normalized.details ?? undefined,
      },
    });
  });

  return app;
};

