import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { saveAs } from 'file-saver';

import {
  analyzeArtifacts,
  ApiError,
  buildReportAssets,
  fetchComplianceMatrix,
  fetchRequirementTraces,
  importArtifacts,
  JobFailedError,
  packArtifacts,
  fetchPackageArchive,
  pollJob,
  reportArtifacts,
} from '../services/api';
import { createReportDataset } from '../services/report';
import type {
  AnalyzeJobResult,
  ApiJob,
  ImportJobResult,
  PackJobResult,
  PipelineLogEntry,
  ReportAssetMap,
  ReportDataset,
  ReportJobResult,
} from '../types/pipeline';

const createLogId = (): string => {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID();
  }
  return Math.random().toString(36).slice(2);
};

const formatMessage = (prefix: string, detail?: string): string =>
  detail ? `${prefix}: ${detail}` : prefix;

const projectVersionForNow = (): string => {
  const now = new Date();
  return now.toISOString().slice(0, 10);
};

type PipelineJobs = {
  import?: ApiJob<ImportJobResult>;
  analyze?: ApiJob<AnalyzeJobResult>;
  report?: ApiJob<ReportJobResult>;
  pack?: ApiJob<PackJobResult>;
};

type PipelineJobKey = keyof PipelineJobs;

const jobKindLabel: Record<PipelineJobKey, string> = {
  import: 'Import',
  analyze: 'Analyze',
  report: 'Report',
  pack: 'Pack',
};

export interface PipelineState {
  logs: PipelineLogEntry[];
  error: string | null;
  isRunning: boolean;
  isDownloading: boolean;
  jobs: PipelineJobs;
  reportData: ReportDataset | null;
  reportAssets: ReportAssetMap | null;
  packageJob: ApiJob<PackJobResult> | null;
  lastCompletedAt: string | null;
}

export interface UsePipelineResult {
  runPipeline: (files: File[]) => Promise<void>;
  downloadArtifacts: () => Promise<void>;
  reset: () => void;
  state: PipelineState;
}

const appendJobLabel = (kind: PipelineJobKey, message: string): string => `${jobKindLabel[kind]} · ${message}`;

const parseDispositionFileName = (value: string | null): string | undefined => {
  if (!value) {
    return undefined;
  }
  const utf8Match = value.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8Match && utf8Match[1]) {
    try {
      return decodeURIComponent(utf8Match[1]);
    } catch {
      return utf8Match[1];
    }
  }
  const quotedMatch = value.match(/filename="([^";]+)"/i);
  if (quotedMatch && quotedMatch[1]) {
    return quotedMatch[1];
  }
  const bareMatch = value.match(/filename=([^;]+)/i);
  if (bareMatch && bareMatch[1]) {
    return bareMatch[1].replace(/"/g, '');
  }
  return undefined;
};

const sanitizeDownloadName = (name: string, fallback: string): string => {
  const trimmed = name.trim();
  const normalized = trimmed.replace(/[^a-zA-Z0-9._-]/g, '_');
  return normalized || fallback;
};

export const usePipeline = (token: string): UsePipelineResult => {
  const abortRef = useRef<AbortController | null>(null);
  const [logs, setLogs] = useState<PipelineLogEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [jobs, setJobs] = useState<PipelineJobs>({});
  const [reportData, setReportData] = useState<ReportDataset | null>(null);
  const [reportAssets, setReportAssets] = useState<ReportAssetMap | null>(null);
  const [packageJob, setPackageJob] = useState<ApiJob<PackJobResult> | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [isDownloading, setIsDownloading] = useState(false);
  const [lastCompletedAt, setLastCompletedAt] = useState<string | null>(null);

  const appendLog = useCallback((severity: PipelineLogEntry['severity'], message: string) => {
    const entry: PipelineLogEntry = {
      id: createLogId(),
      timestamp: new Date().toISOString(),
      severity,
      message,
    };
    setLogs((previous) => [...previous, entry]);
  }, []);

  const updateJob = useCallback(
    (kind: PipelineJobKey, job: ApiJob<any>, reused?: boolean) => {
      setJobs((previous) => ({
        ...previous,
        [kind]: {
          ...job,
          reused: reused ?? job.reused,
        },
      }));
    },
    [],
  );

  const clearState = useCallback(() => {
    setLogs([]);
    setJobs({});
    setReportData(null);
    setReportAssets(null);
    setPackageJob(null);
    setError(null);
    setLastCompletedAt(null);
    setIsRunning(false);
    setIsDownloading(false);
  }, []);

  useEffect(() => {
    return () => {
      abortRef.current?.abort();
    };
  }, []);

  useEffect(() => {
    if (!token) {
      abortRef.current?.abort();
      clearState();
    }
  }, [token, clearState]);

  const handleJobFailure = useCallback(
    (kind: PipelineJobKey, failure: JobFailedError | ApiError | Error) => {
      if (failure instanceof JobFailedError) {
        const statusMessage = failure.job.error?.message ?? 'İş başarısız oldu.';
        appendLog('error', appendJobLabel(kind, statusMessage));
        setError(statusMessage);
        return;
      }
      if (failure instanceof ApiError) {
        const apiMessage = formatMessage('Sunucu hatası', failure.message);
        appendLog('error', appendJobLabel(kind, apiMessage));
        setError(apiMessage);
        return;
      }
      appendLog('error', appendJobLabel(kind, failure.message));
      setError(failure.message);
    },
    [appendLog],
  );

  const runPipeline = useCallback(
    async (files: File[]) => {
      const trimmedToken = token.trim();
      if (!trimmedToken) {
        setError('Lütfen önce geçerli bir token girin.');
        return;
      }
      if (!files.length) {
        setError('Pipeline için en az bir dosya seçmelisiniz.');
        return;
      }

      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;

      setIsRunning(true);
      setError(null);
      setReportData(null);
      setReportAssets(null);
      setPackageJob(null);
      setLastCompletedAt(null);
      setJobs({});
      setLogs([]);

      try {
        appendLog('info', 'Import isteği gönderiliyor...');
        const importInitial = await importArtifacts({
          token: trimmedToken,
          files,
          projectVersion: projectVersionForNow(),
          signal: controller.signal,
        });
        updateJob('import', importInitial, importInitial.reused);

        const importJob = await pollJob<ImportJobResult>({
          token: trimmedToken,
          jobId: importInitial.id,
          initial: importInitial,
          signal: controller.signal,
          onUpdate: (job) => updateJob('import', job, importInitial.reused),
          pollIntervalMs: 600,
        });
        updateJob('import', importJob, importInitial.reused);
        appendLog(
          'success',
          appendJobLabel('import', importInitial.reused ? 'Önceki sonuç yeniden kullanıldı.' : 'Import tamamlandı.'),
        );
        importJob.result?.warnings?.forEach((warning) => {
          appendLog('warning', appendJobLabel('import', warning));
        });

        appendLog('info', 'Analyze isteği gönderiliyor...');
        const analyzeInitial = await analyzeArtifacts({
          token: trimmedToken,
          importId: importJob.id,
          signal: controller.signal,
        });
        updateJob('analyze', analyzeInitial, analyzeInitial.reused);

        const analyzeJob = await pollJob<AnalyzeJobResult>({
          token: trimmedToken,
          jobId: analyzeInitial.id,
          initial: analyzeInitial,
          signal: controller.signal,
          onUpdate: (job) => updateJob('analyze', job, analyzeInitial.reused),
          pollIntervalMs: 600,
        });
        updateJob('analyze', analyzeJob, analyzeInitial.reused);
        appendLog(
          'success',
          appendJobLabel('analyze', analyzeInitial.reused ? 'Önceki analiz bulundu.' : 'Analiz tamamlandı.'),
        );

        appendLog('info', 'Report isteği gönderiliyor...');
        const reportInitial = await reportArtifacts({
          token: trimmedToken,
          analysisId: analyzeJob.id,
          signal: controller.signal,
        });
        updateJob('report', reportInitial, reportInitial.reused);

        const reportJob = await pollJob<ReportJobResult>({
          token: trimmedToken,
          jobId: reportInitial.id,
          initial: reportInitial,
          signal: controller.signal,
          onUpdate: (job) => updateJob('report', job, reportInitial.reused),
          pollIntervalMs: 600,
        });
        updateJob('report', reportJob, reportInitial.reused);
        appendLog(
          'success',
          appendJobLabel('report', reportInitial.reused ? 'Rapor önbellekten getirildi.' : 'Rapor üretimi tamamlandı.'),
        );

        setLastCompletedAt(reportJob.updatedAt);
        setReportAssets(buildReportAssets(reportJob));

        appendLog('info', 'Pack isteği gönderiliyor...');
        const packInitial = await packArtifacts({
          token: trimmedToken,
          reportId: reportJob.id,
          signal: controller.signal,
        });
        updateJob('pack', packInitial, packInitial.reused);

        const packJobResult = await pollJob<PackJobResult>({
          token: trimmedToken,
          jobId: packInitial.id,
          initial: packInitial,
          signal: controller.signal,
          onUpdate: (job) => updateJob('pack', job, packInitial.reused),
          pollIntervalMs: 600,
        });
        updateJob('pack', packJobResult, packInitial.reused);
        setPackageJob(packJobResult);
        appendLog(
          'success',
          appendJobLabel('pack', packInitial.reused ? 'Önceki paket yeniden kullanıldı.' : 'Paket oluşturuldu.'),
        );

        appendLog('info', 'Rapor çıktıları yükleniyor...');
        const [compliance, traces] = await Promise.all([
          fetchComplianceMatrix({ token: trimmedToken, reportId: reportJob.id, signal: controller.signal }),
          fetchRequirementTraces({ token: trimmedToken, reportId: reportJob.id, signal: controller.signal }),
        ]);
        setReportData(createReportDataset(reportJob.id, compliance, traces));
        appendLog('success', 'Uyum ve izlenebilirlik verileri güncellendi.');
      } catch (caught) {
        if (caught instanceof DOMException && caught.name === 'AbortError') {
          appendLog('warning', 'İşlem iptal edildi.');
          return;
        }
        const failure = caught as Error;
        if (failure instanceof JobFailedError || failure instanceof ApiError) {
          const job = failure instanceof JobFailedError ? failure.job : undefined;
          const kind =
            job?.kind === 'analyze'
              ? 'analyze'
              : job?.kind === 'report'
                ? 'report'
                : job?.kind === 'pack'
                  ? 'pack'
                  : 'import';
          handleJobFailure(kind, failure);
        } else {
          appendLog('error', failure.message);
          setError(failure.message);
        }
      } finally {
        abortRef.current = null;
        setIsRunning(false);
      }
    },
    [
      token,
      appendLog,
      handleJobFailure,
      updateJob,
    ],
  );

  const downloadArtifacts = useCallback(async () => {
    const trimmedToken = token.trim();
    if (!trimmedToken) {
      setError('Dosya indirebilmek için token gereklidir.');
      return;
    }
    if (!packageJob || packageJob.status !== 'completed') {
      setError('Rapor paketini indirmek için önce paket oluşturulmalıdır.');
      return;
    }

    setIsDownloading(true);
    appendLog('info', 'Paket arşivi indiriliyor...');
    try {
      const response = await fetchPackageArchive({
        token: trimmedToken,
        packageId: packageJob.id,
      });
      const blob = await response.blob();
      const disposition = response.headers.get('Content-Disposition');
      const suggestedName = parseDispositionFileName(disposition);
      const fallback = `soipack-package-${packageJob.id}.zip`;
      const fileName = sanitizeDownloadName(suggestedName ?? fallback, fallback);
      saveAs(blob, fileName);
      appendLog('success', 'Paket arşivi indirildi.');
    } catch (caught) {
      const failure = caught as Error;
      appendLog('error', formatMessage('Paket indirme başarısız', failure.message));
      setError(failure.message);
    } finally {
      setIsDownloading(false);
    }
  }, [appendLog, packageJob, token]);

  const reset = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    clearState();
  }, [clearState]);

  const state: PipelineState = useMemo(
    () => ({
      logs,
      error,
      isRunning,
      isDownloading,
      jobs,
      reportData,
      reportAssets,
      packageJob,
      lastCompletedAt,
    }),
    [logs, error, isRunning, isDownloading, jobs, reportData, reportAssets, packageJob, lastCompletedAt],
  );

  return {
    runPipeline,
    downloadArtifacts,
    reset,
    state,
  };
};
