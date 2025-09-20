import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import JSZip from 'jszip';
import { saveAs } from 'file-saver';

import {
  analyzeArtifacts,
  ApiError,
  buildReportAssets,
  fetchComplianceMatrix,
  fetchReportAsset,
  fetchRequirementTraces,
  importArtifacts,
  JobFailedError,
  pollJob,
  reportArtifacts,
} from '../services/api';
import { createReportDataset } from '../services/report';
import type {
  AnalyzeJobResult,
  ApiJob,
  ImportJobResult,
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
};

type PipelineJobKey = keyof PipelineJobs;

const jobKindLabel: Record<PipelineJobKey, string> = {
  import: 'Import',
  analyze: 'Analyze',
  report: 'Report',
};

export interface PipelineState {
  logs: PipelineLogEntry[];
  error: string | null;
  isRunning: boolean;
  isDownloading: boolean;
  jobs: PipelineJobs;
  reportData: ReportDataset | null;
  reportAssets: ReportAssetMap | null;
  lastCompletedAt: string | null;
}

export interface UsePipelineResult {
  runPipeline: (files: File[]) => Promise<void>;
  downloadArtifacts: () => Promise<void>;
  reset: () => void;
  state: PipelineState;
}

const appendJobLabel = (kind: PipelineJobKey, message: string): string => `${jobKindLabel[kind]} · ${message}`;

export const usePipeline = (token: string): UsePipelineResult => {
  const abortRef = useRef<AbortController | null>(null);
  const [logs, setLogs] = useState<PipelineLogEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [jobs, setJobs] = useState<PipelineJobs>({});
  const [reportData, setReportData] = useState<ReportDataset | null>(null);
  const [reportAssets, setReportAssets] = useState<ReportAssetMap | null>(null);
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
          const kind: PipelineJobKey = job?.kind === 'analyze' ? 'analyze' : job?.kind === 'report' ? 'report' : 'import';
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
    if (!reportAssets) {
      setError('Rapor paketini indirmek için önce bir rapor oluşturun.');
      return;
    }

    setIsDownloading(true);
    appendLog('info', 'Rapor artefaktları paketleniyor...');
    try {
      const zip = new JSZip();
      const entries: Array<{ key: keyof ReportAssetMap['assets']; type: 'json' | 'text' } > = [
        { key: 'analysis', type: 'json' },
        { key: 'snapshot', type: 'json' },
        { key: 'traces', type: 'json' },
        { key: 'complianceJson', type: 'json' },
        { key: 'complianceHtml', type: 'text' },
        { key: 'traceHtml', type: 'text' },
        { key: 'gapsHtml', type: 'text' },
      ];

      for (const entry of entries) {
        const assetPath = reportAssets.assets[entry.key];
        if (!assetPath) {
          continue;
        }
        const response = await fetchReportAsset({
          token: trimmedToken,
          reportId: reportAssets.reportId,
          asset: assetPath,
        });
        if (entry.type === 'json') {
          const text = await response.text();
          try {
            const parsed = JSON.parse(text);
            zip.file(assetPath, `${JSON.stringify(parsed, null, 2)}\n`);
          } catch {
            zip.file(assetPath, text);
          }
        } else {
          const content = await response.text();
          zip.file(assetPath, content);
        }
      }

      const blob = await zip.generateAsync({ type: 'blob' });
      saveAs(blob, `soipack-report-${reportAssets.reportId}.zip`);
      appendLog('success', 'Rapor paket arşivi hazırlandı.');
    } catch (caught) {
      const failure = caught as Error;
      appendLog('error', formatMessage('Paket indirme başarısız', failure.message));
      setError(failure.message);
    } finally {
      setIsDownloading(false);
    }
  }, [appendLog, reportAssets, token]);

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
      lastCompletedAt,
    }),
    [logs, error, isRunning, isDownloading, jobs, reportData, reportAssets, lastCompletedAt],
  );

  return {
    runPipeline,
    downloadArtifacts,
    reset,
    state,
  };
};
