import { useMemo, type ChangeEvent } from 'react';

import type { JobKind, JobStatus, PipelineLogEntry } from '../types/pipeline';

import { StatusBadge } from './StatusBadge';

interface UploadAndRunProps {
  files: File[];
  onFilesChange: (files: File[]) => void;
  logs: PipelineLogEntry[];
  isEnabled: boolean;
  onRun: () => void;
  isRunning: boolean;
  canRun: boolean;
  jobStates: Array<{
    kind: JobKind;
    status: JobStatus;
    reused?: boolean;
    updatedAt: string;
  }>;
  error: string | null;
  lastCompletedAt: string | null;
  independentSources: string[];
  independentArtifacts: string[];
  onIndependentSourcesChange: (values: string[]) => void;
  onIndependentArtifactsChange: (values: string[]) => void;
}

const INDEPENDENT_SOURCE_OPTIONS: Array<{ value: string; label: string }> = [
  { value: 'jiraCsv', label: 'Jira CSV (gereksinim / defect)' },
  { value: 'reqif', label: 'ReqIF gereksinimleri' },
  { value: 'junit', label: 'JUnit test sonuçları' },
  { value: 'lcov', label: 'LCOV kapsam raporları' },
  { value: 'cobertura', label: 'Cobertura kapsam raporları' },
  { value: 'git', label: 'Git arşivleri' },
  { value: 'polyspace', label: 'Polyspace statik analizi' },
  { value: 'ldra', label: 'LDRA raporları' },
  { value: 'vectorcast', label: 'VectorCAST sonuçları' },
  { value: 'staticAnalysis', label: 'Diğer statik analiz çıktıları' },
  { value: 'doorsClassic', label: 'DOORS Classic gereksinimleri' },
  { value: 'doorsNext', label: 'DOORS Next gereksinimleri' },
  { value: 'polarion', label: 'Polarion kayıtları' },
  { value: 'jenkins', label: 'Jenkins pipeline sonuçları' },
  { value: 'other', label: 'Diğer kaynaklar' },
];

const INDEPENDENT_ARTIFACT_OPTIONS: Array<{ value: string; label: string }> = [
  { value: 'plan', label: 'Plan dokümanları' },
  { value: 'standard', label: 'Standart / politika kayıtları' },
  { value: 'review', label: 'Gözden geçirme kayıtları' },
  { value: 'analysis', label: 'Analiz artefaktları' },
  { value: 'test', label: 'Test kanıtları' },
  { value: 'coverage_stmt', label: 'Statement coverage' },
  { value: 'coverage_dec', label: 'Decision coverage' },
  { value: 'coverage_mcdc', label: 'MC/DC coverage' },
  { value: 'trace', label: 'İzlenebilirlik kayıtları' },
  { value: 'cm_record', label: 'Yapılandırma yönetimi kayıtları' },
  { value: 'qa_record', label: 'QA denetim kayıtları' },
  { value: 'problem_report', label: 'Problem raporları' },
  { value: 'conformity', label: 'Uygunluk bildirimi' },
];

const toggleSelection = (values: string[], value: string): string[] =>
  values.includes(value) ? values.filter((entry) => entry !== value) : [...values, value];

const severityStyles: Record<PipelineLogEntry['severity'], string> = {
  info: 'border-slate-700 bg-slate-800/40 text-slate-200',
  success: 'border-emerald-700/50 bg-emerald-950/40 text-emerald-200',
  warning: 'border-amber-700/60 bg-amber-950/30 text-amber-200',
  error: 'border-rose-700/60 bg-rose-950/30 text-rose-200'
};

const severityLabels: Record<PipelineLogEntry['severity'], string> = {
  info: 'Bilgi',
  success: 'Başarılı',
  warning: 'Uyarı',
  error: 'Hata'
};

const jobStatusLabels: Record<JobStatus, string> = {
  queued: 'Kuyrukta',
  running: 'Çalışıyor',
  completed: 'Tamamlandı',
  failed: 'Hata'
};

const jobStatusStyles: Record<JobStatus, string> = {
  queued: 'bg-slate-800/80 text-slate-200 border border-slate-700/70',
  running: 'bg-amber-500/10 text-amber-200 border border-amber-500/40',
  completed: 'bg-emerald-500/10 text-emerald-200 border border-emerald-500/40',
  failed: 'bg-rose-500/10 text-rose-200 border border-rose-500/40'
};

const jobKindLabels: Record<JobKind, string> = {
  import: 'Import',
  analyze: 'Analyze',
  report: 'Report',
  pack: 'Pack'
};

export function UploadAndRun({
  files,
  onFilesChange,
  logs,
  isEnabled,
  onRun,
  isRunning,
  canRun,
  jobStates,
  error,
  lastCompletedAt,
  independentSources,
  independentArtifacts,
  onIndependentSourcesChange,
  onIndependentArtifactsChange,
}: UploadAndRunProps) {
  const totalSize = useMemo(() => {
    if (!files.length) return '0 B';
    const size = files.reduce((acc, file) => acc + file.size, 0);
    if (size > 1024 * 1024) {
      return `${(size / (1024 * 1024)).toFixed(2)} MB`;
    }
    if (size > 1024) {
      return `${(size / 1024).toFixed(1)} KB`;
    }
    return `${size} B`;
  }, [files]);

  return (
    <div className="space-y-6">
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 backdrop-blur-sm">
        <div className="border-b border-slate-800 px-6 py-4">
          <h2 className="text-lg font-semibold text-white">Dosya Yükleme</h2>
          <p className="text-sm text-slate-400">
            Gereklilik, test ve kapsam artefaktlarını seçerek sunucudaki import → analyze →
            report pipeline&apos;ını tetikleyebilirsiniz.
          </p>
        </div>
        <div className="space-y-6 px-6 py-6">
          <label
            className={`flex min-h-[160px] cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed transition ${
              isEnabled
                ? 'border-slate-700 hover:border-brand hover:bg-slate-900/80'
                : 'cursor-not-allowed border-slate-800 bg-slate-950/60 text-slate-600'
            }`}
          >
            <input
              type="file"
              multiple
              className="hidden"
              onChange={(event: ChangeEvent<HTMLInputElement>) => {
                const nextFiles = Array.from(event.currentTarget.files ?? []);
                onFilesChange(nextFiles as File[]);
              }}
              disabled={!isEnabled}
            />
              <div className="flex flex-col items-center gap-3 text-center">
                <div className="rounded-full bg-brand/10 p-3 text-brand">
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  className="h-8 w-8"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    d="M3 16.5V8.25M3 16.5a2.25 2.25 0 002.25 2.25H18.75A2.25 2.25 0 0021 16.5M3 16.5L8.25 11.25M21 16.5V8.25M21 16.5L15.75 11.25M15.75 11.25L12 7.5m0 0L8.25 11.25M12 7.5V3"
                  />
                </svg>
              </div>
              <div>
                <p className="text-sm font-medium text-white">
                  {isEnabled ? 'Dosyaları sürükleyip bırakın ya da seçin' : 'Token girişi gerekli'}
                </p>
                <p className="text-xs text-slate-400">
                  Desteklenen formatlar: ReqIF, CSV (gereksinim/tasarım/defect), JUnit, LCOV/Cobertura,
                  JSON, ZIP (Git/Polyspace/LDRA/VectorCAST), LOG (QA kayıtları)
                </p>
              </div>
              <div className="text-xs text-slate-500">
                {files.length > 0
                  ? `${files.length} dosya seçildi · Toplam boyut ${totalSize}`
                  : 'Henüz dosya seçilmedi'}
              </div>
            </div>
          </label>
          {error && (
            <div className="rounded-xl border border-rose-700/40 bg-rose-950/40 px-4 py-3 text-sm text-rose-200">
              {error}
            </div>
          )}
          <div className="rounded-xl border border-slate-800/60 bg-slate-950/40 p-4">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">
              Bağımsızlık tercihleri
            </h3>
            <p className="mt-2 text-xs text-slate-400">
              DO-178C bağımsızlık gereksinimlerini karşılamak için kaynak ve artefaktları işaretleyin. Seçimler
              import isteğinde JSON alanları olarak gönderilir ve CLI tarafından `--independent-source`
              / `--independent-artifact` bayraklarına dönüştürülür.
            </p>
            <div className="mt-4 grid gap-4 lg:grid-cols-2">
              <fieldset className="space-y-3">
                <legend className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Bağımsız kaynaklar
                </legend>
                <div className="grid gap-2">
                  {INDEPENDENT_SOURCE_OPTIONS.map((option) => {
                    const checked = independentSources.includes(option.value);
                    return (
                      <label
                        key={option.value}
                        className="inline-flex items-start gap-2 text-xs text-slate-300"
                      >
                        <input
                          type="checkbox"
                          className="mt-0.5 h-4 w-4 rounded border-slate-600 bg-slate-900 text-brand focus:ring-brand"
                          checked={checked}
                          disabled={!isEnabled}
                          onChange={() =>
                            onIndependentSourcesChange(
                              toggleSelection(independentSources, option.value),
                            )
                          }
                        />
                        <span>{option.label}</span>
                      </label>
                    );
                  })}
                </div>
              </fieldset>
              <fieldset className="space-y-3">
                <legend className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Bağımsız artefaktlar
                </legend>
                <div className="grid gap-2">
                  {INDEPENDENT_ARTIFACT_OPTIONS.map((option) => {
                    const checked = independentArtifacts.includes(option.value);
                    return (
                      <label
                        key={option.value}
                        className="inline-flex items-start gap-2 text-xs text-slate-300"
                      >
                        <input
                          type="checkbox"
                          className="mt-0.5 h-4 w-4 rounded border-slate-600 bg-slate-900 text-brand focus:ring-brand"
                          checked={checked}
                          disabled={!isEnabled}
                          onChange={() =>
                            onIndependentArtifactsChange(
                              toggleSelection(independentArtifacts, option.value),
                            )
                          }
                        />
                        <span>{option.label}</span>
                      </label>
                    );
                  })}
                </div>
              </fieldset>
            </div>
          </div>
          <div className="grid gap-4 lg:grid-cols-2">
            <div className="rounded-xl border border-slate-800/60 bg-slate-950/40 p-4">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">Pipeline aşamaları</h3>
              <ul className="mt-3 space-y-2 text-sm text-slate-200">
                {jobStates.length === 0 && (
                  <li className="text-xs text-slate-500">Henüz iş gönderilmedi.</li>
                )}
                {jobStates.map((job) => (
                  <li key={`${job.kind}-${job.updatedAt}`} className="flex items-center justify-between gap-3">
                    <div className="space-y-1">
                      <span className="text-xs uppercase tracking-wide text-slate-400">
                        {jobKindLabels[job.kind]}
                        {job.reused ? ' · Önbellek' : ''}
                      </span>
                      <div className={`inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-semibold ${jobStatusStyles[job.status]}`}>
                        {jobStatusLabels[job.status]}
                      </div>
                    </div>
                    <time className="text-xs text-slate-500" dateTime={job.updatedAt}>
                      {new Date(job.updatedAt).toLocaleTimeString('tr-TR')}
                    </time>
                  </li>
                ))}
              </ul>
            </div>
            <div className="rounded-xl border border-slate-800/60 bg-slate-950/40 p-4">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">Çalıştırma Özeti</h3>
              <div className="mt-3 space-y-2 text-sm text-slate-300">
                <div className="flex items-center gap-2">
                  <StatusBadge status={files.length ? 'covered' : 'partial'} />
                  <span>{files.length ? 'Seçili dosyalar hazır.' : 'Dosya seçimi bekleniyor.'}</span>
                </div>
                <div className="text-xs text-slate-500">
                  {lastCompletedAt
                    ? `Son rapor: ${new Date(lastCompletedAt).toLocaleString('tr-TR')}`
                    : 'Henüz rapor üretilmedi.'}
                </div>
              </div>
              <div className="mt-4 flex justify-end">
                <button
                  type="button"
                  onClick={onRun}
                  disabled={!isEnabled || isRunning || !canRun}
                  className={`inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold transition focus:outline-none focus:ring-2 focus:ring-brand focus:ring-offset-2 focus:ring-offset-slate-900 ${
                    !isEnabled || isRunning || !canRun
                      ? 'cursor-not-allowed bg-slate-800 text-slate-500'
                      : 'bg-brand text-white shadow-lg shadow-brand/20 hover:bg-brand-light'
                  }`}
                >
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    fill="none"
                    viewBox="0 0 24 24"
                    strokeWidth="1.5"
                    stroke="currentColor"
                    className="h-5 w-5"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      d="M5.25 5.25l13.5 6.75-13.5 6.75V5.25z"
                    />
                  </svg>
                  {isRunning ? 'Pipeline Çalışıyor...' : 'Pipeline Başlat'}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 backdrop-blur-sm">
        <div className="border-b border-slate-800 px-6 py-4">
          <h3 className="text-lg font-semibold text-white">Çalıştırma Günlüğü</h3>
          <p className="text-sm text-slate-400">Sunucu geri bildirimleri burada kronolojik olarak listelenir.</p>
        </div>
        <div className="space-y-4 px-6 py-6">
          {logs.map((log) => (
            <article
              key={log.id}
              className={`rounded-xl border px-4 py-3 text-sm transition ${severityStyles[log.severity]}`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-semibold uppercase tracking-wide text-xs text-slate-400">
                  {severityLabels[log.severity]}
                </span>
                <time className="text-xs text-slate-400" dateTime={log.timestamp}>
                  {new Date(log.timestamp).toLocaleString('tr-TR')}
                </time>
              </div>
              <p className="mt-1 text-slate-100">{log.message}</p>
            </article>
          ))}
        </div>
      </div>
    </div>
  );
}
