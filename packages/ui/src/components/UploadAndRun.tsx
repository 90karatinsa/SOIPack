import { useEffect, useMemo, useState, type ChangeEvent } from 'react';

import { MANUAL_ARTIFACT_TYPES } from '../types/connectors';
import type {
  DoorsNextConnectorFormState,
  JamaConnectorFormState,
  JenkinsConnectorFormState,
  JiraCloudConnectorFormState,
  ManualArtifactType,
  ManualArtifactsSelection,
  PolarionConnectorFormState,
  RemoteConnectorPayload,
  UploadRunPayload,
} from '../types/connectors';
import type {
  JobKind,
  JobStatus,
  PipelineLogEntry,
  PostQuantumSignatureMetadata,
} from '../types/pipeline';

import { StatusBadge } from './StatusBadge';

interface UploadAndRunProps {
  files: File[];
  onFilesChange: (files: File[]) => void;
  logs: PipelineLogEntry[];
  isEnabled: boolean;
  onRun: (payload: UploadRunPayload) => void;
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
  polarion: PolarionConnectorFormState;
  onPolarionChange: (value: PolarionConnectorFormState) => void;
  jenkins: JenkinsConnectorFormState;
  onJenkinsChange: (value: JenkinsConnectorFormState) => void;
  doorsNext: DoorsNextConnectorFormState;
  onDoorsNextChange: (value: DoorsNextConnectorFormState) => void;
  jama: JamaConnectorFormState;
  onJamaChange: (value: JamaConnectorFormState) => void;
  jiraCloud: JiraCloudConnectorFormState;
  onJiraCloudChange: (value: JiraCloudConnectorFormState) => void;
  packJobStatus: JobStatus | null;
  postQuantumSignature: PostQuantumSignatureMetadata | null;
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

type ManualSelection = ManualArtifactType | 'auto' | 'unassigned';

const MANUAL_ARTIFACT_LABELS: Record<ManualArtifactType, string> = {
  plan: 'Plan dokümanları',
  standard: 'Standart / politika kayıtları',
  review: 'Gözden geçirme kayıtları',
  analysis: 'Analiz artefaktları',
  test: 'Test kanıtları',
  coverage_stmt: 'Statement coverage',
  coverage_dec: 'Decision coverage',
  coverage_mcdc: 'MC/DC coverage',
  trace: 'İzlenebilirlik kayıtları',
  cm_record: 'Yapılandırma yönetimi kayıtları',
  qa_record: 'QA denetim kayıtları',
  problem_report: 'Problem raporları',
  conformity: 'Uygunluk bildirimi',
};

const manualBadgeManualClass = 'border border-brand/40 bg-brand/10 text-brand';

const MANUAL_SELECTION_LABELS: Record<ManualSelection, string> = {
  auto: 'Otomatik seçim',
  unassigned: 'Seçim gerekli',
  plan: MANUAL_ARTIFACT_LABELS.plan,
  standard: MANUAL_ARTIFACT_LABELS.standard,
  review: MANUAL_ARTIFACT_LABELS.review,
  analysis: MANUAL_ARTIFACT_LABELS.analysis,
  test: MANUAL_ARTIFACT_LABELS.test,
  coverage_stmt: MANUAL_ARTIFACT_LABELS.coverage_stmt,
  coverage_dec: MANUAL_ARTIFACT_LABELS.coverage_dec,
  coverage_mcdc: MANUAL_ARTIFACT_LABELS.coverage_mcdc,
  trace: MANUAL_ARTIFACT_LABELS.trace,
  cm_record: MANUAL_ARTIFACT_LABELS.cm_record,
  qa_record: MANUAL_ARTIFACT_LABELS.qa_record,
  problem_report: MANUAL_ARTIFACT_LABELS.problem_report,
  conformity: MANUAL_ARTIFACT_LABELS.conformity,
};

const MANUAL_SELECTION_BADGE_STYLES: Record<ManualSelection, string> = {
  auto: 'border border-slate-700/70 bg-slate-900/60 text-slate-200',
  unassigned: 'border border-amber-500/40 bg-amber-500/10 text-amber-200',
  plan: manualBadgeManualClass,
  standard: manualBadgeManualClass,
  review: manualBadgeManualClass,
  analysis: manualBadgeManualClass,
  test: manualBadgeManualClass,
  coverage_stmt: manualBadgeManualClass,
  coverage_dec: manualBadgeManualClass,
  coverage_mcdc: manualBadgeManualClass,
  trace: manualBadgeManualClass,
  cm_record: manualBadgeManualClass,
  qa_record: manualBadgeManualClass,
  problem_report: manualBadgeManualClass,
  conformity: manualBadgeManualClass,
};

const MANUAL_ARTIFACT_OPTIONS: Array<{ value: ManualSelection; label: string; disabled?: boolean }>
  = [
    { value: 'unassigned', label: 'Artefakt seçiniz...', disabled: true },
    { value: 'auto', label: 'Otomatik (sunucuya bırak)' },
    ...MANUAL_ARTIFACT_TYPES.map((value) => ({ value, label: MANUAL_ARTIFACT_LABELS[value] })),
  ];

const formatFileSize = (size: number): string => {
  if (size > 1024 * 1024) {
    return `${(size / (1024 * 1024)).toFixed(2)} MB`;
  }
  if (size > 1024) {
    return `${(size / 1024).toFixed(1)} KB`;
  }
  return `${size} B`;
};

const getFileKey = (file: File): string => `${file.name}:${file.lastModified}:${file.size}`;

const isManualArtifactTypeValue = (value: string): value is ManualArtifactType =>
  MANUAL_ARTIFACT_TYPES.includes(value as ManualArtifactType);

const isManualSelectionValue = (value: string): value is ManualSelection =>
  value === 'auto' || value === 'unassigned' || isManualArtifactTypeValue(value);

const isManualArtifactSelection = (value: ManualSelection): value is ManualArtifactType =>
  value !== 'auto' && value !== 'unassigned';

const inferManualSelection = (file: File): ManualSelection => {
  const name = file.name.toLowerCase();
  if (/(psac|phac|plan)/i.test(name)) {
    return 'plan';
  }
  if (/(stdp|standard|policy)/i.test(name)) {
    return 'standard';
  }
  if (/(peer[-_]?review|review|svr|pvr|cvr)/i.test(name)) {
    return 'review';
  }
  if (/(analysis|assessment|hazard|safety)/i.test(name)) {
    return 'analysis';
  }
  if (/(test|procedure|result)/i.test(name) && !name.includes('contest')) {
    return 'test';
  }
  if (/mcdc/i.test(name)) {
    return 'coverage_mcdc';
  }
  if (/(decision|dcov)/i.test(name)) {
    return 'coverage_dec';
  }
  if (/(statement|stmt)/i.test(name)) {
    return 'coverage_stmt';
  }
  if (/(trace|matrix)/i.test(name)) {
    return 'trace';
  }
  if (/(cm[-_]?record|configuration[-_]?management)/i.test(name)) {
    return 'cm_record';
  }
  if (/(qa|quality|audit)/i.test(name)) {
    return 'qa_record';
  }
  if (/(problem|issue|defect|bug|pr[-_]?)/i.test(name)) {
    return 'problem_report';
  }
  if (/conform/i.test(name) || /compliance/i.test(name)) {
    return 'conformity';
  }

  if (
    ['.reqif', '.xml', '.json', '.zip', '.tar', '.tgz', '.gz', '.info', '.csv', '.xlsx', '.xls'].some((ext) =>
      name.endsWith(ext),
    )
  ) {
    return 'auto';
  }

  return 'unassigned';
};

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
  polarion,
  onPolarionChange,
  jenkins,
  onJenkinsChange,
  doorsNext,
  onDoorsNextChange,
  jama,
  onJamaChange,
  jiraCloud,
  onJiraCloudChange,
  packJobStatus,
  postQuantumSignature,
}: UploadAndRunProps) {
  const [manualSelections, setManualSelections] = useState<Record<string, ManualSelection>>({});
  const [manualSelectionError, setManualSelectionError] = useState<string | null>(null);

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

  useEffect(() => {
    setManualSelections((previous) => {
      const next: Record<string, ManualSelection> = {};
      files.forEach((file) => {
        const key = getFileKey(file);
        next[key] = previous[key] ?? inferManualSelection(file);
      });
      return next;
    });
    if (files.length === 0) {
      setManualSelectionError(null);
    }
  }, [files]);

  useEffect(() => {
    if (files.length === 0) {
      return;
    }
    const hasMissingSelection = files.some((file) => {
      const selection = manualSelections[getFileKey(file)] ?? 'unassigned';
      return selection === 'unassigned';
    });
    if (!hasMissingSelection) {
      setManualSelectionError(null);
    }
  }, [files, manualSelections]);

  const trim = (value: string): string => value.trim();

  const handleManualSelectionChange = (fileKey: string, value: string) => {
    if (!isManualSelectionValue(value)) {
      return;
    }
    setManualSelections((previous) => ({
      ...previous,
      [fileKey]: value,
    }));
  };

  const buildConnectorPayload = (): RemoteConnectorPayload => {
    const connectors: RemoteConnectorPayload = {};

    if (polarion.enabled) {
      const baseUrl = trim(polarion.baseUrl);
      const projectId = trim(polarion.projectId);
      if (baseUrl && projectId) {
        const payload: RemoteConnectorPayload['polarion'] = { baseUrl, projectId };
        const username = trim(polarion.username);
        const password = trim(polarion.password);
        const token = trim(polarion.token);
        if (username) {
          payload.username = username;
        }
        if (password) {
          payload.password = password;
        }
        if (token) {
          payload.token = token;
        }
        connectors.polarion = payload;
      }
    }

    if (jenkins.enabled) {
      const baseUrl = trim(jenkins.baseUrl);
      const job = trim(jenkins.job);
      if (baseUrl && job) {
        const buildRaw = trim(jenkins.build);
        let buildValue: string | number | undefined;
        if (buildRaw) {
          const numeric = Number.parseInt(buildRaw, 10);
          buildValue = Number.isNaN(numeric) || `${numeric}` !== buildRaw ? buildRaw : numeric;
        }
        const payload: RemoteConnectorPayload['jenkins'] = { baseUrl, job };
        if (buildValue !== undefined) {
          payload.build = buildValue;
        }
        const username = trim(jenkins.username);
        const password = trim(jenkins.password);
        const token = trim(jenkins.token);
        if (username) {
          payload.username = username;
        }
        if (password) {
          payload.password = password;
        }
        if (token) {
          payload.token = token;
        }
        connectors.jenkins = payload;
      }
    }

    if (doorsNext.enabled) {
      const baseUrl = trim(doorsNext.baseUrl);
      const projectArea = trim(doorsNext.projectArea);
      if (baseUrl && projectArea) {
        const payload: RemoteConnectorPayload['doorsNext'] = { baseUrl, projectArea };
        const username = trim(doorsNext.username);
        const password = trim(doorsNext.password);
        const accessToken = trim(doorsNext.accessToken);
        if (username) {
          payload.username = username;
        }
        if (password) {
          payload.password = password;
        }
        if (accessToken) {
          payload.accessToken = accessToken;
        }
        connectors.doorsNext = payload;
      }
    }

    if (jama.enabled) {
      const baseUrl = trim(jama.baseUrl);
      const projectIdRaw = trim(jama.projectId);
      const token = trim(jama.token);
      if (baseUrl && projectIdRaw && token) {
        const numericId = Number.parseInt(projectIdRaw, 10);
        const projectId = Number.isNaN(numericId) || `${numericId}` !== projectIdRaw ? projectIdRaw : numericId;
        connectors.jama = { baseUrl, projectId, token };
      }
    }

    if (jiraCloud.enabled) {
      const baseUrl = trim(jiraCloud.baseUrl);
      const projectKey = trim(jiraCloud.projectKey);
      const email = trim(jiraCloud.email);
      const token = trim(jiraCloud.token);
      if (baseUrl && projectKey && email && token) {
        const payload: RemoteConnectorPayload['jiraCloud'] = {
          baseUrl,
          projectKey,
          email,
          token,
        };
        const requirementsJql = trim(jiraCloud.requirementsJql);
        if (requirementsJql) {
          payload.requirementsJql = requirementsJql;
        }
        const testsJql = trim(jiraCloud.testsJql);
        if (testsJql) {
          payload.testsJql = testsJql;
        }
        const pageSizeRaw = trim(jiraCloud.pageSize);
        if (pageSizeRaw) {
          const pageSizeValue = Number.parseInt(pageSizeRaw, 10);
          if (!Number.isNaN(pageSizeValue)) {
            payload.pageSize = pageSizeValue;
          }
        }
        const maxPagesRaw = trim(jiraCloud.maxPages);
        if (maxPagesRaw) {
          const maxPagesValue = Number.parseInt(maxPagesRaw, 10);
          if (!Number.isNaN(maxPagesValue)) {
            payload.maxPages = maxPagesValue;
          }
        }
        const timeoutRaw = trim(jiraCloud.timeoutMs);
        if (timeoutRaw) {
          const timeoutValue = Number.parseInt(timeoutRaw, 10);
          if (!Number.isNaN(timeoutValue)) {
            payload.timeoutMs = timeoutValue;
          }
        }
        connectors.jiraCloud = payload;
      }
    }

    return connectors;
  };

  const handleRunClick = () => {
    if (!isEnabled || isRunning || !canRun) {
      return;
    }

    const hasMissingSelection = files.some((file) => {
      const selection = manualSelections[getFileKey(file)] ?? 'unassigned';
      return selection === 'unassigned';
    });

    if (hasMissingSelection) {
      setManualSelectionError('Lütfen tüm dosyalar için DO-178C artefakt türü seçin.');
      return;
    }

    const manualArtifacts: ManualArtifactsSelection = {};
    files.forEach((file) => {
      const selection = manualSelections[getFileKey(file)];
      if (selection && isManualArtifactSelection(selection)) {
        const existing = manualArtifacts[selection] ?? [];
        manualArtifacts[selection] = [...existing, file.name];
      }
    });

    onRun({
      independentSources,
      independentArtifacts,
      connectors: buildConnectorPayload(),
      manualArtifacts,
    });
  };

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
          {files.length > 0 && (
            <div
              className="space-y-4 rounded-xl border border-slate-800/60 bg-slate-950/40 p-4"
              data-testid="manual-artifact-list"
            >
              <div className="flex items-center justify-between gap-3">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">
                  Yüklenen dosyalar
                </h3>
                <span className="text-[11px] text-slate-500">
                  DO-178C artefakt sınıflandırmasını seçin
                </span>
              </div>
              <ul className="space-y-3">
                {files.map((file, index) => {
                  const fileKey = getFileKey(file);
                  const selection = manualSelections[fileKey] ?? 'unassigned';
                  const selectId = `manual-artifact-${index}`;
                  const badgeClass = MANUAL_SELECTION_BADGE_STYLES[selection];
                  const badgeLabel = MANUAL_SELECTION_LABELS[selection];
                  return (
                    <li
                      key={fileKey}
                      className="rounded-lg border border-slate-800/60 bg-slate-900/40 p-4"
                      data-testid={`manual-artifact-item-${index}`}
                    >
                      <div className="flex flex-wrap items-center justify-between gap-3">
                        <div>
                          <p className="text-sm font-semibold text-slate-100">{file.name}</p>
                          <p className="text-xs text-slate-500">{formatFileSize(file.size)}</p>
                        </div>
                        <span
                          data-testid={`manual-artifact-badge-${index}`}
                          className={`inline-flex items-center rounded-full px-3 py-1 text-[11px] font-medium ${badgeClass}`}
                        >
                          {badgeLabel}
                        </span>
                      </div>
                      <label
                        className="mt-3 block text-xs font-medium text-slate-400"
                        htmlFor={selectId}
                      >
                        DO-178C artefaktı
                      </label>
                      <select
                        id={selectId}
                        name={selectId}
                        className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                        value={selection}
                        aria-invalid={selection === 'unassigned'}
                        required
                        disabled={!isEnabled}
                        onChange={(event) => handleManualSelectionChange(fileKey, event.currentTarget.value)}
                      >
                        {MANUAL_ARTIFACT_OPTIONS.map((option) => (
                          <option key={option.value} value={option.value} disabled={option.disabled}>
                            {option.label}
                          </option>
                        ))}
                      </select>
                    </li>
                  );
                })}
              </ul>
              {manualSelectionError && (
                <div
                  className="rounded-lg border border-amber-500/40 bg-amber-950/40 px-3 py-2 text-xs text-amber-200"
                  role="alert"
                >
                  {manualSelectionError}
                </div>
              )}
            </div>
          )}
          {error && (
            <div className="rounded-xl border border-rose-700/40 bg-rose-950/40 px-4 py-3 text-sm text-rose-200">
              {error}
            </div>
          )}
          <div className="rounded-xl border border-slate-800/60 bg-slate-950/40 p-4">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">
              Uzak bağlayıcılar
            </h3>
            <p className="mt-2 text-xs text-slate-400">
              Polarion, Jenkins, DOORS Next, Jama ve Jira Cloud kaynakları için API bağlantı bilgilerini girin.
              Bağlayıcılar etkinleştirildiğinde yapılandırmalar import isteğine JSON olarak eklenir.
            </p>
            <div className="mt-4 grid gap-4 lg:grid-cols-2">
              <section className="rounded-lg border border-slate-800/60 bg-slate-900/40 p-4">
                <div className="flex items-center justify-between gap-3">
                  <label htmlFor="connector-polarion-enabled" className="flex items-center gap-2 text-sm text-slate-200">
                    <input
                      id="connector-polarion-enabled"
                      type="checkbox"
                      className="h-4 w-4 rounded border-slate-600 bg-slate-900 text-brand focus:ring-brand"
                      checked={polarion.enabled}
                      disabled={!isEnabled}
                      onChange={(event) =>
                        onPolarionChange({
                          ...polarion,
                          enabled: event.currentTarget.checked,
                        })
                      }
                    />
                    <span>Polarion ALM</span>
                  </label>
                  <span className="text-xs text-slate-500">Gereksinim / test içe aktarma</span>
                </div>
                <div className="mt-4 grid gap-3 text-xs text-slate-300">
                  <label className="grid gap-1" htmlFor="connector-polarion-url">
                    <span>Polarion URL</span>
                    <input
                      id="connector-polarion-url"
                      type="url"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      placeholder="https://polarion.example.com"
                      value={polarion.baseUrl}
                      disabled={!isEnabled || !polarion.enabled}
                      onChange={(event) =>
                        onPolarionChange({
                          ...polarion,
                          baseUrl: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                  <label className="grid gap-1" htmlFor="connector-polarion-project">
                    <span>Proje kimliği</span>
                    <input
                      id="connector-polarion-project"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      placeholder="SOIPACK"
                      value={polarion.projectId}
                      disabled={!isEnabled || !polarion.enabled}
                      onChange={(event) =>
                        onPolarionChange({
                          ...polarion,
                          projectId: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                  <label className="grid gap-1" htmlFor="connector-polarion-username">
                    <span>Kullanıcı adı</span>
                    <input
                      id="connector-polarion-username"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      value={polarion.username}
                      disabled={!isEnabled || !polarion.enabled}
                      onChange={(event) =>
                        onPolarionChange({
                          ...polarion,
                          username: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                  <label className="grid gap-1" htmlFor="connector-polarion-password">
                    <span>Parola</span>
                    <input
                      id="connector-polarion-password"
                      type="password"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      value={polarion.password}
                      disabled={!isEnabled || !polarion.enabled}
                      onChange={(event) =>
                        onPolarionChange({
                          ...polarion,
                          password: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                  <label className="grid gap-1" htmlFor="connector-polarion-token">
                    <span>Erişim token</span>
                    <input
                      id="connector-polarion-token"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      value={polarion.token}
                      disabled={!isEnabled || !polarion.enabled}
                      onChange={(event) =>
                        onPolarionChange({
                          ...polarion,
                          token: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                </div>
              </section>
              <section className="rounded-lg border border-slate-800/60 bg-slate-900/40 p-4">
                <div className="flex items-center justify-between gap-3">
                  <label htmlFor="connector-jenkins-enabled" className="flex items-center gap-2 text-sm text-slate-200">
                    <input
                      id="connector-jenkins-enabled"
                      type="checkbox"
                      className="h-4 w-4 rounded border-slate-600 bg-slate-900 text-brand focus:ring-brand"
                      checked={jenkins.enabled}
                      disabled={!isEnabled}
                      onChange={(event) =>
                        onJenkinsChange({
                          ...jenkins,
                          enabled: event.currentTarget.checked,
                        })
                      }
                    />
                    <span>Jenkins</span>
                  </label>
                  <span className="text-xs text-slate-500">CI pipeline sonuçları</span>
                </div>
                <div className="mt-4 grid gap-3 text-xs text-slate-300">
                  <label className="grid gap-1" htmlFor="connector-jenkins-url">
                    <span>Jenkins URL</span>
                    <input
                      id="connector-jenkins-url"
                      type="url"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      placeholder="https://jenkins.example.com"
                      value={jenkins.baseUrl}
                      disabled={!isEnabled || !jenkins.enabled}
                      onChange={(event) =>
                        onJenkinsChange({
                          ...jenkins,
                          baseUrl: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                  <label className="grid gap-1" htmlFor="connector-jenkins-job">
                    <span>Job adı</span>
                    <input
                      id="connector-jenkins-job"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      placeholder="soipack-pipeline"
                      value={jenkins.job}
                      disabled={!isEnabled || !jenkins.enabled}
                      onChange={(event) =>
                        onJenkinsChange({
                          ...jenkins,
                          job: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                  <label className="grid gap-1" htmlFor="connector-jenkins-build">
                    <span>Build numarası / etiketi</span>
                    <input
                      id="connector-jenkins-build"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      placeholder="latest"
                      value={jenkins.build}
                      disabled={!isEnabled || !jenkins.enabled}
                      onChange={(event) =>
                        onJenkinsChange({
                          ...jenkins,
                          build: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                  <label className="grid gap-1" htmlFor="connector-jenkins-username">
                    <span>Kullanıcı adı</span>
                    <input
                      id="connector-jenkins-username"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      value={jenkins.username}
                      disabled={!isEnabled || !jenkins.enabled}
                      onChange={(event) =>
                        onJenkinsChange({
                          ...jenkins,
                          username: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                  <label className="grid gap-1" htmlFor="connector-jenkins-password">
                    <span>Parola</span>
                    <input
                      id="connector-jenkins-password"
                      type="password"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      value={jenkins.password}
                      disabled={!isEnabled || !jenkins.enabled}
                      onChange={(event) =>
                        onJenkinsChange({
                          ...jenkins,
                          password: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                  <label className="grid gap-1" htmlFor="connector-jenkins-token">
                    <span>API token</span>
                    <input
                      id="connector-jenkins-token"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      value={jenkins.token}
                      disabled={!isEnabled || !jenkins.enabled}
                      onChange={(event) =>
                        onJenkinsChange({
                          ...jenkins,
                          token: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                </div>
              </section>
              <section className="rounded-lg border border-slate-800/60 bg-slate-900/40 p-4">
                <div className="flex items-center justify-between gap-3">
                  <label htmlFor="connector-doorsnext-enabled" className="flex items-center gap-2 text-sm text-slate-200">
                    <input
                      id="connector-doorsnext-enabled"
                      type="checkbox"
                      className="h-4 w-4 rounded border-slate-600 bg-slate-900 text-brand focus:ring-brand"
                      checked={doorsNext.enabled}
                      disabled={!isEnabled}
                      onChange={(event) =>
                        onDoorsNextChange({
                          ...doorsNext,
                          enabled: event.currentTarget.checked,
                        })
                      }
                    />
                    <span>DOORS Next</span>
                  </label>
                  <span className="text-xs text-slate-500">OSLC gereksinim &amp; ilişki</span>
                </div>
                <div className="mt-4 grid gap-3 text-xs text-slate-300">
                  <label className="grid gap-1" htmlFor="connector-doorsnext-url">
                    <span>Sunucu URL</span>
                    <input
                      id="connector-doorsnext-url"
                      type="url"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      placeholder="https://doors-next.example.com"
                      value={doorsNext.baseUrl}
                      disabled={!isEnabled || !doorsNext.enabled}
                      onChange={(event) =>
                        onDoorsNextChange({
                          ...doorsNext,
                          baseUrl: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                  <label className="grid gap-1" htmlFor="connector-doorsnext-project">
                    <span>Project area</span>
                    <input
                      id="connector-doorsnext-project"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      placeholder="SOIPACK-AREA"
                      value={doorsNext.projectArea}
                      disabled={!isEnabled || !doorsNext.enabled}
                      onChange={(event) =>
                        onDoorsNextChange({
                          ...doorsNext,
                          projectArea: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                  <label className="grid gap-1" htmlFor="connector-doorsnext-username">
                    <span>Kullanıcı adı</span>
                    <input
                      id="connector-doorsnext-username"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      value={doorsNext.username}
                      disabled={!isEnabled || !doorsNext.enabled}
                      onChange={(event) =>
                        onDoorsNextChange({
                          ...doorsNext,
                          username: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                  <label className="grid gap-1" htmlFor="connector-doorsnext-password">
                    <span>Parola</span>
                    <input
                      id="connector-doorsnext-password"
                      type="password"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      value={doorsNext.password}
                      disabled={!isEnabled || !doorsNext.enabled}
                      onChange={(event) =>
                        onDoorsNextChange({
                          ...doorsNext,
                          password: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                  <label className="grid gap-1" htmlFor="connector-doorsnext-token">
                    <span>OSLC token</span>
                    <input
                      id="connector-doorsnext-token"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      value={doorsNext.accessToken}
                      disabled={!isEnabled || !doorsNext.enabled}
                      onChange={(event) =>
                        onDoorsNextChange({
                          ...doorsNext,
                          accessToken: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                </div>
              </section>
              <section className="rounded-lg border border-slate-800/60 bg-slate-900/40 p-4">
                <div className="flex items-center justify-between gap-3">
                  <label htmlFor="connector-jama-enabled" className="flex items-center gap-2 text-sm text-slate-200">
                    <input
                      id="connector-jama-enabled"
                      type="checkbox"
                      className="h-4 w-4 rounded border-slate-600 bg-slate-900 text-brand focus:ring-brand"
                      checked={jama.enabled}
                      disabled={!isEnabled}
                      onChange={(event) =>
                        onJamaChange({
                          ...jama,
                          enabled: event.currentTarget.checked,
                        })
                      }
                    />
                    <span>Jama Connect</span>
                  </label>
                  <span className="text-xs text-slate-500">REST gereksinim &amp; testleri</span>
                </div>
                <div className="mt-4 grid gap-3 text-xs text-slate-300">
                  <label className="grid gap-1" htmlFor="connector-jama-url">
                    <span>Jama URL</span>
                    <input
                      id="connector-jama-url"
                      type="url"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      placeholder="https://jama.example.com"
                      value={jama.baseUrl}
                      disabled={!isEnabled || !jama.enabled}
                      onChange={(event) =>
                        onJamaChange({
                          ...jama,
                          baseUrl: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                  <label className="grid gap-1" htmlFor="connector-jama-project">
                    <span>Proje kimliği</span>
                    <input
                      id="connector-jama-project"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      placeholder="42"
                      value={jama.projectId}
                      disabled={!isEnabled || !jama.enabled}
                      onChange={(event) =>
                        onJamaChange({
                          ...jama,
                          projectId: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                  <label className="grid gap-1" htmlFor="connector-jama-token">
                    <span>REST token</span>
                    <input
                      id="connector-jama-token"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      value={jama.token}
                      disabled={!isEnabled || !jama.enabled}
                      onChange={(event) =>
                        onJamaChange({
                          ...jama,
                          token: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                </div>
              </section>
              <section className="rounded-lg border border-slate-800/60 bg-slate-900/40 p-4">
                <div className="flex items-center justify-between gap-3">
                  <label
                    htmlFor="connector-jira-cloud-enabled"
                    className="flex items-center gap-2 text-sm text-slate-200"
                  >
                    <input
                      id="connector-jira-cloud-enabled"
                      type="checkbox"
                      className="h-4 w-4 rounded border-slate-600 bg-slate-900 text-brand focus:ring-brand"
                      checked={jiraCloud.enabled}
                      disabled={!isEnabled}
                      onChange={(event) =>
                        onJiraCloudChange({
                          ...jiraCloud,
                          enabled: event.currentTarget.checked,
                        })
                      }
                    />
                    <span>Jira Cloud</span>
                  </label>
                  <span className="text-xs text-slate-500">REST gereksinim &amp; testleri</span>
                </div>
                <div className="mt-4 grid gap-3 text-xs text-slate-300">
                  <label className="grid gap-1" htmlFor="connector-jira-cloud-url">
                    <span>Site URL</span>
                    <input
                      id="connector-jira-cloud-url"
                      type="url"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      placeholder="https://your-domain.atlassian.net"
                      value={jiraCloud.baseUrl}
                      disabled={!isEnabled || !jiraCloud.enabled}
                      onChange={(event) =>
                        onJiraCloudChange({
                          ...jiraCloud,
                          baseUrl: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                  <label className="grid gap-1" htmlFor="connector-jira-cloud-project">
                    <span>Proje anahtarı</span>
                    <input
                      id="connector-jira-cloud-project"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      placeholder="SOI"
                      value={jiraCloud.projectKey}
                      disabled={!isEnabled || !jiraCloud.enabled}
                      onChange={(event) =>
                        onJiraCloudChange({
                          ...jiraCloud,
                          projectKey: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                  <label className="grid gap-1" htmlFor="connector-jira-cloud-email">
                    <span>API e-posta</span>
                    <input
                      id="connector-jira-cloud-email"
                      type="email"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      placeholder="ops@example.com"
                      value={jiraCloud.email}
                      disabled={!isEnabled || !jiraCloud.enabled}
                      onChange={(event) =>
                        onJiraCloudChange({
                          ...jiraCloud,
                          email: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                  <label className="grid gap-1" htmlFor="connector-jira-cloud-token">
                    <span>API token</span>
                    <input
                      id="connector-jira-cloud-token"
                      type="password"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      value={jiraCloud.token}
                      disabled={!isEnabled || !jiraCloud.enabled}
                      onChange={(event) =>
                        onJiraCloudChange({
                          ...jiraCloud,
                          token: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                  <label className="grid gap-1" htmlFor="connector-jira-cloud-req-jql">
                    <span>Gereksinim JQL</span>
                    <textarea
                      id="connector-jira-cloud-req-jql"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      rows={2}
                      value={jiraCloud.requirementsJql}
                      disabled={!isEnabled || !jiraCloud.enabled}
                      onChange={(event) =>
                        onJiraCloudChange({
                          ...jiraCloud,
                          requirementsJql: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                  <label className="grid gap-1" htmlFor="connector-jira-cloud-tests-jql">
                    <span>Test JQL</span>
                    <textarea
                      id="connector-jira-cloud-tests-jql"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      rows={2}
                      value={jiraCloud.testsJql}
                      disabled={!isEnabled || !jiraCloud.enabled}
                      onChange={(event) =>
                        onJiraCloudChange({
                          ...jiraCloud,
                          testsJql: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                  <label className="grid gap-1" htmlFor="connector-jira-cloud-page-size">
                    <span>Sayfa boyutu</span>
                    <input
                      id="connector-jira-cloud-page-size"
                      type="number"
                      min="1"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      placeholder="50"
                      value={jiraCloud.pageSize}
                      disabled={!isEnabled || !jiraCloud.enabled}
                      onChange={(event) =>
                        onJiraCloudChange({
                          ...jiraCloud,
                          pageSize: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                  <label className="grid gap-1" htmlFor="connector-jira-cloud-max-pages">
                    <span>Maksimum sayfa</span>
                    <input
                      id="connector-jira-cloud-max-pages"
                      type="number"
                      min="1"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      placeholder="5"
                      value={jiraCloud.maxPages}
                      disabled={!isEnabled || !jiraCloud.enabled}
                      onChange={(event) =>
                        onJiraCloudChange({
                          ...jiraCloud,
                          maxPages: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                  <label className="grid gap-1" htmlFor="connector-jira-cloud-timeout">
                    <span>Zaman aşımı (ms)</span>
                    <input
                      id="connector-jira-cloud-timeout"
                      type="number"
                      min="1000"
                      step="1000"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                      placeholder="45000"
                      value={jiraCloud.timeoutMs}
                      disabled={!isEnabled || !jiraCloud.enabled}
                      onChange={(event) =>
                        onJiraCloudChange({
                          ...jiraCloud,
                          timeoutMs: event.currentTarget.value,
                        })
                      }
                    />
                  </label>
                </div>
              </section>
            </div>
          </div>
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
                  onClick={handleRunClick}
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

      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 backdrop-blur-sm" data-testid="pack-signature-panel">
        <div className="border-b border-slate-800 px-6 py-4">
          <h3 className="text-lg font-semibold text-white">Paket İmzaları</h3>
          <p className="text-sm text-slate-400">Post-kuantum imza sonuçları ve anahtar bilgisi</p>
        </div>
        <div className="px-6 py-5 text-sm text-slate-200">
          {packJobStatus === 'completed' ? (
            postQuantumSignature ? (
              <div className="space-y-3" data-testid="pack-signature-present">
                <div className="grid gap-1">
                  <span className="text-xs uppercase tracking-wide text-slate-500">Algoritma</span>
                  <span data-testid="pack-signature-algorithm" className="font-mono text-base text-emerald-300">
                    {postQuantumSignature.algorithm}
                  </span>
                </div>
                <div className="grid gap-1">
                  <span className="text-xs uppercase tracking-wide text-slate-500">Genel anahtar (Base64)</span>
                  <code
                    data-testid="pack-signature-public-key"
                    className="block overflow-x-auto rounded-md border border-slate-700 bg-slate-950 p-3 text-xs text-emerald-200"
                  >
                    {postQuantumSignature.publicKey}
                  </code>
                </div>
              </div>
            ) : (
              <p className="text-sm text-amber-200" data-testid="pack-signature-missing">
                Bu paket için post-kuantum imzası üretilmedi.
              </p>
            )
          ) : packJobStatus ? (
            <p className="text-sm text-slate-300" data-testid="pack-signature-pending">
              Post-kuantum imza bilgisi paket işlemi tamamlandığında görüntülenecektir.
            </p>
          ) : (
            <p className="text-sm text-slate-300" data-testid="pack-signature-awaiting">
              Önce raporu paketleyerek post-kuantum imzası üretmelisiniz.
            </p>
          )}
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
