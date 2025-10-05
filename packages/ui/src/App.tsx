import { Alert } from '@bora/ui-kit';
import { useEffect, useMemo, useState } from 'react';
import type { ChangeEvent } from 'react';

import { ComplianceMatrix } from './components/ComplianceMatrix';
import { DownloadPackageButton } from './components/DownloadPackageButton';
import { GsnGraph } from './components/GsnGraph';
import { LicenseInput } from './components/LicenseInput';
import { NavigationTabs, type View } from './components/NavigationTabs';
import { TokenInput } from './components/TokenInput';
import { TraceabilityMatrix } from './components/TraceabilityMatrix';
import { UploadAndRun } from './components/UploadAndRun';
import { usePipeline } from './hooks/usePipeline';
import AdminUsersPage from './pages/AdminUsersPage';
import { TimelinePage } from './pages/TimelinePage';
import { RiskCockpitPage } from './pages/RiskCockpitPage';
import RequirementsEditorPage, { type RequirementRecord } from './pages/RequirementsEditorPage';
import { RoleGate, useRbac } from './providers/RbacProvider';
import {
  ApiError,
  fetchReportGsnGraph,
  getWorkspaceDocumentThread,
  type WorkspaceDocumentThread,
} from './services/api';
import { I18nProvider, useI18n } from './providers/I18nProvider';
import type { Locale } from './microcopy';
import type {
  DoorsNextConnectorFormState,
  JamaConnectorFormState,
  JenkinsConnectorFormState,
  JiraCloudConnectorFormState,
  PolarionConnectorFormState,
  UploadRunPayload,
} from './types/connectors';
import type { CoverageStatus, StageIdentifier } from './types/pipeline';

const STAGE_STORAGE_KEY = 'soipack:ui:activeStage';
const VALID_STAGE_IDS: StageIdentifier[] = ['all', 'SOI-1', 'SOI-2', 'SOI-3', 'SOI-4'];

const LOCALE_LABELS: Record<Locale, string> = {
  en: 'English',
  tr: 'Türkçe',
};

const createPolarionFormState = (): PolarionConnectorFormState => ({
  enabled: false,
  baseUrl: '',
  projectId: '',
  username: '',
  password: '',
  token: '',
});

const createJenkinsFormState = (): JenkinsConnectorFormState => ({
  enabled: false,
  baseUrl: '',
  job: '',
  build: '',
  username: '',
  password: '',
  token: '',
});

const createDoorsNextFormState = (): DoorsNextConnectorFormState => ({
  enabled: false,
  baseUrl: '',
  projectArea: '',
  username: '',
  password: '',
  accessToken: '',
});

const createJamaFormState = (): JamaConnectorFormState => ({
  enabled: false,
  baseUrl: '',
  projectId: '',
  token: '',
});

const createJiraCloudFormState = (): JiraCloudConnectorFormState => ({
  enabled: false,
  baseUrl: '',
  projectKey: '',
  email: '',
  token: '',
  requirementsJql: '',
  testsJql: '',
  pageSize: '',
  maxPages: '',
  timeoutMs: '',
});

const readStoredStage = (): StageIdentifier => {
  if (typeof window === 'undefined') {
    return 'all';
  }
  const stored = window.localStorage.getItem(STAGE_STORAGE_KEY);
  if (stored && (VALID_STAGE_IDS as string[]).includes(stored)) {
    return stored as StageIdentifier;
  }
  return 'all';
};

function AppContent() {
  const { t, availableLocales, locale, setLocale } = useI18n();
  const { roles } = useRbac();
  const [token, setToken] = useState('');
  const [license, setLicense] = useState('');
  const [activeView, setActiveView] = useState<View>('upload');
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [independentSources, setIndependentSources] = useState<string[]>([]);
  const [independentArtifacts, setIndependentArtifacts] = useState<string[]>([]);
  const [polarion, setPolarion] = useState<PolarionConnectorFormState>(createPolarionFormState);
  const [jenkins, setJenkins] = useState<JenkinsConnectorFormState>(createJenkinsFormState);
  const [doorsNext, setDoorsNext] = useState<DoorsNextConnectorFormState>(createDoorsNextFormState);
  const [jama, setJama] = useState<JamaConnectorFormState>(createJamaFormState);
  const [jiraCloud, setJiraCloud] = useState<JiraCloudConnectorFormState>(createJiraCloudFormState);
  const [activeStatuses, setActiveStatuses] = useState<CoverageStatus[]>([
    'covered',
    'partial',
    'missing'
  ]);
  const [activeStage, setActiveStage] = useState<StageIdentifier>(readStoredStage);

  const trimmedToken = token.trim();
  const trimmedLicense = license.trim();
  const isTokenActive = trimmedToken.length > 0;
  const isLicenseActive = trimmedLicense.length > 0;
  const isAuthorized = isTokenActive && isLicenseActive;
  const { runPipeline, downloadArtifacts, state, reset } = usePipeline({ token, license });

  const { logs, isRunning, isDownloading, jobs, reportData, packageJob, error, lastCompletedAt } = state;

  const canRunPipeline = selectedFiles.length > 0;

  const canAccessRequirements = roles.has('workspace:write') || roles.has('admin');
  const canAccessAdminUsers = roles.has('admin');

  const handleLocaleChange = (event: ChangeEvent<HTMLSelectElement>) => {
    setLocale(event.currentTarget.value as Locale);
  };

  const navigationViews = useMemo(() => {
    const baseViews: View[] = ['upload', 'compliance', 'traceability', 'gsn', 'risk', 'timeline'];
    if (canAccessRequirements) {
      baseViews.push('requirements');
    }
    if (canAccessAdminUsers) {
      baseViews.push('adminUsers');
    }
    return baseViews;
  }, [canAccessRequirements, canAccessAdminUsers]);

  useEffect(() => {
    if (!navigationViews.includes(activeView)) {
      setActiveView(navigationViews[0] ?? 'upload');
    }
  }, [navigationViews, activeView]);

  useEffect(() => {
    const stageOptions = reportData?.objectivesByStage ?? [];
    if (stageOptions.length === 0) {
      return;
    }
    const availableIds = stageOptions.map((stage) => stage.id);
    if (!availableIds.includes(activeStage)) {
      const fallbackStage = (availableIds.includes('all') ? 'all' : availableIds[0]) as StageIdentifier;
      setActiveStage(fallbackStage);
      if (typeof window !== 'undefined') {
        window.localStorage.setItem(STAGE_STORAGE_KEY, fallbackStage);
      }
    }
  }, [reportData, activeStage]);

  useEffect(() => {
    if (!reportData) {
      setGsnGraph(null);
      setGsnError(null);
      setGsnNotFound(false);
      setGsnLoading(false);
    }
  }, [reportData]);

  const [requirementsThread, setRequirementsThread] = useState<WorkspaceDocumentThread<RequirementRecord[]> | null>(null);
  const [requirementsError, setRequirementsError] = useState<string | null>(null);
  const [requirementsLoading, setRequirementsLoading] = useState(false);
  const [gsnGraph, setGsnGraph] = useState<string | null>(null);
  const [gsnError, setGsnError] = useState<string | null>(null);
  const [gsnNotFound, setGsnNotFound] = useState(false);
  const [gsnLoading, setGsnLoading] = useState(false);

  useEffect(() => {
    if (activeView !== 'requirements' || !canAccessRequirements) {
      return;
    }

    if (!isAuthorized) {
      setRequirementsThread(null);
      setRequirementsError('Gereksinim editörü için token ve lisans gereklidir.');
      setRequirementsLoading(false);
      return;
    }

    const controller = new AbortController();
    setRequirementsLoading(true);
    setRequirementsError(null);

    getWorkspaceDocumentThread<RequirementRecord[]>({
      token: trimmedToken,
      license: trimmedLicense,
      workspaceId: 'demo-workspace',
      documentId: 'requirements',
      signal: controller.signal,
    })
      .then((thread) => {
        if (!controller.signal.aborted) {
          setRequirementsThread(thread);
        }
      })
      .catch((err) => {
        if (!controller.signal.aborted) {
          setRequirementsThread(null);
          setRequirementsError(err instanceof ApiError ? err.message : 'Gereksinim belgesi yüklenemedi.');
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setRequirementsLoading(false);
        }
      });

    return () => {
      controller.abort();
    };
  }, [activeView, canAccessRequirements, isAuthorized, trimmedToken, trimmedLicense]);

  useEffect(() => {
    if (activeView !== 'gsn') {
      return;
    }

    if (!isAuthorized) {
      setGsnGraph(null);
      setGsnError(null);
      setGsnNotFound(false);
      setGsnLoading(false);
      return;
    }

    const currentReportId = reportData?.reportId;
    if (!currentReportId) {
      setGsnGraph(null);
      setGsnError(null);
      setGsnNotFound(false);
      setGsnLoading(false);
      return;
    }

    const controller = new AbortController();
    setGsnLoading(true);
    setGsnError(null);
    setGsnNotFound(false);

    fetchReportGsnGraph({
      token: trimmedToken,
      license: trimmedLicense,
      reportId: currentReportId,
      signal: controller.signal,
    })
      .then((dot) => {
        if (!controller.signal.aborted) {
          setGsnGraph(dot);
          setGsnError(null);
          setGsnNotFound(false);
        }
      })
      .catch((error) => {
        if (controller.signal.aborted) {
          return;
        }
        if (error instanceof ApiError && error.status === 404) {
          setGsnGraph(null);
          setGsnError(null);
          setGsnNotFound(true);
        } else {
          setGsnGraph(null);
          setGsnNotFound(false);
          setGsnError(
            error instanceof ApiError ? error.message : 'GSN grafiği yüklenirken bir hata oluştu.',
          );
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setGsnLoading(false);
        }
      });

    return () => {
      controller.abort();
    };
  }, [activeView, isAuthorized, trimmedToken, trimmedLicense, reportData?.reportId]);

  const handleRun = (submission: UploadRunPayload) => {
    if (!canRunPipeline || isRunning) return;
    void runPipeline({
      files: selectedFiles,
      independentSources,
      independentArtifacts,
      polarion: submission.connectors.polarion,
      jenkins: submission.connectors.jenkins,
      doorsNext: submission.connectors.doorsNext,
      jama: submission.connectors.jama,
      jiraCloud: submission.connectors.jiraCloud,
    });
  };

  const handleToggleStatus = (status: CoverageStatus) => {
    setActiveStatuses((previous) =>
      previous.includes(status)
        ? previous.filter((item) => item !== status)
        : [...previous, status]
    );
  };

  const handleStageChange = (stage: StageIdentifier) => {
    setActiveStage(stage);
    if (typeof window !== 'undefined') {
      window.localStorage.setItem(STAGE_STORAGE_KEY, stage);
    }
  };

  const jobStates = useMemo(
    () =>
      (['import', 'analyze', 'report', 'pack'] as const)
        .map((kind) => {
          const job = jobs[kind];
          if (!job) {
            return null;
          }
          return {
            kind,
            status: job.status,
            reused: job.reused,
            updatedAt: job.updatedAt
          };
        })
        .filter((item): item is NonNullable<typeof item> => item !== null),
    [jobs]
  );

  const complianceRows = reportData?.requirements ?? [];
  const complianceSummary = reportData?.summary ?? { total: 0, covered: 0, partial: 0, missing: 0 };
  const stageOptions = reportData?.objectivesByStage ?? [];
  const packJobStatus = packageJob?.status ?? null;
  const postQuantumSignature =
    packageJob?.result?.postQuantumSignature ?? packageJob?.result?.outputs?.postQuantumSignature ?? null;

  const handleTokenClear = () => {
    setToken('');
    setLicense('');
    setSelectedFiles([]);
    setIndependentSources([]);
    setIndependentArtifacts([]);
    setPolarion(createPolarionFormState());
    setJenkins(createJenkinsFormState());
    setDoorsNext(createDoorsNextFormState());
    setJama(createJamaFormState());
    setJiraCloud(createJiraCloudFormState());
    reset();
  };

  const handleLicenseClear = () => {
    setLicense('');
    setSelectedFiles([]);
    setIndependentSources([]);
    setIndependentArtifacts([]);
    setPolarion(createPolarionFormState());
    setJenkins(createJenkinsFormState());
    setDoorsNext(createDoorsNextFormState());
    setJama(createJamaFormState());
    setJiraCloud(createJiraCloudFormState());
    reset();
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 py-10 text-slate-100">
      <div className="mx-auto flex max-w-7xl flex-col gap-6 px-6">
        <header className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="space-y-2">
            <span className="inline-flex items-center gap-2 rounded-full bg-brand/10 px-3 py-1 text-xs font-semibold uppercase tracking-wider text-brand">
              SOIPack Demo
            </span>
            <h1 className="text-3xl font-bold text-white sm:text-4xl">{t('dashboard.title')}</h1>
            <p className="max-w-2xl text-sm text-slate-400">{t('app.heroDescription')}</p>
          </div>
          <div className="flex flex-col gap-3 self-stretch sm:flex-row sm:items-start sm:justify-end lg:flex-col lg:items-end">
            <div className="flex items-center gap-2 self-start rounded-md border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-300 shadow-inner shadow-slate-900/40 sm:self-auto lg:self-end">
              <label htmlFor="app-language-select" className="font-medium text-slate-400">
                {t('app.languageLabel')}
              </label>
              <select
                id="app-language-select"
                className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-100 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                value={locale}
                onChange={handleLocaleChange}
              >
                {availableLocales.map((candidate) => (
                  <option key={candidate} value={candidate}>
                    {LOCALE_LABELS[candidate]}
                  </option>
                ))}
              </select>
            </div>
            <DownloadPackageButton
              onDownload={() => downloadArtifacts()}
              disabled={!isAuthorized || !packageJob || packageJob.status !== 'completed'}
              isBusy={isDownloading}
            />
          </div>
        </header>

        <TokenInput token={token} onTokenChange={setToken} onClear={handleTokenClear} />

        <LicenseInput
          license={license}
          onLicenseChange={(value) => setLicense(value)}
          onClear={handleLicenseClear}
        />

        <NavigationTabs activeView={activeView} onChange={setActiveView} disabled={!isTokenActive} views={navigationViews} />

        {!isTokenActive && (
          <div className="relative rounded-3xl border border-slate-800 bg-slate-950/70 p-8 text-center text-slate-400 shadow-inner shadow-slate-950/40">
            <p className="text-sm font-medium text-slate-300">
              Demo'yu keşfetmek için lütfen geçerli bir REST token girin.
            </p>
            <p className="mt-2 text-xs text-slate-500">
              Token girildiğinde yükleme, matriksler ve paket indirme aktif hale gelecektir.
            </p>
          </div>
        )}

        {isTokenActive && !isLicenseActive && (
          <div className="rounded-3xl border border-amber-700/40 bg-amber-950/30 p-6 text-center text-amber-100">
            <p className="text-sm font-medium">Lütfen JSON lisans dosyasını yükleyin veya yapıştırın.</p>
            <p className="mt-2 text-xs text-amber-200">Lisans olmadan gönderilen istekler sunucu tarafından reddedilecektir.</p>
          </div>
        )}

        <main className={`${isTokenActive ? 'space-y-6' : 'pointer-events-none opacity-50'}`}>
          {activeView === 'upload' && (
            <UploadAndRun
              files={selectedFiles}
              onFilesChange={setSelectedFiles}
              logs={logs}
              isEnabled={isTokenActive}
              onRun={handleRun}
              isRunning={isRunning}
              canRun={canRunPipeline}
              jobStates={jobStates}
              error={error}
              lastCompletedAt={lastCompletedAt}
              independentSources={independentSources}
              independentArtifacts={independentArtifacts}
              onIndependentSourcesChange={setIndependentSources}
              onIndependentArtifactsChange={setIndependentArtifacts}
              polarion={polarion}
              onPolarionChange={setPolarion}
              jenkins={jenkins}
              onJenkinsChange={setJenkins}
              doorsNext={doorsNext}
              onDoorsNextChange={setDoorsNext}
              jama={jama}
              onJamaChange={setJama}
              jiraCloud={jiraCloud}
              onJiraCloudChange={setJiraCloud}
              packJobStatus={packJobStatus}
              postQuantumSignature={postQuantumSignature}
            />
          )}

          {activeView === 'compliance' && (
            <ComplianceMatrix
              rows={complianceRows}
              activeStatuses={activeStatuses}
              onToggleStatus={handleToggleStatus}
              summary={complianceSummary}
              isEnabled={Boolean(reportData)}
              generatedAt={reportData?.generatedAt}
              version={reportData?.version}
              stages={stageOptions}
              activeStageId={activeStage}
              onStageChange={handleStageChange}
            />
          )}

          {activeView === 'traceability' && (
            <TraceabilityMatrix
              rows={complianceRows}
              isEnabled={Boolean(reportData)}
              generatedAt={reportData?.generatedAt}
            />
          )}
          {activeView === 'gsn' && (
            <div className="space-y-4 rounded-3xl border border-slate-800 bg-slate-900/70 p-6 shadow-lg shadow-slate-950/30">
              {!isAuthorized ? (
                <Alert
                  variant="warning"
                  title="Kimlik bilgileri gerekli"
                  description="GSN grafiğini görüntülemek için token ve lisans sağlamalısınız."
                />
              ) : !reportData ? (
                <Alert
                  variant="warning"
                  title="Rapor bekleniyor"
                  description="GSN grafiğini görmek için önce bir rapor oluşturmalısınız."
                />
              ) : gsnLoading ? (
                <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-6 text-center text-slate-300">
                  GSN grafiği yükleniyor…
                </div>
              ) : gsnError ? (
                <Alert variant="destructive" title="GSN grafiği yüklenemedi" description={gsnError} />
              ) : gsnNotFound ? (
                <Alert
                  variant="warning"
                  title="GSN grafiği bulunamadı"
                  description="Bu rapor için GSN grafiği henüz üretilmedi."
                />
              ) : gsnGraph ? (
                <div className="space-y-4">
                  <div className="space-y-1">
                    <h2 className="text-lg font-semibold text-white">GSN Graphviz DOT</h2>
                    <p className="text-sm text-slate-400">
                      Raporun ürettiği güvence grafiği aşağıda Graphviz DOT formatında görüntülenmektedir.
                    </p>
                  </div>
                  <GsnGraph
                    dot={gsnGraph}
                    data-testid="gsn-graph-content"
                    className="max-h-96 overflow-auto rounded-2xl border border-slate-800 bg-slate-950/70 p-4 shadow-inner shadow-slate-950/40"
                    loadingMessage="GSN grafiği görselleştiriliyor…"
                    fallbackMessage="GSN grafiği görselleştirilemedi. DOT içeriği aşağıda gösterilmeye devam ediyor."
                  />
                  <pre
                    data-testid="gsn-graph-dot"
                    className="max-h-96 overflow-auto whitespace-pre rounded-2xl border border-slate-800 bg-slate-950/70 p-4 text-xs text-emerald-300 shadow-inner shadow-slate-950/40"
                  >
                    {gsnGraph}
                  </pre>
                </div>
              ) : (
                <Alert
                  variant="warning"
                  title="GSN grafiği mevcut değil"
                  description="Bu rapor için Graphviz çıktısı sağlanmadı."
                />
              )}
            </div>
          )}
          {activeView === 'risk' && (
            <RiskCockpitPage token={token} license={license} isAuthorized={isAuthorized} />
          )}
          {activeView === 'timeline' && (
            <TimelinePage token={token} license={license} isAuthorized={isAuthorized} />
          )}
          {activeView === 'requirements' && (
            <RoleGate role={['workspace:write', 'admin']}>
              {!isAuthorized ? (
                <Alert variant="warning" title="Kimlik bilgileri gerekli" description="Gereksinimleri düzenlemek için hem token hem de lisans sağlamalısınız." />
              ) : requirementsError ? (
                <Alert variant="destructive" title="Belge yüklenemedi" description={requirementsError} />
              ) : requirementsLoading && !requirementsThread ? (
                <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6 text-center text-slate-300">
                  Gereksinim dokümanı yükleniyor…
                </div>
              ) : (
                <RequirementsEditorPage
                  token={token}
                  license={license}
                  workspaceId="demo-workspace"
                  documentId="requirements"
                  initialThread={requirementsThread}
                />
              )}
            </RoleGate>
          )}
          {activeView === 'adminUsers' && (
            <RoleGate role="admin">
              {!isAuthorized ? (
                <Alert variant="warning" title="Kimlik bilgileri gerekli" description="Yönetici kullanıcılarını görüntülemek için token ve lisans girmelisiniz." />
              ) : (
                <AdminUsersPage token={token} license={license} />
              )}
            </RoleGate>
          )}
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <I18nProvider>
      <AppContent />
    </I18nProvider>
  );
}
