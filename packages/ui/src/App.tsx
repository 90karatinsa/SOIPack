import { useMemo, useState } from 'react';

import { ComplianceMatrix } from './components/ComplianceMatrix';
import { DownloadPackageButton } from './components/DownloadPackageButton';
import { LicenseInput } from './components/LicenseInput';
import { NavigationTabs, type View } from './components/NavigationTabs';
import { TokenInput } from './components/TokenInput';
import { TraceabilityMatrix } from './components/TraceabilityMatrix';
import { UploadAndRun } from './components/UploadAndRun';
import { usePipeline } from './hooks/usePipeline';
import type { CoverageStatus } from './types/pipeline';

export default function App() {
  const [token, setToken] = useState('');
  const [license, setLicense] = useState('');
  const [activeView, setActiveView] = useState<View>('upload');
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [activeStatuses, setActiveStatuses] = useState<CoverageStatus[]>([
    'covered',
    'partial',
    'missing'
  ]);

  const isTokenActive = token.trim().length > 0;
  const isLicenseActive = license.trim().length > 0;
  const isAuthorized = isTokenActive && isLicenseActive;
  const { runPipeline, downloadArtifacts, state, reset } = usePipeline({ token, license });

  const { logs, isRunning, isDownloading, jobs, reportData, packageJob, error, lastCompletedAt } = state;

  const canRunPipeline = selectedFiles.length > 0;

  const handleRun = () => {
    if (!canRunPipeline || isRunning) return;
    void runPipeline(selectedFiles);
  };

  const handleToggleStatus = (status: CoverageStatus) => {
    setActiveStatuses((previous) =>
      previous.includes(status)
        ? previous.filter((item) => item !== status)
        : [...previous, status]
    );
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

  const handleTokenClear = () => {
    setToken('');
    setLicense('');
    setSelectedFiles([]);
    reset();
  };

  const handleLicenseClear = () => {
    setLicense('');
    setSelectedFiles([]);
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
            <h1 className="text-3xl font-bold text-white sm:text-4xl">Uyumluluk & İzlenebilirlik Panosu</h1>
            <p className="max-w-2xl text-sm text-slate-400">
              Geçerli bir REST token ile import, analyze ve report işlerinizin durumunu takip edip
              oluşan uyum ve izlenebilirlik çıktılarının özetini görüntüleyebilir, rapor artefaktlarını indirebilirsiniz.
            </p>
          </div>
          <DownloadPackageButton
            onDownload={() => downloadArtifacts()}
            disabled={!isAuthorized || !packageJob || packageJob.status !== 'completed'}
            isBusy={isDownloading}
          />
        </header>

        <TokenInput token={token} onTokenChange={setToken} onClear={handleTokenClear} />

        <LicenseInput
          license={license}
          onLicenseChange={(value) => setLicense(value)}
          onClear={handleLicenseClear}
        />

        <NavigationTabs activeView={activeView} onChange={setActiveView} disabled={!isTokenActive} />

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
            />
          )}

          {activeView === 'traceability' && (
            <TraceabilityMatrix
              rows={complianceRows}
              isEnabled={Boolean(reportData)}
              generatedAt={reportData?.generatedAt}
            />
          )}
        </main>
      </div>
    </div>
  );
}
