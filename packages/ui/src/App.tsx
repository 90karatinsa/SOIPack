import { useEffect, useMemo, useRef, useState } from 'react';
import JSZip from 'jszip';
import { saveAs } from 'file-saver';
import {
  complianceMatrix,
  complianceSummary,
  demoPackageFiles,
  traceabilityMatrix,
  uploadLogs,
  type CoverageStatus,
  type UploadLogEntry
} from './demoData';
import { TokenInput } from './components/TokenInput';
import { NavigationTabs, type View } from './components/NavigationTabs';
import { UploadAndRun } from './components/UploadAndRun';
import { ComplianceMatrix } from './components/ComplianceMatrix';
import { TraceabilityMatrix } from './components/TraceabilityMatrix';
import { DownloadPackageButton } from './components/DownloadPackageButton';

export default function App() {
  const [token, setToken] = useState('');
  const [activeView, setActiveView] = useState<View>('upload');
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [displayedLogs, setDisplayedLogs] = useState<UploadLogEntry[]>(uploadLogs);
  const [activeStatuses, setActiveStatuses] = useState<CoverageStatus[]>([
    'covered',
    'partial',
    'missing'
  ]);
  const [isRunning, setIsRunning] = useState(false);
  const [isPreparingDownload, setIsPreparingDownload] = useState(false);
  const timeoutsRef = useRef<number[]>([]);

  const isTokenActive = token.trim().length > 0;

  const complianceData = useMemo(() => complianceMatrix, []);
  const traceabilityData = useMemo(() => traceabilityMatrix, []);

  useEffect(() => {
    return () => {
      timeoutsRef.current.forEach((timeoutId) => window.clearTimeout(timeoutId));
    };
  }, []);

  const handleRun = () => {
    if (!isTokenActive || isRunning) return;

    timeoutsRef.current.forEach((timeoutId) => window.clearTimeout(timeoutId));
    timeoutsRef.current = [];

    setDisplayedLogs([]);
    setIsRunning(true);

    uploadLogs.forEach((log, index) => {
      const timeoutId = window.setTimeout(() => {
        setDisplayedLogs((previous) => [...previous, log]);
        if (index === uploadLogs.length - 1) {
          setIsRunning(false);
        }
      }, index * 650);
      timeoutsRef.current.push(timeoutId);
    });
  };

  const handleToggleStatus = (status: CoverageStatus) => {
    setActiveStatuses((previous) =>
      previous.includes(status)
        ? previous.filter((item) => item !== status)
        : [...previous, status]
    );
  };

  const handleDownload = async () => {
    if (!isTokenActive || isPreparingDownload) return;

    setIsPreparingDownload(true);
    try {
      const zip = new JSZip();
      zip.file('compliance.json', JSON.stringify(complianceData, null, 2));
      zip.file('traceability.json', JSON.stringify(traceabilityData, null, 2));
      zip.file('logs.json', JSON.stringify(uploadLogs, null, 2));
      Object.entries(demoPackageFiles).forEach(([path, content]) => {
        zip.file(path, content);
      });
      const blob = await zip.generateAsync({ type: 'blob' });
      saveAs(blob, 'soipack-ui-demo.zip');
    } finally {
      setIsPreparingDownload(false);
    }
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
              REST token girdiğinizde demo verileriyle yükleme, uyum ve izlenebilirlik matrislerini
              inceleyebilir, ayrıca zip paketini indirebilirsiniz.
            </p>
          </div>
          <DownloadPackageButton
            onDownload={handleDownload}
            disabled={!isTokenActive}
            isBusy={isPreparingDownload}
          />
        </header>

        <TokenInput token={token} onTokenChange={setToken} onClear={() => setToken('')} />

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

        <main className={`${isTokenActive ? 'space-y-6' : 'pointer-events-none opacity-50'}`}>
          {activeView === 'upload' && (
            <UploadAndRun
              files={selectedFiles}
              onFilesChange={setSelectedFiles}
              logs={displayedLogs}
              isEnabled={isTokenActive}
              onRun={handleRun}
              isRunning={isRunning}
            />
          )}

          {activeView === 'compliance' && (
            <ComplianceMatrix
              rows={complianceData}
              activeStatuses={activeStatuses}
              onToggleStatus={handleToggleStatus}
              summary={complianceSummary}
              isEnabled={isTokenActive}
            />
          )}

          {activeView === 'traceability' && (
            <TraceabilityMatrix rows={traceabilityData} isEnabled={isTokenActive} />
          )}
        </main>
      </div>
    </div>
  );
}
