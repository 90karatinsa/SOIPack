import { useMemo, type ChangeEvent } from 'react';
import type { UploadLogEntry } from '../demoData';
import { StatusBadge } from './StatusBadge';

interface UploadAndRunProps {
  files: File[];
  onFilesChange: (files: File[]) => void;
  logs: UploadLogEntry[];
  isEnabled: boolean;
  onRun: () => void;
  isRunning: boolean;
}

const severityStyles: Record<UploadLogEntry['severity'], string> = {
  info: 'border-slate-700 bg-slate-800/40 text-slate-200',
  success: 'border-emerald-700/50 bg-emerald-950/40 text-emerald-200',
  warning: 'border-amber-700/60 bg-amber-950/30 text-amber-200',
  error: 'border-rose-700/60 bg-rose-950/30 text-rose-200'
};

const severityLabels: Record<UploadLogEntry['severity'], string> = {
  info: 'Bilgi',
  success: 'Başarılı',
  warning: 'Uyarı',
  error: 'Hata'
};

export function UploadAndRun({
  files,
  onFilesChange,
  logs,
  isEnabled,
  onRun,
  isRunning
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
            Gereklilik, test ve risk dosyalarını buradan seçin. Demo modu örnek veriler ile
            çalışır.
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
                  Kabul edilen formatlar: CSV, XLSX, JSON (demo verisi ile çalışır)
                </p>
              </div>
              <div className="text-xs text-slate-500">
                {files.length > 0
                  ? `${files.length} dosya seçildi · Toplam boyut ${totalSize}`
                  : 'Henüz dosya seçilmedi'}
              </div>
            </div>
          </label>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <StatusBadge status={files.length ? 'covered' : 'partial'} />
              <span className="text-sm text-slate-300">
                {files.length ? 'Demo verisi hazır' : 'Demo verisi yüklenecek'}
              </span>
            </div>
            <button
              type="button"
              onClick={onRun}
              disabled={!isEnabled || isRunning}
              className={`inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold transition focus:outline-none focus:ring-2 focus:ring-brand focus:ring-offset-2 focus:ring-offset-slate-900 ${
                !isEnabled || isRunning
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
              {isRunning ? 'Çalıştırılıyor...' : 'Run'}
            </button>
          </div>
        </div>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 backdrop-blur-sm">
        <div className="border-b border-slate-800 px-6 py-4">
          <h3 className="text-lg font-semibold text-white">Çalıştırma Günlüğü</h3>
          <p className="text-sm text-slate-400">Demo çıktıları anlık olarak burada görünür.</p>
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
