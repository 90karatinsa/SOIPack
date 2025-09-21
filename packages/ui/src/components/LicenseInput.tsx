import { useState, type ChangeEvent } from 'react';

interface LicenseInputProps {
  license: string;
  onLicenseChange: (encodedLicense: string, source?: { name?: string; raw?: string }) => void;
  onClear: () => void;
}

const encodeLicense = (raw: string): string => {
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new Error('Lisans içeriği boş olamaz.');
  }

  let canonical: string;
  try {
    const parsed = JSON.parse(trimmed);
    canonical = JSON.stringify(parsed);
  } catch {
    throw new Error('Geçerli bir JSON lisans dosyası gereklidir.');
  }

  if (typeof Buffer !== 'undefined') {
    return Buffer.from(canonical, 'utf-8').toString('base64').replace(/\s+/g, '').trim();
  }

  if (typeof window !== 'undefined') {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(canonical);
    let binary = '';
    bytes.forEach((byte) => {
      binary += String.fromCharCode(byte);
    });
    return window.btoa(binary).replace(/\s+/g, '').trim();
  }

  throw new Error('Lisans base64 kodlanamadı.');
};

export function LicenseInput({ license, onLicenseChange, onClear }: LicenseInputProps) {
  const [error, setError] = useState<string | null>(null);
  const [sourceLabel, setSourceLabel] = useState<string>('');
  const [rawValue, setRawValue] = useState<string>('');

  const handleFileChange = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.currentTarget.files?.[0];
    event.currentTarget.value = '';
    if (!file) {
      return;
    }

    try {
      const text = await file.text();
      const encoded = encodeLicense(text);
      onLicenseChange(encoded, { name: file.name, raw: text });
      setSourceLabel(file.name);
      setRawValue(JSON.stringify(JSON.parse(text), null, 2));
      setError(null);
    } catch (caught) {
      const failure = caught as Error;
      setError(failure.message);
    }
  };

  const handleTextareaChange = (event: ChangeEvent<HTMLTextAreaElement>) => {
    const value = event.currentTarget.value;
    setRawValue(value);
    if (!value.trim()) {
      setError('Lisans içeriği boş olamaz.');
      return;
    }
    try {
      const encoded = encodeLicense(value);
      onLicenseChange(encoded, { raw: value });
      setSourceLabel('Panodan yapıştırıldı');
      setError(null);
    } catch (caught) {
      const failure = caught as Error;
      setError(failure.message);
    }
  };

  const handleClear = () => {
    setRawValue('');
    setSourceLabel('');
    setError(null);
    onClear();
  };

  const isActive = Boolean(license.trim());

  return (
    <div className="flex w-full flex-col gap-3 rounded-2xl border border-slate-800 bg-slate-900/60 p-6 text-sm text-slate-200 shadow-lg shadow-slate-950/40 backdrop-blur">
      <div className="flex items-center justify-between">
        <label className="text-xs font-semibold uppercase tracking-wide text-slate-400">
          Lisans Anahtarı
        </label>
        {isActive && (
          <button
            type="button"
            onClick={handleClear}
            className="text-xs font-semibold text-brand transition hover:text-brand-light"
          >
            Lisansı temizle
          </button>
        )}
      </div>
      <div className="flex flex-col gap-3 md:flex-row md:items-start">
        <div className="flex-1 space-y-3">
          <label className="flex cursor-pointer flex-col gap-2 rounded-xl border border-dashed border-slate-700/80 bg-slate-950/40 p-4 text-xs text-slate-300 transition hover:border-brand hover:bg-slate-900/70">
            <span className="font-semibold text-white">JSON lisans dosyası seçin</span>
            <span className="text-slate-400">.key veya .json uzantılı dosyalar desteklenir.</span>
            <input
              type="file"
              accept=".json,.key,application/json"
              className="hidden"
              onChange={handleFileChange}
              aria-label="Lisans dosyası seçin"
            />
          </label>
          <div className="space-y-2">
            <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">JSON içeriğini yapıştırın</span>
            <textarea
              value={rawValue}
              onChange={handleTextareaChange}
              placeholder='{"tenant":"demo","expiresAt":"2024-12-31"}'
              className="h-28 w-full rounded-xl border border-slate-800 bg-slate-950/70 px-4 py-3 font-mono text-xs text-slate-100 shadow-inner shadow-slate-950/50 outline-none transition focus:border-brand focus:ring-2 focus:ring-brand/60"
            />
          </div>
        </div>
        <div className="flex w-full max-w-xs flex-col gap-2 rounded-xl border border-slate-800/80 bg-slate-950/60 p-4 text-xs text-slate-400">
          <div>
            <span className="font-semibold text-white">Durum:</span>{' '}
            {isActive ? 'Yüklendi' : 'Lisans gereklidir'}
          </div>
          {isActive && sourceLabel && (
            <div className="truncate text-ellipsis" title={sourceLabel}>
              Kaynak: {sourceLabel}
            </div>
          )}
          {error && <div className="rounded-lg border border-rose-700/50 bg-rose-950/40 px-3 py-2 text-rose-200">{error}</div>}
        </div>
      </div>
    </div>
  );
}

export { encodeLicense };
