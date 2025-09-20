import type { ChangeEvent } from 'react';

interface TokenInputProps {
  token: string;
  onTokenChange: (token: string) => void;
  onClear: () => void;
}

export function TokenInput({ token, onTokenChange, onClear }: TokenInputProps) {
  const handleChange = (event: ChangeEvent<HTMLInputElement>) => {
    onTokenChange(event.currentTarget.value);
  };

  return (
    <div className="flex w-full flex-col gap-3 rounded-2xl border border-slate-800 bg-slate-900/60 p-6 text-sm text-slate-200 shadow-lg shadow-slate-950/40 backdrop-blur">
      <label className="text-xs font-semibold uppercase tracking-wide text-slate-400">
        REST Token
      </label>
      <div className="flex flex-col gap-3 md:flex-row md:items-center">
        <div className="relative flex-1">
          <input
            type="password"
            value={token}
            onChange={handleChange}
            placeholder="Token girilmeden demo kilitli kalır"
            className="w-full rounded-xl border border-slate-800 bg-slate-950/70 px-4 py-3 font-mono text-sm text-slate-100 shadow-inner shadow-slate-950/50 outline-none transition focus:border-brand focus:ring-2 focus:ring-brand/60"
          />
          {token && (
            <button
              type="button"
              onClick={onClear}
              className="absolute inset-y-0 right-0 flex items-center px-4 text-slate-400 transition hover:text-white"
            >
              Temizle
            </button>
          )}
        </div>
        <div className="rounded-xl border border-slate-800/80 bg-slate-950/60 px-4 py-2 text-xs text-slate-400">
          <span className="font-semibold text-white">Durum:</span>{' '}
          {token ? 'Aktif' : 'Kilidi Açmak İçin Token Gerekli'}
        </div>
      </div>
    </div>
  );
}
