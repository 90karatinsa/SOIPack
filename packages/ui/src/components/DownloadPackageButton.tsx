interface DownloadPackageButtonProps {
  onDownload: () => Promise<void> | void;
  disabled: boolean;
  isBusy: boolean;
}

export function DownloadPackageButton({ onDownload, disabled, isBusy }: DownloadPackageButtonProps) {
  return (
    <button
      type="button"
      onClick={onDownload}
      disabled={disabled || isBusy}
      className={`inline-flex items-center gap-2 rounded-xl border border-brand/50 bg-brand px-4 py-2 text-sm font-semibold text-white shadow-lg shadow-brand/20 transition hover:bg-brand-light focus:outline-none focus:ring-2 focus:ring-brand focus:ring-offset-2 focus:ring-offset-slate-900 ${
        disabled || isBusy ? 'cursor-not-allowed opacity-60' : ''
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
          d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M7.5 12l4.5 4.5m0 0l4.5-4.5m-4.5 4.5V3"
        />
      </svg>
      {isBusy ? 'Paket Hazırlanıyor...' : 'Paket indir'}
    </button>
  );
}
