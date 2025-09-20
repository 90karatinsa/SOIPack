import type { CoverageStatus } from '../types/pipeline';

const styles: Record<CoverageStatus, string> = {
  covered:
    'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 shadow-sm shadow-emerald-500/10',
  partial:
    'bg-amber-500/10 text-amber-300 border border-amber-500/30 shadow-sm shadow-amber-500/10',
  missing:
    'bg-rose-500/10 text-rose-300 border border-rose-500/30 shadow-sm shadow-rose-500/10'
};

const labels: Record<CoverageStatus, string> = {
  covered: 'Karşılandı',
  partial: 'Kısmi',
  missing: 'Eksik'
};

interface StatusBadgeProps {
  status: CoverageStatus;
}

export function StatusBadge({ status }: StatusBadgeProps) {
  return (
    <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold tracking-wide uppercase ${styles[status]}`}>
      {labels[status]}
    </span>
  );
}
