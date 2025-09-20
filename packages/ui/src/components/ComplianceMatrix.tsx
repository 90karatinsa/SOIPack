import type { CoverageStatus, ComplianceMatrixRow } from '../demoData';
import { StatusBadge } from './StatusBadge';

interface ComplianceSummary {
  totalRequirements: number;
  covered: number;
  partial: number;
  missing: number;
}

interface ComplianceMatrixProps {
  rows: ComplianceMatrixRow[];
  activeStatuses: CoverageStatus[];
  onToggleStatus: (status: CoverageStatus) => void;
  summary: ComplianceSummary;
  isEnabled: boolean;
}

const filterLabels: Record<CoverageStatus, string> = {
  covered: 'Karşılandı',
  partial: 'Kısmi',
  missing: 'Eksik'
};

const statusAccent: Record<CoverageStatus, string> = {
  covered: 'bg-emerald-500/10 text-emerald-200 ring-emerald-500/30',
  partial: 'bg-amber-500/10 text-amber-200 ring-amber-500/40',
  missing: 'bg-rose-500/10 text-rose-200 ring-rose-500/40'
};

export function ComplianceMatrix({
  rows,
  activeStatuses,
  onToggleStatus,
  summary,
  isEnabled
}: ComplianceMatrixProps) {
  const filteredRows = rows.filter((row) => activeStatuses.includes(row.status));

  return (
    <div className="space-y-6">
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 shadow-xl shadow-slate-950/40 backdrop-blur">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 px-6 py-5">
          <div>
            <h2 className="text-lg font-semibold text-white">Uyum Matrisi</h2>
            <p className="text-sm text-slate-400">
              Gerekliliklerin durumlarını filtreleyerek eksik alanları kolayca tespit edin.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            {(Object.keys(filterLabels) as CoverageStatus[]).map((status) => {
              const isActive = activeStatuses.includes(status);
              return (
                <button
                  key={status}
                  type="button"
                  onClick={() => onToggleStatus(status)}
                  className={`inline-flex items-center gap-2 rounded-full px-3 py-1 text-sm font-medium transition focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-slate-900 ${
                    isActive
                      ? `${statusAccent[status]} focus:ring-brand`
                      : 'bg-slate-800/80 text-slate-300 hover:bg-slate-800 focus:ring-brand/40'
                  } ${isEnabled ? '' : 'cursor-not-allowed opacity-50'}`}
                  disabled={!isEnabled}
                >
                  <span
                    className={`h-2 w-2 rounded-full ${
                      status === 'covered'
                        ? 'bg-emerald-400'
                        : status === 'partial'
                        ? 'bg-amber-400'
                        : 'bg-rose-400'
                    }`}
                  />
                  {filterLabels[status]}
                </button>
              );
            })}
          </div>
        </div>

        <div className="grid gap-4 px-6 py-4 text-sm text-slate-300 md:grid-cols-4">
          <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-4">
            <p className="text-xs uppercase text-slate-500">Toplam gereklilik</p>
            <p className="mt-1 text-2xl font-semibold text-white">{summary.totalRequirements}</p>
          </div>
          <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4">
            <p className="text-xs uppercase text-emerald-300/70">Karşılandı</p>
            <p className="mt-1 text-2xl font-semibold text-emerald-200">{summary.covered}</p>
          </div>
          <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4">
            <p className="text-xs uppercase text-amber-300/70">Kısmi</p>
            <p className="mt-1 text-2xl font-semibold text-amber-200">{summary.partial}</p>
          </div>
          <div className="rounded-xl border border-rose-500/20 bg-rose-500/5 p-4">
            <p className="text-xs uppercase text-rose-300/70">Eksik</p>
            <p className="mt-1 text-2xl font-semibold text-rose-200">{summary.missing}</p>
          </div>
        </div>

        <div className="overflow-hidden">
          <table className="min-w-full divide-y divide-slate-800 text-left text-sm text-slate-200">
            <thead className="bg-slate-900/80 text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th scope="col" className="px-6 py-3 font-medium">
                  Gereklilik
                </th>
                <th scope="col" className="px-6 py-3 font-medium">
                  Açıklama
                </th>
                <th scope="col" className="px-6 py-3 font-medium">
                  Sorumlu Ekip
                </th>
                <th scope="col" className="px-6 py-3 font-medium">
                  Durum
                </th>
                <th scope="col" className="px-6 py-3 font-medium">
                  Kapsama
                </th>
                <th scope="col" className="px-6 py-3 font-medium">
                  Testler
                </th>
                <th scope="col" className="px-6 py-3 font-medium">
                  Güncelleme
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 bg-slate-900/40">
              {filteredRows.map((row) => (
                <tr key={row.id} className="transition hover:bg-slate-900/60">
                  <td className="px-6 py-4">
                    <div className="font-semibold text-white">{row.id}</div>
                    <div className="text-xs text-slate-400">{row.requirement}</div>
                  </td>
                  <td className="max-w-xs px-6 py-4 text-slate-300">
                    <p className="text-sm leading-relaxed">{row.description}</p>
                  </td>
                  <td className="px-6 py-4 text-sm text-slate-300">{row.owner}</td>
                  <td className="px-6 py-4">
                    <StatusBadge status={row.status} />
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <div className="h-2 w-24 rounded-full bg-slate-800">
                        <div
                          className={`h-2 rounded-full ${
                            row.status === 'covered'
                              ? 'bg-emerald-400'
                              : row.status === 'partial'
                              ? 'bg-amber-400'
                              : 'bg-rose-400'
                          }`}
                          style={{ width: `${row.coverage}%` }}
                        />
                      </div>
                      <span className="text-xs text-slate-400">%{row.coverage}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4 text-xs text-slate-300">
                    {row.linkedTests.length > 0 ? (
                      <div className="flex flex-wrap gap-2">
                        {row.linkedTests.map((test) => (
                          <span
                            key={test}
                            className="rounded-full bg-slate-800 px-2 py-1 font-mono text-[11px] text-slate-300"
                          >
                            {test}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="italic text-slate-500">Bağlı test yok</span>
                    )}
                  </td>
                  <td className="px-6 py-4 text-xs text-slate-400">
                    {new Date(row.lastUpdated).toLocaleDateString('tr-TR', {
                      day: '2-digit',
                      month: '2-digit',
                      year: 'numeric',
                      hour: '2-digit',
                      minute: '2-digit'
                    })}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {filteredRows.length === 0 && (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-10 text-center text-slate-400">
          Seçilen filtrelere uygun kayıt bulunamadı.
        </div>
      )}
    </div>
  );
}
