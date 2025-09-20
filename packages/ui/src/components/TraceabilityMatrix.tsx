import type { CoverageStatus, RequirementViewModel } from '../types/pipeline';
import { StatusBadge } from './StatusBadge';

interface TraceabilityMatrixProps {
  rows: RequirementViewModel[];
  isEnabled: boolean;
  generatedAt?: string;
}

const coverageStatusLabels: Record<CoverageStatus, string> = {
  covered: 'Karşılandı',
  partial: 'Kısmi',
  missing: 'Eksik'
};

export function TraceabilityMatrix({ rows, isEnabled, generatedAt }: TraceabilityMatrixProps) {
  return (
    <div className="space-y-5">
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 shadow-xl shadow-slate-950/40 backdrop-blur">
        <div className="border-b border-slate-800 px-6 py-5">
          <h2 className="text-lg font-semibold text-white">İzlenebilirlik Matrisi</h2>
          <p className="text-sm text-slate-400">
            Gerekliliklerden tasarım artefaktlarına ve test senaryolarına kadar tam görünürlük.
          </p>
          {generatedAt && (
            <p className="mt-2 text-xs text-slate-500">Analiz anı: {new Date(generatedAt).toLocaleString('tr-TR')}</p>
          )}
        </div>
        <div className="space-y-4 px-6 py-6">
          {rows.map((row) => (
            <article
              key={row.id}
              className={`rounded-2xl border border-slate-800/60 bg-slate-950/40 p-6 transition hover:border-brand/40 hover:bg-slate-900/80 ${
                isEnabled ? '' : 'opacity-60'
              }`}
            >
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div>
                  <div className="text-xs uppercase tracking-wide text-slate-500">{row.id}</div>
                  <h3 className="text-xl font-semibold text-white">{row.title}</h3>
                  <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-slate-500">
                    {row.requirementStatus && (
                      <span className="rounded-full bg-slate-800 px-2 py-1">Durum: {row.requirementStatus}</span>
                    )}
                    {row.tags.map((tag) => (
                      <span key={tag} className="rounded-full bg-slate-800 px-2 py-1">
                        #{tag}
                      </span>
                    ))}
                  </div>
                </div>
                <StatusBadge status={row.coverageStatus} />
              </div>

              <div className="mt-5 grid gap-4 md:grid-cols-3">
                <section className="rounded-xl border border-slate-800/60 bg-slate-900/50 p-4">
                  <h4 className="text-xs font-semibold uppercase text-slate-400">Tasarım Artefaktları</h4>
                  <ul className="mt-3 space-y-2 text-sm text-slate-300">
                    {row.code.length > 0 ? (
                      row.code.map((code) => (
                        <li key={code.path} className="flex items-center justify-between gap-2">
                          <span className="truncate" title={code.path}>
                            {code.path}
                          </span>
                          <span className="text-xs text-slate-500">
                            {code.coveragePercent !== undefined ? `%${code.coveragePercent}` : 'Ölçüm yok'}
                          </span>
                        </li>
                      ))
                    ) : (
                      <li className="italic text-slate-500">Kod referansı bulunamadı.</li>
                    )}
                  </ul>
                </section>

                <section className="rounded-xl border border-slate-800/60 bg-slate-900/50 p-4">
                  <h4 className="text-xs font-semibold uppercase text-slate-400">Doğrulama Testleri</h4>
                  <ul className="mt-3 space-y-3 text-sm text-slate-300">
                    {row.tests.length > 0 ? (
                      row.tests.map((test) => (
                        <li key={test.id} className="flex items-start justify-between gap-3">
                          <div>
                            <div className="font-medium text-white">{test.name}</div>
                            <div className="text-xs text-slate-400">{test.id}</div>
                          </div>
                          <StatusBadge status={test.status} />
                        </li>
                      ))
                    ) : (
                      <li className="italic text-slate-500">Test kanıtı bulunamadı.</li>
                    )}
                  </ul>
                </section>

                <section className="rounded-xl border border-slate-800/60 bg-slate-900/50 p-4">
                  <h4 className="text-xs font-semibold uppercase text-slate-400">Kapsam Özeti</h4>
                  <div className="mt-3 space-y-2 text-sm text-slate-300">
                    <p>
                      Gereklilik kapsam durumu{' '}
                      <span className="font-semibold text-white">{coverageStatusLabels[row.coverageStatus]}</span>
                    </p>
                    <p className="text-xs text-slate-500">
                      {row.description ?? 'Bu gereklilik için açıklama paylaşılmadı.'}
                    </p>
                  </div>
                </section>
              </div>
            </article>
          ))}
        </div>
      </div>
    </div>
  );
}
