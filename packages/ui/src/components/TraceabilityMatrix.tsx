import type { TraceabilityMatrixRow } from '../demoData';
import { StatusBadge } from './StatusBadge';

interface TraceabilityMatrixProps {
  rows: TraceabilityMatrixRow[];
  isEnabled: boolean;
}

export function TraceabilityMatrix({ rows, isEnabled }: TraceabilityMatrixProps) {
  return (
    <div className="space-y-5">
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 shadow-xl shadow-slate-950/40 backdrop-blur">
        <div className="border-b border-slate-800 px-6 py-5">
          <h2 className="text-lg font-semibold text-white">İzlenebilirlik Matrisi</h2>
          <p className="text-sm text-slate-400">
            Gerekliliklerden tasarım artefaktlarına ve test senaryolarına kadar tam görünürlük.
          </p>
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
                  <h3 className="text-xl font-semibold text-white">{row.requirement}</h3>
                </div>
                <StatusBadge status={row.status} />
              </div>

              <div className="mt-5 grid gap-4 md:grid-cols-3">
                <section className="rounded-xl border border-slate-800/60 bg-slate-900/50 p-4">
                  <h4 className="text-xs font-semibold uppercase text-slate-400">Tasarım Artefaktları</h4>
                  <ul className="mt-3 space-y-2 text-sm text-slate-300">
                    {row.designArtifacts.map((artifact) => (
                      <li key={artifact} className="flex items-center gap-2">
                        <span className="h-2 w-2 rounded-full bg-brand/60" />
                        {artifact}
                      </li>
                    ))}
                  </ul>
                </section>

                <section className="rounded-xl border border-slate-800/60 bg-slate-900/50 p-4">
                  <h4 className="text-xs font-semibold uppercase text-slate-400">Doğrulama Testleri</h4>
                  <ul className="mt-3 space-y-3 text-sm text-slate-300">
                    {row.verificationTests.map((test) => (
                      <li key={test.id} className="flex items-start justify-between gap-3">
                        <div>
                          <div className="font-medium text-white">{test.name}</div>
                          <div className="text-xs text-slate-400">{test.id}</div>
                        </div>
                        <StatusBadge status={test.status} />
                      </li>
                    ))}
                  </ul>
                </section>

                <section className="rounded-xl border border-slate-800/60 bg-slate-900/50 p-4">
                  <h4 className="text-xs font-semibold uppercase text-slate-400">Riskler</h4>
                  <ul className="mt-3 space-y-2 text-sm text-slate-300">
                    {row.risks.map((risk) => (
                      <li key={risk} className="flex items-center gap-2">
                        <span className="h-2 w-2 rounded-full bg-rose-500/70" />
                        {risk}
                      </li>
                    ))}
                  </ul>
                </section>
              </div>
            </article>
          ))}
        </div>
      </div>
    </div>
  );
}
