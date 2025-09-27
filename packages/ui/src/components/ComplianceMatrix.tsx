import type {
  CoverageStatus,
  RequirementViewModel,
  StageIdentifier,
  StageObjectiveView,
} from '../types/pipeline';

import { StatusBadge } from './StatusBadge';

interface ComplianceMatrixProps {
  rows: RequirementViewModel[];
  activeStatuses: CoverageStatus[];
  onToggleStatus: (status: CoverageStatus) => void;
  summary: {
    total: number;
    covered: number;
    partial: number;
    missing: number;
  };
  isEnabled: boolean;
  generatedAt?: string;
  version?: string;
  stages: StageObjectiveView[];
  activeStageId: StageIdentifier;
  onStageChange: (stage: StageIdentifier) => void;
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

const stageButtonBase =
  'flex min-w-[160px] flex-col rounded-xl border px-4 py-3 text-left text-sm transition focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-slate-900';
const stageButtonActive =
  'border-blue-500/60 bg-blue-500/10 text-blue-100 shadow-[0_10px_30px_rgba(59,130,246,0.25)] focus:ring-blue-400';
const stageButtonInactive =
  'border-slate-800 bg-slate-900/80 text-slate-300 hover:border-slate-700 hover:bg-slate-900 focus:ring-blue-400/60';

export function ComplianceMatrix({
  rows,
  activeStatuses,
  onToggleStatus,
  summary,
  isEnabled,
  generatedAt,
  version,
  stages,
  activeStageId,
  onStageChange,
}: ComplianceMatrixProps) {
  const filteredRows = rows.filter((row) => activeStatuses.includes(row.coverageStatus));
  const activeStage = stages.find((stage) => stage.id === activeStageId) ?? stages[0];
  const stageObjectives = activeStage?.objectives ?? [];

  return (
    <div className="space-y-6">
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 shadow-xl shadow-slate-950/40 backdrop-blur">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 px-6 py-5">
          <div>
            <h2 className="text-lg font-semibold text-white">Uyum Matrisi</h2>
            <p className="text-sm text-slate-400">
              Gerekliliklerin kapsam durumlarını filtreleyerek eksik alanları kolayca tespit edin.
            </p>
            {(generatedAt || version) && (
              <p className="mt-2 text-xs text-slate-500">
                {generatedAt && `Analiz: ${new Date(generatedAt).toLocaleString('tr-TR')}`}
                {generatedAt && version ? ' · ' : ''}
                {version && `Rapor sürümü: ${version}`}
              </p>
            )}
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
            <p className="mt-1 text-2xl font-semibold text-white">{summary.total}</p>
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

        {stages.length > 0 && (
          <div className="border-t border-slate-800 px-6 py-6">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
              <div className="space-y-1">
                <h3 className="text-base font-semibold text-white">SOI Aşamaları</h3>
                <p className="text-sm text-slate-400">
                  Hedef uyumluluğunu aşama bazında inceleyin. Seçilen aşama rapor çıktılarıyla eşleşir.
                </p>
              </div>
              <div className="flex flex-wrap gap-3">
                {stages.map((stage) => {
                  const isActiveStage = stage.id === activeStage?.id;
                  return (
                    <button
                      key={stage.id}
                      type="button"
                      onClick={() => onStageChange(stage.id)}
                      className={`${stageButtonBase} ${
                        isActiveStage ? stageButtonActive : stageButtonInactive
                      } ${isEnabled ? '' : 'cursor-not-allowed opacity-50'}`}
                      disabled={!isEnabled}
                    >
                      <span className="text-sm font-semibold">{stage.label}</span>
                      <span className="text-xs text-slate-400">
                        {stage.summary.covered}/{stage.summary.total} hedef tamamlandı
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>

            {activeStage && (
              <div className="mt-5 flex flex-col gap-2 text-xs text-slate-400 sm:flex-row sm:items-center sm:justify-between">
                <span className="text-sm font-semibold text-white">{activeStage.label}</span>
                <div className="flex flex-wrap gap-3">
                  <span className="rounded-full bg-slate-800 px-3 py-1 text-xs text-slate-300">
                    Toplam {activeStage.summary.total}
                  </span>
                  <span className="rounded-full bg-emerald-500/10 px-3 py-1 text-xs text-emerald-200">
                    {activeStage.summary.covered} karşılandı
                  </span>
                  <span className="rounded-full bg-amber-500/10 px-3 py-1 text-xs text-amber-200">
                    {activeStage.summary.partial} kısmi
                  </span>
                  <span className="rounded-full bg-rose-500/10 px-3 py-1 text-xs text-rose-200">
                    {activeStage.summary.missing} eksik
                  </span>
                </div>
              </div>
            )}

            <div className="mt-5 overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60">
              {stageObjectives.length > 0 ? (
                <table className="min-w-full divide-y divide-slate-800 text-left text-sm text-slate-200">
                  <thead className="bg-slate-900/80 text-xs uppercase tracking-wide text-slate-400">
                    <tr>
                      <th className="px-5 py-3 font-medium">Hedef</th>
                      <th className="px-5 py-3 font-medium">Durum</th>
                      <th className="px-5 py-3 font-medium">Sağlanan Kanıtlar</th>
                      <th className="px-5 py-3 font-medium">Eksik Kanıtlar</th>
                      <th className="px-5 py-3 font-medium">Referanslar</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {stageObjectives.map((objective) => (
                      <tr key={objective.id} className="bg-slate-900/40 transition hover:bg-slate-900/60">
                        <td className="px-5 py-4">
                          <div className="font-semibold text-white">{objective.id}</div>
                          {(objective.table || objective.name) && (
                            <div className="text-xs text-slate-400">
                              {objective.table}
                              {objective.table && objective.name ? ' • ' : ''}
                              {objective.name}
                            </div>
                          )}
                          {objective.description && (
                            <div className="mt-2 text-xs text-slate-400">{objective.description}</div>
                          )}
                        </td>
                        <td className="px-5 py-4">
                          <StatusBadge status={objective.status} />
                        </td>
                        <td className="px-5 py-4">
                          {objective.satisfiedArtifacts.length ? (
                            <div className="flex flex-wrap gap-2">
                              {objective.satisfiedArtifacts.map((artifact) => (
                                <span
                                  key={artifact}
                                  className="rounded-full bg-emerald-500/10 px-2 py-1 text-xs text-emerald-200"
                                >
                                  {artifact}
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span className="text-xs text-slate-500">Kanıt bulunmuyor</span>
                          )}
                        </td>
                        <td className="px-5 py-4">
                          {objective.missingArtifacts.length ? (
                            <div className="flex flex-wrap gap-2">
                              {objective.missingArtifacts.map((artifact) => (
                                <span
                                  key={artifact}
                                  className="rounded-full bg-rose-500/10 px-2 py-1 text-xs text-rose-200"
                                >
                                  {artifact}
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span className="text-xs text-slate-500">Eksik kanıt yok</span>
                          )}
                        </td>
                        <td className="px-5 py-4">
                          {objective.evidenceRefs.length ? (
                            <ul className="space-y-1 text-xs text-slate-400">
                              {objective.evidenceRefs.map((reference) => (
                                <li key={reference}>{reference}</li>
                              ))}
                            </ul>
                          ) : (
                            <span className="text-xs text-slate-500">Referans yok</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="px-6 py-6 text-sm text-slate-400">Bu aşamada hedef verisi bulunmuyor.</div>
              )}
            </div>
          </div>
        )}

        <div className="overflow-hidden">
          <table className="min-w-full divide-y divide-slate-800 text-left text-sm text-slate-200">
            <thead className="bg-slate-900/80 text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th scope="col" className="px-6 py-3 font-medium">
                  Gereklilik
                </th>
                <th scope="col" className="px-6 py-3 font-medium">
                  Detaylar
                </th>
                <th scope="col" className="px-6 py-3 font-medium">
                  Durum
                </th>
                <th scope="col" className="px-6 py-3 font-medium">
                  Kapsama
                </th>
                <th scope="col" className="px-6 py-3 font-medium">
                  Kod Yolları
                </th>
                <th scope="col" className="px-6 py-3 font-medium">
                  Testler
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 bg-slate-900/40">
              {filteredRows.map((row) => (
                <tr key={row.id} className="transition hover:bg-slate-900/60">
                  <td className="px-6 py-4">
                    <div className="font-semibold text-white">{row.id}</div>
                    <div className="text-xs text-slate-400">{row.title}</div>
                  </td>
                  <td className="max-w-xs px-6 py-4 text-slate-300">
                    {row.description ? (
                      <p className="text-sm leading-relaxed">{row.description}</p>
                    ) : (
                      <p className="text-sm italic text-slate-500">Açıklama belirtilmedi.</p>
                    )}
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
                  </td>
                  <td className="px-6 py-4">
                    <StatusBadge status={row.coverageStatus} />
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <div className="h-2 w-24 rounded-full bg-slate-800">
                        <div
                          className={`h-2 rounded-full ${
                            row.coverageStatus === 'covered'
                              ? 'bg-emerald-400'
                              : row.coverageStatus === 'partial'
                              ? 'bg-amber-400'
                              : 'bg-rose-400'
                          }`}
                          style={{ width: `${Math.min(row.coveragePercent ?? 0, 100)}%` }}
                        />
                      </div>
                      <span className="text-xs text-slate-400">
                        {row.coveragePercent !== undefined ? `%${row.coveragePercent}` : 'Veri yok'}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4 text-xs text-slate-300">
                    {row.code.length > 0 ? (
                      <div className="flex flex-col gap-2">
                        {row.code.map((entry) => (
                          <div key={entry.path} className="flex items-center justify-between gap-3">
                            <span className="truncate text-sm text-slate-200" title={entry.path}>
                              {entry.path}
                            </span>
                            <span className="text-xs text-slate-500">
                              {entry.coveragePercent !== undefined
                                ? `%${entry.coveragePercent}`
                                : 'Ölçüm yok'}
                            </span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <span className="italic text-slate-500">Kod referansı yok</span>
                    )}
                  </td>
                  <td className="px-6 py-4 text-xs text-slate-300">
                    {row.tests.length > 0 ? (
                      <div className="flex flex-col gap-2">
                        {row.tests.map((test) => (
                          <div key={test.id} className="flex items-center justify-between gap-3">
                            <div>
                              <div className="text-sm text-slate-200">{test.name}</div>
                              <div className="text-[11px] text-slate-500">{test.id}</div>
                            </div>
                            <StatusBadge status={test.status} />
                          </div>
                        ))}
                      </div>
                    ) : (
                      <span className="italic text-slate-500">Bağlı test yok</span>
                    )}
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
