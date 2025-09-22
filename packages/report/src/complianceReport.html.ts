import type { CoverageMetric, CoverageReport } from '@soipack/adapters';

const formatMetric = (metric: CoverageMetric | undefined): string => {
  if (!metric) {
    return '—';
  }
  return `${metric.covered}/${metric.total} (${metric.percentage}%)`;
};

const renderTotalsTable = (totals: CoverageReport['totals']): string => {
  const rows = [
    { label: 'Satır', metric: totals.statements },
    { label: 'Dallanma', metric: totals.branches },
    { label: 'MC/DC', metric: totals.mcdc },
  ]
    .filter((row) => row.metric !== undefined)
    .map(
      (row) => `<tr>
          <th scope="row">${row.label}</th>
          <td>${formatMetric(row.metric)}</td>
        </tr>`,
    )
    .join('');

  return `<table>
    <thead>
      <tr>
        <th scope="col">Metik</th>
        <th scope="col">Sonuç</th>
      </tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>`;
};

const renderFileRows = (files: CoverageReport['files']): string =>
  files
    .map((file) => `<tr>
        <td>
          <div class="cell-title">${file.file}</div>
        </td>
        <td>${formatMetric(file.statements)}</td>
        <td>${formatMetric(file.branches)}</td>
        <td>${formatMetric(file.mcdc)}</td>
      </tr>`)
    .join('');

export interface CoverageSummarySectionContext {
  coverage: CoverageReport;
  warnings: string[];
}

export const renderCoverageSummarySection = ({
  coverage,
  warnings,
}: CoverageSummarySectionContext): string => {
  const totalsTable = renderTotalsTable(coverage.totals);
  const fileTable = coverage.files.length
    ? `<table>
        <thead>
          <tr>
            <th scope="col">Dosya</th>
            <th scope="col">Satır</th>
            <th scope="col">Dallanma</th>
            <th scope="col">MC/DC</th>
          </tr>
        </thead>
        <tbody>${renderFileRows(coverage.files)}</tbody>
      </table>`
    : '<p class="muted">Dosya bazlı kapsam verisi bulunamadı.</p>';

  const warningsSection = warnings.length
    ? `<section class="section" aria-labelledby="coverage-warnings">
        <h3 id="coverage-warnings">Kapsam Uyarıları</h3>
        <ul class="list">
          ${warnings.map((warning) => `<li class="muted">${warning}</li>`).join('')}
        </ul>
      </section>`
    : '';

  return `<section class="section" aria-labelledby="coverage-summary">
    <h2 id="coverage-summary">Kapsam Özeti</h2>
    <p class="section-lead">
      Statement, dallanma ve MC/DC metrikleri 0.1 hassasiyetinde normalize edilmiştir.
    </p>
    ${totalsTable}
    ${fileTable}
  </section>${warningsSection}`;
};
