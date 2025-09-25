import type { CoverageMetric, CoverageReport } from '@soipack/adapters';

const escapeHtml = (value: string): string =>
  value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

const formatDateTime = (value?: string): string => {
  if (!value) {
    return '—';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return escapeHtml(value);
  }
  const [isoDate, isoTime] = date.toISOString().split('T');
  return `${isoDate} ${isoTime.slice(0, 5)} UTC`;
};

const formatFileSize = (size?: number): string => {
  if (typeof size !== 'number' || !Number.isFinite(size) || size <= 0) {
    return '—';
  }
  const kiloBytes = size / 1024;
  if (kiloBytes >= 1024) {
    return `${(kiloBytes / 1024).toFixed(1)} MB`;
  }
  return `${kiloBytes.toFixed(1)} KB`;
};

const renderLink = (label: string, url?: string): string => {
  if (!url) {
    return escapeHtml(label);
  }
  return `<a href="${escapeHtml(url)}" target="_blank" rel="noreferrer">${escapeHtml(label)}</a>`;
};

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

export interface ChangeRequestBacklogItem {
  key: string;
  summary: string;
  status: string;
  statusCategory?: string;
  assignee?: string | null;
  updatedAt?: string;
  priority?: string | null;
  url?: string;
  transitions?: Array<{ id: string; name: string; toStatus: string; category?: string }>;
  attachments?: Array<{ id: string; filename: string; url?: string; size?: number; createdAt?: string }>;
}

export interface ChangeRequestBacklogSectionContext {
  items: ChangeRequestBacklogItem[];
}

const renderTransitionSummary = (
  transitions: ChangeRequestBacklogItem['transitions'],
): string => {
  if (!transitions || transitions.length === 0) {
    return '';
  }
  const summary = transitions
    .map((transition) => `${escapeHtml(transition.name)} → ${escapeHtml(transition.toStatus)}`)
    .join(', ');
  return `<div class="cell-description"><strong>Geçişler:</strong> ${summary}</div>`;
};

const renderAttachmentSummary = (
  attachments: ChangeRequestBacklogItem['attachments'],
): string => {
  if (!attachments || attachments.length === 0) {
    return '';
  }
  const summary = attachments
    .map((attachment) => {
      const sizeLabel = attachment.size ? ` (${formatFileSize(attachment.size)})` : '';
      return renderLink(`${attachment.filename}${sizeLabel}`, attachment.url);
    })
    .join('<br />');
  return `<div class="cell-description"><strong>Ekler:</strong> ${summary}</div>`;
};

export const renderChangeRequestBacklogSection = ({
  items,
}: ChangeRequestBacklogSectionContext): string => {
  if (!items || items.length === 0) {
    return '';
  }

  const rows = items
    .map((item) => {
      const keyCell = renderLink(item.key, item.url);
      const statusLabel = item.statusCategory
        ? `${escapeHtml(item.status)} <span class="muted">(${escapeHtml(item.statusCategory)})</span>`
        : escapeHtml(item.status);
      const assignee = item.assignee ? escapeHtml(item.assignee) : '<span class="muted">Atanmamış</span>';
      const priority = item.priority ? escapeHtml(item.priority) : '—';
      const updatedAt = formatDateTime(item.updatedAt);

      return `<tr>
          <th scope="row">${keyCell}</th>
          <td>
            <div class="cell-title">${escapeHtml(item.summary)}</div>
            ${renderTransitionSummary(item.transitions)}
            ${renderAttachmentSummary(item.attachments)}
          </td>
          <td>${statusLabel}</td>
          <td>${assignee}</td>
          <td>${priority}</td>
          <td>${updatedAt}</td>
        </tr>`;
    })
    .join('');

  return `<section class="section" aria-labelledby="change-request-backlog">
    <h2 id="change-request-backlog">Değişiklik Talepleri Birikimi</h2>
    <p class="section-lead">
      DO-178C uyumluluğu için takip edilen değişiklik taleplerinin durumunu gösterir.
    </p>
    <table>
      <thead>
        <tr>
          <th scope="col">Talep</th>
          <th scope="col">Özet</th>
          <th scope="col">Durum</th>
          <th scope="col">Atanan</th>
          <th scope="col">Öncelik</th>
          <th scope="col">Güncellendi</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  </section>`;
};

export interface LedgerAttestationDiffItem {
  snapshotId: string;
  ledgerRoot: string;
  attestedAt: string;
  manifestDigest?: string;
  previousLedgerRoot?: string | null;
  addedEvidence?: string[];
  removedEvidence?: string[];
}

export interface LedgerAttestationDiffSectionContext {
  diffs: LedgerAttestationDiffItem[];
}

const formatEvidenceList = (values?: string[]): string => {
  if (!values || values.length === 0) {
    return '<span class="muted">Yok</span>';
  }
  return values.map((value) => `<span class="badge badge-soft">${escapeHtml(value)}</span>`).join(' ');
};

export const renderLedgerDiffSection = ({ diffs }: LedgerAttestationDiffSectionContext): string => {
  if (!diffs || diffs.length === 0) {
    return '';
  }

  const rows = diffs
    .map((diff) => {
      const manifestLine = diff.manifestDigest
        ? `<div class="muted">Manifest: ${escapeHtml(diff.manifestDigest)}</div>`
        : '';
      const previousLine = diff.previousLedgerRoot
        ? `<div class="muted">Önceki kök: ${escapeHtml(diff.previousLedgerRoot)}</div>`
        : '';

      return `<tr>
          <th scope="row">${escapeHtml(diff.snapshotId)}</th>
          <td>
            <div class="cell-title">${escapeHtml(diff.ledgerRoot)}</div>
            ${manifestLine}
            ${previousLine}
          </td>
          <td>${formatDateTime(diff.attestedAt)}</td>
          <td>
            <div class="cell-description"><strong>Eklenen:</strong> ${formatEvidenceList(diff.addedEvidence)}</div>
            <div class="cell-description"><strong>Çıkarılan:</strong> ${formatEvidenceList(diff.removedEvidence)}</div>
          </td>
        </tr>`;
    })
    .join('');

  return `<section class="section" aria-labelledby="ledger-attestations">
    <h2 id="ledger-attestations">Ledger Attestasyon Özeti</h2>
    <p class="section-lead">
      Kanıt defteri mutabakatı sırasında eklenen ve kaldırılan kanıt girişlerini gösterir.
    </p>
    <table>
      <thead>
        <tr>
          <th scope="col">Snapshot</th>
          <th scope="col">Ledger Kökü</th>
          <th scope="col">Attestasyon</th>
          <th scope="col">Değişiklikler</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  </section>`;
};
