import { promises as fs } from 'node:fs';
import path from 'node:path';

import { renderComplianceMatrix, renderGaps, renderTraceMatrix, printToPDF } from './index';
import { createReportFixture } from './__fixtures__/snapshot';

const main = async (): Promise<void> => {
  const fixture = createReportFixture();
  const outputDir = path.resolve(__dirname, '..', 'dist', 'reports');
  await fs.mkdir(outputDir, { recursive: true });

  const compliance = renderComplianceMatrix(fixture.snapshot, {
    manifestId: fixture.manifestId,
    objectivesMetadata: fixture.objectives,
    title: 'SOIPack Kurumsal Uyum Matrisi',
  });

  await fs.writeFile(path.join(outputDir, 'compliance-matrix.html'), compliance.html, 'utf-8');
  await fs.writeFile(
    path.join(outputDir, 'compliance-matrix.json'),
    JSON.stringify(compliance.json, null, 2),
    'utf-8',
  );

  const traceHtml = renderTraceMatrix(fixture.traces, {
    manifestId: fixture.manifestId,
    title: 'SOIPack İzlenebilirlik Matrisi',
    coverage: fixture.snapshot.requirementCoverage,
  });
  await fs.writeFile(path.join(outputDir, 'trace-matrix.html'), traceHtml, 'utf-8');

  const gapsHtml = renderGaps(fixture.snapshot, {
    manifestId: fixture.manifestId,
    objectivesMetadata: fixture.objectives,
    title: 'SOIPack Uyum Boşlukları',
  });
  await fs.writeFile(path.join(outputDir, 'gaps.html'), gapsHtml, 'utf-8');

  const pdfBuffer = await printToPDF(compliance.html, {
    manifestId: fixture.manifestId,
    generatedAt: fixture.snapshot.generatedAt,
  });
  await fs.writeFile(path.join(outputDir, 'compliance-matrix.pdf'), pdfBuffer);

  // eslint-disable-next-line no-console
  console.log(`Reports generated at ${outputDir}`);
};

main().catch((error) => {
  // eslint-disable-next-line no-console
  console.error('Failed to generate demo reports:', error);
  process.exitCode = 1;
});
