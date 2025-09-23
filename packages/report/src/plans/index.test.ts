import { createReportFixture } from '../__fixtures__/snapshot';

import { renderPlanDocument, renderPlanPdf, planTemplateSections } from './index';

describe('plan templates', () => {
  const fixture = createReportFixture();
  const baseOptions = {
    snapshot: fixture.snapshot,
    objectivesMetadata: fixture.objectives,
    manifestId: fixture.manifestId,
    project: { name: 'Demo Avionics', version: '1.0.0' },
    level: 'C' as const,
    generatedAt: fixture.snapshot.generatedAt,
  };

  it('renders PSAC template with objective metrics and project metadata', async () => {
    const result = await renderPlanDocument('psac', baseOptions);

    expect(result.title).toContain('PSAC');
    expect(result.html).toContain('Demo Avionics');
    expect(result.html).toContain('Objective coverage stands');
    expect(result.html).not.toContain('{{');
    expect(result.sections).toHaveProperty('introduction');
    expect(result.coverageSummary.coveredCount).toBe(fixture.snapshot.stats.objectives.covered);
    expect(result.docx.subarray(0, 2).toString('ascii')).toBe('PK');
  });

  it('applies section overrides to SVP content', async () => {
    const customSection = '<p>Custom verification cadence.</p>';
    const result = await renderPlanDocument('svp', {
      ...baseOptions,
      sections: { testingStrategy: customSection },
    });

    expect(planTemplateSections.svp).toContain('testingStrategy');
    expect(result.sections.testingStrategy).toBe(customSection);
    expect(result.html).toContain('Custom verification cadence');
  });

  it('renders plan PDF output with pdfmake', async () => {
    const pdfBuffer = await renderPlanPdf('scmp', baseOptions);
    expect(pdfBuffer.subarray(0, 4).toString('ascii')).toBe('%PDF');
  });
});
