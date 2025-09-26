import { createHash } from 'node:crypto';

import JSZip from 'jszip';

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

  it('renders DO-330 tool assessment with signature tables and checksums', async () => {
    const toolAssessment = {
      summary: 'VectorCAST ve Jama araçları TQL-4 gereksinimlerini sağlamak üzere doğrulandı.',
      qualificationArguments: [
        'Regression paketi her sürümde referans sonuçlarla kıyaslanıyor.',
        'Araç güncellemeleri kalite panelinde bağımsız olarak onaylanıyor.',
      ],
      environmentNotes: ['CI Runner Ubuntu 22.04', 'VectorCAST 2023R1'],
      tools: [
        {
          id: 'vectorcast',
          name: 'VectorCAST',
          version: '2023R1',
          vendor: 'Vector Informatik',
          toolClass: 'TQL-4',
          usage: 'Yapısal kapsam konsolidasyonu',
          qualificationSummary: 'Sürüm 5.2 referans veri setiyle kıyaslandı',
          evidence: ['reports/vectorcast-validation.pdf'],
          status: 'Approved',
        },
        {
          id: 'jama-adapter',
          name: 'Jama Adapter',
          version: '1.2.0',
          vendor: 'SOIPack',
          toolClass: 'TQL-5',
          usage: 'Gereksinim içe aktarma ve izleme',
          qualificationSummary: 'API sandbox veri setiyle doğrulandı',
          evidence: ['reports/jama-validation.md'],
          status: 'In Review',
        },
      ],
      signatures: [
        {
          role: 'Lead Compliance Manager',
          name: 'A. Inspector',
          organization: 'Safety Org',
          date: '2024-05-01',
        },
        {
          role: 'DER',
          name: 'B. Reviewer',
          organization: 'ODA',
          date: '2024-05-02',
        },
      ],
    };

    const plan = await renderPlanDocument('do330-ta', {
      ...baseOptions,
      toolAssessment,
    });

    expect(plan.sections).toHaveProperty('qualificationStrategy');
    expect(plan.sections).toHaveProperty('signatures');
    expect(plan.html).toContain('Tool Assessment Summary');
    expect(plan.html).toContain('Lead Compliance Manager');

    const pdfBuffer = await renderPlanPdf('do330-ta', {
      ...baseOptions,
      toolAssessment,
    });

    const docxSha = createHash('sha256').update(plan.docx).digest('hex');
    const pdfSha = createHash('sha256').update(pdfBuffer).digest('hex');
    expect(docxSha).toHaveLength(64);
    expect(pdfSha).toHaveLength(64);
    expect(docxSha).not.toBe(pdfSha);

    const zip = await JSZip.loadAsync(plan.docx);
    const documentXml = await zip.file('word/document.xml')?.async('string');
    expect(documentXml).toContain('Tool Assessment Signatures');
    expect(documentXml).toContain('Lead Compliance Manager');

    const pdfText = pdfBuffer.toString('latin1');
    expect(pdfText.length).toBeGreaterThan(1000);
  });
});
