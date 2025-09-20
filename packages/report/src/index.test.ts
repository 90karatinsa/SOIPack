import { createRequirement, TestCase } from '@soipack/core';
import { buildTraceMatrix, createTraceLink } from '@soipack/engine';

import { generatePdf, renderHtmlReport, renderJsonReport } from './index';

describe('@soipack/report', () => {
  const requirement = createRequirement('REQ-1', 'Secure login', {
    status: 'approved',
    tags: ['security'],
  });
  const testCase: TestCase = {
    id: 'TC-1',
    name: 'should request 2FA',
    requirementId: 'REQ-1',
    status: 'pending',
  };
  const matrix = buildTraceMatrix([createTraceLink(requirement, testCase, 0.9)]);

  it('renders HTML table with requirement and tests', () => {
    const html = renderHtmlReport(matrix, [requirement], [testCase], {
      title: 'Custom Report',
    });

    expect(html).toContain('<h1>Custom Report</h1>');
    expect(html).toContain('Secure login');
    expect(html).toContain('should request 2FA');
  });

  it('builds JSON report with metadata', () => {
    const json = renderJsonReport(matrix, [requirement], [testCase]);

    expect(json).toEqual({
      generatedAt: expect.any(String),
      requirements: [
        {
          requirement: requirement,
          tests: [testCase],
        },
      ],
    });
  });

  it('generates PDF using a provided page implementation', async () => {
    const html = renderHtmlReport(matrix, [requirement], [testCase]);
    const pdfBuffer = Buffer.from('pdf');
    const stub = {
      async setContent(content: string) {
        expect(content).toBe(html);
      },
      async pdf() {
        return pdfBuffer;
      },
    };

    await expect(generatePdf(stub, html)).resolves.toBe(pdfBuffer);
  });
});
