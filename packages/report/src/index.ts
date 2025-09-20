import { Requirement, TestCase } from '@soipack/core';
import { TraceMatrix } from '@soipack/engine';

export interface HtmlReportOptions {
  title?: string;
}

export interface PdfPage {
  setContent: (html: string) => Promise<void>;
  pdf: (options: { printBackground: boolean }) => Promise<Buffer>;
}

export const renderHtmlReport = (
  matrix: TraceMatrix[],
  requirements: Requirement[],
  testCases: TestCase[],
  options: HtmlReportOptions = {},
): string => {
  const title = options.title ?? 'SOIPack Traceability Report';
  const requirementLookup = new Map(requirements.map((item) => [item.id, item]));
  const testLookup = new Map(testCases.map((item) => [item.id, item]));

  const rows = matrix
    .map((entry) => {
      const requirement = requirementLookup.get(entry.requirementId);
      const tests = entry.testCaseIds.map((id) => testLookup.get(id)?.name ?? id).join(', ');

      return `<tr><td>${requirement?.title ?? entry.requirementId}</td><td>${tests}</td></tr>`;
    })
    .join('');

  return `<!DOCTYPE html><html><head><meta charset="utf-8" /><title>${title}</title></head><body><h1>${title}</h1><table><thead><tr><th>Requirement</th><th>Test Cases</th></tr></thead><tbody>${rows}</tbody></table></body></html>`;
};

export const renderJsonReport = (
  matrix: TraceMatrix[],
  requirements: Requirement[],
  testCases: TestCase[],
): Record<string, unknown> => ({
  generatedAt: new Date().toISOString(),
  requirements: matrix.map((entry) => ({
    requirement: requirements.find((item) => item.id === entry.requirementId) ?? {
      id: entry.requirementId,
      title: entry.requirementId,
      status: 'draft',
      tags: [],
    },
    tests: entry.testCaseIds.map(
      (id) => testCases.find((test) => test.id === id) ?? { id, name: id },
    ),
  })),
});

export const generatePdf = async (page: PdfPage, html: string): Promise<Buffer> => {
  await page.setContent(html);
  return page.pdf({ printBackground: true });
};
