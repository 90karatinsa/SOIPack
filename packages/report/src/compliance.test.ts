import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import type { BuildInfo } from '@soipack/adapters';
import { renderComplianceMatrix } from './index';
import { createReportFixture } from './__fixtures__/snapshot';

type HtmlValidator = typeof import('html-validator');

jest.mock('html-validator', () => ({
  __esModule: true,
  default: jest.fn(async () => ({ messages: [] })),
}));

const hashHtml = (value: string): string => createHash('sha256').update(value).digest('hex');
const goldenDir = path.resolve(__dirname, '__fixtures__', 'goldens');
const maybeUpdateGolden = (fileName: string, value: string) => {
  if (process.env.UPDATE_GOLDENS === '1') {
    writeFileSync(path.join(goldenDir, fileName), value, 'utf-8');
  }
};

const gitFixture: BuildInfo = {
  hash: '1234567890abcdef1234567890abcdef12345678',
  author: 'Stage Bot',
  date: '2024-03-15T10:00:00Z',
  message: 'Implement stage filtering',
  branches: ['main'],
  tags: [],
  dirty: false,
  remoteOrigins: ['https://example.com/repo.git'],
};

describe('compliance matrix stages', () => {
  const validatorModule = jest.requireMock('html-validator') as { default: HtmlValidator['default'] & { mockClear?: () => void } };
  const validator = validatorModule.default;

  beforeEach(() => {
    validatorModule.default.mockClear?.();
  });

  it('emits stage metadata and renders HTML tabs', () => {
    const fixture = createReportFixture();
    const result = renderComplianceMatrix(fixture.snapshot, {
      manifestId: fixture.manifestId,
      objectivesMetadata: fixture.objectives,
      title: 'Kurumsal Uyum Matrisi',
      git: gitFixture,
      signoffs: fixture.signoffs,
    });

    expect(result.json.manifestId).toBe(fixture.manifestId);
    expect(result.json.stages[0]).toEqual(
      expect.objectContaining({
        id: 'all',
        summary: expect.objectContaining({ total: fixture.snapshot.objectives.length }),
      }),
    );
    expect(result.json.stages.find((stage) => stage.id === 'SOI-1')).toBeDefined();
    expect(result.html).toContain('stage-tabs');

    maybeUpdateGolden('compliance-matrix.html', result.html);
    const goldenHtml = readFileSync(path.join(goldenDir, 'compliance-matrix.html'), 'utf-8');
    expect(hashHtml(result.html)).toBe(hashHtml(goldenHtml));
  });
});
