import { createReportDataset } from './report';
import type {
  ComplianceMatrixPayload,
  RequirementTracePayload,
} from '../types/pipeline';

describe('TraceabilityMatrix dataset', () => {
  it('TraceabilityMatrix includes designs and grouped suggestions for each requirement', () => {
    const compliance: ComplianceMatrixPayload = {
      manifestId: 'manifest-1',
      generatedAt: '2024-04-01T00:00:00.000Z',
      version: '1.2.3',
      stats: {
        objectives: { total: 0, covered: 0, partial: 0, missing: 0 },
        requirements: { total: 1 },
        tests: { total: 0, passed: 0, failed: 0, skipped: 0 },
        codePaths: { total: 1 },
        designs: { total: 2 },
      },
      objectives: [],
      stages: [],
      requirementCoverage: [
        {
          requirementId: 'REQ-1',
          title: 'Kritik fonksiyon davranışı',
          status: 'partial',
          coverage: {
            statements: { covered: 3, total: 5, percentage: 60 },
          },
          codePaths: ['src/control.ts'],
          designs: ['DES-1', 'DES-2'],
        },
      ],
      traceSuggestions: [
        {
          requirementId: 'REQ-1',
          type: 'code',
          targetId: 'src/alerts.ts',
          targetName: 'src/alerts.ts',
          confidence: 'medium',
          reason: 'Kod yolu gereklilik tanımıyla eşleşen anahtar kelimeleri içeriyor.',
        },
        {
          requirementId: 'REQ-1',
          type: 'test',
          targetId: 'TC-ALERT-NEW',
          targetName: 'alarm tetikleme testi',
          confidence: 'high',
          reason: 'Test açıklaması gereklilik kimliğini referans alıyor.',
        },
        {
          requirementId: 'REQ-TRACE-ONLY',
          type: 'test',
          targetId: 'TC-TRACE-ONLY',
          targetName: 'yalnızca iz testi',
          confidence: 'low',
          reason: 'Gereklilik kimliği test ismine benziyor.',
        },
      ],
    };

    const traces: RequirementTracePayload[] = [
      {
        requirement: {
          id: 'REQ-1',
          title: 'Kritik fonksiyon davranışı',
          description: 'Kontrol döngüsü hataları algılamalı.',
          status: 'approved',
          tags: ['control'],
        },
        tests: [
          { testId: 'TC-CTRL-1', name: 'nominal davranış', status: 'passed' },
        ],
        code: [
          {
            path: 'src/control.ts',
            coverage: {
              statements: { covered: 3, total: 5, percentage: 60 },
            },
          },
        ],
        designs: [
          {
            id: 'DES-1',
            title: 'Kontrol akış tasarımı',
            description: 'Ana kontrol döngüsü diyagramı.',
            status: 'implemented',
            tags: ['control'],
            requirementRefs: ['REQ-1'],
            codeRefs: ['src/control.ts'],
          },
        ],
      },
      {
        requirement: {
          id: 'REQ-TRACE-ONLY',
          title: 'Sadece izlenen gereklilik',
          description: 'Uyum kapsamına dahil edilmedi.',
          status: 'draft',
          tags: [],
        },
        tests: [],
        code: [],
        designs: [
          {
            id: 'DES-TRACE',
            title: 'İz tasarımı',
            description: 'Gözden geçirme tasarımı.',
            status: 'draft',
            tags: [],
            requirementRefs: ['REQ-TRACE-ONLY'],
            codeRefs: [],
          },
        ],
      },
    ];

    const dataset = createReportDataset('report-123', compliance, traces);

    const requirement = dataset.requirements.find((item) => item.id === 'REQ-1');
    expect(requirement).toBeDefined();
    expect(requirement?.designs).toEqual([
      { id: 'DES-1', title: 'Kontrol akış tasarımı', status: 'implemented' },
      { id: 'DES-2', title: 'DES-2' },
    ]);
    expect(requirement?.suggestions.code).toEqual([
      {
        type: 'code',
        targetId: 'src/alerts.ts',
        target: 'src/alerts.ts',
        confidence: 'medium',
        reason: 'Kod yolu gereklilik tanımıyla eşleşen anahtar kelimeleri içeriyor.',
      },
    ]);
    expect(requirement?.suggestions.tests).toEqual([
      {
        type: 'test',
        targetId: 'TC-ALERT-NEW',
        target: 'alarm tetikleme testi',
        confidence: 'high',
        reason: 'Test açıklaması gereklilik kimliğini referans alıyor.',
      },
    ]);

    const traceOnlyRequirement = dataset.requirements.find((item) => item.id === 'REQ-TRACE-ONLY');
    expect(traceOnlyRequirement).toBeDefined();
    expect(traceOnlyRequirement?.designs).toEqual([
      { id: 'DES-TRACE', title: 'İz tasarımı', status: 'draft' },
    ]);
    expect(traceOnlyRequirement?.suggestions.tests).toEqual([
      {
        type: 'test',
        targetId: 'TC-TRACE-ONLY',
        target: 'yalnızca iz testi',
        confidence: 'low',
        reason: 'Gereklilik kimliği test ismine benziyor.',
      },
    ]);
    expect(traceOnlyRequirement?.suggestions.code).toEqual([]);
  });
});
