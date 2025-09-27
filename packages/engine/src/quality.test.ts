import { evaluateQualityFindings } from './quality';
import type { RequirementTrace } from './index';

describe('evaluateQualityFindings - clarity heuristics', () => {
  const createTrace = (requirement: RequirementTrace['requirement']): RequirementTrace => ({
    requirement,
    tests: [],
    code: [],
    designs: [],
  });

  it('flags English and Turkish ambiguity cues within the same requirement', () => {
    const requirement = {
      id: 'REQ-TR-CLAR',
      title:
        'SİSTEM OLMALI ve GEREKTİĞİNDE destek moduna geçerek as appropriate prosedürlerini tetikleyecektir.',
      description: 'Operasyon YETERLİ hata toleransı bırakmalıdır.',
      status: 'draft' as const,
      tags: [],
    };

    const findings = evaluateQualityFindings([createTrace(requirement)], [], []);

    expect(findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: 'REQ-TR-CLAR-clarity-should-olmali',
          severity: 'warn',
          category: 'analysis',
        }),
        expect.objectContaining({
          id: 'REQ-TR-CLAR-clarity-as-needed-gerektiginde',
          severity: 'warn',
          category: 'analysis',
        }),
        expect.objectContaining({
          id: 'REQ-TR-CLAR-clarity-subjective-adjective',
          severity: 'warn',
          category: 'analysis',
        }),
        expect.objectContaining({
          id: 'REQ-TR-CLAR-clarity-as-appropriate',
          severity: 'warn',
          category: 'analysis',
        }),
      ]),
    );
  });

  it('does not report clarity warnings when requirement text is precise', () => {
    const requirement = {
      id: 'REQ-TR-CLEAR',
      title: 'Sistem, 5 saniye içinde otomatik moda geçer ve operatöre durum mesajı gönderir.',
      status: 'draft' as const,
      tags: [],
    };

    const findings = evaluateQualityFindings([createTrace(requirement)], [], []);

    expect(findings.filter((finding) => finding.id.includes('clarity-'))).toHaveLength(0);
  });
});
