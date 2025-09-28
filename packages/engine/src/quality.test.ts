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

describe('evaluateQualityFindings - duplicate detection', () => {
  const createTrace = (requirement: RequirementTrace['requirement']): RequirementTrace => ({
    requirement,
    tests: [],
    code: [],
    designs: [],
  });

  it('emits warnings for near-duplicate requirement wording', () => {
    const traces = [
      createTrace({
        id: 'REQ-LOG-001',
        title: 'Sistem hata olaylarını kaydetmelidir.',
        description: 'Her kritik hata oluştuğunda ayrıntılı günlük saklanacaktır.',
        status: 'draft' as const,
        tags: [],
      }),
      createTrace({
        id: 'REQ-LOG-002',
        title: 'Sistem kritik hata olaylarını kaydetmelidir.',
        description: 'Kritik bir arıza oluştuğunda ayrıntılı log tutulacaktır.',
        status: 'draft' as const,
        tags: [],
      }),
    ];

    const findings = evaluateQualityFindings(traces, [], []);
    const duplicateFindings = findings.filter((finding) => finding.id.includes('duplicate-'));

    expect(duplicateFindings).toHaveLength(2);
    duplicateFindings.forEach((finding) => {
      expect(finding).toEqual(
        expect.objectContaining({
          category: 'analysis',
          severity: expect.stringMatching(/warn|error/),
          recommendation: expect.stringContaining('Benzer gereksinimleri'),
        }),
      );
    });
    expect(duplicateFindings.map((finding) => finding.id)).toEqual(
      expect.arrayContaining([
        'REQ-LOG-001-duplicate-REQ-LOG-002',
        'REQ-LOG-002-duplicate-REQ-LOG-001',
      ]),
    );
  });

  it('does not flag unrelated requirements', () => {
    const traces = [
      createTrace({
        id: 'REQ-ALT-POWER',
        title: 'Sistem 30 dakika boyunca batarya modunda çalışmalıdır.',
        description: 'Ana güç kesildiğinde acil güç kaynağı devreye girer.',
        status: 'draft' as const,
        tags: [],
      }),
      createTrace({
        id: 'REQ-DISPLAY-BRIGHTNESS',
        title: 'Ekran parlaklığı ortam ışığına göre otomatik ayarlanacaktır.',
        description: 'Sensörler her 5 saniyede bir ölçüm yapacaktır.',
        status: 'draft' as const,
        tags: [],
      }),
      createTrace({
        id: 'REQ-LOGGING',
        title: 'Sistem hata kayıtlarını 90 gün saklayacaktır.',
        status: 'draft' as const,
        tags: [],
      }),
    ];

    const findings = evaluateQualityFindings(traces, [], []);

    expect(findings.filter((finding) => finding.id.includes('duplicate-'))).toHaveLength(0);
  });
});
