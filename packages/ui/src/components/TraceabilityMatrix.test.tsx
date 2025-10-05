import { render, screen, within } from '@testing-library/react';

import { TraceabilityMatrix } from './TraceabilityMatrix';
import type { RequirementViewModel } from '../types/pipeline';

describe('TraceabilityMatrix', () => {
  const createRequirement = (): RequirementViewModel => ({
    id: 'REQ-001',
    title: 'Uçuş kontrol yazılımı loglanmalı',
    description: 'Kritik olaylar uçuş sırasında kaydedilmelidir.',
    requirementStatus: 'approved',
    tags: ['safety', 'logging'],
    coverageStatus: 'partial',
    coveragePercent: 72,
    coverageLabel: '%72',
    code: [
      { path: 'src/logger.ts', coveragePercent: 88, coverageLabel: '%88' }
    ],
    tests: [
      { id: 'TC-REQ-001', name: 'Log entries persisted', status: 'covered', result: 'passed' }
    ],
    designs: [
      { id: 'DES-001', title: 'Logger architecture', status: 'accepted' },
      { id: 'DES-002', title: 'Storage interface' }
    ],
    suggestions: {
      code: [
        {
          type: 'code',
          targetId: 'src/audit/log-writer.ts',
          target: 'src/audit/log-writer.ts',
          confidence: 'high',
          reason: 'Benzer log yazma rutini bulundu.'
        }
      ],
      tests: [
        {
          type: 'test',
          targetId: 'TC-AUDIT-01',
          target: 'TC-AUDIT-01',
          confidence: 'medium',
          reason: 'Aynı gereklilik için önerilen test.'
        }
      ]
    }
  });

  it('shows design artefacts and trace suggestion badges for each requirement', () => {
    const requirement = createRequirement();

    render(
      <TraceabilityMatrix
        rows={[requirement]}
        isEnabled
        generatedAt="2024-02-01T09:30:00Z"
      />
    );

    const designSection = screen.getByRole('heading', { name: /Tasarım Artefaktları/i });
    expect(designSection).toBeInTheDocument();
    expect(screen.getByText('Logger architecture')).toBeInTheDocument();
    expect(screen.getByText('DES-001')).toBeInTheDocument();
    expect(screen.getByText(/Durum: accepted/i)).toBeInTheDocument();

    const suggestionHeading = screen.getByRole('heading', { name: /Önerilen İz Bağlantıları/i });
    expect(suggestionHeading).toBeInTheDocument();
    expect(screen.getByText('Kod Bağlantıları')).toBeInTheDocument();
    expect(screen.getByText('Test Bağlantıları')).toBeInTheDocument();

    const codeSuggestion = screen.getByText('src/audit/log-writer.ts').closest('li');
    expect(codeSuggestion).not.toBeNull();
    expect(within(codeSuggestion as HTMLElement).getByText(/Güven: Yüksek/)).toBeInTheDocument();

    const testSuggestion = screen.getByText('TC-AUDIT-01').closest('li');
    expect(testSuggestion).not.toBeNull();
    expect(within(testSuggestion as HTMLElement).getByText(/Güven: Orta/)).toBeInTheDocument();
  });
});
