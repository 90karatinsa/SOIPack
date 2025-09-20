export type CoverageStatus = 'covered' | 'partial' | 'missing';

export interface UploadLogEntry {
  id: string;
  timestamp: string;
  severity: 'info' | 'success' | 'warning' | 'error';
  message: string;
}

export interface ComplianceMatrixRow {
  id: string;
  requirement: string;
  description: string;
  owner: string;
  status: CoverageStatus;
  coverage: number;
  linkedTests: string[];
  lastUpdated: string;
}

export interface TraceabilityMatrixRow {
  id: string;
  requirement: string;
  designArtifacts: string[];
  verificationTests: {
    id: string;
    name: string;
    status: CoverageStatus;
  }[];
  risks: string[];
  status: CoverageStatus;
}

export const uploadLogs: UploadLogEntry[] = [
  {
    id: 'log-1',
    timestamp: '2024-04-18T09:15:12Z',
    severity: 'info',
    message: '3 kaynak dosya seçildi: requirements.xlsx, verification.csv, risks.json'
  },
  {
    id: 'log-2',
    timestamp: '2024-04-18T09:15:14Z',
    severity: 'success',
    message: 'Ön doğrulama tamamlandı. Şema uyumluluğu %100.'
  },
  {
    id: 'log-3',
    timestamp: '2024-04-18T09:15:19Z',
    severity: 'warning',
    message: 'REQ-014 için doğrulama testi eksik. İzlenebilirlik matrisi güncellendi.'
  },
  {
    id: 'log-4',
    timestamp: '2024-04-18T09:15:23Z',
    severity: 'success',
    message: 'Rapor üretimi tamamlandı. Uyum ve izlenebilirlik matrisleri hazır.'
  }
];

export const complianceMatrix: ComplianceMatrixRow[] = [
  {
    id: 'REQ-001',
    requirement: 'Login güvenliği',
    description: 'MFA ve oturum kısıtlamaları uygulanmalı.',
    owner: 'Security Guild',
    status: 'covered',
    coverage: 100,
    linkedTests: ['SEC-API-12', 'SEC-E2E-03'],
    lastUpdated: '2024-04-17T21:05:00Z'
  },
  {
    id: 'REQ-004',
    requirement: 'Audit logları',
    description: 'Kritik işlemler 7 yıl saklanmalı.',
    owner: 'Platform Team',
    status: 'partial',
    coverage: 72,
    linkedTests: ['LOG-UNIT-08'],
    lastUpdated: '2024-04-16T08:12:00Z'
  },
  {
    id: 'REQ-009',
    requirement: 'API hız limiti',
    description: 'Token başına dakikada 120 çağrı sınırı.',
    owner: 'Edge Services',
    status: 'covered',
    coverage: 96,
    linkedTests: ['EDGE-PERF-02', 'EDGE-CHAOS-01'],
    lastUpdated: '2024-04-18T06:32:00Z'
  },
  {
    id: 'REQ-014',
    requirement: 'Kritik alarm bildirimi',
    description: '5 dakika içinde on-call ekibe iletilmeli.',
    owner: 'Observability',
    status: 'missing',
    coverage: 35,
    linkedTests: [],
    lastUpdated: '2024-04-12T18:52:00Z'
  },
  {
    id: 'REQ-021',
    requirement: 'Veri şifreleme',
    description: 'Hassas veriler AES-256 ile şifrelenmeli.',
    owner: 'Data Platform',
    status: 'partial',
    coverage: 68,
    linkedTests: ['DATA-SEC-11'],
    lastUpdated: '2024-04-10T11:05:00Z'
  },
  {
    id: 'REQ-032',
    requirement: 'Erişilebilirlik',
    description: 'WCAG 2.1 AA seviyesine uyum.',
    owner: 'Experience',
    status: 'covered',
    coverage: 88,
    linkedTests: ['UX-ACCESS-05', 'UX-ACCESS-09'],
    lastUpdated: '2024-04-14T14:45:00Z'
  }
];

export const traceabilityMatrix: TraceabilityMatrixRow[] = [
  {
    id: 'TRACE-REQ-001',
    requirement: 'Login güvenliği',
    designArtifacts: ['sequence-diagram-login.mermaid', 'threat-model-v2.md'],
    verificationTests: [
      { id: 'SEC-API-12', name: 'Token revocation endpoint', status: 'covered' },
      { id: 'SEC-E2E-03', name: 'MFA happy path', status: 'covered' }
    ],
    risks: ['Oturum kaçırma', 'Brute force girişimleri'],
    status: 'covered'
  },
  {
    id: 'TRACE-REQ-004',
    requirement: 'Audit logları',
    designArtifacts: ['audit-sink-arch.png', 'retention-plan.xlsx'],
    verificationTests: [
      { id: 'LOG-UNIT-08', name: 'Retention policy enforcement', status: 'partial' },
      { id: 'LOG-E2E-02', name: 'Tam sistem kurtarma', status: 'missing' }
    ],
    risks: ['Regülasyon cezası', 'Olay analizi yetersizliği'],
    status: 'partial'
  },
  {
    id: 'TRACE-REQ-009',
    requirement: 'API hız limiti',
    designArtifacts: ['rate-limit-config.yaml'],
    verificationTests: [
      { id: 'EDGE-PERF-02', name: 'Burst traffic throttling', status: 'covered' },
      { id: 'EDGE-CHAOS-01', name: 'Regional failover throttling', status: 'covered' }
    ],
    risks: ['Servis kesintisi', 'Kaynak tüketimi artışı'],
    status: 'covered'
  },
  {
    id: 'TRACE-REQ-014',
    requirement: 'Kritik alarm bildirimi',
    designArtifacts: ['pager-duty-flow.svg'],
    verificationTests: [
      { id: 'OBS-SIM-04', name: 'Alert storm scenario', status: 'missing' }
    ],
    risks: ['Olay kaçırma', 'SLA ihlali'],
    status: 'missing'
  }
];

export const complianceSummary = {
  totalRequirements: complianceMatrix.length,
  covered: complianceMatrix.filter((item) => item.status === 'covered').length,
  partial: complianceMatrix.filter((item) => item.status === 'partial').length,
  missing: complianceMatrix.filter((item) => item.status === 'missing').length
};

export const demoPackageFiles: Record<string, string> = {
  'README.txt': `SOIPack UI Demo Paketi\n\nBu paket demo amaçlı oluşturulmuştur.\n- compliance.json: Uyum matrisi verileri\n- traceability.json: İzlenebilirlik matrisi verileri\n- logs.json: Çalıştırma geçmişi\n`
};
