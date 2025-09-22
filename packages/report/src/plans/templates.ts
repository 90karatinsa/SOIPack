import type { PlanTemplateDefinition, PlanTemplateId } from './types';

const psacSections = [
  { id: 'introduction', title: '1. Certification Team & Responsibilities' },
  { id: 'softwareLifecycle', title: '2. Software Life Cycle' },
  { id: 'developmentEnvironment', title: '3. Development Environment' },
  { id: 'complianceStrategy', title: '4. Compliance Approach' },
  { id: 'schedule', title: '5. Schedule & Milestones' },
];

const sdpSections = [
  { id: 'introduction', title: '1. Project Introduction' },
  { id: 'organization', title: '2. Organizational Responsibilities' },
  { id: 'developmentStandards', title: '3. Development Standards & Methods' },
  { id: 'infrastructure', title: '4. Engineering Infrastructure' },
  { id: 'configurationManagement', title: '5. Configuration Management Interfaces' },
];

const svpSections = [
  { id: 'verificationScope', title: '1. Verification Scope' },
  { id: 'reviewsAndAnalysis', title: '2. Reviews & Analyses' },
  { id: 'testingStrategy', title: '3. Testing Strategy' },
  { id: 'coverageAssessment', title: '4. Coverage Assessment' },
  { id: 'anomalyResolution', title: '5. Anomaly Resolution' },
];

const scmpSections = [
  { id: 'introduction', title: '1. Configuration Management Overview' },
  { id: 'responsibilities', title: '2. Roles & Responsibilities' },
  { id: 'baselines', title: '3. Baselines & Libraries' },
  { id: 'changeControl', title: '4. Change Control' },
  { id: 'audits', title: '5. Audits & Status Accounting' },
];

const sqapSections = [
  { id: 'qualityPolicy', title: '1. Quality Policy' },
  { id: 'processAssurance', title: '2. Process Assurance' },
  { id: 'audits', title: '3. Audits & Reviews' },
  { id: 'metrics', title: '4. Metrics & Reporting' },
  { id: 'records', title: '5. Records & Archiving' },
];

export const planTemplateDefinitions: Record<PlanTemplateId, PlanTemplateDefinition> = {
  psac: {
    id: 'psac',
    title: 'Plan for Software Aspects of Certification (PSAC)',
    purpose: 'Defines the certification strategy, responsibilities, and milestones for achieving DO-178C compliance.',
    sections: psacSections,
  },
  sdp: {
    id: 'sdp',
    title: 'Software Development Plan (SDP)',
    purpose: 'Describes the life-cycle processes, standards, and resources that guide software development activities.',
    sections: sdpSections,
  },
  svp: {
    id: 'svp',
    title: 'Software Verification Plan (SVP)',
    purpose: 'Captures the verification objectives, methods, and coverage expectations applied to the software.',
    sections: svpSections,
  },
  scmp: {
    id: 'scmp',
    title: 'Software Configuration Management Plan (SCMP)',
    purpose: 'Explains how configuration items are baselined, controlled, and audited throughout the project.',
    sections: scmpSections,
  },
  sqap: {
    id: 'sqap',
    title: 'Software Quality Assurance Plan (SQAP)',
    purpose: 'Outlines the quality assurance policies, audits, and records used to ensure process compliance.',
    sections: sqapSections,
  },
};

export const basePlanTemplate = `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>{{ planDefinition.title }} - {{ projectLabel }}</title>
    <style>
      body {
        font-family: 'Segoe UI', Arial, sans-serif;
        margin: 36px;
        color: #1c1c1c;
      }
      header {
        border-bottom: 2px solid #0a5c9b;
        margin-bottom: 24px;
        padding-bottom: 16px;
      }
      h1 {
        margin: 0;
        font-size: 28px;
        color: #0a5c9b;
      }
      .subtitle {
        margin-top: 6px;
        color: #3e5974;
      }
      .summary-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 12px;
        margin-top: 16px;
      }
      .summary-card {
        background: #f4f6fb;
        border-radius: 8px;
        padding: 12px 16px;
        border: 1px solid #d0d7e7;
      }
      .summary-card strong {
        display: block;
        font-size: 12px;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        color: #445b78;
      }
      .summary-card span {
        font-size: 18px;
        font-weight: 600;
        color: #1c1c1c;
      }
      section {
        margin-top: 28px;
      }
      section h2 {
        font-size: 20px;
        border-bottom: 1px solid #d0d7e7;
        padding-bottom: 6px;
      }
      table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 12px;
      }
      th,
      td {
        border: 1px solid #d0d7e7;
        padding: 8px 10px;
        text-align: left;
        vertical-align: top;
      }
      th {
        background: #eef3fb;
        font-size: 12px;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        color: #3b5773;
      }
      .status-pill {
        display: inline-block;
        padding: 3px 12px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: 600;
      }
      .status-covered {
        background: #e2f6ea;
        color: #1f7a39;
      }
      .status-partial {
        background: #fff2cc;
        color: #8a6000;
      }
      .status-missing {
        background: #fde4e1;
        color: #b3261e;
      }
      .objective-id {
        font-weight: 600;
        white-space: nowrap;
      }
      .small {
        font-size: 12px;
        color: #5c708a;
      }
      ul {
        padding-left: 20px;
      }
      .footer {
        margin-top: 48px;
        font-size: 12px;
        color: #5c708a;
      }
    </style>
  </head>
  <body>
    <header>
      <h1>{{ planDefinition.title }}</h1>
      <p class="subtitle">{{ planDefinition.purpose }}</p>
      <div class="summary-grid">
        <div class="summary-card">
          <strong>Project</strong>
          <span>{{ projectLabel }}</span>
        </div>
        <div class="summary-card">
          <strong>Certification Level</strong>
          <span>{{ levelLabel }}</span>
        </div>
        <div class="summary-card">
          <strong>Manifest ID</strong>
          <span>{{ manifestId or 'Pending' }}</span>
        </div>
        <div class="summary-card">
          <strong>Generated</strong>
          <span>{{ generatedAt }}</span>
        </div>
      </div>
      <div class="summary-grid">
        <div class="summary-card">
          <strong>Objective Coverage</strong>
          <span>{{ coverageSummary.coveredCount }}/{{ coverageSummary.total }} ({{ coverageSummary.coveragePercent }}%)</span>
        </div>
        <div class="summary-card">
          <strong>Verification Tests</strong>
          <span>{{ stats.tests.total }} total · {{ stats.tests.passed }} passed · {{ stats.tests.failed }} failed · {{ stats.tests.skipped }} skipped</span>
        </div>
        <div class="summary-card">
          <strong>Tracked Requirements</strong>
          <span>{{ stats.requirements.total }}</span>
        </div>
        <div class="summary-card">
          <strong>Code Elements</strong>
          <span>{{ stats.codePaths.total }}</span>
        </div>
      </div>
    </header>
    <section>
      <h2>Purpose &amp; Overview</h2>
      {{ overview | safe }}
    </section>
    {% for section in sectionDefinitions %}
      <section>
        <h2>{{ section.title }}</h2>
        {{ sections[section.id] | safe }}
      </section>
    {% endfor %}
    <section>
      <h2>Objective Coverage Summary</h2>
      <p>{{ coverageSummary.text }}</p>
      <table>
        <thead>
          <tr>
            <th>Objective Table</th>
            <th>Total</th>
            <th>Covered</th>
            <th>Partial</th>
            <th>Missing</th>
          </tr>
        </thead>
        <tbody>
          {% for table in tableSummary %}
            <tr>
              <td>{{ table.table }}</td>
              <td>{{ table.total }}</td>
              <td>{{ table.covered }}</td>
              <td>{{ table.partial }}</td>
              <td>{{ table.missing }}</td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
    </section>
    <section>
      <h2>Detailed Objective Mapping</h2>
      <table>
        <thead>
          <tr>
            <th>Objective</th>
            <th>Table</th>
            <th>Description</th>
            <th>Status</th>
            <th>Evidence &amp; Gaps</th>
          </tr>
        </thead>
        <tbody>
          {% for objective in objectiveRows %}
            <tr>
              <td class="objective-id">{{ objective.id }}</td>
              <td>{{ objective.table or '—' }}</td>
              <td>
                <strong>{{ objective.name }}</strong><br />
                <span class="small">{{ objective.description }}</span>
              </td>
              <td>
                <span class="status-pill {{ objective.statusClass }}">{{ objective.statusLabel }}</span>
              </td>
              <td>
                {% if objective.satisfiedArtifacts.length %}
                  <strong>Available:</strong> {{ objective.satisfiedArtifacts | join(', ') }}<br />
                {% endif %}
                {% if objective.missingArtifacts.length %}
                  <strong>Gaps:</strong> {{ objective.missingArtifacts | join(', ') }}<br />
                {% endif %}
                {% if objective.evidenceRefs.length %}
                  <span class="small">Refs: {{ objective.evidenceRefs | join(', ') }}</span>
                {% endif %}
              </td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
    </section>
    {% if openObjectives.length %}
      <section>
        <h2>Open Compliance Items</h2>
        <p>{{ openSummary }}</p>
        <ul>
          {% for objective in openObjectives %}
            <li>
              <strong>{{ objective.id }}</strong>
              — {{ objective.name }}
              (<span class="status-pill {{ objective.statusClass }}">{{ objective.statusLabel }}</span>)
            </li>
          {% endfor %}
        </ul>
      </section>
    {% endif %}
    {% if additionalNotes %}
      <section>
        <h2>Notes</h2>
        {{ additionalNotes | safe }}
      </section>
    {% endif %}
    <p class="footer">
      Generated by SOIPack {{ packageVersion }} on {{ generatedAt }} for {{ projectLabel }}.
    </p>
  </body>
</html>
`;
