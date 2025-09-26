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

const do330ToolAssessmentSections = [
  { id: 'qualificationStrategy', title: '1. DO-330 Qualification Strategy' },
  { id: 'toolInventory', title: '2. Tool Inventory & Usage Context' },
  { id: 'validationEvidence', title: '3. Validation Evidence & Argumentation' },
  { id: 'operationalControls', title: '4. Operational Controls & Monitoring' },
  { id: 'signatures', title: '5. Approval Signatures' },
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
  'do330-ta': {
    id: 'do330-ta',
    title: 'DO-330 Tool Assessment Report',
    purpose:
      'Summarizes tool qualification classes, validation arguments, and approval signatures required by RTCA DO-330.',
    sections: do330ToolAssessmentSections,
  },
};
