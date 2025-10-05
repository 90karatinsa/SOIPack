import type {
  DoorsNextConnectorConfig,
  JamaConnectorConfig,
  JenkinsConnectorConfig,
  JiraCloudConnectorConfig,
  PolarionConnectorConfig,
} from '../services/api';

export const MANUAL_ARTIFACT_TYPES = [
  'plan',
  'standard',
  'review',
  'analysis',
  'test',
  'coverage_stmt',
  'coverage_dec',
  'coverage_mcdc',
  'trace',
  'cm_record',
  'qa_record',
  'problem_report',
  'conformity',
] as const;

export type ManualArtifactType = (typeof MANUAL_ARTIFACT_TYPES)[number];

export type ManualArtifactsSelection = Partial<Record<ManualArtifactType, string[]>>;

export interface PolarionConnectorFormState {
  enabled: boolean;
  baseUrl: string;
  projectId: string;
  username: string;
  password: string;
  token: string;
}

export interface JenkinsConnectorFormState {
  enabled: boolean;
  baseUrl: string;
  job: string;
  build: string;
  username: string;
  password: string;
  token: string;
}

export interface DoorsNextConnectorFormState {
  enabled: boolean;
  baseUrl: string;
  projectArea: string;
  username: string;
  password: string;
  accessToken: string;
}

export interface JamaConnectorFormState {
  enabled: boolean;
  baseUrl: string;
  projectId: string;
  token: string;
}

export interface JiraCloudConnectorFormState {
  enabled: boolean;
  baseUrl: string;
  projectKey: string;
  email: string;
  token: string;
  requirementsJql: string;
  testsJql: string;
  pageSize: string;
  maxPages: string;
  timeoutMs: string;
}

export interface RemoteConnectorPayload {
  polarion?: PolarionConnectorConfig;
  jenkins?: JenkinsConnectorConfig;
  doorsNext?: DoorsNextConnectorConfig;
  jama?: JamaConnectorConfig;
  jiraCloud?: JiraCloudConnectorConfig;
}

export interface UploadRunPayload {
  independentSources: string[];
  independentArtifacts: string[];
  connectors: RemoteConnectorPayload;
  manualArtifacts: ManualArtifactsSelection;
}

