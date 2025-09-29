import type {
  DoorsNextConnectorConfig,
  JamaConnectorConfig,
  JenkinsConnectorConfig,
  PolarionConnectorConfig,
} from '../services/api';

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

export interface RemoteConnectorPayload {
  polarion?: PolarionConnectorConfig;
  jenkins?: JenkinsConnectorConfig;
  doorsNext?: DoorsNextConnectorConfig;
  jama?: JamaConnectorConfig;
}

export interface UploadRunPayload {
  independentSources: string[];
  independentArtifacts: string[];
  connectors: RemoteConnectorPayload;
}

