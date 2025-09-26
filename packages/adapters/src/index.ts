import { Requirement } from '@soipack/core';

export * from './types';
export { importJiraCsv } from './jiraCsv';
export type { JiraCsvOptions } from './jiraCsv';
export { importReqIF } from './reqif';
export { parseJUnitStream } from './adapters/junit';
export { parseLcovStream } from './adapters/lcov';
export { parseReqifStream } from './adapters/reqif';
export { importJUnitXml } from './junitXml';
export { importLcov } from './lcov';
export { importCobertura } from './cobertura';
export { importGitMetadata } from './git';
export type { GitImportOptions } from './git';
export { fromPolyspace } from './polyspace';
export { fromLDRA } from './ldra';
export { fromVectorCAST } from './vectorcast';
export { importQaLogs } from './qaLogs';
export { fetchPolarionArtifacts } from './polarion';
export type { PolarionClientOptions } from './polarion';
export { fetchJamaArtifacts } from './jama';
export type { JamaClientOptions, JamaImportBundle, JamaTraceLink } from './jama';
export { fetchJenkinsArtifacts } from './jenkins';
export type { JenkinsClientOptions } from './jenkins';
export { fetchJiraChangeRequests } from './jiraCloud';
export type {
  JiraCloudClientOptions,
  JiraChangeRequest,
  JiraChangeRequestAttachment,
  JiraChangeRequestTransition,
} from './jiraCloud';

export interface AdapterMetadata {
  name: string;
  supportedArtifacts: string[];
  description?: string;
}

export interface RawRecord {
  id: string | number;
  title: string;
  description?: string | null;
}

export const registerAdapter = (metadata: AdapterMetadata): AdapterMetadata => {
  if (metadata.supportedArtifacts.length === 0) {
    throw new Error('Adapter must support at least one artifact type.');
  }

  return {
    ...metadata,
    supportedArtifacts: metadata.supportedArtifacts.map((artifact) => artifact.toLowerCase()),
  };
};

export const toRequirement = (record: RawRecord): Requirement => ({
  id: String(record.id),
  title: record.title.trim(),
  description: record.description ?? undefined,
  status: 'draft',
  tags: [],
});
