import { Requirement } from '@soipack/core';

import type { ParseResult, RemoteRequirementRecord, RemoteTraceLink } from './types';

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
export { fetchDoorsNextArtifacts } from './doorsNext';
export type {
  DoorsNextClientOptions,
  DoorsNextArtifactBundle,
  DoorsNextRelationship,
} from './doorsNext';
export { importDoorsClassicCsv } from './doorsClassic';
export type { DoorsClassicImportBundle } from './doorsClassic';

export interface RemoteImportBundle {
  requirements: RemoteRequirementRecord[];
  traces: RemoteTraceLink[];
}

export type RemoteImportFactory = () => Promise<ParseResult<RemoteImportBundle>>;

const normalizeRequirementId = (value: string): string => value.trim();

const normalizeRequirementKey = (value: string): string => normalizeRequirementId(value).toLowerCase();

export const aggregateImportBundle = (factories: RemoteImportFactory[]): RemoteImportFactory => {
  return async () => {
    const aggregated: RemoteImportBundle = { requirements: [], traces: [] };
    const warnings: string[] = [];
    const seen = new Set<string>();

    for (const factory of factories) {
      const { data, warnings: importerWarnings } = await factory();
      warnings.push(...importerWarnings);

      data.requirements.forEach((requirement) => {
        const normalizedId = normalizeRequirementId(requirement.id);
        if (!normalizedId) {
          return;
        }
        const key = normalizeRequirementKey(normalizedId);
        if (seen.has(key)) {
          return;
        }
        seen.add(key);
        aggregated.requirements.push({ ...requirement, id: normalizedId });
      });

      if (data.traces.length > 0) {
        aggregated.traces.push(...data.traces);
      }
    }

    return { data: aggregated, warnings };
  };
};

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

export const doorsNextAdapterMetadata = registerAdapter({
  name: 'IBM DOORS Next Generation',
  supportedArtifacts: ['requirements', 'tests', 'designs'],
  description: 'Fetches DOORS Next /rm requirements, test cases, and design records via OSLC.',
});
