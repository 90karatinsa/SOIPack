import { Requirement } from '@soipack/core';

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
