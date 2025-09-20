#!/usr/bin/env node
import type { AdapterMetadata } from '@soipack/adapters';
import { registerAdapter } from '@soipack/adapters';
import { createRequirement, Requirement, RequirementStatus, TestCase } from '@soipack/core';
import { buildTraceMatrix, createTraceLink } from '@soipack/engine';
import { renderHtmlReport, renderJsonReport } from '@soipack/report';

export type CliCommand = 'list-adapters' | 'generate-report';

export interface RequirementInput {
  id: string;
  title: string;
  description?: string;
  status?: RequirementStatus;
  tags?: string[];
}

export interface TestCaseInput {
  id: string;
  requirementId: string;
  name: string;
  status?: TestCase['status'];
}

export interface CliContext {
  adapters: AdapterMetadata[];
  requirements: RequirementInput[];
  testCases: TestCaseInput[];
}

const buildDomainObjects = (
  context: CliContext,
): {
  adapters: AdapterMetadata[];
  requirements: Requirement[];
  testCases: TestCase[];
} => {
  const adapters = context.adapters.map(registerAdapter);
  const requirements = context.requirements.map((requirement) =>
    createRequirement(requirement.id, requirement.title, {
      description: requirement.description,
      status: requirement.status,
      tags: requirement.tags,
    }),
  );
  const testCases = context.testCases.map((test) => ({
    id: test.id,
    requirementId: test.requirementId,
    name: test.name,
    status: test.status ?? 'pending',
  }));

  return { adapters, requirements, testCases };
};

export const runCli = async (command: CliCommand, context: CliContext): Promise<string> => {
  const { adapters, requirements, testCases } = buildDomainObjects(context);

  switch (command) {
    case 'list-adapters': {
      return adapters
        .map((adapter) => `${adapter.name}: ${adapter.supportedArtifacts.join(', ')}`)
        .join('\n');
    }
    case 'generate-report': {
      const requirementMap = new Map(requirements.map((item) => [item.id, item]));
      const links = testCases
        .map((test) => {
          const requirement = requirementMap.get(test.requirementId);
          return requirement ? createTraceLink(requirement, test, 1) : undefined;
        })
        .filter((value): value is ReturnType<typeof createTraceLink> => Boolean(value));

      const matrix = buildTraceMatrix(links);
      const html = renderHtmlReport(matrix, requirements, testCases);
      const json = renderJsonReport(matrix, requirements, testCases);

      return [html, JSON.stringify(json, null, 2)].join('\n');
    }
    default: {
      throw new Error(`Unknown command: ${command}`);
    }
  }
};

if (require.main === module) {
  const [, , command = 'list-adapters'] = process.argv;
  runCli(command as CliCommand, { adapters: [], requirements: [], testCases: [] })
    .then((output) => {
      if (output) {
        // eslint-disable-next-line no-console
        console.log(output);
      }
    })
    .catch((error) => {
      // eslint-disable-next-line no-console
      console.error(error);
      process.exitCode = 1;
    });
}
