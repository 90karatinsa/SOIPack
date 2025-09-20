import { Requirement, TestCase } from '@soipack/core';
import { buildTraceMatrix, createTraceLink } from '@soipack/engine';
import { renderJsonReport } from '@soipack/report';
import express, { Express } from 'express';

export interface ServerConfig {
  requirements: Requirement[];
  testCases: TestCase[];
}

export const createServer = (config: ServerConfig): Express => {
  const app = express();
  app.use(express.json());

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok' });
  });

  app.get('/requirements', (_req, res) => {
    res.json({ requirements: config.requirements });
  });

  app.get('/report', (_req, res) => {
    const requirementMap = new Map(config.requirements.map((item) => [item.id, item]));
    const links = config.testCases
      .map((test) => {
        const requirement = requirementMap.get(test.requirementId);
        return requirement ? createTraceLink(requirement, test, 1) : undefined;
      })
      .filter((value): value is ReturnType<typeof createTraceLink> => Boolean(value));

    const matrix = buildTraceMatrix(links);
    const report = renderJsonReport(matrix, config.requirements, config.testCases);

    res.json(report);
  });

  return app;
};
