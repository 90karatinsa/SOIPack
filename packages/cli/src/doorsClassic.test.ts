import { promises as fs } from 'fs';
import os from 'os';
import path from 'path';

import { runImport } from './index';

describe('doorsClassic importer', () => {
  it('doorsClassic aggregates CSV exports into requirements and trace links', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'soipack-doors-classic-'));
    try {
      const workDir = path.join(tempDir, 'work');
      const fixtureBase = path.resolve(
        __dirname,
        '../../adapters/src/fixtures/doors-classic',
      );
      const reqsPath = path.join(fixtureBase, 'requirements.sample.csv');
      const tracesPath = path.join(fixtureBase, 'missing-parent.sample.csv');
      const testsPath = path.join(fixtureBase, 'latin1.sample.csv');

      const result = await runImport({
        output: workDir,
        doorsClassicReqs: [reqsPath],
        doorsClassicTraces: [tracesPath],
        doorsClassicTests: [testsPath],
      });

      expect(result.warnings).toEqual(
        expect.arrayContaining([expect.stringContaining('parent absolute number 3')]),
      );

      expect(result.workspace.requirements.map((req) => req.id)).toEqual(
        expect.arrayContaining(['REQ-100', 'REQ-110', 'REQ-111', 'REQ-210', 'REQ-211', 'REQ-300']),
      );

      expect(result.workspace.traceLinks).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ from: 'REQ-110', to: 'REQ-100', type: 'satisfies' }),
          expect.objectContaining({ from: 'REQ-111', to: 'REQ-110', type: 'satisfies' }),
          expect.objectContaining({ from: 'REQ-110', to: 'TC-900', type: 'verifies' }),
          expect.objectContaining({ from: 'REQ-110', to: 'DES-200', type: 'implements' }),
          expect.objectContaining({ from: 'REQ-111', to: 'REQ-200', type: 'satisfies' }),
        ]),
      );

      const traceEvidence = result.workspace.evidenceIndex.trace ?? [];
      expect(traceEvidence.filter((entry) => entry.source === 'doorsClassic')).toHaveLength(3);

      expect(result.workspace.metadata.sources?.doorsClassic).toEqual(
        expect.objectContaining({ modules: 3, requirements: 6, traces: 5 }),
      );

      const workspaceData = JSON.parse(
        await fs.readFile(result.workspacePath, 'utf8'),
      ) as {
        requirements: Array<{ id: string }>;
        traceLinks: Array<{ from: string; to: string; type: string }>;
        metadata: { inputs: Record<string, unknown>; sources?: { doorsClassic?: { modules: number } } };
      };

      expect(workspaceData.traceLinks).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ from: 'REQ-110', to: 'REQ-100', type: 'satisfies' }),
          expect.objectContaining({ from: 'REQ-110', to: 'TC-900', type: 'verifies' }),
        ]),
      );
      const classicInputs = workspaceData.metadata.inputs as Record<string, string[]>;
      expect(classicInputs.doorsClassicReqs).toEqual(
        expect.arrayContaining([
          expect.stringContaining('requirements.sample.csv'),
        ]),
      );
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });
});
