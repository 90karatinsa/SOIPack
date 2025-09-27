import { promises as fs } from 'fs';
import os from 'os';
import path from 'path';

jest.mock(
  'yauzl',
  () => ({
    open: jest.fn(),
    fromBuffer: jest.fn(),
    ZipFile: function MockZipFile() {},
  }),
  { virtual: true },
);

jest.mock(
  'saxes',
  () => {
    class MockSaxesParser {
      // eslint-disable-next-line @typescript-eslint/no-empty-function
      on() {}
      write() {
        return this;
      }
      // eslint-disable-next-line @typescript-eslint/no-empty-function
      close() {}
    }
    return { SaxesParser: MockSaxesParser, SaxesTagPlain: class {} };
  },
  { virtual: true },
);

jest.mock(
  'fast-xml-parser',
  () => ({
    XMLParser: class {
      parse() {
        return {};
      }
    },
  }),
  { virtual: true },
);

jest.mock('@soipack/report', () => {
  const actual = jest.requireActual('@soipack/report');
  return {
    ...actual,
    planTemplateSections: {},
    planTemplateTitles: {},
    renderPlanDocument: jest.fn().mockResolvedValue({
      html: '<html></html>',
      docx: Buffer.alloc(0),
      title: 'Stub Plan',
    }),
    renderPlanPdf: jest.fn().mockResolvedValue(Buffer.alloc(0)),
    printToPDF: jest.fn().mockResolvedValue(Buffer.alloc(0)),
  };
});

jest.setTimeout(60000);

import { createSnapshotVersion } from '@soipack/core';

import { exitCodes, runAnalyze, runReport } from './index';

describe('cli stage filtering', () => {
  let tempRoot: string;

  beforeAll(async () => {
    tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'soipack-stage-'));
  });

  afterAll(async () => {
    await fs.rm(tempRoot, { recursive: true, force: true });
  });

  it('filters analysis and report outputs to the selected SOI stage', async () => {
    const stageWorkDir = path.join(tempRoot, 'workspace');
    const stageAnalysisDir = path.join(tempRoot, 'analysis');
    const stageReportDir = path.join(tempRoot, 'reports');
    const stage = 'SOI-2' as const;

    await fs.mkdir(stageWorkDir, { recursive: true });
    await fs.mkdir(stageAnalysisDir, { recursive: true });
    await fs.mkdir(stageReportDir, { recursive: true });

    const stageObjectivesPath = path.join(stageWorkDir, 'objectives.json');
    const objectivesCatalog = [
      {
        id: 'A-3-01',
        table: 'A-3',
        stage: 'SOI-2',
        name: 'SOI-2 Objective',
        desc: 'Stage two objective.',
        artifacts: ['plan'],
        levels: { A: true, B: true, C: true, D: true, E: true },
        independence: 'none',
      },
      {
        id: 'A-3-02',
        table: 'A-3',
        stage: 'SOI-3',
        name: 'SOI-3 Objective',
        desc: 'Stage three objective.',
        artifacts: ['plan'],
        levels: { A: true, B: true, C: true, D: true, E: true },
        independence: 'none',
      },
    ];
    await fs.writeFile(stageObjectivesPath, JSON.stringify(objectivesCatalog, null, 2), 'utf8');

    const workspace = {
      requirements: [],
      designs: [],
      testResults: [],
      coverage: undefined,
      structuralCoverage: undefined,
      traceLinks: [],
      testToCodeMap: {},
      evidenceIndex: {},
      git: null,
      findings: [],
      builds: [],
      metadata: {
        generatedAt: new Date().toISOString(),
        warnings: [],
        inputs: {},
        project: { name: 'Demo Avionics', version: '1.0.0' },
        targetLevel: 'C',
        objectivesPath: stageObjectivesPath,
        version: createSnapshotVersion('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'),
      },
    };
    await fs.writeFile(
      path.join(stageWorkDir, 'workspace.json'),
      JSON.stringify(workspace, null, 2),
      'utf8',
    );

    const analysisResult = await runAnalyze({
      input: stageWorkDir,
      output: stageAnalysisDir,
      level: 'C',
      objectives: stageObjectivesPath,
      projectName: 'Demo Avionics',
      projectVersion: '1.0.0',
      stage,
    });

    expect([exitCodes.success, exitCodes.missingEvidence]).toContain(analysisResult.exitCode);

    const analysisData = JSON.parse(
      await fs.readFile(path.join(stageAnalysisDir, 'analysis.json'), 'utf8'),
    ) as {
      metadata: { stage?: string };
      objectives: Array<{ id: string; stage: string }>;
    };
    expect(analysisData.metadata.stage).toBe(stage);
    expect(analysisData.objectives).not.toHaveLength(0);
    analysisData.objectives.forEach((objective) => {
      expect(objective.stage).toBe(stage);
    });

    const expectedObjectiveIds = objectivesCatalog
      .filter((objective) => objective.levels.C && objective.stage === stage)
      .map((objective) => objective.id)
      .sort();
    const analysisObjectiveIds = analysisData.objectives.map((objective) => objective.id).sort();
    expect(analysisObjectiveIds).toEqual(expectedObjectiveIds);

    const reportResult = await runReport({
      input: stageAnalysisDir,
      output: stageReportDir,
      stage,
    });

    const complianceData = JSON.parse(
      await fs.readFile(reportResult.complianceJson, 'utf8'),
    ) as {
      stages: Array<{ id: string }>;
      objectives: Array<{ id: string }>;
    };
    expect(complianceData.stages.map((entry) => entry.id)).toEqual(['all', stage]);
    const complianceObjectiveIds = complianceData.objectives.map((entry) => entry.id).sort();
    expect(complianceObjectiveIds).toEqual(expectedObjectiveIds);
  });
});
