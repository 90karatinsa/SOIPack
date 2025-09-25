# Tool Qualification Pack Workflow

SOIPack now produces a DO-330 Tool Qualification Pack (TQP/TAR) directly from the tool usage
metadata that accompanies a workspace. The pack helps teams summarise how verification tools are
classified, controlled, and validated when preparing evidence for certification reviews.

## 1. Describe the tools you rely on

Create an array of tool usage descriptors following the `ToolUsageMetadata` structure. Each entry
captures the tool identity, intended objectives, produced artefacts, mitigation controls, and
validation activities.【F:packages/report/src/index.ts†L213-L268】 A minimal example:

```jsonc
[
  {
    "id": "tool-vectorcast",
    "name": "VectorCAST",
    "version": "2023R1",
    "vendor": "Vector Informatik",
    "category": "verification",
    "tql": "TQL-4",
    "objectives": ["DO-178C A-5-08", "DO-178C A-5-10"],
    "outputs": [
      {
        "name": "Coverage Merge",
        "description": "MC/DC kapsam çıktısını tekleştirir",
        "producedArtifacts": ["coverage_mcdc", "coverage_dec"]
      }
    ],
    "controls": [
      {
        "id": "CTRL-1",
        "description": "Kapsam scripti gözden geçirilir",
        "owner": "Verification Lead",
        "frequency": "Her sürüm"
      }
    ],
    "validation": [
      {
        "id": "VAL-1",
        "description": "Baz dataset ile sonuç karşılaştırması",
        "method": "Bağımsız veri tekrar yürütmesi",
        "expectedResult": "%1 altında fark",
        "status": "passed"
      }
    ]
  }
]
```

Store this array inside your workspace metadata or export it as a standalone JSON file that the
report generator can consume.

## 2. Generate the Tool Qualification Pack

Invoke `renderToolQualificationPack` with the metadata to produce Markdown outlines for the plan and
accomplishment report. The helper returns filenames and a summary that can be reused elsewhere in the
pipeline.【F:packages/report/src/index.ts†L296-L360】【F:packages/report/src/index.ts†L362-L406】

```ts
import { renderToolQualificationPack } from '@soipack/report';

const pack = renderToolQualificationPack(toolUsage, {
  programName: 'Flight Control',
  level: 'A',
  author: 'QA Team',
});

await fs.promises.writeFile(`reports/${pack.tqp.filename}`, pack.tqp.content);
await fs.promises.writeFile(`reports/${pack.tar.filename}`, pack.tar.content);
```

The generated Markdown captures controls, validation activities, open items, and residual risks for
each tool. Pending activities are counted automatically so reviewers can focus on remaining work.

## 3. Embed links in compliance reports

Pass the pack summary to `renderComplianceMatrix` (and other report renderers) through the
`toolQualification` option to surface DO-330 links alongside the usual risk and objective summary. The
HTML renderer lists each tool, its proposed TQL, and outstanding activities, while the JSON payload
stores the same metadata for downstream automation.【F:packages/report/src/index.ts†L310-L347】【F:packages/report/src/index.ts†L472-L515】

```ts
const report = renderComplianceMatrix(snapshot, {
  manifestId: manifest.id,
  objectivesMetadata,
  signoffs,
  toolQualification: {
    tqpHref: pack.tqp.filename,
    tarHref: pack.tar.filename,
    generatedAt: pack.summary.generatedAt,
    tools: pack.summary.tools,
  },
});

await fs.promises.writeFile('reports/compliance_matrix.html', report.html);
await fs.promises.writeFile('reports/compliance_matrix.json', JSON.stringify(report.json, null, 2));
```

The compliance report will show a new "DO-330 Araç Niteliklendirme" section containing quick links to
the TQP/TAR files and a table that highlights each tool's outputs and any open validation tasks.

## 4. Verify the workflow

Run the focused Jest suite to ensure tool qualification logic stays intact:

```bash
npm test --workspace @soipack/report -- -t "ToolQualification"
```

This executes the pack-generation and embedding tests so regressions in the workflow are caught during
CI.【F:packages/report/src/index.test.ts†L232-L323】
