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

The generated Markdown captures controls, validation activities, compliance cross-links, and residual
risks for each tool. Pending activities are counted automatically so reviewers can focus on remaining
work.【F:packages/report/src/index.ts†L864-L1007】

### Link compliance context and ledger hashes

Pass the compliance snapshot and ledger hashes through the optional `compliance` block to add live
cross-links to the pack. The generator walks each tool's declared objectives, renders their latest
status badge, independence posture, and any recorded ledger hashes, then appends a residual risk
summary to both the TQP and TAR outputs.【F:packages/report/src/index.ts†L876-L1007】

```ts
const pack = renderToolQualificationPack(toolUsage, {
  programName: 'Flight Control',
  level: 'A',
  author: 'QA Team',
  compliance: {
    snapshot: {
      objectives: snapshot.objectives,
      independenceSummary: snapshot.independenceSummary,
    },
    objectivesMetadata,
    ledgerHashes, // e.g. evidence path -> SHA-256 string
  },
});
```

Both Markdown files now include an "Uyum Bağlantıları" section that lists every referenced objective
with its stage label, compliance status badge, independence alert (highlighting missing artifacts),
and any ledger hashes associated with the supporting evidence. A blockquote-style "Kalıcı Risk Özeti"
is emitted even when no residual risk exists so downstream reviewers can confirm the absence of
remaining concerns.【F:packages/report/src/index.ts†L948-L1007】 The returned `summary.tools[]`
entries also expose `residualRiskCount` and `residualRiskSummary`, enabling the compliance dashboard
to surface the same overview without re-rendering the pack.【F:packages/report/src/index.ts†L910-L934】

### Generate packs from the CLI

The `soipack report` command accepts a `--tool-usage` flag that points to the metadata JSON. When
provided, the CLI writes the rendered plan/report to `reports/tool-qualification/` and persists the
summary inside `analysis.json` alongside the compliance metadata.【F:packages/cli/src/index.ts†L3025-L3124】【F:packages/cli/src/index.test.ts†L828-L880】

```bash
soipack report \
  --input dist/analysis \
  --output dist/reports \
  --tool-usage data/tool-usage.json
```

After the command finishes you will find Markdown files for both the TQP and TAR, a
`toolQualification` entry inside `analysis.json`, and DO-330 links injected into
`compliance.json`/`compliance.html`.

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
the TQP/TAR files and a table that highlights each tool's outputs, open validation tasks, and the
residual risk summary string carried from the pack generator.【F:packages/report/src/index.ts†L1728-L1785】【F:packages/report/src/index.ts†L3094-L3137】

## 4. Verify the workflow

Run the focused Jest suite to ensure tool qualification logic stays intact:

```bash
npm test --workspace @soipack/report -- -t "ToolQualification"
```

This executes the pack-generation and embedding tests so regressions in the workflow are caught during
CI.【F:packages/report/src/index.test.ts†L232-L323】
