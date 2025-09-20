# Objective Mapping Rules

The objective mapper evaluates every DO-178C objective against the evidence that
was imported from adapters. Each objective declares a list of artifact types
(e.g. `psac`, `testResults`) that must be satisfied. The mapper inspects the
bundle's `evidenceIndex` and assigns a coverage status according to the
following rules:

| Condition | Status | Notes |
| --- | --- | --- |
| All required artifact types have at least one matching evidence entry | `covered` | Evidence references are recorded as `<artifactType>:<path>` strings. |
| At least one artifact type is supported but others are missing | `partial` | Gap analysis will list the missing artifact types in their respective category (plan, standard, test, coverage). |
| None of the required artifact types are satisfied | `missing` | The objective is reported as missing and will appear in gap analysis buckets. |

## Example

Consider the following fragment from an `ImportBundle`:

```ts
const bundle = {
  objectives: [
    {
      id: 'A-Verification-Obj1',
      area: 'Verification',
      description: 'Verify implementation with tests and coverage.',
      artifacts: ['testResults', 'coverage'],
      level: { A: true, B: false, C: false, D: false, E: false },
    },
  ],
  evidenceIndex: {
    testResults: [
      { source: 'junit', path: 'reports/junit.xml', summary: 'Test execution', timestamp: '2024-01-10T10:00:00Z' },
    ],
    coverage: [
      { source: 'lcov', path: 'reports/lcov.info', summary: 'Statement coverage', timestamp: '2024-01-10T10:00:00Z' },
    ],
  },
};
```

When the mapper processes this input it produces the following
`ObjectiveCoverage` entry:

```json
{
  "objectiveId": "A-Verification-Obj1",
  "status": "covered",
  "evidenceRefs": [
    "testResults:reports/junit.xml",
    "coverage:reports/lcov.info"
  ],
  "satisfiedArtifacts": ["testResults", "coverage"],
  "missingArtifacts": []
}
```

If the coverage artifact was absent, the status would change to `partial`, and
`missingArtifacts` would include `coverage`. This information feeds the gap
analysis, which groups missing artifacts by the plan, standard, test, and
coverage categories that stakeholders expect in DO-178C assessments.
