# Risk and Readiness

SOIPack blends traditional compliance evidence with live quality signals to keep audit teams aware of emerging risk.
The readiness index extends that view by collapsing multiple certification drivers into a single, explainable
percentile score.

## Readiness Index

The readiness index expresses how close a program is to audit readiness on a 0-100 percentile scale. It combines
objective coverage, independence health, structural coverage, and recent risk trends into a weighted score so
audit leads can quickly triage where to invest verification effort.

### Inputs

The engine pulls four normalized component scores before weighting:

- **Objectives** – ratio of satisfied DO-178C objectives versus partial/missing objectives at the target level.
- **Independence** – severity of independence deficits, penalizing required objectives without independent evidence.
- **Structural coverage** – structural coverage quality across statement, branch/decision, and MC/DC metrics.
- **Risk trend** – recent change impact, audit flags, and risk delta projections produced by the risk forecaster.

Each component returns a value between 0 and 100 plus a "missing" flag when data is unavailable. Missing signals
contribute zero to the final score but are surfaced in reports and JSON exports so remediation can be tracked.

### Formula

The readiness percentile is a weighted sum of component scores:

```
percentile = Σ(score_component × weight_component)
```

Scores are first converted to the 0-1 range, multiplied by the normalized component weight, and then re-scaled to
percentile points. The JSON and CSV exports include the exact contribution for each component so teams can audit the
calculation and explain it to certification authorities.

### Default weights

Unless overridden in engine configuration, the component weights are:

| Component             | Weight |
|---------------------- |-------:|
| Objectives            | 0.40   |
| Independence          | 0.20   |
| Structural coverage   | 0.25   |
| Risk trend            | 0.15   |

Weights are normalized internally, so custom weights do not need to add up to 1.0. Contributions shown in reports
reflect the normalized values after the engine has applied any overrides.

### Interpretation guidance

Use the readiness percentile as an overlay to traditional compliance dashboards:

- **≥ 85** – certification evidence is audit-ready; remaining work should focus on documentation polish.
- **70 – 85** – mostly ready; review flagged components for independence gaps or residual risk trends.
- **50 – 70** – caution; prioritize closing missing objectives and structural coverage debt before formal reviews.
- **< 50** – high risk; build a mitigation plan and capture recovery actions in change request and audit tracking tools.

When components are marked "veri eksik" (data missing), treat the readiness percentile as a lower bound and close the
data gap before using the score for go/no-go decisions.

### Reproducibility

The readiness engine seeds its random tie-breaking logic for deterministic output (default seed `1337`). Reports and
API payloads include the seed alongside the percentile and component breakdown so independent reviewers can reproduce
the score with the same inputs.
