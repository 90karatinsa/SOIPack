# Performance Benchmark

This benchmark exercises the traceability engine and the server job queue with large synthetic datasets to confirm that recent streaming optimizations keep memory consumption low while preserving throughput.

## Methodology

- **Script**: `npm run benchmark` executes `scripts/benchmark.ts`.
- **Datasets**:
  - Baseline: 5 000 requirements / 10 000 tests.
  - Target: 50 000 requirements / 100 000 tests.
- **Engine workload**: builds a `TraceEngine` bundle and iterates requirement coverage via the new streaming API to avoid materialising large arrays.
- **Server workload**: creates an ephemeral `JobQueue` populated via `adoptCompleted` and streams summaries using the new iterator to avoid per-tenant array copies.
- **Metrics**: `process.memoryUsage().rss` sampling for peak memory and elapsed wall-clock time per workload.

## Results

| Scenario  | Engine Duration | Engine Peak Memory | Server Duration | Server Peak Memory | Completed Jobs | Coverage Rate |
|-----------|-----------------|--------------------|-----------------|--------------------|----------------|---------------|
| Baseline  | 0.26 s          | 127 MB             | 0.30 s          | 157 MB             | 15 000         | 80.00 %       |
| Target    | 2.12 s          | 248 MB             | 1.94 s          | 312 MB             | 150 000        | 80.00 %       |

- **Target scenario totals**: 4.06 s combined duration, 312 MB peak RSS.
- Acceptance criteria satisfied: peak memory < 1 GB and total runtime < 60 s for 50k/100k dataset.

## Running the benchmark

```bash
npm run benchmark
```

The command prints per-scenario measurements and validates the threshold for the target dataset.
