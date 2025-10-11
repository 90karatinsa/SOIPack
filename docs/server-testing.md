# Server Testing Notes

This document captures quick commands for executing the server test suite when iterating on
API endpoints. The full server suite may take a long time to complete, so these focused
commands are handy while validating individual additions.

## Run the full server tests

```sh
npm run test:server
```

> **Note:** If the run appears to stall, re-run the command with `CI=1` to disable
> watch mode behaviour that can keep Jest alive when open handles are detected.

## Run the service metadata and license tests only

```sh
npm run test --workspace @soipack/server -- --runTestsByPath packages/server/src/index.test.ts --testNamePattern "(service metadata|license) endpoint" --runInBand
```

This executes only the scenarios covering the `/v1/service/metadata` and `/v1/license`
endpoints, including cache validation, stale-job detection, and license header enforcement.
