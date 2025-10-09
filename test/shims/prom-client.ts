export class Counter {
  constructor(_options: unknown) {}
  inc(): void {}
}

export class Gauge {
  constructor(_options: unknown) {}
  set(): void {}
}

export class Histogram {
  constructor(_options: unknown) {}
  observe(): void {}
}

export class Registry {
  registerMetric(): void {}
}

export const collectDefaultMetrics = (): void => {};
