interface PgClientStub {
  query: (...args: unknown[]) => Promise<unknown>;
  release: () => void;
}

class PoolStub {
  async connect(): Promise<PgClientStub> {
    return {
      query: async () => ({ rows: [] }),
      release: () => undefined,
    };
  }

  async end(): Promise<void> {
    // no-op
  }
}

export const newDb = () => ({
  adapters: {
    createPg: () => ({
      Pool: PoolStub,
    }),
  },
  public: {
    none: async () => undefined,
    one: async () => ({}),
    many: async () => [],
    map: () => undefined,
    registerFunction: () => undefined,
  },
});
