type CommandConstructor = new (...args: unknown[]) => { input?: unknown };

export interface MockedClient {
  reset: () => void;
  on: (command: CommandConstructor) => {
    resolves: (value: unknown) => void;
  };
  commandCalls: (command: CommandConstructor) => Array<{ args: [{ input: unknown }] }>;
}

export const mockClient = (_client: new (...args: unknown[]) => unknown): MockedClient => {
  return {
    reset: () => undefined,
    on: () => ({
      resolves: () => undefined,
    }),
    commandCalls: () => [],
  };
};
