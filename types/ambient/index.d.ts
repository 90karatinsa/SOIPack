declare module 'pg-mem';
declare module 'pg' {
  export class Pool {
    constructor(...args: unknown[]);
    query<T = unknown>(...args: unknown[]): Promise<{ rows: T[]; rowCount?: number }>;
    end(): Promise<void>;
  }

  export const types: {
    setTypeParser: (...args: unknown[]) => void;
  };
}
