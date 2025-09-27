declare module 'nunjucks' {
  export class Environment {
    constructor(paths?: string | string[], options?: unknown);
    renderString(template: string, context?: unknown): string;
  }

  export function configure(paths?: string | string[], options?: unknown): Environment;

  export interface Template {
    render(context?: unknown): string;
  }

  export function compile(template: string, env?: Environment): Template;

  const nunjucks: {
    Environment: typeof Environment;
    configure: typeof configure;
    renderString(template: string, context?: Record<string, unknown>): string;
    compile: typeof compile;
  };

  export default nunjucks;
}
