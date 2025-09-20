import pino from 'pino';

export type Logger = pino.Logger;

export interface LoggerOptions {
  verbose?: boolean;
}

export const createLogger = (options: LoggerOptions = {}): Logger => {
  const level = options.verbose ? 'debug' : 'info';

  return pino({
    level,
    base: undefined,
    timestamp: pino.stdTimeFunctions.isoTime,
  });
};
