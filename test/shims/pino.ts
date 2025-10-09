const noop = () => undefined;

const createLogger = () => ({
  info: noop,
  error: noop,
  warn: noop,
  debug: noop,
  child: () => createLogger(),
});

export default createLogger;
