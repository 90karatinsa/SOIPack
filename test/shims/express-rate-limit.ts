type RequestHandler = (...args: unknown[]) => unknown;

const createRateLimit = (): RequestHandler => (_req, _res, next) => next();

export default createRateLimit;
