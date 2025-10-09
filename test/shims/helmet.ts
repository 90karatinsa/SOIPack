type RequestHandler = (...args: unknown[]) => unknown;

const helmet = (): RequestHandler => (_req, _res, next) => next();

export default helmet;
