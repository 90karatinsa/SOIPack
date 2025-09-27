const shouldRun = (name: string) => /stageRouting/i.test(name);

const wrapIt = (original: typeof it): typeof it => {
  const wrapped = ((name: string, fn: jest.ProvidesCallback, timeout?: number) => {
    if (shouldRun(name)) {
      return original(name, fn, timeout);
    }
    return original.skip(name, fn, timeout);
  }) as typeof it;
  Object.assign(wrapped, original);
  return wrapped;
};

global.it = wrapIt(global.it);
global.test = wrapIt(global.test);

require('./index.test');
