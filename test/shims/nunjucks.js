class FileSystemLoader {
  constructor() {}
}

class Environment {
  constructor() {}
  addFilter() {}
  addGlobal() {}
  render() {
    return '';
  }
  renderString() {
    return '';
  }
}

const configure = () => new Environment();

const compile = () => ({
  render: () => '',
});

const nunjucks = {
  FileSystemLoader,
  Environment,
  configure,
  renderString: () => '',
  compile,
};

module.exports = nunjucks;
module.exports.default = nunjucks;
module.exports.FileSystemLoader = FileSystemLoader;
module.exports.Environment = Environment;
module.exports.configure = configure;
module.exports.compile = compile;
module.exports.renderString = () => '';
