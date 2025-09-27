const attributePattern = /([A-Za-z0-9_-]+)="([^"]*)"/g;

const parseAttributes = (source: string): Record<string, string> => {
  const attributes: Record<string, string> = {};
  let match: RegExpExecArray | null;
  while ((match = attributePattern.exec(source)) !== null) {
    attributes[match[1]] = match[2];
  }
  return attributes;
};

const parseLineNodes = (content: string): Array<Record<string, string>> => {
  const lines: Array<Record<string, string>> = [];
  const lineRegex = /<line([^>]*)\/>/g;
  let match: RegExpExecArray | null;
  while ((match = lineRegex.exec(content)) !== null) {
    lines.push(parseAttributes(match[1]));
  }
  return lines;
};

const parseMethods = (
  content: string,
): Array<Record<string, unknown>> | undefined => {
  const methodsSection = content.match(/<methods>([\s\S]*?)<\/methods>/);
  if (!methodsSection) {
    return undefined;
  }
  const methodsContent = methodsSection[1];
  const methodRegex = /<method([^>]*)>([\s\S]*?)<\/method>/g;
  const methods: Array<Record<string, unknown>> = [];
  let match: RegExpExecArray | null;
  while ((match = methodRegex.exec(methodsContent)) !== null) {
    const attributes = parseAttributes(match[1]);
    const linesBlock = match[2].match(/<lines>([\s\S]*?)<\/lines>/);
    const lineNodes = linesBlock ? parseLineNodes(linesBlock[1]) : [];
    methods.push({ ...attributes, lines: { line: lineNodes } });
  }
  return methods.length > 0 ? methods : undefined;
};

const parseClasses = (content: string): Array<Record<string, unknown>> => {
  const classes: Array<Record<string, unknown>> = [];
  const classRegex = /<class([^>]*)>([\s\S]*?)<\/class>/g;
  let match: RegExpExecArray | null;
  while ((match = classRegex.exec(content)) !== null) {
    const attributes = parseAttributes(match[1]);
    const body = match[2];
    const methods = parseMethods(body);
    const bodyWithoutMethods = body.replace(/<methods>[\s\S]*?<\/methods>/g, '');
    const linesBlock = bodyWithoutMethods.match(/<lines>([\s\S]*?)<\/lines>/);
    const lineNodes = linesBlock ? parseLineNodes(linesBlock[1]) : [];
    const entry: Record<string, unknown> = {
      ...attributes,
      lines: { line: lineNodes },
    };
    if (methods) {
      entry.methods = { method: methods };
    }
    classes.push(entry);
  }
  return classes;
};

const parsePackages = (xml: string): Array<Record<string, unknown>> => {
  const packagesSection = xml.match(/<packages>([\s\S]*?)<\/packages>/);
  if (!packagesSection) {
    return [];
  }
  const packagesContent = packagesSection[1];
  const packageRegex = /<package([^>]*)>([\s\S]*?)<\/package>/g;
  const packages: Array<Record<string, unknown>> = [];
  let match: RegExpExecArray | null;
  while ((match = packageRegex.exec(packagesContent)) !== null) {
    const attributes = parseAttributes(match[1]);
    const body = match[2];
    const classesSection = body.match(/<classes>([\s\S]*?)<\/classes>/);
    const classes = classesSection ? parseClasses(classesSection[1]) : [];
    packages.push({ ...attributes, classes: { class: classes } });
  }
  return packages;
};

export class XMLParser {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  constructor(_options?: unknown) {}

  parse(xml: string): Record<string, unknown> {
    const packages = parsePackages(xml);
    return {
      coverage: {
        packages: {
          package: packages,
        },
      },
    };
  }
}
