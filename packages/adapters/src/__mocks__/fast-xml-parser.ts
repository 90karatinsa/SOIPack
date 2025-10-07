interface SimpleNode {
  name: string;
  attributes: Record<string, string>;
  children: Array<SimpleNode | string>;
}

const parseAttributes = (token: string): { name: string; attributes: Record<string, string> } => {
  const trimmed = token.trim();
  const spaceIndex = trimmed.search(/\s/);
  const name = spaceIndex === -1 ? trimmed : trimmed.slice(0, spaceIndex);
  const rest = spaceIndex === -1 ? '' : trimmed.slice(spaceIndex + 1);
  const attributes: Record<string, string> = {};
  const attrPattern = /([^\s=]+)\s*=\s*("([^"]*)"|'([^']*)')/g;
  let match: RegExpExecArray | null;
  while ((match = attrPattern.exec(rest)) !== null) {
    const [, key, , doubleQuoted, singleQuoted] = match;
    const value = doubleQuoted ?? singleQuoted ?? '';
    attributes[key] = value;
  }
  return { name, attributes };
};

const buildObject = (node: SimpleNode): Record<string, unknown> => {
  const result: Record<string, unknown> = { ...node.attributes };
  const textParts: string[] = [];
  const groups = new Map<string, unknown[]>();

  node.children.forEach((child) => {
    if (typeof child === 'string') {
      const trimmed = child.trim();
      if (trimmed) {
        textParts.push(trimmed);
      }
      return;
    }
    const childValue = buildObject(child);
    const bucket = groups.get(child.name) ?? [];
    bucket.push(childValue);
    groups.set(child.name, bucket);
  });

  groups.forEach((items, key) => {
    result[key] = items.length === 1 ? items[0] : items;
  });

  if (textParts.length > 0) {
    result['#text'] = textParts.join(' ');
  }

  return result;
};

const createNode = (name: string, attributes: Record<string, string>): SimpleNode => ({
  name,
  attributes,
  children: [],
});

export class XMLParser {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  constructor(_options?: unknown) {}

  public parse(content: string): Record<string, unknown> {
    const root: SimpleNode = createNode('root', {});
    const stack: SimpleNode[] = [root];
    const tagPattern = /<([^>]+)>/g;
    let lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = tagPattern.exec(content)) !== null) {
      const textChunk = content.slice(lastIndex, match.index);
      if (textChunk.trim()) {
        stack[stack.length - 1]?.children.push(textChunk);
      }
      const raw = match[1]?.trim() ?? '';
      lastIndex = tagPattern.lastIndex;
      if (!raw) {
        continue;
      }
      if (raw.startsWith('?') || raw.startsWith('!')) {
        continue;
      }
      if (raw.startsWith('/')) {
        const name = raw.slice(1).trim();
        const node = stack.pop();
        if (!node || node.name !== name) {
          throw new Error(`Unexpected closing tag </${name}>`);
        }
        continue;
      }
      const selfClosing = raw.endsWith('/');
      const token = selfClosing ? raw.slice(0, -1) : raw;
      const { name, attributes } = parseAttributes(token);
      const node = createNode(name, attributes);
      const parent = stack[stack.length - 1];
      parent.children.push(node);
      if (!selfClosing) {
        stack.push(node);
      }
    }

    const trailing = content.slice(lastIndex);
    if (trailing.trim()) {
      stack[stack.length - 1]?.children.push(trailing);
    }

    if (stack.length !== 1) {
      throw new Error('Malformed XML content.');
    }

    const result: Record<string, unknown> = {};
    root.children.forEach((child) => {
      if (typeof child === 'string') {
        return;
      }
      const value = buildObject(child);
      const existing = result[child.name];
      if (existing === undefined) {
        result[child.name] = value;
      } else if (Array.isArray(existing)) {
        existing.push(value);
      } else {
        result[child.name] = [existing, value];
      }
    });

    return result;
  }
}
