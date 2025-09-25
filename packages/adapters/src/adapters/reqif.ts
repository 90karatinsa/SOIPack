import { createReadStream } from 'fs';
import path from 'path';
import { Readable } from 'stream';

import { SaxesParser, SaxesTagPlain } from 'saxes';

import { ParseResult, ReqIFRequirement } from '../types';

interface InternalRequirement {
  id: string;
  title?: string;
  shortName?: string;
  descriptionHtml?: string;
  text?: string;
  parentId?: string;
  childrenIds: Set<string>;
  tracesTo: Set<string>;
}

interface SpecObjectState {
  id?: string;
  capturingLongName: boolean;
  capturingShortName: boolean;
  longNameBuffer: string[];
  shortNameBuffer: string[];
  capturingStringValue: boolean;
  stringValueBuffer: string[];
  stringValueSegments: string[];
  capturingStringText: boolean;
  capturingXhtml: boolean;
  xhtmlHtmlParts: string[];
  xhtmlTextParts: string[];
  inXhtmlValue: boolean;
  xhtmlHtmlSegments: string[];
  xhtmlTextSegments: string[];
}

interface HierarchyNode {
  parentId?: string;
  objectId?: string;
}

const escapeHtml = (value: string): string =>
  value
    .replace(/&/gu, '&amp;')
    .replace(/</gu, '&lt;')
    .replace(/>/gu, '&gt;')
    .replace(/"/gu, '&quot;')
    .replace(/'/gu, '&#39;');

const normalizeWhitespace = (value: string): string => value.replace(/\s+/gu, ' ').trim();

const toOpenTag = (tag: SaxesTagPlain): string => {
  const name = tag.name;
  const attributes = Object.entries(tag.attributes as Record<string, unknown>)
    .map(([key, raw]) => `${key}="${escapeHtml(String(raw))}"`)
    .join(' ');
  const renderedAttributes = attributes ? ` ${attributes}` : '';
  return `<${name}${renderedAttributes}>`;
};

const toCloseTag = (tagName: string): string => `</${tagName}>`;

const ensureRequirement = (
  map: Map<string, InternalRequirement>,
  identifier: string,
): InternalRequirement => {
  const existing = map.get(identifier);
  if (existing) {
    return existing;
  }
  const created: InternalRequirement = {
    id: identifier,
    childrenIds: new Set<string>(),
    tracesTo: new Set<string>(),
  };
  map.set(identifier, created);
  return created;
};

const finalizeRequirementState = (
  requirements: Map<string, InternalRequirement>,
  state: SpecObjectState,
  warnings: string[],
  counter: { value: number },
): void => {
  let identifier = state.id?.trim();
  if (!identifier) {
    counter.value += 1;
    identifier = `item-${counter.value}`;
    warnings.push(`SPEC-OBJECT without IDENTIFIER found; generated id ${identifier}.`);
  }

  const requirement = ensureRequirement(requirements, identifier);

  const longName = normalizeWhitespace(state.longNameBuffer.join(' '));
  const shortName = normalizeWhitespace(state.shortNameBuffer.join(' '));
  const textValue = normalizeWhitespace(
    [...state.stringValueSegments, state.stringValueBuffer.join(' ')].join(' '),
  );
  const html = state.xhtmlHtmlSegments.map((segment) => segment.trim()).filter(Boolean).join('');
  const textFromHtml = normalizeWhitespace(state.xhtmlTextSegments.join(' '));
  const combinedText = normalizeWhitespace([textFromHtml, textValue].filter(Boolean).join(' '));

  if (longName) {
    requirement.title = longName;
  }
  if (shortName) {
    requirement.shortName = shortName;
  }
  const descriptionText = combinedText || textFromHtml || textValue;
  if (descriptionText) {
    requirement.text = descriptionText;
  }
  if (html) {
    requirement.descriptionHtml = html;
  } else if (descriptionText && !requirement.descriptionHtml) {
    requirement.descriptionHtml = escapeHtml(descriptionText);
  }
  if (!requirement.title) {
    requirement.title = requirement.shortName ?? descriptionText ?? identifier;
  }
};

const parseReqifReadable = async (
  stream: Readable,
  location: string,
): Promise<ParseResult<ReqIFRequirement[]>> =>
  new Promise((resolve, reject) => {
    const parser = new SaxesParser({ xmlns: false });
    const requirements = new Map<string, InternalRequirement>();
    const warnings: string[] = [];
    const hierarchyStack: HierarchyNode[] = [];
    const counter = { value: 0 };

    let currentSpecObject: SpecObjectState | undefined;
    let settled = false;
    let objectRefContext: 'hierarchy' | 'relation-source' | 'relation-target' | undefined;
    let objectRefBuffer: string[] = [];
    let currentRelation:
      | undefined
      | {
          source?: string;
          target?: string;
          capturing: 'SOURCE' | 'TARGET' | undefined;
        };

    const closeWithError = (error: Error): void => {
      if (settled) {
        return;
      }
      settled = true;
      parser.close();
      stream.destroy(error);
      reject(new Error(`Invalid ReqIF XML at ${location}: ${error.message}`));
    };

    parser.on('error', (error) => {
      closeWithError(error as Error);
    });

    parser.on('opentag', (tag: SaxesTagPlain) => {
      const name = tag.name.toUpperCase();

      if (name === 'SPEC-OBJECT') {
        currentSpecObject = {
          id: normalizeWhitespace(String((tag.attributes as Record<string, unknown>).IDENTIFIER ?? '')) || undefined,
          capturingLongName: false,
          capturingShortName: false,
          longNameBuffer: [],
          shortNameBuffer: [],
          capturingStringValue: false,
          stringValueBuffer: [],
          stringValueSegments: [],
          capturingStringText: false,
          capturingXhtml: false,
          xhtmlHtmlParts: [],
          xhtmlTextParts: [],
          inXhtmlValue: false,
          xhtmlHtmlSegments: [],
          xhtmlTextSegments: [],
        };
        return;
      }

      if (currentSpecObject) {
        if (name === 'LONG-NAME') {
          currentSpecObject.capturingLongName = true;
          currentSpecObject.longNameBuffer = [];
          return;
        }
        if (name === 'SHORT-NAME') {
          currentSpecObject.capturingShortName = true;
          currentSpecObject.shortNameBuffer = [];
          return;
        }
        if (!currentSpecObject.capturingXhtml && name === 'ATTRIBUTE-VALUE-XHTML') {
          currentSpecObject.inXhtmlValue = true;
          currentSpecObject.xhtmlHtmlParts = [];
          currentSpecObject.xhtmlTextParts = [];
          return;
        }
        if (!currentSpecObject.capturingStringValue && name === 'ATTRIBUTE-VALUE-STRING') {
          currentSpecObject.capturingStringValue = true;
          currentSpecObject.stringValueBuffer = [];
          return;
        }
        if (currentSpecObject.inXhtmlValue && name === 'THE-VALUE') {
          currentSpecObject.capturingXhtml = true;
          return;
        }
        if (currentSpecObject.capturingStringValue && name === 'THE-VALUE') {
          currentSpecObject.capturingStringText = true;
          return;
        }
        if (
          currentSpecObject.capturingXhtml &&
          !['THE-VALUE', 'ATTRIBUTE-VALUE-XHTML', 'ATTRIBUTE-VALUE-STRING'].includes(name)
        ) {
          currentSpecObject.xhtmlHtmlParts.push(toOpenTag(tag));
          return;
        }
      }

      if (name === 'SPEC-HIERARCHY') {
        const parentId = hierarchyStack.length > 0 ? hierarchyStack[hierarchyStack.length - 1].objectId : undefined;
        hierarchyStack.push({ parentId });
        return;
      }

      if (name === 'SPEC-RELATION') {
        currentRelation = { capturing: undefined };
        return;
      }

      if (name === 'SOURCE' && currentRelation) {
        currentRelation.capturing = 'SOURCE';
        return;
      }

      if (name === 'TARGET' && currentRelation) {
        currentRelation.capturing = 'TARGET';
        return;
      }

      if (name === 'SPEC-OBJECT-REF') {
        if (currentRelation?.capturing === 'SOURCE') {
          objectRefContext = 'relation-source';
          objectRefBuffer = [];
          return;
        }
        if (currentRelation?.capturing === 'TARGET') {
          objectRefContext = 'relation-target';
          objectRefBuffer = [];
          return;
        }
        if (hierarchyStack.length > 0) {
          objectRefContext = 'hierarchy';
          objectRefBuffer = [];
        }
        return;
      }

      if (
        currentSpecObject?.capturingXhtml &&
        !['THE-VALUE', 'ATTRIBUTE-VALUE-XHTML', 'ATTRIBUTE-VALUE-STRING'].includes(name)
      ) {
        currentSpecObject.xhtmlHtmlParts.push(toOpenTag(tag));
      }
    });

    const appendText = (text: string): void => {
      if (currentSpecObject) {
        if (currentSpecObject.capturingLongName) {
          currentSpecObject.longNameBuffer.push(text);
        } else if (currentSpecObject.capturingShortName) {
          currentSpecObject.shortNameBuffer.push(text);
        } else if (currentSpecObject.capturingStringText) {
          currentSpecObject.stringValueBuffer.push(text);
        }
        if (currentSpecObject.capturingXhtml) {
          currentSpecObject.xhtmlHtmlParts.push(escapeHtml(text));
          currentSpecObject.xhtmlTextParts.push(text);
        }
      }
      if (objectRefContext) {
        objectRefBuffer.push(text);
      }
    };

    parser.on('text', appendText);
    (parser as unknown as { on: (event: 'cdata', handler: (value: string) => void) => SaxesParser }).on(
      'cdata',
      appendText,
    );

    (parser as unknown as {
      on: (event: 'closetag', handler: (tag: string | SaxesTagPlain) => void) => SaxesParser;
    }).on('closetag', (rawTag: string | SaxesTagPlain) => {
      const tagName = typeof rawTag === 'string' ? rawTag : rawTag.name;
      const name = tagName.toUpperCase();

      if (currentSpecObject) {
        if (name === 'LONG-NAME') {
          currentSpecObject.capturingLongName = false;
        } else if (name === 'SHORT-NAME') {
          currentSpecObject.capturingShortName = false;
        } else if (name === 'THE-VALUE' && currentSpecObject.capturingXhtml) {
          currentSpecObject.capturingXhtml = false;
        } else if (name === 'THE-VALUE' && currentSpecObject.capturingStringText) {
          currentSpecObject.capturingStringText = false;
        } else if (name === 'ATTRIBUTE-VALUE-XHTML' && currentSpecObject.inXhtmlValue) {
          currentSpecObject.inXhtmlValue = false;
          if (currentSpecObject.xhtmlHtmlParts.length > 0) {
            currentSpecObject.xhtmlHtmlSegments.push(currentSpecObject.xhtmlHtmlParts.join(''));
          }
          if (currentSpecObject.xhtmlTextParts.length > 0) {
            currentSpecObject.xhtmlTextSegments.push(currentSpecObject.xhtmlTextParts.join(' '));
          }
          currentSpecObject.xhtmlHtmlParts = [];
          currentSpecObject.xhtmlTextParts = [];
        } else if (name === 'ATTRIBUTE-VALUE-STRING' && currentSpecObject.capturingStringValue) {
          currentSpecObject.capturingStringValue = false;
          if (currentSpecObject.stringValueBuffer.length > 0) {
            currentSpecObject.stringValueSegments.push(currentSpecObject.stringValueBuffer.join(' '));
          }
          currentSpecObject.stringValueBuffer = [];
        } else if (
          currentSpecObject.capturingXhtml &&
          !['THE-VALUE', 'ATTRIBUTE-VALUE-XHTML', 'ATTRIBUTE-VALUE-STRING'].includes(name)
        ) {
          currentSpecObject.xhtmlHtmlParts.push(toCloseTag(tagName));
        }
      }

      if (name === 'SPEC-OBJECT') {
        if (currentSpecObject) {
          finalizeRequirementState(requirements, currentSpecObject, warnings, counter);
        }
        currentSpecObject = undefined;
        return;
      }

      if (name === 'SPEC-HIERARCHY') {
        hierarchyStack.pop();
        return;
      }

      if (name === 'SPEC-OBJECT-REF' && objectRefContext) {
        const identifier = normalizeWhitespace(objectRefBuffer.join(' '));
        if (identifier) {
          if (objectRefContext === 'hierarchy') {
            const node = hierarchyStack[hierarchyStack.length - 1];
            node.objectId = identifier;
            if (node.parentId) {
              const parentRequirement = ensureRequirement(requirements, node.parentId);
              const childRequirement = ensureRequirement(requirements, identifier);
              parentRequirement.childrenIds.add(identifier);
              if (!childRequirement.parentId) {
                childRequirement.parentId = node.parentId;
              }
            } else {
              ensureRequirement(requirements, identifier);
            }
          } else if (objectRefContext === 'relation-source') {
            currentRelation = currentRelation ?? { capturing: undefined };
            currentRelation.source = identifier;
          } else if (objectRefContext === 'relation-target') {
            currentRelation = currentRelation ?? { capturing: undefined };
            currentRelation.target = identifier;
          }
        }
        objectRefContext = undefined;
        objectRefBuffer = [];
        return;
      }

      if (name === 'SOURCE' && currentRelation) {
        currentRelation.capturing = undefined;
        return;
      }

      if (name === 'TARGET' && currentRelation) {
        currentRelation.capturing = undefined;
        return;
      }

      if (name === 'SPEC-RELATION' && currentRelation) {
        if (currentRelation.source && currentRelation.target) {
          const sourceRequirement = ensureRequirement(requirements, currentRelation.source);
          sourceRequirement.tracesTo.add(currentRelation.target);
          ensureRequirement(requirements, currentRelation.target);
        }
        currentRelation = undefined;
      }
    });

    parser.on('end', () => {
      if (settled) {
        return;
      }
      if (currentSpecObject) {
        finalizeRequirementState(requirements, currentSpecObject, warnings, counter);
      }
      if (requirements.size === 0) {
        warnings.push(`No SPEC-OBJECT entries found in ReqIF file at ${location}.`);
      }
      settled = true;
      resolve({
        data: Array.from(requirements.values()).map((entry) => ({
          id: entry.id,
          title: entry.title ?? entry.id,
          shortName: entry.shortName,
          descriptionHtml: entry.descriptionHtml,
          text: entry.text,
          parentId: entry.parentId,
          childrenIds: Array.from(entry.childrenIds),
          tracesTo: Array.from(entry.tracesTo),
        })),
        warnings,
      });
    });

    stream.on('error', (error) => {
      if (settled) {
        return;
      }
      settled = true;
      reject(new Error(`Unable to read ${location}: ${(error as Error).message}`));
    });

    stream.on('data', (chunk) => {
      try {
        const payload = typeof chunk === 'string' ? chunk : chunk.toString();
        parser.write(payload);
      } catch (error) {
        closeWithError(error as Error);
      }
    });

    stream.on('end', () => {
      parser.close();
    });

    if (typeof (stream as Readable & { setEncoding?: (encoding: string) => void }).setEncoding === 'function') {
      (stream as Readable & { setEncoding?: (encoding: string) => void }).setEncoding('utf8');
    }
  });

export const parseReqifStream = async (filePath: string): Promise<ParseResult<ReqIFRequirement[]>> => {
  const location = path.resolve(filePath);
  const stream = createReadStream(location, { encoding: 'utf8' });
  return await parseReqifReadable(stream, location);
};

export const parseReqifFromReadable = async (
  readable: Readable,
  location: string,
): Promise<ParseResult<ReqIFRequirement[]>> => parseReqifReadable(readable, location);
