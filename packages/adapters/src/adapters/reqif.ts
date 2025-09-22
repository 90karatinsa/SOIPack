import { createReadStream } from 'fs';
import path from 'path';

import { SaxesParser, SaxesTagPlain } from 'saxes';

import { ParseResult, ReqIFRequirement } from '../types';

interface SpecObjectState {
  id?: string;
  text?: string;
  capturingValue: boolean;
  buffer: string[];
  captured: boolean;
}

const normalize = (value: unknown): string | undefined => {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value === 'string') {
    return value;
  }
  return String(value);
};

const finalizeText = (state: SpecObjectState): void => {
  if (state.captured) {
    return;
  }
  const text = state.buffer.join('').trim();
  if (text.length > 0) {
    state.text = text;
    state.captured = true;
  }
  state.buffer = [];
};

const resolveTagName = (tag: unknown): string => {
  if (typeof tag === 'string') {
    return tag;
  }
  if (tag && typeof (tag as SaxesTagPlain).name === 'string') {
    return (tag as SaxesTagPlain).name;
  }
  return '';
};

export const parseReqifStream = async (filePath: string): Promise<ParseResult<ReqIFRequirement[]>> =>
  new Promise((resolve, reject) => {
    const location = path.resolve(filePath);
    const stream = createReadStream(location, { encoding: 'utf8' });
    const parser = new SaxesParser({ xmlns: false });
    const warnings: string[] = [];
    const requirements: ReqIFRequirement[] = [];
    let current: SpecObjectState | undefined;
    let counter = 0;
    let settled = false;

    parser.on('error', (error) => {
      if (settled) {
        return;
      }
      settled = true;
      parser.close();
      stream.destroy(error as Error);
      reject(new Error(`Invalid ReqIF XML at ${location}: ${(error as Error).message}`));
    });

    parser.on('opentag', (tag: SaxesTagPlain) => {
      const name = tag.name.toUpperCase();
      if (name === 'SPEC-OBJECT') {
        current = {
          id: normalize((tag.attributes as Record<string, unknown>).IDENTIFIER),
          capturingValue: false,
          buffer: [],
          captured: false,
        };
        return;
      }

      if (!current) {
        return;
      }

      if (name === 'THE-VALUE') {
        current.capturingValue = true;
        current.buffer = [];
      }
    });

    parser.on('text', (text) => {
      if (!current || !current.capturingValue) {
        return;
      }
      current.buffer.push(text);
    });

    parser.on('closetag', (tag) => {
      const rawName = resolveTagName(tag);
      if (!rawName) {
        return;
      }
      const name = rawName.toUpperCase();
      if (!current) {
        return;
      }

      if (name === 'THE-VALUE') {
        current.capturingValue = false;
        finalizeText(current);
        return;
      }

      if (name === 'SPEC-OBJECT') {
        if (!current.captured) {
          const text = current.buffer.join('').trim();
          if (text.length > 0) {
            current.text = text;
            current.captured = true;
          }
        }

        counter += 1;
        const id = current.id ?? `item-${counter}`;
        const text = current.text ?? '';
        if (!current.text) {
          warnings.push(`SPEC-OBJECT ${id} does not contain a THE-VALUE entry.`);
        }
        requirements.push({ id, text });
        current = undefined;
      }
    });

    parser.on('end', () => {
      if (settled) {
        return;
      }
      if (current) {
        counter += 1;
        const id = current.id ?? `item-${counter}`;
        const text = current.text ?? '';
        if (!current.text) {
          warnings.push(`SPEC-OBJECT ${id} does not contain a THE-VALUE entry.`);
        }
        requirements.push({ id, text });
      }
      if (requirements.length === 0) {
        warnings.push(`No SPEC-OBJECT entries found in ReqIF file at ${location}.`);
      }
      settled = true;
      resolve({ data: requirements, warnings });
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
        if (settled) {
          return;
        }
        settled = true;
        parser.close();
        stream.destroy(error as Error);
        reject(new Error(`Invalid ReqIF XML at ${location}: ${(error as Error).message}`));
      }
    });
    stream.on('end', () => {
      parser.close();
    });
  });
