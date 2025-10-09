export type SaxesTagPlain = {
  name: string;
  attributes: Record<string, string>;
};

type EventHandler = (...args: unknown[]) => void;

export class SaxesParser {
  private readonly handlers: Record<string, EventHandler[]> = {};

  private buffer = '';

  constructor(_options?: unknown) {}

  on(event: string, handler: EventHandler): this {
    if (!this.handlers[event]) {
      this.handlers[event] = [];
    }
    this.handlers[event].push(handler);
    return this;
  }

  write(chunk: string): this {
    this.buffer += chunk;
    return this;
  }

  private emit(event: string, ...args: unknown[]): void {
    const handlers = this.handlers[event] ?? [];
    handlers.forEach((handler) => {
      try {
        handler(...args);
      } catch {
        // Ignore handler errors to mimic lenient sax behavior in tests.
      }
    });
  }

  close(): this {
    const specObjectPattern = /<SPEC-OBJECT[^>]*IDENTIFIER="([^"]+)"[^>]*>([\s\S]*?)<\/SPEC-OBJECT>/gi;
    let match: RegExpExecArray | null;
    while ((match = specObjectPattern.exec(this.buffer)) !== null) {
      const [, identifier, body] = match;
      this.emit('opentag', { name: 'SPEC-OBJECT', attributes: { IDENTIFIER: identifier } });
      this.emit('opentag', { name: 'VALUES', attributes: {} });
      this.emit('opentag', { name: 'ATTRIBUTE-VALUE-XHTML', attributes: {} });
      this.emit('opentag', { name: 'THE-VALUE', attributes: {} });

      const valueMatch = /<THE-VALUE>([\s\S]*?)<\/THE-VALUE>/i.exec(body);
      if (valueMatch) {
        const text = valueMatch[1] ?? '';
        this.emit('text', text);
      }

      this.emit('closetag', 'THE-VALUE');
      this.emit('closetag', 'ATTRIBUTE-VALUE-XHTML');
      this.emit('closetag', 'VALUES');
      this.emit('closetag', 'SPEC-OBJECT');
    }

    this.emit('end');
    return this;
  }
}
