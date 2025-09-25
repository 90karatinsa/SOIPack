import fs from 'fs/promises';
import os from 'os';
import path from 'path';

import { importGitMetadata } from './git';

const buildScript = (lines: string[]): string => `${lines.join('\n')}\n`;

const installFakeGit = async (lines: string[]) => {
  const binDir = await fs.mkdtemp(path.join(os.tmpdir(), 'fake-git-bin-'));
  const scriptPath = path.join(binDir, 'git');
  const scriptSource = buildScript(lines);
  await fs.writeFile(scriptPath, scriptSource, 'utf8');
  await fs.chmod(scriptPath, 0o755);

  const originalPath = process.env.PATH ?? '';
  process.env.PATH = `${binDir}:${originalPath}`;

  return {
    binaryPath: scriptPath,
    restore: async () => {
      process.env.PATH = originalPath;
      await fs.rm(binDir, { recursive: true, force: true });
    },
  };
};

describe('importGitMetadata', () => {
  it('truncates stderr output and records structured warnings when commands fail', async () => {
    const repoDir = await fs.mkdtemp(path.join(os.tmpdir(), 'git-repo-'));
    const fakeGit = await installFakeGit([
      '#!/usr/bin/env node',
      "const args = process.argv.slice(2);",
      "const known = new Set(['rev-parse', 'log', 'for-each-ref', 'tag', 'remote', 'status']);",
      'const command = args.find((arg) => known.has(arg)) ?? \"\";',
      '',
      "if (command === 'rev-parse') {",
      "  console.log('abcdef1234567890abcdef1234567890abcdef12');",
      '  process.exit(0);',
      '}',
      '',
      "if (command === 'log') {",
      "  console.log('Test Author');",
      "  console.log('2024-01-01T00:00:00.000Z');",
      "  console.log('Initial commit');",
      '  process.exit(0);',
      '}',
      '',
      "if (command === 'for-each-ref') {",
      "  console.error('simulated failure '.repeat(200));",
      '  process.exit(1);',
      '}',
      '',
      "if (command === 'tag') {",
      "  console.log('v1.0.0');",
      '  process.exit(0);',
      '}',
      '',
      "if (command === 'remote') {",
      "  console.error(\"fatal: No such remote 'origin'\");",
      '  process.exit(128);',
      '}',
      '',
      "if (command === 'status') {",
      '  process.exit(0);',
      '}',
      '',
      "console.error('unexpected command: ' + command);",
      'process.exit(1);',
    ]);

    try {
      const result = await importGitMetadata(repoDir, {
        maxStderrBytes: 64,
        timeoutMs: 200,
        binaryPath: fakeGit.binaryPath,
      });

      expect(result.data).not.toBeNull();
      const failureWarning = result.warnings.find((warning) => warning.includes('for-each-ref'));
      expect(failureWarning).toBeDefined();
      expect(failureWarning).toContain('simulated failure');
      expect(failureWarning).toContain('stderr:');
      expect(failureWarning).toContain('…');
      expect(result.warnings.every((warning) => !warning.includes('No such remote'))).toBe(true);
    } finally {
      await fakeGit.restore();
      await fs.rm(repoDir, { recursive: true, force: true });
    }
  });

  it('returns null build info and warns when git commands exceed the timeout', async () => {
    const repoDir = await fs.mkdtemp(path.join(os.tmpdir(), 'git-timeout-'));
    const fakeGit = await installFakeGit([
      '#!/usr/bin/env node',
      "const args = process.argv.slice(2);",
      "const known = new Set(['rev-parse', 'log', 'for-each-ref', 'tag', 'remote', 'status']);",
      'const command = args.find((arg) => known.has(arg)) ?? \"\";',
      '',
      "if (command === 'rev-parse') {",
      '  setTimeout(() => {',
      "    console.log('deadbeefdeadbeefdeadbeefdeadbeefdeadbeef');",
      '    process.exit(0);',
      '  }, 200);',
      '  return;',
      '}',
      '',
      "if (command === 'log') {",
      "  console.log('Slow Author');",
      "  console.log('2024-01-02T00:00:00.000Z');",
      "  console.log('Delayed commit');",
      '  process.exit(0);',
      '}',
      '',
      "if (command === 'for-each-ref' || command === 'tag' || command === 'remote' || command === 'status') {",
      '  process.exit(0);',
      '}',
      '',
      'process.exit(1);',
    ]);

    try {
      const result = await importGitMetadata(repoDir, {
        timeoutMs: 50,
        binaryPath: fakeGit.binaryPath,
      });

      expect(result.data).toBeNull();
      expect(result.warnings).toEqual(
        expect.arrayContaining([expect.stringContaining('timed out')]),
      );
    } finally {
      await fakeGit.restore();
      await fs.rm(repoDir, { recursive: true, force: true });
    }
  });
});
