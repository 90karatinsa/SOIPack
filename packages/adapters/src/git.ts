import { execFile } from 'child_process';
import path from 'path';
import { promisify } from 'util';

import { BuildInfo, ParseResult } from './types';

const execFileAsync = promisify(execFile);

const runGitCommand = async (
  args: string[],
  cwd: string,
  warnings: string[],
): Promise<string | undefined> => {
  try {
    const { stdout } = await execFileAsync('git', args, { cwd });
    return stdout.trim();
  } catch (error) {
    warnings.push(`Git command failed (${['git', ...args].join(' ')}): ${(error as Error).message}`);
    return undefined;
  }
};

const parseGitList = (raw: string | undefined): string[] => {
  if (!raw) {
    return [];
  }

  return Array.from(
    new Set(
      raw
        .split('\n')
        .map((entry) => entry.trim())
        .filter((entry) => entry.length > 0),
    ),
  ).sort((a, b) => a.localeCompare(b));
};

export const importGitMetadata = async (repositoryPath: string): Promise<ParseResult<BuildInfo | null>> => {
  const warnings: string[] = [];
  const cwd = path.resolve(repositoryPath);

  const hash = await runGitCommand(['rev-parse', 'HEAD'], cwd, warnings);
  if (!hash) {
    return { data: null, warnings };
  }

  const logFormat = '%an%n%aI%n%s';
  const output = await runGitCommand(['log', '-1', `--pretty=format:${logFormat}`], cwd, warnings);
  if (!output) {
    return {
      data: {
        hash,
        author: '',
        date: '',
        message: '',
        branches: [],
        tags: [],
        dirty: false,
        remoteOrigins: [],
      },
      warnings,
    };
  }
  const [author, date, ...messageParts] = output.split('\n');
  const message = messageParts.join('\n').trim();

  const branches = parseGitList(
    await runGitCommand(['for-each-ref', '--format=%(refname:short)', '--contains=HEAD', 'refs/heads'], cwd, warnings),
  );

  const tags = parseGitList(await runGitCommand(['tag', '--points-at', 'HEAD'], cwd, warnings));

  let remoteOrigins: string[] = [];
  try {
    const { stdout } = await execFileAsync('git', ['remote', 'get-url', '--all', 'origin'], { cwd });
    remoteOrigins = parseGitList(stdout);
  } catch (error) {
    const message = (error as Error).message;
    if (message && !/No such remote/i.test(message)) {
      warnings.push(`Git command failed (git remote get-url --all origin): ${message}`);
    }
  }

  const statusOutput = await runGitCommand(['status', '--porcelain'], cwd, warnings);
  const dirty = Boolean(statusOutput && statusOutput.trim().length > 0);
  if (dirty) {
    warnings.push('Repository has uncommitted changes.');
  }

  if (!hash) {
    warnings.push('Unable to resolve commit hash.');
  }
  if (!author) {
    warnings.push('Unable to resolve commit author.');
  }
  if (!date) {
    warnings.push('Unable to resolve commit date.');
  }

  return {
    data: {
      hash,
      author: author ?? '',
      date: date ?? '',
      message,
      branches,
      tags,
      dirty,
      remoteOrigins,
    },
    warnings,
  };
};
