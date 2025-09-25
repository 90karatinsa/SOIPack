import { execFile, type ExecFileException } from 'child_process';
import path from 'path';
import { promisify } from 'util';

import { BuildInfo, ParseResult } from './types';

const execFileAsync = promisify(execFile);

const DEFAULT_GIT_TIMEOUT_MS = 15000;
const DEFAULT_STDERR_LIMIT = 4096;
const TRUNCATION_SUFFIX = '…';

export interface GitImportOptions {
  timeoutMs?: number;
  maxStderrBytes?: number;
  binaryPath?: string;
}

const resolveTimeout = (options?: GitImportOptions): number | undefined => {
  if (!options || options.timeoutMs === undefined) {
    return DEFAULT_GIT_TIMEOUT_MS;
  }
  if (options.timeoutMs <= 0) {
    return undefined;
  }
  return options.timeoutMs;
};

const resolveStderrLimit = (options?: GitImportOptions): number => {
  if (!options || options.maxStderrBytes === undefined || options.maxStderrBytes <= 0) {
    return DEFAULT_STDERR_LIMIT;
  }
  return options.maxStderrBytes;
};

const truncateOutput = (value: string | undefined, limit: number): string | undefined => {
  if (!value) {
    return undefined;
  }

  const buffer = Buffer.from(value, 'utf8');
  if (buffer.length <= limit) {
    return buffer.toString('utf8').trim();
  }

  const truncated = buffer.subarray(0, limit).toString('utf8').trimEnd();
  return `${truncated}${TRUNCATION_SUFFIX}`.trim();
};

const runGitCommand = async (
  args: string[],
  cwd: string,
  warnings: string[],
  options?: GitImportOptions,
): Promise<string | undefined> => {
  const timeout = resolveTimeout(options);
  const stderrLimit = resolveStderrLimit(options);
  const binary = options?.binaryPath ?? 'git';
  const command = [binary, ...args].join(' ');

  try {
    const execOptions = timeout !== undefined ? { cwd, timeout } : { cwd };
    const { stdout } = await execFileAsync(binary, args, execOptions);
    return stdout.trim();
  } catch (error) {
    const execError = error as ExecFileException & { stderr?: string };
    if (execError.killed && execError.signal) {
      const timeoutMessage = timeout && timeout > 0 ? ` after ${timeout}ms` : '';
      warnings.push(`Git command timed out (${command})${timeoutMessage}.`);
    } else {
      const exitCode = execError.code ?? 'unknown';
      const stderrSnippet = truncateOutput(execError.stderr, stderrLimit);
      let message = `Git command failed (${command}) with exit code ${exitCode}.`;
      if (stderrSnippet) {
        message += ` stderr: ${stderrSnippet}`;
      }
      warnings.push(message);
    }
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

export const importGitMetadata = async (
  repositoryPath: string,
  options: GitImportOptions = {},
): Promise<ParseResult<BuildInfo | null>> => {
  const warnings: string[] = [];
  const cwd = path.resolve(repositoryPath);

  const hash = await runGitCommand(['rev-parse', 'HEAD'], cwd, warnings, options);
  if (!hash) {
    return { data: null, warnings };
  }

  const logFormat = '%an%n%aI%n%s';
  const output = await runGitCommand(['log', '-1', `--pretty=format:${logFormat}`], cwd, warnings, options);
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
    await runGitCommand(
      ['for-each-ref', '--format=%(refname:short)', '--contains=HEAD', 'refs/heads'],
      cwd,
      warnings,
      options,
    ),
  );

  const tags = parseGitList(await runGitCommand(['tag', '--points-at', 'HEAD'], cwd, warnings, options));

  let remoteOrigins: string[] = [];
  const priorWarnings = warnings.length;
  const remoteOutput = await runGitCommand(
    ['remote', 'get-url', '--all', 'origin'],
    cwd,
    warnings,
    options,
  );
  if (remoteOutput) {
    remoteOrigins = parseGitList(remoteOutput);
  } else if (warnings.length > priorWarnings) {
    const lastWarning = warnings[warnings.length - 1] ?? '';
    if (/No such remote/i.test(lastWarning)) {
      warnings.pop();
    }
  }

  const statusOutput = await runGitCommand(['status', '--porcelain'], cwd, warnings, options);
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
