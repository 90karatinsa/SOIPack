import { execFile } from 'child_process';
import path from 'path';
import { promisify } from 'util';

import { BuildInfo, ParseResult } from './types';

const execFileAsync = promisify(execFile);

const runGitCommand = async (args: string[], cwd: string, warnings: string[]): Promise<string | undefined> => {
  try {
    const { stdout } = await execFileAsync('git', args, { cwd });
    return stdout.trim();
  } catch (error) {
    warnings.push(`Git command failed (${['git', ...args].join(' ')}): ${(error as Error).message}`);
    return undefined;
  }
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
      },
      warnings,
    };
  }
  const [author, date, ...messageParts] = output.split('\n');
  const message = messageParts.join('\n').trim();

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
    },
    warnings,
  };
};
