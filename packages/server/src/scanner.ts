import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

export interface ScanTarget {
  field: string;
  path: string;
  originalname: string;
  mimetype: string;
  size: number;
}

export interface FileScanResult {
  clean: boolean;
  threat?: string;
  engine?: string;
  details?: Record<string, unknown>;
}

export interface FileScanner {
  scan(target: ScanTarget): Promise<FileScanResult>;
}

export const createNoopScanner = (): FileScanner => ({
  async scan(): Promise<FileScanResult> {
    return { clean: true };
  },
});

export interface CommandScannerOptions {
  args?: string[];
  timeoutMs?: number;
  infectedExitCodes?: number[];
}

interface ExecError extends Error {
  code?: number | string;
  stdout?: string | Buffer;
  stderr?: string | Buffer;
}

export const createCommandScanner = (
  command: string,
  options: CommandScannerOptions = {},
): FileScanner => {
  const infectedExitCodes = options.infectedExitCodes ?? [1];
  return {
    async scan(target: ScanTarget): Promise<FileScanResult> {
      const args = [...(options.args ?? []), target.path];
      try {
        await execFileAsync(command, args, { timeout: options.timeoutMs });
        return { clean: true };
      } catch (error) {
        const execError = error as ExecError;
        const exitCodeRaw = execError.code;
        const exitCode = typeof exitCodeRaw === 'number' ? exitCodeRaw : Number.parseInt(String(exitCodeRaw ?? ''), 10);
        const stdout = execError.stdout ? execError.stdout.toString().trim() : '';
        const stderr = execError.stderr ? execError.stderr.toString().trim() : '';

        if (Number.isFinite(exitCode) && infectedExitCodes.includes(Number(exitCode))) {
          const threatDetails = stdout || stderr || 'Şüpheli içerik tespit edildi';
          return {
            clean: false,
            threat: threatDetails,
            engine: command,
            details: {
              exitCode: Number(exitCode),
              stdout: stdout || undefined,
              stderr: stderr || undefined,
            },
          };
        }

        const message = stderr || stdout || execError.message || 'Dosya tarama komutu başarısız oldu.';
        throw new Error(message);
      }
    },
  };
};
