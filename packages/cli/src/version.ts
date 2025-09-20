import { execSync } from 'child_process';

import packageInfo from '../package.json';

export interface VersionInfo {
  version: string;
  commit: string;
}

const readCommitHash = (): string => {
  if (process.env.SOIPACK_COMMIT) {
    return process.env.SOIPACK_COMMIT;
  }

  try {
    return execSync('git rev-parse HEAD', {
      stdio: ['ignore', 'pipe', 'ignore'],
    })
      .toString()
      .trim();
  } catch (error) {
    return 'unknown';
  }
};

export const getVersionInfo = (): VersionInfo => ({
  version: packageInfo.version,
  commit: readCommitHash(),
});

export const formatVersion = (info: VersionInfo = getVersionInfo()): string =>
  `${info.version} (commit ${info.commit})`;
