import { parseLcovStream } from './adapters/lcov';
import { CoverageReport, ParseResult } from './types';

export const importLcov = async (filePath: string): Promise<ParseResult<CoverageReport>> => {
  try {
    return await parseLcovStream(filePath);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { data: { totals: { statements: { covered: 0, total: 0, percentage: 0 } }, files: [] }, warnings: [message] };
  }
};
