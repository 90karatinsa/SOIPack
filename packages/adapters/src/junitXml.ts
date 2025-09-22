import { parseJUnitStream } from './adapters/junit';
import { ParseResult, TestResult } from './types';

export const importJUnitXml = async (filePath: string): Promise<ParseResult<TestResult[]>> => {
  try {
    return await parseJUnitStream(filePath);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { data: [], warnings: [message] };
  }
};
