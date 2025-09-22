import { parseReqifStream } from './adapters/reqif';
import { ParseResult, ReqIFRequirement } from './types';

export const importReqIF = async (filePath: string): Promise<ParseResult<ReqIFRequirement[]>> => {
  try {
    return await parseReqifStream(filePath);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { data: [], warnings: [message] };
  }
};
