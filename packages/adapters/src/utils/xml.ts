import { XMLParser } from 'fast-xml-parser';

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '',
  textNodeName: '#text',
  removeNSPrefix: true,
  allowBooleanAttributes: true,
  parseAttributeValue: true,
  trimValues: true,
});

export const parseXml = <T>(content: string): T => parser.parse(content) as T;
