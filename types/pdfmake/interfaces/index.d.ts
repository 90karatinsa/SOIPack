/// <reference types="node" />

export type Content =
  | string
  | number
  | boolean
  | null
  | { [key: string]: unknown }
  | Content[];

export interface TDocumentDefinitions {
  content: Content | Content[];
  styles?: Record<string, Record<string, unknown>>;
  defaultStyle?: Record<string, unknown>;
  footer?: Content | ((currentPage: number, pageCount: number) => Content);
  header?: Content | ((currentPage: number, pageCount: number) => Content);
  info?: {
    title?: string;
    author?: string;
    subject?: string;
    keywords?: string;
    creator?: string;
    producer?: string;
  };
  pageMargins?: [number, number, number, number];
}
