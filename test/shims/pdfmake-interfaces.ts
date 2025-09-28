/* eslint-disable @typescript-eslint/no-explicit-any */

export type StyleDictionary = Record<string, any>;

export type Content =
  | string
  | {
      text?: string;
      style?: string;
      margin?: [number, number?, number?, number?];
      ul?: Array<string | Record<string, any>>;
      table?: {
        widths?: Array<string | number>;
        body: Array<Array<Content>>;
      };
      layout?: string;
      [key: string]: any;
    };

export interface TDocumentDefinitions {
  content: Content[];
  styles?: StyleDictionary;
  defaultStyle?: Record<string, any>;
  pageMargins?: [number, number, number, number];
  pageOrientation?: string;
  info?: Record<string, any>;
  [key: string]: any;
}
