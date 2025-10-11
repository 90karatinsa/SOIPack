interface ImportMetaEnv {
  readonly VITE_ENVIRONMENT?: string;
  readonly [key: string]: string | undefined;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
