import en from '../locales/en.json';
import tr from '../locales/tr.json';

export type MessageDictionary = Record<string, string>;

export interface I18nConfig {
  messages: Record<string, MessageDictionary>;
  defaultLocale: string;
}

export interface TranslateOptions {
  locale?: string;
  values?: Record<string, unknown>;
  fallbackLocale?: string;
}

export interface I18n {
  translate: (key: string, options?: TranslateOptions) => string;
  resolveLocale: (locale?: string) => string;
  getAvailableLocales: () => string[];
}

const formatMessage = (template: string, values?: Record<string, unknown>): string => {
  if (!values) {
    return template;
  }
  return template.replace(/\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}/g, (_match, key: string) => {
    const value = values[key];
    return value === undefined || value === null ? '' : String(value);
  });
};

const normalizeLocale = (input: string): string => input.trim().toLowerCase();

export const createI18n = ({ messages, defaultLocale }: I18nConfig): I18n => {
  if (!messages[defaultLocale]) {
    throw new Error(`Default locale "${defaultLocale}" is not available in the message catalog.`);
  }

  const localeMap = new Map<string, MessageDictionary>();
  for (const [locale, dictionary] of Object.entries(messages)) {
    localeMap.set(normalizeLocale(locale), dictionary);
  }

  const normalizedDefault = normalizeLocale(defaultLocale);

  const resolveLocale = (locale?: string): string => {
    if (!locale) {
      return normalizedDefault;
    }
    const normalizedInput = normalizeLocale(locale);
    if (localeMap.has(normalizedInput)) {
      return normalizedInput;
    }
    const baseTag = normalizedInput.split('-')[0];
    if (baseTag && localeMap.has(baseTag)) {
      return baseTag;
    }
    return normalizedDefault;
  };

  const translate = (key: string, options?: TranslateOptions): string => {
    const { locale, values, fallbackLocale } = options ?? {};
    const resolvedLocale = resolveLocale(locale);
    const dictionary = localeMap.get(resolvedLocale) ?? {};
    const fallbackDictionary =
      fallbackLocale && localeMap.has(normalizeLocale(fallbackLocale))
        ? localeMap.get(normalizeLocale(fallbackLocale))
        : localeMap.get(normalizedDefault);

    const template = dictionary[key] ?? fallbackDictionary?.[key];
    if (!template) {
      return key;
    }
    return formatMessage(template, values);
  };

  const getAvailableLocales = (): string[] => Array.from(localeMap.keys());

  return {
    translate,
    resolveLocale,
    getAvailableLocales,
  };
};

const builtinI18n = createI18n({
  messages: {
    en,
    tr,
  },
  defaultLocale: 'en',
});

export const DEFAULT_LOCALE = builtinI18n.resolveLocale('en');

export const translate = (key: string, options?: TranslateOptions): string =>
  builtinI18n.translate(key, options);

export const resolveLocale = (locale?: string): string => builtinI18n.resolveLocale(locale);

export const getAvailableLocales = (): string[] => builtinI18n.getAvailableLocales();

export const getI18n = (): I18n => builtinI18n;
