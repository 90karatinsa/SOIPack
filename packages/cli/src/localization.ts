import { DEFAULT_LOCALE, getAvailableLocales, resolveLocale, translate } from '@soipack/core';

let currentLocale = DEFAULT_LOCALE;

export const setCliLocale = (locale?: string): void => {
  currentLocale = resolveLocale(locale);
};

export const getCliLocale = (): string => currentLocale;

export const translateCli = (key: string, values?: Record<string, unknown>): string =>
  translate(key, { locale: currentLocale, values });

export const getCliAvailableLocales = (): string[] => getAvailableLocales();

// Ensure tests start from the default locale
setCliLocale(DEFAULT_LOCALE);
