import type { ReactNode } from 'react';
import { createContext, useContext, useMemo, useState, useCallback } from 'react';

import {
  availableLocales,
  defaultLocale,
  translate,
  type Locale
} from '../microcopy';

interface I18nContextValue {
  locale: Locale;
  availableLocales: readonly Locale[];
  setLocale: (next: Locale) => void;
  t: (key: string) => string;
}

const I18nContext = createContext<I18nContextValue | undefined>(undefined);

const LOCALE_STORAGE_KEY = 'soipack.ui.locale';

const availableLocaleSet = new Set<Locale>(availableLocales);

const resolveLocale = (candidate?: string | null): Locale | null => {
  if (!candidate) {
    return null;
  }

  const normalized = candidate.toLowerCase();
  if (availableLocaleSet.has(normalized as Locale)) {
    return normalized as Locale;
  }

  const base = normalized.split('-')[0];
  if (availableLocaleSet.has(base as Locale)) {
    return base as Locale;
  }

  return null;
};

const getBrowserLocale = (): Locale | null => {
  if (typeof window === 'undefined') {
    return null;
  }

  const navigatorLanguages = [window.navigator?.language, ...(window.navigator?.languages ?? [])];
  for (const candidate of navigatorLanguages) {
    const resolved = resolveLocale(candidate);
    if (resolved) {
      return resolved;
    }
  }

  return null;
};

const readStoredLocale = (): Locale | null => {
  if (typeof window === 'undefined') {
    return null;
  }

  try {
    return resolveLocale(window.localStorage.getItem(LOCALE_STORAGE_KEY));
  } catch (error) {
    return null;
  }
};

const persistLocale = (locale: Locale) => {
  if (typeof window === 'undefined') {
    return;
  }

  try {
    window.localStorage.setItem(LOCALE_STORAGE_KEY, locale);
  } catch (error) {
    // Ignore persistence failures.
  }
};

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(() => {
    const stored = readStoredLocale();
    if (stored) {
      return stored;
    }

    const browserLocale = getBrowserLocale();
    if (browserLocale) {
      return browserLocale;
    }

    return defaultLocale;
  });

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next);
    persistLocale(next);
  }, []);

  const value = useMemo<I18nContextValue>(
    () => ({
      locale,
      availableLocales,
      setLocale,
      t: (key) => translate(locale, key)
    }),
    [locale, setLocale]
  );

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n() {
  const context = useContext(I18nContext);
  if (!context) {
    throw new Error('useI18n must be used inside I18nProvider');
  }
  return context;
}

export function useT() {
  return useI18n().t;
}
