import type { ReactNode } from 'react';
import { createContext, useContext, useMemo, useState } from 'react';

import { translate, type Locale } from '../microcopy';

interface I18nContextValue {
  locale: Locale;
  setLocale: (next: Locale) => void;
  t: (key: string) => string;
}

const I18nContext = createContext<I18nContextValue | undefined>(undefined);

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocale] = useState<Locale>('tr');

  const value = useMemo<I18nContextValue>(
    () => ({
      locale,
      setLocale,
      t: (key) => translate(locale, key)
    }),
    [locale]
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
