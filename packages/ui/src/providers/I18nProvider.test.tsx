import { act, renderHook } from '@testing-library/react';

import { I18nProvider, useI18n } from './I18nProvider';

describe('I18nProvider', () => {
  const originalLanguage = window.navigator.language;
  const originalLanguages = window.navigator.languages;

  afterEach(() => {
    jest.restoreAllMocks();

    Object.defineProperty(window.navigator, 'language', {
      configurable: true,
      value: originalLanguage
    });

    Object.defineProperty(window.navigator, 'languages', {
      configurable: true,
      value: originalLanguages
    });
  });

  it('hydrates locale from localStorage when available', () => {
    const getItemSpy = jest.spyOn(Storage.prototype, 'getItem').mockReturnValue('tr');

    const { result } = renderHook(() => useI18n(), {
      wrapper: ({ children }) => <I18nProvider>{children}</I18nProvider>
    });

    expect(getItemSpy).toHaveBeenCalledWith('soipack.ui.locale');
    expect(result.current.locale).toBe('tr');
    expect(result.current.availableLocales).toEqual(['en', 'tr']);
  });

  it('falls back to browser language when storage is empty', () => {
    jest.spyOn(Storage.prototype, 'getItem').mockReturnValue(null);

    Object.defineProperty(window.navigator, 'language', {
      configurable: true,
      value: 'tr-TR'
    });

    const { result } = renderHook(() => useI18n(), {
      wrapper: ({ children }) => <I18nProvider>{children}</I18nProvider>
    });

    expect(result.current.locale).toBe('tr');
  });

  it('persists locale changes via setLocale', () => {
    jest.spyOn(Storage.prototype, 'getItem').mockReturnValue('en');
    const setItemSpy = jest.spyOn(Storage.prototype, 'setItem');

    const { result } = renderHook(() => useI18n(), {
      wrapper: ({ children }) => <I18nProvider>{children}</I18nProvider>
    });

    act(() => {
      result.current.setLocale('tr');
    });

    expect(result.current.locale).toBe('tr');
    expect(setItemSpy).toHaveBeenLastCalledWith('soipack.ui.locale', 'tr');
  });
});
