import { createI18n, DEFAULT_LOCALE, getAvailableLocales, resolveLocale, translate } from './i18n';

describe('i18n', () => {
  it('provides builtin locales', () => {
    expect(getAvailableLocales()).toEqual(expect.arrayContaining(['en', 'tr']));
  });

  it('falls back to default locale for unknown languages', () => {
    expect(resolveLocale('unknown')).toBe(DEFAULT_LOCALE);
  });

  it('matches base locale when region is provided', () => {
    expect(resolveLocale('tr-TR')).toBe('tr');
  });

  it('translates known keys in different locales', () => {
    expect(translate('errors.unexpected', { locale: 'en' })).toBe('An unexpected error occurred.');
    expect(translate('errors.unexpected', { locale: 'tr' })).toBe('Beklenmeyen bir hata oluştu.');
  });

  it('returns key name when translation is missing', () => {
    expect(translate('unknown.key', { locale: 'en' })).toBe('unknown.key');
  });

  it('supports custom catalogs through createI18n', () => {
    const custom = createI18n({
      defaultLocale: 'en',
      messages: {
        en: { greeting: 'Hello {{name}}' },
        tr: { greeting: 'Merhaba {{name}}' },
      },
    });

    expect(custom.translate('greeting', { values: { name: 'Ada' } })).toBe('Hello Ada');
    expect(custom.translate('greeting', { locale: 'tr', values: { name: 'Ada' } })).toBe('Merhaba Ada');
  });
});
