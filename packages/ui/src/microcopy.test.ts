import { translate } from './microcopy';

describe('translate', () => {
  it('returns the translation for a Turkish locale', () => {
    expect(translate('tr', 'dashboard.title')).toBe('Uyumluluk & İzlenebilirlik Panosu');
  });

  it('returns the translation for an English locale', () => {
    expect(translate('en', 'dashboard.title')).toBe('Compliance & Traceability Dashboard');
  });

  it('falls back to the English dictionary when the locale is missing the key', () => {
    expect(translate('tr', 'common.ok')).toBe('OK');
  });

  it('returns the key when no translation is available', () => {
    expect(translate('en', 'unknown.key')).toBe('unknown.key');
  });
});
