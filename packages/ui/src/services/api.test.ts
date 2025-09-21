import { buildAuthHeaders } from './api';

describe('buildAuthHeaders', () => {
  it('returns sanitized headers when token and license are provided', () => {
    const headers = buildAuthHeaders({ token: ' demo-token ', license: '  ZXhhbXBsZV9saWNlbnNl\n' });
    expect(headers.Authorization).toBe('Bearer demo-token');
    expect(headers['X-SOIPACK-License']).toBe('ZXhhbXBsZV9saWNlbnNl');
  });

  it('throws an error when the token is missing', () => {
    expect(() => buildAuthHeaders({ token: '   ', license: 'ZW1wdHk=' })).toThrow('Token gereklidir.');
  });

  it('throws an error when the license is missing', () => {
    expect(() => buildAuthHeaders({ token: 'valid', license: '   ' })).toThrow('Lisans gereklidir.');
  });
});
