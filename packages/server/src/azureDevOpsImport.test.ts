import { HttpError } from './errors';
import {
  computeConnectorFingerprint,
  parseConnectorPayload,
  redactSecrets,
  stripSecrets,
} from './connectors';

describe('AzureDevOpsImport', () => {
  it('AzureDevOpsImport', () => {
    expect.assertions(14);

    try {
      parseConnectorPayload({
        type: 'azureDevOps',
        options: {
          baseUrl: 'https://dev.azure.com/example/',
          organization: 'example-org',
          project: 'safety-project',
        },
      });
    } catch (error) {
      expect(error).toBeInstanceOf(HttpError);
      expect((error as HttpError).code).toBe('INVALID_CONNECTOR_REQUEST');
    }

    const payload = parseConnectorPayload({
      type: 'azureDevOps',
      options: {
        baseUrl: 'https://dev.azure.com/example/?b=2&a=1#ignored',
        organization: 'example-org',
        project: 'safety-project',
        personalAccessToken: 'azure-pat-secret',
        timeoutMs: '45000',
        pageSize: '250',
        rateLimitDelaysMs: ['150', '300'],
      },
    });

    expect(payload.type).toBe('azureDevOps');
    expect(payload.fingerprint).toMatch(/^[0-9a-f]{64}$/i);
    expect(payload.options.baseUrl).toBe('https://dev.azure.com/example/?a=1&b=2');
    expect(payload.options.timeoutMs).toBe(45000);
    expect(payload.options.pageSize).toBe(250);
    expect(payload.options.rateLimitDelaysMs).toEqual([150, 300]);

    const redacted = redactSecrets(payload.options);
    expect(redacted.personalAccessToken).toBe('REDACTED');

    const stripped = stripSecrets(payload.options);
    expect(stripped).not.toHaveProperty('personalAccessToken');

    const fingerprintA = computeConnectorFingerprint({
      ...payload.options,
      personalAccessToken: 'token-a',
    });
    const fingerprintB = computeConnectorFingerprint({
      ...payload.options,
      personalAccessToken: 'token-b',
    });

    expect(fingerprintA).toBe(fingerprintB);
    expect(payload.fingerprint).toBe(fingerprintA);

    try {
      parseConnectorPayload({
        type: 'azureDevOps',
      } as unknown as { type: string; options: Record<string, unknown> });
    } catch (error) {
      expect(error).toBeInstanceOf(HttpError);
      expect((error as HttpError).code).toBe('INVALID_CONNECTOR_REQUEST');
    }
  });
});
