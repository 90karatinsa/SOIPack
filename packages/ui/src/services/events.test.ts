import { waitFor } from '@testing-library/react';

import { createComplianceEventStream, type ComplianceEvent, type EventStreamStatus, type StatusContext } from './events';

const flushMicrotasks = async () => {
  await new Promise((resolve) => process.nextTick(resolve));
};

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe('createComplianceEventStream', () => {
  const encoder = new TextEncoder();

  const createSseResponse = (chunks: string[], status = 200): Response => {
    return new Response(
      new ReadableStream<Uint8Array>({
        start(controller) {
          chunks.forEach((chunk) => controller.enqueue(encoder.encode(chunk)));
          controller.close();
        },
      }),
      {
        status,
        headers: { 'Content-Type': 'text/event-stream' },
      },
    );
  };

  beforeEach(() => {
    global.fetch = jest.fn();
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  it('parses compliance events and schedules reconnects when the stream closes', async () => {
    const events: ComplianceEvent[] = [];
    const statuses: Array<{ status: EventStreamStatus; context?: StatusContext }> = [];
    const errors: Error[] = [];

    (global.fetch as jest.Mock).mockResolvedValueOnce(createSseResponse([]));
    (global.fetch as jest.Mock).mockResolvedValueOnce(
      createSseResponse([
        'id: 42\n',
        'event: riskProfile\n',
        'data: {"type":"riskProfile","tenantId":"demo","profile":{"score":88,"classification":"moderate","breakdown":[],"missingSignals":[]}}\n\n',
      ]),
    );

    const handle = createComplianceEventStream({
      token: 'demo-token',
      license: 'demo-license',
      onEvent: (event) => events.push(event),
      onError: (error) => errors.push(error),
      onStatusChange: (status, context) => statuses.push({ status, context }),
      backoff: { initialDelayMs: 50, maxDelayMs: 50 },
    });

    await flushMicrotasks();
    expect(global.fetch).toHaveBeenCalledTimes(1);
    expect(statuses[0]).toMatchObject({ status: 'connecting' });
    expect(errors).toHaveLength(0);

    await sleep(80);
    await flushMicrotasks();

    expect(global.fetch).toHaveBeenCalledTimes(2);

    await waitFor(() => expect(events).toHaveLength(1));
    expect(events[0]).toMatchObject({ type: 'riskProfile', tenantId: 'demo' });

    const retryStatus = statuses.find(({ status }) => status === 'retrying');
    expect(retryStatus?.context?.delayMs).toBe(50);

    handle.close();
  });

  it('stops retrying and surfaces unauthorized errors', async () => {
    const errors: Error[] = [];
    const statuses: Array<{ status: EventStreamStatus; context?: StatusContext }> = [];

    (global.fetch as jest.Mock).mockResolvedValueOnce(createSseResponse([], 401));

    const handle = createComplianceEventStream({
      token: 'bad-token',
      license: 'bad-license',
      onError: (error) => errors.push(error),
      onStatusChange: (status, context) => statuses.push({ status, context }),
      backoff: { initialDelayMs: 50, maxDelayMs: 50 },
    });

    await flushMicrotasks();

    expect(global.fetch).toHaveBeenCalledTimes(1);

    await waitFor(() => expect(errors).toHaveLength(1));
    expect(errors[0].message).toContain('Kimlik doğrulama başarısız oldu');

    await sleep(80);
    await flushMicrotasks();
    expect(global.fetch).toHaveBeenCalledTimes(1);

    expect(statuses.some(({ status }) => status === 'closed')).toBe(true);

    handle.close();
  });
});
