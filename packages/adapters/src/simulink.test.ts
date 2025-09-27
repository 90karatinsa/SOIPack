import path from 'path';

import { fromSimulink } from './simulink';

const fixturePath = (name: string): string =>
  path.resolve(__dirname, '../fixtures/simulink', name);

describe('Simulink coverage adapter', () => {
  it('normalizes metrics and surfaces warnings from the report', async () => {
    const reportPath = fixturePath('coverage.json');
    const { data, warnings } = await fromSimulink(reportPath);

    expect(data.coverage).toBeDefined();
    expect(data.coverage?.tool).toBe('simulink');
    expect(data.coverage?.files).toEqual([
      {
        path: 'models/throttle_controller.slx',
        stmt: { covered: 80, total: 100 },
        dec: { covered: 40, total: 50 },
        mcdc: { covered: 20, total: 40 },
      },
      {
        path: 'models/sensor_interface.slx',
        stmt: { covered: 12, total: 16 },
        dec: { covered: 6, total: 10 },
      },
    ]);
    expect(data.coverage?.objectiveLinks).toEqual(['A-5-08', 'A-5-09', 'A-5-10']);

    expect(warnings).toEqual(
      expect.arrayContaining([
        expect.stringContaining('yol bilgisi eksik'),
        expect.stringContaining('ifade kapsamı eksik'),
        expect.stringContaining('sayısal değil'),
        'ThrottleControl modeli, hariç tutulan bloklar içeriyor',
      ]),
    );
  });

  it('throws a descriptive error when the JSON payload is invalid', async () => {
    const reportPath = fixturePath('invalid.json');
    await expect(fromSimulink(reportPath)).rejects.toThrow('JSON olarak okunamadı');
  });
});
