import { createRequirement, TestCase } from '@soipack/core';
import request from 'supertest';

import { createServer } from './index';

describe('@soipack/server', () => {
  const requirement = createRequirement('REQ-1', 'Provide login');
  const testCase: TestCase = {
    id: 'TC-1',
    requirementId: 'REQ-1',
    name: 'logs in with valid credentials',
    status: 'passed',
  };
  const app = createServer({ requirements: [requirement], testCases: [testCase] });

  it('returns health status', async () => {
    const response = await request(app).get('/health');
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ status: 'ok' });
  });

  it('returns report with requirement data', async () => {
    const response = await request(app).get('/report');
    expect(response.status).toBe(200);
    expect(response.body.requirements?.[0].requirement.id).toBe('REQ-1');
  });
});
