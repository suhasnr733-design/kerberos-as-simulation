import { describe, it, expect, vi, beforeEach } from 'vitest';
import { checkHealth, getPrincipals, sendASRequest } from '../services/api';

describe('API Service Suite', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('checkHealth returns mock fallback when fetch throws network error', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('Network error'));
    
    const result = await checkHealth();
    expect(result.success).toBe(false);
    expect(result.isMock).toBe(true);
    expect(result.data.status).toBe('offline');
  });

  it('checkHealth parses success data from backend', async () => {
    const mockHealthData = {
      status: 'healthy',
      service: 'Kerberos AS Backend',
      course: 'BCS703',
      ready_for_kerberos: true,
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockHealthData,
    });

    const result = await checkHealth();
    expect(result.success).toBe(true);
    expect(result.isMock).toBe(false);
    expect(result.data.status).toBe('healthy');
  });

  it('getPrincipals returns list of educational principals', async () => {
    const mockPrincipals = {
      realm: 'CANARA.EDU',
      service_principal: 'krbtgt/CANARA.EDU',
      principals: ['alice@CANARA.EDU', 'bob@CANARA.EDU'],
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockPrincipals,
    });

    const result = await getPrincipals();
    expect(result.success).toBe(true);
    expect(result.data.principals).toContain('alice@CANARA.EDU');
  });

  it('sendASRequest generates valid mock response when offline', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('Backend offline'));

    const payload = {
      cname: 'alice@CANARA.EDU',
      realm: 'CANARA.EDU',
      sname: 'krbtgt/CANARA.EDU',
      nonce: 123456,
      timestamp: new Date().toISOString(),
      lifetime: 36000,
    };

    const result = await sendASRequest(payload);
    expect(result.success).toBe(true);
    expect(result.isMock).toBe(true);
    expect(result.data.msg_type).toBe('KRB_AS_REP');
    expect(result.data.cname).toBe('alice@CANARA.EDU');
    expect(result.data.telemetry.length).toBe(8);
  });

  it('sendASRequest handles structured error responses from API', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      json: async () => ({
        msg_type: 'KRB_ERROR',
        error_code: 'KDC_ERR_C_PRINCIPAL_UNKNOWN',
        message: 'Principal not found',
        timestamp: new Date().toISOString(),
      }),
    });

    const payload = {
      cname: 'charlie@CANARA.EDU',
      realm: 'CANARA.EDU',
      sname: 'krbtgt/CANARA.EDU',
      nonce: 123456,
      timestamp: new Date().toISOString(),
      lifetime: 36000,
    };

    const result = await sendASRequest(payload);
    expect(result.success).toBe(false);
    expect(result.isMock).toBe(false);
    expect(result.errorCode).toBe('KDC_ERR_C_PRINCIPAL_UNKNOWN');
  });
});
