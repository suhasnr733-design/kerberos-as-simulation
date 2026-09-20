/**
 * Kerberos Authentication Server (AS) API Service
 * 
 * Interacts with FastAPI backend running on http://127.0.0.1:8000 (or configured VITE_API_BASE_URL)
 * Handles live REST API calls as well as labeled Mock Mode fallback data when backend is unreachable.
 */

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';

/**
 * Health check endpoint call
 * GET /api/health
 */
export async function checkHealth() {
  try {
    const response = await fetch(`${BASE_URL}/api/health`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    return {
      success: true,
      data,
      isMock: false,
    };
  } catch (error) {
    return {
      success: false,
      error: error.message || 'Backend service unreachable',
      isMock: true,
      data: {
        status: 'offline',
        service: 'Kerberos AS Simulation (Mock Mode Active)',
        timestamp: new Date().toISOString(),
        course: 'Cryptography & Network Security (BCS703)',
        semester: 'VII',
        college: 'Canara Engineering College',
        team_members: ['4CB23CS160 (Frontend)', '4CB23CS161 (Backend)'],
        phase: 'Phase 2B: Frontend Standalone Mock Mode',
        ready_for_kerberos: false,
        message: 'Backend server is not running on http://127.0.0.1:8000. Operating in educational Mock Mode.',
      },
    };
  }
}

/**
 * Get available sample principal names
 * GET /api/kerberos/principals
 */
export async function getPrincipals() {
  try {
    const response = await fetch(`${BASE_URL}/api/kerberos/principals`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP error ${response.status}`);
    }

    const data = await response.json();
    return {
      success: true,
      data,
      isMock: false,
    };
  } catch (error) {
    // Educational mock default
    return {
      success: false,
      isMock: true,
      error: error.message,
      data: {
        realm: 'CANARA.EDU',
        service_principal: 'krbtgt/CANARA.EDU',
        principals: ['alice@CANARA.EDU', 'bob@CANARA.EDU'],
      },
    };
  }
}

/**
 * Execute KRB_AS_REQ -> KRB_AS_REP protocol exchange
 * POST /api/kerberos/as-request
 * 
 * @param {Object} payload { cname, realm, sname, nonce, timestamp, lifetime }
 */
export async function sendASRequest(payload) {
  try {
    const response = await fetch(`${BASE_URL}/api/kerberos/as-request`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    const data = await response.json();

    if (!response.ok) {
      // Handle structured Kerberos error or HTTP validation error
      let errorCode = data.error_code;
      let errorMessage = data.message;

      // Handle Pydantic validation errors (HTTP 422)
      if (response.status === 422 && data.detail) {
        errorCode = 'KRB_AP_ERR_BAD_INTEGRITY';
        if (Array.isArray(data.detail)) {
          errorMessage = data.detail.map((err) => `${err.loc ? err.loc.join('.') : ''}: ${err.msg}`).join('; ');
        } else {
          errorMessage = JSON.stringify(data.detail);
        }
      } else if (!errorCode) {
        errorCode = `HTTP_${response.status}`;
        errorMessage = errorMessage || 'AS Exchange failed.';
      }
      
      return {
        success: false,
        isMock: false,
        status: response.status,
        errorCode,
        error: errorMessage,
        timestamp: data.timestamp || new Date().toISOString(),
      };
    }

    return {
      success: true,
      isMock: false,
      data,
    };
  } catch (error) {
    // Network error or backend offline -> generate labelled mock response
    return generateMockASResponse(payload, error.message);
  }
}

/**
 * Generate a clearly labeled mock KRB_AS_REP response matching the 8 backend telemetry steps
 */
function generateMockASResponse(payload, errorMessage) {
  const timestamp = new Date().toISOString();
  
  // Validation checks for mock mode
  if (!payload.cname || payload.cname.trim() === '') {
    return {
      success: false,
      isMock: true,
      errorCode: 'KDC_ERR_C_PRINCIPAL_UNKNOWN',
      error: '[MOCK DATA] Client principal cannot be empty.',
      failedStepNumber: 2,
      timestamp,
    };
  }

  if (payload.realm !== 'CANARA.EDU') {
    return {
      success: false,
      isMock: true,
      errorCode: 'KDC_ERR_WRONG_REALM',
      error: `[MOCK DATA] Unsupported realm '${payload.realm}'. Expected 'CANARA.EDU'.`,
      failedStepNumber: 2,
      timestamp,
    };
  }

  if (payload.sname !== 'krbtgt/CANARA.EDU') {
    return {
      success: false,
      isMock: true,
      errorCode: 'KDC_ERR_S_PRINCIPAL_UNKNOWN',
      error: `[MOCK DATA] Unsupported service principal '${payload.sname}'. Expected 'krbtgt/CANARA.EDU'.`,
      failedStepNumber: 2,
      timestamp,
    };
  }

  // Create labeled mock success structure matching backend 8-step KrbAsRep schema
  return {
    success: true,
    isMock: true,
    mockNotice: 'MOCK DATA — Backend is offline. Operating in standalone simulation mode.',
    data: {
      msg_type: 'KRB_AS_REP',
      pvno: 5,
      cname: payload.cname,
      crealm: payload.realm,
      ticket: {
        sname: payload.sname,
        srealm: payload.realm,
        cipher_b64: 'MOCK_TGT_CIPHERTEXT_AES256_GCM==',
        nonce_b64: 'MOCK_TGT_IV_96BIT==',
        encryption_type: 'AES-256-GCM',
      },
      enc_part: {
        cipher_b64: 'MOCK_CLIENT_RESPONSE_CIPHERTEXT==',
        nonce_b64: 'MOCK_CLIENT_RESPONSE_IV==',
        encryption_type: 'AES-256-GCM',
      },
      telemetry: [
        { step_number: 1, name: 'Request received.', description: `Received KRB_AS_REQ for client '${payload.cname}' requesting service '${payload.sname}'.`, timestamp, status: 'SUCCESS' },
        { step_number: 2, name: 'Principal validated.', description: `Validated request syntax, realm '${payload.realm}', and service '${payload.sname}'.`, timestamp, status: 'SUCCESS' },
        { step_number: 3, name: 'KDC lookup completed.', description: `Found principal '${payload.cname}' in KDC database. Derived client key K_C successfully.`, timestamp, status: 'SUCCESS' },
        { step_number: 4, name: 'Session key generated.', description: 'Generated cryptographically secure random 256-bit session key K_C,TGS.', timestamp, status: 'SUCCESS' },
        { step_number: 5, name: 'TGT constructed.', description: `Constructed TGT with client '${payload.cname}', session key, and lifetime ${payload.lifetime}s.`, timestamp, status: 'SUCCESS' },
        { step_number: 6, name: 'TGT encrypted.', description: 'TGT encrypted with master KDC/TGS key (K_TGS) using AES-256-GCM with unique 96-bit nonce.', timestamp, status: 'SUCCESS' },
        { step_number: 7, name: 'Client response encrypted.', description: 'Encrypted session key, sname, and nonce using derived client key (K_C) via AES-256-GCM.', timestamp, status: 'SUCCESS' },
        { step_number: 8, name: 'AS response generated.', description: 'Constructed final KRB_AS_REP containing opaque encrypted TGT and encrypted client package.', timestamp, status: 'SUCCESS' }
      ]
    }
  };
}
