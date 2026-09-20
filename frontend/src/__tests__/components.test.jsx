import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import Header from '../components/Header';
import ClientRequestForm from '../components/ClientRequestForm';
import ProtocolSteps from '../components/ProtocolSteps';
import StatusMessage from '../components/StatusMessage';

describe('Frontend Component Render Suite', () => {
  it('renders Header with course name and USNs', () => {
    render(
      <Header
        backendHealth={{ status: 'healthy' }}
        isCheckingHealth={false}
        onRefreshHealth={() => {}}
        isMockMode={false}
      />
    );

    expect(screen.getByText(/Kerberos AS Exchange Simulation/i)).toBeDefined();
    expect(screen.getByText(/4CB23CS160/i)).toBeDefined();
    expect(screen.getByText(/4CB23CS161/i)).toBeDefined();
  });

  it('renders ClientRequestForm with defaults and handles nonce refresh', () => {
    const handleSubmit = vi.fn();
    render(
      <ClientRequestForm
        onSubmitRequest={handleSubmit}
        isLoading={false}
        principalsList={['alice@CANARA.EDU', 'bob@CANARA.EDU']}
        onReset={() => {}}
      />
    );

    const submitBtn = screen.getByText(/Submit KRB_AS_REQ/i);
    expect(submitBtn).toBeDefined();

    const newNonceBtn = screen.getByText(/New Nonce/i);
    fireEvent.click(newNonceBtn);

    const newTimeBtn = screen.getByText(/Sync Time/i);
    fireEvent.click(newTimeBtn);
  });

  it('renders ProtocolSteps 8 steps timeline', () => {
    render(
      <ProtocolSteps
        activeStep={1}
        telemetryData={null}
        hasFailed={false}
      />
    );

    expect(screen.getByText(/Step 1: Request received./i)).toBeDefined();
    expect(screen.getByText(/Step 8: AS response generated./i)).toBeDefined();
  });

  it('renders StatusMessage error alert with Kerberos error code', () => {
    render(
      <StatusMessage
        statusInfo={{
          type: 'error',
          message: 'Client principal not found',
          errorCode: 'KDC_ERR_C_PRINCIPAL_UNKNOWN',
          timestamp: '2026-09-20T10:00:00Z',
        }}
      />
    );

    expect(screen.getByText(/KDC_ERR_C_PRINCIPAL_UNKNOWN/i)).toBeDefined();
    expect(screen.getByText(/Client principal not found/i)).toBeDefined();
  });
});
