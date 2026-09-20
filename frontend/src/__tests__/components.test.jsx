import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import Header from '../components/Header';
import ClientRequestForm from '../components/ClientRequestForm';
import ProtocolSteps from '../components/ProtocolSteps';
import StatusMessage from '../components/StatusMessage';
import PacketViewer, { formatPrincipal } from '../components/PacketViewer';

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

  it('displays dynamic unregistered status and does NOT claim registered when charlie is selected', () => {
    render(
      <ClientRequestForm
        onSubmitRequest={() => {}}
        isLoading={false}
        principalsList={['alice@CANARA.EDU', 'bob@CANARA.EDU']}
        onReset={() => {}}
      />
    );

    // Select charlie@CANARA.EDU preset chip
    const charlieBtn = screen.getByText(/charlie@CANARA.EDU/i);
    fireEvent.click(charlieBtn);

    // Verify dynamic unregistered warning is shown
    expect(screen.getByText(/Unregistered principal/i)).toBeDefined();
    expect(screen.getByText(/KDC_ERR_C_PRINCIPAL_UNKNOWN/i)).toBeDefined();

    // Verify it DOES NOT show the false registered message
    expect(screen.queryByText('Client identity registered with the KDC database.')).toBeNull();
  });

  it('correctly formats authenticated principal without duplicating realm', () => {
    // Direct helper unit tests
    expect(formatPrincipal('bob@CANARA.EDU@CANARA.EDU', 'CANARA.EDU')).toBe('bob@CANARA.EDU');
    expect(formatPrincipal('bob@CANARA.EDU', 'CANARA.EDU')).toBe('bob@CANARA.EDU');
    expect(formatPrincipal('bob', 'CANARA.EDU')).toBe('bob@CANARA.EDU');
    expect(formatPrincipal('alice@CANARA.EDU@CANARA.EDU')).toBe('alice@CANARA.EDU');
    expect(formatPrincipal('alice@CANARA.EDU')).toBe('alice@CANARA.EDU');

    // Component render test
    render(
      <PacketViewer
        requestPacket={{
          cname: 'bob@CANARA.EDU',
          realm: 'CANARA.EDU',
          sname: 'krbtgt/CANARA.EDU',
          nonce: 12345,
          timestamp: '2026-09-20T10:00:00Z',
          lifetime: 36000,
        }}
        responsePacket={{
          msg_type: 'KRB_AS_REP',
          pvno: 5,
          cname: 'bob@CANARA.EDU@CANARA.EDU',
          crealm: 'CANARA.EDU',
          ticket: { sname: 'krbtgt/CANARA.EDU', cipher_b64: 'MOCK' },
          enc_part: { cipher_b64: 'MOCK' },
        }}
        isMock={false}
        hasFailed={false}
      />
    );

    // Both request packet and response packet should have clean 'bob@CANARA.EDU'
    const principalElements = screen.getAllByText('bob@CANARA.EDU');
    expect(principalElements.length).toBe(2);
    // Neither should have duplicate realm
    expect(screen.queryByText('bob@CANARA.EDU@CANARA.EDU')).toBeNull();
  });
});
