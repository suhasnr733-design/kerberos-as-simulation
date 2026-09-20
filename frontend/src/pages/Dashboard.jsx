import React, { useState, useEffect } from 'react';
import Header from '../components/Header';
import ClientRequestForm from '../components/ClientRequestForm';
import ProtocolSteps from '../components/ProtocolSteps';
import PacketViewer from '../components/PacketViewer';
import StatusMessage from '../components/StatusMessage';
import LoadingSpinner from '../components/LoadingSpinner';
import { checkHealth, getPrincipals, sendASRequest } from '../services/api';
import { Shield, BookOpen, Layers, Terminal, RefreshCw } from 'lucide-react';

export default function Dashboard() {
  const [backendHealth, setBackendHealth] = useState(null);
  const [isCheckingHealth, setIsCheckingHealth] = useState(false);
  const [principalsData, setPrincipalsData] = useState(null);
  const [isMockMode, setIsMockMode] = useState(false);

  // Exchange state
  const [isLoading, setIsLoading] = useState(false);
  const [requestPacket, setRequestPacket] = useState(null);
  const [responsePacket, setResponsePacket] = useState(null);
  const [statusInfo, setStatusInfo] = useState(null);
  const [telemetry, setTelemetry] = useState(null);
  const [activeStep, setActiveStep] = useState(0);
  const [hasFailed, setHasFailed] = useState(false);
  const [failedStepNumber, setFailedStepNumber] = useState(null);

  // Perform backend health check on initial load
  const performHealthCheck = async () => {
    setIsCheckingHealth(true);
    const healthResult = await checkHealth();
    setBackendHealth(healthResult.data);
    setIsMockMode(healthResult.isMock);

    // Fetch principals list
    const principalsResult = await getPrincipals();
    if (principalsResult.data && principalsResult.data.principals) {
      setPrincipalsData(principalsResult.data.principals);
    }
    setIsCheckingHealth(false);
  };

  useEffect(() => {
    performHealthCheck();
  }, []);

  // Handle AS Request submission
  const handleASRequestSubmit = async (payload) => {
    setIsLoading(true);
    setHasFailed(false);
    setFailedStepNumber(null);
    setRequestPacket(payload);
    setResponsePacket(null);
    setStatusInfo(null);
    setTelemetry(null);

    // Initial step animation feedback
    setActiveStep(1);
    await new Promise((resolve) => setTimeout(resolve, 150));
    setActiveStep(2);

    // Call API service
    const result = await sendASRequest(payload);
    setIsLoading(false);

    if (result.success) {
      setResponsePacket(result.data);
      setTelemetry(result.data.telemetry || null);
      setActiveStep(8);
      setHasFailed(false);
      setFailedStepNumber(null);

      setStatusInfo({
        type: 'success',
        message: result.isMock
          ? 'Simulated KRB_AS_REP exchange completed using educational mock data.'
          : 'KRB_AS_REP successfully generated and verified by FastAPI Authentication Server.',
        timestamp: new Date().toISOString(),
        isMock: result.isMock,
      });
    } else {
      setHasFailed(true);
      
      // Determine which step failed based on Kerberos error code
      let stepErr = 2;
      if (result.errorCode === 'KDC_ERR_C_PRINCIPAL_UNKNOWN') {
        stepErr = 3; // Failed during KDC database lookup
      } else if (result.errorCode === 'KDC_ERR_S_PRINCIPAL_UNKNOWN' || result.errorCode === 'KRB_AP_ERR_SKEW' || result.errorCode === 'KDC_ERR_WRONG_REALM') {
        stepErr = 2; // Failed during principal/realm validation
      }
      setFailedStepNumber(stepErr);
      setActiveStep(stepErr);

      setStatusInfo({
        type: 'error',
        message: result.error || 'AS Exchange request failed.',
        errorCode: result.errorCode || 'KDC_ERR_UNKNOWN',
        timestamp: result.timestamp || new Date().toISOString(),
        isMock: result.isMock,
      });
    }
  };

  // Reset simulation state
  const handleResetSimulation = () => {
    setRequestPacket(null);
    setResponsePacket(null);
    setStatusInfo(null);
    setTelemetry(null);
    setActiveStep(0);
    setHasFailed(false);
    setFailedStepNumber(null);
  };

  return (
    <div className="dashboard-container">
      {/* Top Banner Header */}
      <Header
        backendHealth={backendHealth}
        isCheckingHealth={isCheckingHealth}
        onRefreshHealth={performHealthCheck}
        isMockMode={isMockMode}
      />

      {/* Backend Status Details / Educational Banner */}
      {isMockMode && (
        <div className="glass-panel p-4 border-amber-500/40 bg-amber-950/20">
          <div className="flex items-start gap-3">
            <div className="text-amber-400 font-bold text-lg">⚠️ MOCK MODE ACTIVE:</div>
            <div className="text-sm text-slate-300">
              The FastAPI backend on <code className="text-cyan-300">http://127.0.0.1:8000</code> is currently offline or unreachable.
              The UI is functioning in <strong>Educational Mock Mode</strong>. To connect to the live backend, launch the FastAPI server in your terminal:
              <br />
              <code className="text-xs bg-slate-900 px-2 py-1 rounded text-emerald-400 mt-1 inline-block">
                cd backend &amp;&amp; python -m uvicorn app.main:app --port 8000 --reload
              </code>
            </div>
          </div>
        </div>
      )}

      {/* Status Alerts */}
      <StatusMessage statusInfo={statusInfo} />

      {/* Overview Cards */}
      <div className="glass-panel p-6">
        <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2 mb-3">
          <BookOpen size={20} className="text-cyan-400" />
          Kerberos Initial Authentication Server (AS) Exchange
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          The <strong>KRB_AS_REQ / KRB_AS_REP</strong> exchange allows a client to authenticate to the Key Distribution Center (KDC)
          and obtain a <em>Ticket Granting Ticket (TGT)</em> without transmitting plaintext passwords across the network.
          The AS verifies the client identity in the database, generates a 256-bit ephemeral session key \(K_{'{C,TGS}'}\), encrypts the TGT using the TGS master key \(K_{'{TGS}'}\), and returns the encrypted client part protected by key \(K_C\).
        </p>
      </div>

      {/* Main Grid: Form (Left) & Stepper (Right) */}
      <div className="grid-2col">
        <ClientRequestForm
          onSubmitRequest={handleASRequestSubmit}
          isLoading={isLoading}
          principalsList={principalsData}
          onReset={handleResetSimulation}
        />

        {isLoading ? (
          <LoadingSpinner message="Communicating with Kerberos Authentication Server..." />
        ) : (
          <ProtocolSteps
            activeStep={activeStep}
            telemetryData={telemetry}
            hasFailed={hasFailed}
            failedStepNumber={failedStepNumber}
          />
        )}
      </div>

      {/* Bottom Section: Packet Metadata Inspector */}
      <PacketViewer
        requestPacket={requestPacket}
        responsePacket={responsePacket}
        isMock={statusInfo?.isMock || isMockMode}
      />

      {/* Footer */}
      <footer className="footer-info">
        <div>
          Kerberos Authentication Server (AS) Simulation • Cryptography &amp; Network Security (BCS703)
        </div>
        <div className="text-xs text-slate-500 mt-1">
          Canara Engineering College • Department of Computer Science &amp; Engineering • VII Semester
        </div>
      </footer>
    </div>
  );
}
