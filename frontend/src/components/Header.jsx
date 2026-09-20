import React from 'react';
import { ShieldCheck, Server, RefreshCw, AlertTriangle, Radio } from 'lucide-react';

export default function Header({ backendHealth, isCheckingHealth, onRefreshHealth, isMockMode }) {
  const isHealthy = backendHealth && backendHealth.status === 'healthy';

  return (
    <header className="header-banner">
      <div className="header-title-group">
        <h1>
          <ShieldCheck className="w-8 h-8 text-cyan-400" size={30} color="#38bdf8" />
          Kerberos AS Exchange Simulation
        </h1>
        <div className="header-subtext">
          <span className="college-badge">Canara Engineering College</span>
          <span>•</span>
          <span>Cryptography & Network Security (BCS703)</span>
          <span>•</span>
          <span>Semester VII</span>
          <span>•</span>
          <span className="font-mono text-cyan-400">Team USNs: 4CB23CS160 (Frontend) | 4CB23CS161 (Backend)</span>
        </div>
      </div>

      <div className="header-controls">
        <div className={`status-pill ${isHealthy ? 'healthy' : 'offline'}`}>
          <span className="status-dot"></span>
          <span>{isHealthy ? 'Backend Active (FastAPI)' : 'Backend Offline'}</span>
        </div>

        <div className={`mode-badge ${isMockMode ? 'mock' : 'live'}`}>
          <span className="flex items-center gap-1">
            <Radio size={14} className="inline mr-1" />
            {isMockMode ? 'MOCK DATA MODE' : 'LIVE API MODE'}
          </span>
        </div>

        <button
          onClick={onRefreshHealth}
          disabled={isCheckingHealth}
          className="btn btn-secondary btn-sm"
          title="Refresh backend status"
        >
          <RefreshCw size={14} className={isCheckingHealth ? 'animate-spin' : ''} />
          <span>Check Status</span>
        </button>
      </div>
    </header>
  );
}
