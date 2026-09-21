import React, { useState, useEffect } from 'react';
import { Send, Key, Clock, Shield, RefreshCw, UserCheck, RotateCcw } from 'lucide-react';

export default function ClientRequestForm({
  onSubmitRequest,
  isLoading,
  principalsList,
  onReset,
}) {
  const [cname, setCname] = useState('alice@CANARA.EDU');
  const [realm, setRealm] = useState('CANARA.EDU');
  const [sname, setSname] = useState('krbtgt/CANARA.EDU');
  const [nonce, setNonce] = useState('');
  const [timestamp, setTimestamp] = useState('');
  const [lifetime, setLifetime] = useState(36000);
  const [validationError, setValidationError] = useState('');

  // Determine if entered principal is recognized in KDC database
  const registeredPrincipals = (principalsList && principalsList.length > 0)
    ? principalsList
    : ['alice@CANARA.EDU', 'bob@CANARA.EDU'];

  const isRegistered = registeredPrincipals.some(
    (p) => p.toLowerCase() === cname.trim().toLowerCase() ||
           p.split('@')[0].toLowerCase() === cname.trim().toLowerCase()
  );

  // Auto-generate Nonce and Timestamp on mount or reset
  const generateFreshNonce = () => {
    // 32-bit positive integer
    const randomNonce = Math.floor(Math.random() * 2147483646) + 1;
    setNonce(randomNonce);
  };

  const generateFreshTimestamp = () => {
    // UTC ISO 8601 string
    setTimestamp(new Date().toISOString());
  };

  useEffect(() => {
    generateFreshNonce();
    generateFreshTimestamp();
  }, []);

  const handlePresetSelect = (selectedPrincipal) => {
    setCname(selectedPrincipal);
    generateFreshNonce();
    generateFreshTimestamp();
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    setValidationError('');

    if (!cname.trim()) {
      setValidationError('Client principal (cname) is required.');
      return;
    }
    if (!realm.trim()) {
      setValidationError('Realm is required.');
      return;
    }
    if (!sname.trim()) {
      setValidationError('Service principal (sname) is required.');
      return;
    }
    if (!nonce || parseInt(nonce, 10) <= 0) {
      setValidationError('Nonce must be a positive integer.');
      return;
    }
    if (!timestamp.trim()) {
      setValidationError('Timestamp is required.');
      return;
    }
    const lifetimeVal = parseInt(lifetime, 10);
    if (isNaN(lifetimeVal) || lifetimeVal < 300 || lifetimeVal > 86400) {
      setValidationError('Ticket lifetime must be between 300 and 86400 seconds.');
      return;
    }

    onSubmitRequest({
      cname: cname.trim(),
      realm: realm.trim(),
      sname: sname.trim(),
      nonce: parseInt(nonce, 10),
      timestamp: timestamp.trim(),
      lifetime: lifetimeVal,
    });
  };

  return (
    <div className="glass-panel">
      <div className="panel-header">
        <h2 className="panel-title">
          <Send size={18} color="#38bdf8" />
          KRB_AS_REQ Client Request Builder
        </h2>
        <span className="text-xs text-slate-400 font-mono">Phase 1: Initial Credential Request</span>
      </div>

      <div className="panel-body">
        {/* Preset Selector */}
        <div className="form-group">
          <label className="form-label">Educational Sample Principals:</label>
          <div className="presets-container">
            {principalsList && principalsList.length > 0 ? (
              principalsList.map((principal) => (
                <button
                  key={principal}
                  type="button"
                  onClick={() => handlePresetSelect(principal)}
                  className={`preset-chip ${cname === principal ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40' : ''}`}
                >
                  <UserCheck size={12} className="inline mr-1" />
                  {principal} (Valid)
                </button>
              ))
            ) : (
              <>
                <button
                  type="button"
                  onClick={() => handlePresetSelect('alice@CANARA.EDU')}
                  className="preset-chip"
                >
                  alice@CANARA.EDU (Valid)
                </button>
                <button
                  type="button"
                  onClick={() => handlePresetSelect('bob@CANARA.EDU')}
                  className="preset-chip"
                >
                  bob@CANARA.EDU (Valid)
                </button>
              </>
            )}
            <button
              type="button"
              onClick={() => handlePresetSelect('charlie@CANARA.EDU')}
              className={`preset-chip text-amber-400 border-amber-800/60 ${cname === 'charlie@CANARA.EDU' ? 'bg-amber-500/20 border-amber-500/50' : ''}`}
            >
              charlie@CANARA.EDU (Unknown)
            </button>
          </div>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Client Principal (cname)</label>
            <input
              type="text"
              className="form-input"
              value={cname}
              onChange={(e) => setCname(e.target.value)}
              placeholder="e.g. alice@CANARA.EDU"
              required
            />
            {!cname.trim() ? (
              <div className="form-hint text-slate-400">
                Enter a registered client principal (e.g. alice@CANARA.EDU).
              </div>
            ) : isRegistered ? (
              <div className="form-hint text-emerald-400/90 flex items-center gap-1">
                <UserCheck size={12} />
                <span>Registered client principal in KDC database.</span>
              </div>
            ) : (
              <div className="form-hint text-amber-400/90 flex items-center gap-1">
                <Shield size={12} />
                <span>Unregistered principal — KDC will reject with KDC_ERR_C_PRINCIPAL_UNKNOWN.</span>
              </div>
            )}
          </div>

          <div className="grid-2col" style={{ gap: '1rem', marginBottom: '1rem' }}>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Realm</label>
              <input
                type="text"
                className="form-input"
                value={realm}
                onChange={(e) => setRealm(e.target.value)}
                placeholder="CANARA.EDU"
                required
              />
            </div>

            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Service Principal (sname)</label>
              <input
                type="text"
                className="form-input"
                value={sname}
                onChange={(e) => setSname(e.target.value)}
                placeholder="krbtgt/CANARA.EDU"
                required
              />
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">Nonce (32-bit Random Replay Protection)</label>
            <div className="input-with-button">
              <input
                type="number"
                className="form-input"
                value={nonce}
                onChange={(e) => setNonce(e.target.value)}
                required
              />
              <button
                type="button"
                onClick={generateFreshNonce}
                className="btn btn-secondary btn-sm"
                title="Generate fresh random nonce"
              >
                <RefreshCw size={14} />
                <span>New Nonce</span>
              </button>
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">Client Timestamp (UTC ISO 8601)</label>
            <div className="input-with-button">
              <input
                type="text"
                className="form-input"
                value={timestamp}
                onChange={(e) => setTimestamp(e.target.value)}
                required
              />
              <button
                type="button"
                onClick={generateFreshTimestamp}
                className="btn btn-secondary btn-sm"
                title="Update to current UTC time"
              >
                <Clock size={14} />
                <span>Sync Time</span>
              </button>
            </div>
            <div className="form-hint">Must be within ±300 seconds of KDC clock skew window.</div>
          </div>

          <div className="form-group">
            <label className="form-label">Requested Ticket Lifetime (seconds)</label>
            <input
              type="number"
              className="form-input"
              value={lifetime}
              onChange={(e) => setLifetime(e.target.value)}
              min={300}
              max={86400}
              required
            />
            <div className="form-hint">Default: 36000 seconds (10 hours). Range: 300 to 86400s.</div>
          </div>

          {validationError && (
            <div className="p-3 mb-4 text-xs text-rose-400 bg-rose-950/40 border border-rose-800/50 rounded-md">
              ⚠️ {validationError}
            </div>
          )}

          <div className="form-actions">
            <button
              type="submit"
              disabled={isLoading}
              className="btn btn-primary btn-submit"
            >
              <Send size={16} className="btn-icon" />
              <span>{isLoading ? 'Processing AS Exchange...' : 'Submit KRB_AS_REQ'}</span>
            </button>

            <button
              type="button"
              onClick={() => {
                generateFreshNonce();
                generateFreshTimestamp();
                if (onReset) onReset();
              }}
              className="btn btn-secondary btn-reset"
            >
              <RotateCcw size={16} className="btn-icon" />
              <span>Reset</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
