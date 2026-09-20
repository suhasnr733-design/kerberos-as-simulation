import React from 'react';
import { CheckCircle2, AlertCircle, Loader2, GitCommit } from 'lucide-react';

const DEFAULT_8_STEPS = [
  { step_number: 1, name: 'Request received.', description: 'Received KRB_AS_REQ for client identity requesting service credentials.' },
  { step_number: 2, name: 'Principal validated.', description: 'Validated request syntax, realm (CANARA.EDU), and service (krbtgt/CANARA.EDU).' },
  { step_number: 3, name: 'KDC lookup completed.', description: 'Found principal in KDC database and derived client secret key K_C.' },
  { step_number: 4, name: 'Session key generated.', description: 'Generated cryptographically secure random 256-bit session key K_C,TGS.' },
  { step_number: 5, name: 'TGT constructed.', description: 'Constructed TGT with client identity, session key, authtime, and lifetime.' },
  { step_number: 6, name: 'TGT encrypted.', description: 'TGT encrypted with master KDC/TGS key (K_TGS) using AES-256-GCM with unique nonce.' },
  { step_number: 7, name: 'Client response encrypted.', description: 'Encrypted session key, sname, and nonce using derived client key K_C via AES-256-GCM.' },
  { step_number: 8, name: 'AS response generated.', description: 'Constructed final KRB_AS_REP containing opaque encrypted TGT and encrypted client package.' },
];

export default function ProtocolSteps({ activeStep, stepStatuses, telemetryData, hasFailed, failedStepNumber }) {
  // If real telemetry is returned from backend, use backend steps directly
  let stepsToDisplay = DEFAULT_8_STEPS;

  if (telemetryData && telemetryData.length > 0) {
    // Map backend telemetry steps into render format
    stepsToDisplay = DEFAULT_8_STEPS.map((defStep) => {
      const backendStep = telemetryData.find((t) => t.step_number === defStep.step_number);
      if (backendStep) {
        return {
          step_number: backendStep.step_number,
          name: backendStep.name,
          description: backendStep.description,
          status: backendStep.status === 'SUCCESS' ? 'Completed' : 'Failed',
        };
      }
      return { ...defStep, status: 'Pending' };
    });
  } else {
    // Compute status based on activeStep and failure state
    stepsToDisplay = DEFAULT_8_STEPS.map((step) => {
      let status = 'Pending';

      if (stepStatuses && stepStatuses[step.step_number]) {
        status = stepStatuses[step.step_number];
      } else if (hasFailed && failedStepNumber && step.step_number === failedStepNumber) {
        status = 'Failed';
      } else if (hasFailed && step.step_number === activeStep) {
        status = 'Failed';
      } else if (activeStep !== undefined && activeStep > 0) {
        if (step.step_number < activeStep) {
          status = 'Completed';
        } else if (step.step_number === activeStep) {
          status = hasFailed ? 'Failed' : 'Processing';
        }
      }

      return {
        ...step,
        status,
      };
    });
  }

  return (
    <div className="glass-panel">
      <div className="panel-header">
        <h2 className="panel-title">
          <GitCommit size={18} color="#10b981" />
          Protocol Execution Telemetry & Stepper
        </h2>
        <span className="text-xs text-slate-400 font-mono">8-Step AS Workflow</span>
      </div>

      <div className="panel-body">
        <div className="stepper-list">
          {stepsToDisplay.map((step) => (
            <div key={step.step_number} className={`step-item ${step.status}`}>
              <div className="step-badge">
                {step.status === 'Completed' ? (
                  <CheckCircle2 size={16} />
                ) : step.status === 'Failed' ? (
                  <AlertCircle size={16} />
                ) : step.status === 'Processing' ? (
                  <Loader2 size={16} className="animate-spin" />
                ) : (
                  <span>{step.step_number}</span>
                )}
              </div>

              <div className="step-content">
                <div className="step-title-row">
                  <span className="step-title">
                    Step {step.step_number}: {step.name}
                  </span>
                  <span className="step-status-tag">{step.status}</span>
                </div>
                <p className="step-desc">{step.description}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
