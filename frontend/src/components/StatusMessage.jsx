import React from 'react';
import { AlertTriangle, CheckCircle2, Info, XCircle } from 'lucide-react';

export default function StatusMessage({ statusInfo }) {
  if (!statusInfo) return null;

  const { type, message, errorCode, timestamp, isMock } = statusInfo;

  const isError = type === 'error';
  const isSuccess = type === 'success';

  return (
    <div className={`status-banner ${isError ? 'error' : isSuccess ? 'success' : 'info'}`}>
      <div className="flex-shrink-0 mt-0.5">
        {isError ? (
          <XCircle size={20} className="text-rose-400" />
        ) : isSuccess ? (
          <CheckCircle2 size={20} className="text-emerald-400" />
        ) : (
          <Info size={20} className="text-cyan-400" />
        )}
      </div>

      <div className="flex-1">
        <div className="flex items-center justify-between gap-2">
          <span className="font-semibold text-sm">
            {isError ? 'Kerberos Protocol / API Error' : isSuccess ? 'Kerberos AS Exchange Successful' : 'Notice'}
          </span>
          {isMock && (
            <span className="text-xs px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 font-mono">
              [MOCK DATA]
            </span>
          )}
        </div>

        <p className="mt-1 text-sm">{message}</p>

        {errorCode && (
          <div className="status-code-tag mt-2">
            Error Code: <span className="text-rose-300 font-mono">{errorCode}</span>
          </div>
        )}

        {timestamp && (
          <div className="text-xs opacity-75 mt-1 font-mono">
            Timestamp: {timestamp}
          </div>
        )}
      </div>
    </div>
  );
}
