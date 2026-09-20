import React from 'react';
import { Shield, Lock, Cpu } from 'lucide-react';

export default function LoadingSpinner({ message = 'Executing Kerberos AS Exchange...' }) {
  return (
    <div className="glass-panel p-8">
      <div className="spinner-container">
        <div className="cyber-spinner"></div>
        <div className="text-cyan-400 font-semibold text-sm flex items-center gap-2">
          <Shield size={16} className="animate-pulse" />
          {message}
        </div>
        <div className="text-xs text-slate-400 font-mono">
          Verifying principal • Deriving K_C • Generating Session Key K_C,TGS • Encrypting TGT
        </div>
      </div>
    </div>
  );
}
