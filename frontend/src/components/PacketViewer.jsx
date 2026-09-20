import React from 'react';
import { Eye, Lock, ShieldAlert, CheckCircle, FileCode, Cpu } from 'lucide-react';

export default function PacketViewer({ requestPacket, responsePacket, isMock }) {
  return (
    <div className="glass-panel">
      <div className="panel-header">
        <h2 className="panel-title">
          <Eye size={18} color="#a855f7" />
          Packet Metadata Inspector (KRB_AS_REQ & KRB_AS_REP)
        </h2>
        <span className="text-xs text-purple-300 font-mono">
          {isMock ? '⚠️ Showing Mock Data Packets' : '🔒 Verified Safe Metadata (No Keys Exposed)'}
        </span>
      </div>

      <div className="panel-body">
        <div className="packet-grid">
          {/* KRB_AS_REQ Panel */}
          <div className="packet-card">
            <div className="packet-title">
              <span className="flex items-center gap-2">
                <FileCode size={16} />
                KRB_AS_REQ (Client Request)
              </span>
              <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                Outbound
              </span>
            </div>

            {requestPacket ? (
              <>
                <div className="packet-field">
                  <span className="packet-key">Client Principal (cname):</span>
                  <span className="packet-val text-cyan-300">{requestPacket.cname}</span>
                </div>
                <div className="packet-field">
                  <span className="packet-key">Realm:</span>
                  <span className="packet-val">{requestPacket.realm}</span>
                </div>
                <div className="packet-field">
                  <span className="packet-key">Service Principal (sname):</span>
                  <span className="packet-val text-cyan-300">{requestPacket.sname}</span>
                </div>
                <div className="packet-field">
                  <span className="packet-key">Nonce:</span>
                  <span className="packet-val">{requestPacket.nonce}</span>
                </div>
                <div className="packet-field">
                  <span className="packet-key">Timestamp (UTC):</span>
                  <span className="packet-val">{requestPacket.timestamp}</span>
                </div>
                <div className="packet-field">
                  <span className="packet-key">Lifetime:</span>
                  <span className="packet-val">{requestPacket.lifetime} seconds</span>
                </div>

                <div className="encrypted-block mt-3">
                  <div className="encrypted-header">
                    <Lock size={12} />
                    <span>Client Credentials Security</span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Client password is never sent over the network. Only identity & replay-protection nonce are transmitted in KRB_AS_REQ.
                  </p>
                </div>
              </>
            ) : (
              <div className="text-center py-8 text-slate-500 text-sm">
                No request submitted yet. Use the Client Request Form to issue KRB_AS_REQ.
              </div>
            )}
          </div>

          {/* KRB_AS_REP Panel */}
          <div className="packet-card">
            <div className="packet-title">
              <span className="flex items-center gap-2">
                <Cpu size={16} />
                KRB_AS_REP (AS Response)
              </span>
              <span className="text-xs px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
                Inbound
              </span>
            </div>

            {responsePacket ? (
              <>
                <div className="packet-field">
                  <span className="packet-key">Message Type:</span>
                  <span className="packet-val text-emerald-400 font-bold">{responsePacket.msg_type || 'KRB_AS_REP'}</span>
                </div>
                <div className="packet-field">
                  <span className="packet-key">Protocol Version (pvno):</span>
                  <span className="packet-val">{responsePacket.pvno || 5}</span>
                </div>
                <div className="packet-field">
                  <span className="packet-key">Authenticated Principal:</span>
                  <span className="packet-val text-emerald-300">{responsePacket.cname}@{responsePacket.crealm}</span>
                </div>
                <div className="packet-field">
                  <span className="packet-key">Encrypted TGT Indicator:</span>
                  <span className="packet-val text-emerald-400 font-semibold flex items-center gap-1 justify-end">
                    <CheckCircle size={12} /> Present (AES-256-GCM)
                  </span>
                </div>
                <div className="packet-field">
                  <span className="packet-key">Encrypted Client Part:</span>
                  <span className="packet-val text-emerald-400 font-semibold flex items-center gap-1 justify-end">
                    <CheckCircle size={12} /> Protected with K_C
                  </span>
                </div>
                <div className="packet-field">
                  <span className="packet-key">Session Key Availability:</span>
                  <span className="packet-val text-purple-300 font-semibold">
                    Encrypted inside Enc_Part
                  </span>
                </div>

                {/* Ticket Encrypted Ciphertext preview */}
                <div className="encrypted-block mt-3">
                  <div className="encrypted-header">
                    <Lock size={12} />
                    <span>Ticket Granting Ticket (TGT) Payload</span>
                  </div>
                  <div className="text-xs font-mono text-purple-300 break-all mb-1">
                    Ciphertext: {responsePacket.ticket?.cipher_b64 ? `${responsePacket.ticket.cipher_b64.substring(0, 32)}...` : '[Encrypted data hidden]'}
                  </div>
                  <div className="text-xs text-slate-400">
                    Target Service: {responsePacket.ticket?.sname || 'krbtgt/CANARA.EDU'} | Encryption: AES-256-GCM (Master Key K_TGS)
                  </div>
                </div>

                {/* Encrypted Client Part preview */}
                <div className="encrypted-block mt-2">
                  <div className="encrypted-header">
                    <Lock size={12} />
                    <span>Encrypted Client Response Package</span>
                  </div>
                  <div className="text-xs font-mono text-purple-300 break-all mb-1">
                    Ciphertext: {responsePacket.enc_part?.cipher_b64 ? `${responsePacket.enc_part.cipher_b64.substring(0, 32)}...` : '[Encrypted data hidden]'}
                  </div>
                  <div className="text-xs text-slate-400">
                    Contains session key K_C,TGS, nonce echo, & ticket expiration. Decryptable only by client key K_C.
                  </div>
                </div>
              </>
            ) : (
              <div className="text-center py-8 text-slate-500 text-sm">
                Awaiting AS Response... Submit request to inspect KRB_AS_REP.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
