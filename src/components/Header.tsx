import React from 'react';
import { Lock, UserCheck, RefreshCw, Terminal, Eye, FileText, LogOut } from 'lucide-react';
import { AuthUser } from '../types';

interface HeaderProps {
  currentUser: AuthUser | null;
  activeTab: 'journal' | 'audit' | 'threat-model' | 'constitution';
  setActiveTab: (tab: 'journal' | 'audit' | 'threat-model' | 'constitution') => void;
  onSwitchUser: (uid: string) => void;
  onSignOut?: () => void;
  isSwitching: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  currentUser,
  activeTab,
  setActiveTab,
  onSwitchUser,
  onSignOut,
  isSwitching,
}) => {
  return (
    <header className="h-20 border-b border-[#262626] flex items-center justify-between px-4 sm:px-8 bg-[#0a0a0a] text-[#e5e7eb] sticky top-0 z-50">
      {/* Brand & Title */}
      <div className="flex items-center gap-4">
        <div className="w-10 h-10 bg-[#f59e0b] rounded-lg flex items-center justify-center text-[#050505] font-bold text-xl shadow-sm select-none">
          &Sigma;
        </div>
        <div>
          <h1 className="text-lg font-serif italic tracking-wide text-white leading-tight">
            Personal Gemini Journal
          </h1>
          <p className="text-[10px] uppercase tracking-[0.2em] text-[#737373] font-sans font-medium">
            Zero-Trust Vault &bull; Gemini 2.5
          </p>
        </div>
      </div>

      {/* Navigation Controls (Pill Aesthetic) */}
      <nav className="hidden md:flex items-center gap-1.5 sm:gap-2">
        <button
          id="tab-journal"
          onClick={() => setActiveTab('journal')}
          className={`px-3 py-1 rounded-full text-[10px] uppercase tracking-wider transition-all flex items-center gap-1.5 font-medium ${
            activeTab === 'journal'
              ? 'bg-white text-black font-bold shadow-xs'
              : 'border border-[#262626] text-[#a3a3a3] hover:text-white hover:border-[#3f3f46] hover:bg-[#171717]'
          }`}
        >
          <Lock className="h-3 w-3" />
          <span>Journal Vault</span>
        </button>

        <button
          id="tab-audit"
          onClick={() => setActiveTab('audit')}
          className={`px-3 py-1 rounded-full text-[10px] uppercase tracking-wider transition-all flex items-center gap-1.5 font-medium ${
            activeTab === 'audit'
              ? 'bg-white text-black font-bold shadow-xs'
              : 'border border-[#262626] text-[#a3a3a3] hover:text-white hover:border-[#3f3f46] hover:bg-[#171717]'
          }`}
        >
          <Terminal className="h-3 w-3" />
          <span>Security Audit</span>
        </button>

        <button
          id="tab-threat-model"
          onClick={() => setActiveTab('threat-model')}
          className={`px-3 py-1 rounded-full text-[10px] uppercase tracking-wider transition-all flex items-center gap-1.5 font-medium ${
            activeTab === 'threat-model'
              ? 'bg-white text-black font-bold shadow-xs'
              : 'border border-[#262626] text-[#a3a3a3] hover:text-white hover:border-[#3f3f46] hover:bg-[#171717]'
          }`}
        >
          <Eye className="h-3 w-3" />
          <span>Threat Model</span>
        </button>

        <button
          id="tab-constitution"
          onClick={() => setActiveTab('constitution')}
          className={`px-3 py-1 rounded-full text-[10px] uppercase tracking-wider transition-all flex items-center gap-1.5 font-medium ${
            activeTab === 'constitution'
              ? 'bg-white text-black font-bold shadow-xs'
              : 'border border-[#262626] text-[#a3a3a3] hover:text-white hover:border-[#3f3f46] hover:bg-[#171717]'
          }`}
        >
          <FileText className="h-3 w-3" />
          <span>Constitution</span>
        </button>
      </nav>

      {/* User Session & Security Switcher */}
      <div className="flex items-center gap-3 sm:gap-4">
        <div className="hidden xl:flex items-center gap-1.5 px-2.5 py-1 bg-[#171717] rounded border border-[#262626] text-xs">
          <UserCheck className="h-3.5 w-3.5 text-[#10b981]" />
          <span className="text-[10px] uppercase text-[#737373]">Signed In:</span>
          <span className="font-mono text-[#d1d5db] font-medium truncate max-w-[130px]">
            {currentUser?.displayName || currentUser?.email || 'User'}
          </span>
        </div>

        {/* Persona Switcher for Quick Penetration / Evaluation Testing */}
        <div className="relative">
          <select
            id="select-security-principal"
            aria-label="Switch Test Security Principal"
            disabled={isSwitching}
            value={
              currentUser?.uid === 'usr_alice_sec' ||
              currentUser?.uid === 'usr_bob_cloud' ||
              currentUser?.uid === 'usr_charlie_aud'
                ? currentUser.uid
                : 'custom_firebase'
            }
            onChange={(e) => {
              if (e.target.value !== 'custom_firebase') {
                onSwitchUser(e.target.value);
              }
            }}
            className="text-[11px] bg-[#171717] text-[#e5e7eb] border border-[#262626] rounded px-2.5 py-1.5 pr-6 cursor-pointer focus:outline-none focus:border-[#f59e0b] hover:border-[#3f3f46] font-mono transition-colors"
          >
            <option value="usr_alice_sec">Alice (SecOps)</option>
            <option value="usr_bob_cloud">Bob (Cloud Arch)</option>
            <option value="usr_charlie_aud">Charlie (Auditor)</option>
            {currentUser &&
              currentUser.uid !== 'usr_alice_sec' &&
              currentUser.uid !== 'usr_bob_cloud' &&
              currentUser.uid !== 'usr_charlie_aud' && (
                <option value="custom_firebase">
                  {currentUser.displayName || currentUser.email || 'Firebase Auth'}
                </option>
              )}
          </select>
          {isSwitching && (
            <RefreshCw className="h-3 w-3 text-[#f59e0b] animate-spin absolute right-2 top-2.5 pointer-events-none" />
          )}
        </div>

        {/* Sign Out Button */}
        {onSignOut && (
          <button
            id="btn-sign-out"
            onClick={onSignOut}
            title="Sign Out of Session"
            className="p-1.5 rounded border border-[#262626] hover:border-[#ef4444] text-[#a3a3a3] hover:text-[#ef4444] hover:bg-[#171717] transition-colors cursor-pointer"
          >
            <LogOut className="h-4 w-4" />
          </button>
        )}
      </div>
    </header>
  );
};
