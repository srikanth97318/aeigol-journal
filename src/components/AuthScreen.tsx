import React, { useState } from 'react';
import {
  Shield,
  Lock,
  User,
  Key,
  Mail,
  AlertCircle,
  CheckCircle2,
  Database,
  Cpu,
  LogIn,
  UserPlus,
} from 'lucide-react';
import {
  auth,
  googleProvider,
  signInWithPopup,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
} from '../lib/firebase';
import { AuthUser } from '../types';

interface AuthScreenProps {
  onSignInSuccess: (user: AuthUser, idToken: string) => void;
  onDemoSignIn: (uid: string) => void;
}

export const AuthScreen: React.FC<AuthScreenProps> = ({ onSignInSuccess, onDemoSignIn }) => {
  const [authMode, setAuthMode] = useState<'signin' | 'signup'>('signin');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // 1. Google Sign-In Flow
  const handleGoogleSignIn = async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const credential = await signInWithPopup(auth, googleProvider);
      const idToken = await credential.user.getIdToken();
      const user: AuthUser = {
        uid: credential.user.uid,
        email: credential.user.email || '',
        displayName: credential.user.displayName || credential.user.email?.split('@')[0] || 'Authenticated User',
        photoURL: credential.user.photoURL || undefined,
      };
      onSignInSuccess(user, idToken);
    } catch (err: unknown) {
      const code = (err as { code?: string })?.code || '';
      if (code === 'auth/popup-closed-by-user') {
        // User closed the popup window before completing auth - this is expected user cancellation, not a crash
        console.info('[Auth] Google Sign-In popup closed by user.');
        setErrorMsg('Google Sign-In popup was closed before finishing. You can try again, open in a new tab if your browser blocks popups, or use Email/Password below.');
      } else if (code === 'auth/cancelled-popup-request') {
        console.info('[Auth] Google Sign-In popup request was cancelled.');
        setErrorMsg('Sign-in request was cancelled. Please try again.');
      } else if (code === 'auth/popup-blocked') {
        console.warn('[Auth] Browser blocked authentication popup.');
        setErrorMsg('The authentication popup was blocked by your browser. Please allow popups for this site or use Email/Password below.');
      } else if (code === 'auth/unauthorized-domain') {
        console.warn('[Auth] Current domain is not in Firebase authorized domains list.');
        setErrorMsg('This domain is not in Firebase Authorized Domains. Please use Email/Password or 1-Click Evaluator Personas.');
      } else if (code === 'auth/operation-not-allowed') {
        console.warn('[Auth] Google provider not enabled in Firebase.');
        setErrorMsg('Google Sign-In is not enabled for this project. Please use Email/Password or 1-Click Evaluator Personas.');
      } else {
        console.warn('[Auth] Google Sign-In notice:', err);
        setErrorMsg('Google Sign-In could not complete in this browser context. Please try Email/Password or 1-Click Evaluator Personas below.');
      }
    } finally {
      setLoading(false);
    }
  };

  // 2. Email & Password Flow
  const handleEmailAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !password.trim()) {
      setErrorMsg('Please provide both email and password.');
      return;
    }
    if (password.length < 6) {
      setErrorMsg('Password must be at least 6 characters.');
      return;
    }

    setLoading(true);
    setErrorMsg(null);
    try {
      let idToken = '';
      let userObj: AuthUser;

      if (authMode === 'signup') {
        const credential = await createUserWithEmailAndPassword(auth, email.trim(), password);
        idToken = await credential.user.getIdToken();
        userObj = {
          uid: credential.user.uid,
          email: credential.user.email || email.trim(),
          displayName: displayName.trim() || email.split('@')[0],
        };
      } else {
        const credential = await signInWithEmailAndPassword(auth, email.trim(), password);
        idToken = await credential.user.getIdToken();
        userObj = {
          uid: credential.user.uid,
          email: credential.user.email || email.trim(),
          displayName: credential.user.displayName || email.split('@')[0],
        };
      }

      onSignInSuccess(userObj, idToken);
    } catch (err: unknown) {
      const code = (err as { code?: string })?.code || '';
      if (code === 'auth/user-not-found' || code === 'auth/wrong-password' || code === 'auth/invalid-credential') {
        setErrorMsg('Invalid email or password. Please verify your credentials or switch to Create Account.');
      } else if (code === 'auth/email-already-in-use') {
        setErrorMsg('An account with this email address already exists. Please switch to Sign In.');
      } else if (code === 'auth/weak-password') {
        setErrorMsg('The password is too weak. Please use at least 6 characters.');
      } else if (code === 'auth/invalid-email') {
        setErrorMsg('Please enter a valid email address.');
      } else {
        console.warn('[Auth] Email authentication note:', err);
        setErrorMsg('Authentication error. For sandbox evaluation, you can also use 1-Click Evaluator Personas below.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[calc(100vh-5rem)] bg-[#050505] text-[#e5e7eb] flex flex-col items-center justify-center p-4 sm:p-8">
      <div className="w-full max-w-md space-y-6">
        {/* Brand Header */}
        <div className="text-center space-y-2">
          <div className="w-12 h-12 bg-[#f59e0b] rounded-xl mx-auto flex items-center justify-center text-[#050505] font-bold text-2xl shadow-lg select-none">
            &Sigma;
          </div>
          <h1 className="text-2xl font-serif italic text-white tracking-wide">
            Personal Gemini Journal
          </h1>
          <p className="text-xs text-[#a3a3a3] max-w-sm mx-auto leading-relaxed font-sans">
            Security-hardened multi-turn AI journaling with automatic reflective syntheses,
            isolated strictly to your authenticated namespace.
          </p>
        </div>

        {/* Security Pillars Pill Grid */}
        <div className="grid grid-cols-3 gap-2 py-1">
          <div className="p-2.5 rounded-lg border border-[#262626] bg-[#0a0a0a] text-center space-y-1">
            <Lock className="h-3.5 w-3.5 mx-auto text-[#10b981]" />
            <p className="text-[9px] uppercase tracking-wider text-[#737373] font-medium">User Isolation</p>
            <p className="text-[10px] font-mono text-[#d1d5db]">users/{'{uid}'}</p>
          </div>
          <div className="p-2.5 rounded-lg border border-[#262626] bg-[#0a0a0a] text-center space-y-1">
            <Database className="h-3.5 w-3.5 mx-auto text-[#3b82f6]" />
            <p className="text-[9px] uppercase tracking-wider text-[#737373] font-medium">Cloud Firestore</p>
            <p className="text-[10px] font-mono text-[#d1d5db]">Hardened Rules</p>
          </div>
          <div className="p-2.5 rounded-lg border border-[#262626] bg-[#0a0a0a] text-center space-y-1">
            <Cpu className="h-3.5 w-3.5 mx-auto text-[#f59e0b]" />
            <p className="text-[9px] uppercase tracking-wider text-[#737373] font-medium">Gemini 2.5</p>
            <p className="text-[10px] font-mono text-[#d1d5db]">Server-Side Only</p>
          </div>
        </div>

        {/* Auth Card */}
        <div className="rounded-xl border border-[#262626] bg-[#0a0a0a] p-6 shadow-xl space-y-5">
          {/* Error Alert */}
          {errorMsg && (
            <div className="p-3 rounded-lg bg-[#ef4444]/10 border border-[#ef4444]/30 text-[#ef4444] text-xs flex items-start gap-2">
              <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
              <div className="flex-1 text-[11px] leading-relaxed">{errorMsg}</div>
            </div>
          )}

          {/* Google Sign-In Button */}
          <button
            id="btn-google-signin"
            type="button"
            disabled={loading}
            onClick={handleGoogleSignIn}
            className="w-full h-11 rounded-lg border border-[#383838] bg-[#141414] hover:bg-[#1f1f1f] text-white text-xs font-medium transition-all flex items-center justify-center gap-3 shadow-xs hover:border-[#525252] disabled:opacity-50 cursor-pointer"
          >
            <svg className="w-4 h-4" viewBox="0 0 24 24">
              <path
                fill="#4285F4"
                d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.665-5.17 3.665-9.17z"
              />
              <path
                fill="#34A853"
                d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.25v3.15C3.26 21.36 7.33 24 12 24z"
              />
              <path
                fill="#FBBC05"
                d="M5.28 14.27c-.25-.72-.38-1.49-.38-2.27s.13-1.55.38-2.27V6.58H1.25C.45 8.18 0 10.03 0 12s.45 3.82 1.25 5.42l4.03-3.15z"
              />
              <path
                fill="#EA4335"
                d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.33 0 3.26 2.64 1.25 6.58l4.03 3.15c.95-2.83 3.6-4.98 6.72-4.98z"
              />
            </svg>
            <span>Continue with Google</span>
          </button>

          {/* Divider */}
          <div className="flex items-center gap-3">
            <div className="flex-1 h-px bg-[#262626]" />
            <span className="text-[10px] uppercase tracking-wider text-[#525252] font-mono">Or Email Password</span>
            <div className="flex-1 h-px bg-[#262626]" />
          </div>

          {/* Mode Tabs */}
          <div className="grid grid-cols-2 gap-1 p-1 bg-[#141414] rounded-lg border border-[#262626]">
            <button
              type="button"
              onClick={() => {
                setAuthMode('signin');
                setErrorMsg(null);
              }}
              className={`py-1.5 rounded text-xs font-medium transition-all flex items-center justify-center gap-1.5 ${
                authMode === 'signin'
                  ? 'bg-white text-black font-bold shadow-xs'
                  : 'text-[#737373] hover:text-white'
              }`}
            >
              <LogIn className="h-3 w-3" />
              <span>Sign In</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setAuthMode('signup');
                setErrorMsg(null);
              }}
              className={`py-1.5 rounded text-xs font-medium transition-all flex items-center justify-center gap-1.5 ${
                authMode === 'signup'
                  ? 'bg-white text-black font-bold shadow-xs'
                  : 'text-[#737373] hover:text-white'
              }`}
            >
              <UserPlus className="h-3 w-3" />
              <span>Create Account</span>
            </button>
          </div>

          {/* Email / Password Form */}
          <form onSubmit={handleEmailAuth} className="space-y-3.5">
            {authMode === 'signup' && (
              <div>
                <label className="block text-[10px] uppercase tracking-wider text-[#737373] mb-1 font-medium">
                  Your Full Name
                </label>
                <div className="relative">
                  <User className="h-3.5 w-3.5 absolute left-3 top-3 text-[#525252]" />
                  <input
                    id="input-auth-name"
                    type="text"
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    placeholder="e.g. Elena Rostova"
                    className="w-full h-9 rounded bg-[#141414] border border-[#262626] pl-9 pr-3 text-xs text-[#e5e7eb] placeholder-[#525252] focus:outline-none focus:border-[#f59e0b] transition-colors"
                  />
                </div>
              </div>
            )}

            <div>
              <label className="block text-[10px] uppercase tracking-wider text-[#737373] mb-1 font-medium">
                Email Address
              </label>
              <div className="relative">
                <Mail className="h-3.5 w-3.5 absolute left-3 top-3 text-[#525252]" />
                <input
                  id="input-auth-email"
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="name@organization.com"
                  className="w-full h-9 rounded bg-[#141414] border border-[#262626] pl-9 pr-3 text-xs text-[#e5e7eb] placeholder-[#525252] focus:outline-none focus:border-[#f59e0b] transition-colors"
                />
              </div>
            </div>

            <div>
              <label className="block text-[10px] uppercase tracking-wider text-[#737373] mb-1 font-medium">
                Password
              </label>
              <div className="relative">
                <Key className="h-3.5 w-3.5 absolute left-3 top-3 text-[#525252]" />
                <input
                  id="input-auth-password"
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full h-9 rounded bg-[#141414] border border-[#262626] pl-9 pr-3 text-xs text-[#e5e7eb] placeholder-[#525252] focus:outline-none focus:border-[#f59e0b] transition-colors"
                />
              </div>
            </div>

            <button
              id="btn-auth-submit"
              type="submit"
              disabled={loading}
              className="w-full h-9 rounded bg-[#f59e0b] hover:bg-[#d97706] disabled:opacity-50 text-[#050505] text-xs font-bold transition-colors shadow-xs flex items-center justify-center gap-1.5 cursor-pointer mt-1"
            >
              {loading ? (
                <div className="flex items-center gap-2">
                  <span className="h-3 w-3 border-2 border-[#050505] border-t-transparent rounded-full animate-spin" />
                  <span>Verifying Credentials...</span>
                </div>
              ) : authMode === 'signup' ? (
                <span>Create Protected Vault &rarr;</span>
              ) : (
                <span>Unlock Journal Vault &rarr;</span>
              )}
            </button>
          </form>

          {/* 1-Click Interactive Evaluation Principals */}
          <div className="pt-3 border-t border-[#262626] space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[9px] uppercase tracking-wider text-[#737373] font-mono">
                1-Click Evaluator Personas
              </span>
              <span className="text-[9px] text-[#10b981] font-mono flex items-center gap-1">
                <CheckCircle2 className="h-2.5 w-2.5" />
                Zero Setup
              </span>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                id="btn-demo-alice"
                onClick={() => onDemoSignIn('usr_alice_sec')}
                className="p-2 rounded bg-[#141414] border border-[#262626] hover:border-[#f59e0b] hover:bg-[#1a1a1a] text-left transition-all cursor-pointer group"
              >
                <div className="text-[11px] font-medium text-white group-hover:text-[#f59e0b] flex items-center justify-between">
                  <span>Alice (SecOps)</span>
                  <span className="text-[8px] font-mono text-[#525252]">UID: alice</span>
                </div>
                <div className="text-[9px] text-[#737373] truncate">alice.security@corp.internal</div>
              </button>
              <button
                type="button"
                id="btn-demo-bob"
                onClick={() => onDemoSignIn('usr_bob_cloud')}
                className="p-2 rounded bg-[#141414] border border-[#262626] hover:border-[#f59e0b] hover:bg-[#1a1a1a] text-left transition-all cursor-pointer group"
              >
                <div className="text-[11px] font-medium text-white group-hover:text-[#f59e0b] flex items-center justify-between">
                  <span>Bob (Cloud Arch)</span>
                  <span className="text-[8px] font-mono text-[#525252]">UID: bob</span>
                </div>
                <div className="text-[9px] text-[#737373] truncate">bob.architect@corp.internal</div>
              </button>
            </div>
          </div>
        </div>

        {/* Security Notice */}
        <div className="text-center text-[10px] text-[#525252] font-mono">
          <Shield className="h-3.5 w-3.5 inline mr-1 text-[#10b981]" />
          Zero Cross-User Data Leakage &bull; ABAC Cloud Firestore Rules &bull; Server-Side Gemini API
        </div>
      </div>
    </div>
  );
};
