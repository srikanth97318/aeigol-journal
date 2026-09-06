import React, { useState, useEffect, useCallback } from 'react';
import { Header } from './components/Header';
import { JournalView } from './components/JournalView';
import { SecurityAuditView } from './components/SecurityAuditView';
import { ThreatModelView } from './components/ThreatModelView';
import { ConstitutionView } from './components/ConstitutionView';
import { AuthScreen } from './components/AuthScreen';
import {
  auth,
  onAuthStateChanged,
  signOut,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
} from './lib/firebase';
import { AuthUser, Conversation, Message, Summary, AuditReport } from './types';

// Pre-defined credentials for evaluation and testing personas (using real Firebase Auth)
const DEMO_ACCOUNTS: Record<string, { email: string; pass: string; displayName: string }> = {
  usr_alice_sec: {
    email: 'alice.secops@aegisjournal.com',
    pass: 'AegisSecOps2026!Key',
    displayName: 'Alice (SecOps Lead)',
  },
  usr_bob_cloud: {
    email: 'bob.cloud@aegisjournal.com',
    pass: 'AegisCloud2026!Key',
    displayName: 'Bob (Cloud Architect)',
  },
  usr_charlie_aud: {
    email: 'charlie.auditor@aegisjournal.com',
    pass: 'AegisAudit2026!Key',
    displayName: 'Charlie (Compliance Auditor)',
  },
};

export default function App() {
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);
  const [currentToken, setCurrentToken] = useState<string | null>(null);
  const [isAuthChecking, setIsAuthChecking] = useState(true);

  const [activeTab, setActiveTab] = useState<'journal' | 'audit' | 'threat-model' | 'constitution'>('journal');
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [activeConversation, setActiveConversation] = useState<Conversation | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [summaries, setSummaries] = useState<Summary[]>([]);
  const [auditReport, setAuditReport] = useState<AuditReport | null>(null);

  const [isLoadingSession, setIsLoadingSession] = useState(false);
  const [isLoadingMessages, setIsLoadingMessages] = useState(false);
  const [isSendingMessage, setIsSendingMessage] = useState(false);
  const [isGeneratingSummary, setIsGeneratingSummary] = useState(false);
  const [isRunningAudit, setIsRunningAudit] = useState(false);
  const [isSwitchingUser, setIsSwitchingUser] = useState(false);

  // Helper to construct Authorization header (strictly verified Bearer token)
  const getAuthHeader = useCallback(
    (customToken?: string): Record<string, string> => {
      const token = customToken || currentToken;
      return token ? { Authorization: `Bearer ${token}` } : {};
    },
    [currentToken]
  );

  // 1. Fetch User Data (Conversations & Summaries)
  const fetchUserData = useCallback(
    async (user: AuthUser, token?: string) => {
      setIsLoadingSession(true);
      try {
        const headers = {
          ...getAuthHeader(token),
        };

        // 1. Fetch user's isolated conversations
        const convsRes = await fetch(`/api/users/${user.uid}/conversations`, { headers });
        if (convsRes.ok) {
          const convsData = await convsRes.json();
          const list: Conversation[] = convsData.conversations || [];
          setConversations(list);
          if (list.length > 0) {
            setActiveConversation((prev) => {
              if (prev && list.some((c) => c.id === prev.id)) {
                return prev;
              }
              return list[0];
            });
          } else {
            setActiveConversation(null);
            setMessages([]);
          }
        }

        // 2. Fetch user's isolated summaries
        const sumsRes = await fetch(`/api/users/${user.uid}/summaries`, { headers });
        if (sumsRes.ok) {
          const sumsData = await sumsRes.json();
          setSummaries(sumsData.summaries || []);
        }
      } catch (err) {
        console.error('Failed to load user partition data:', err);
      } finally {
        setIsLoadingSession(false);
      }
    },
    [getAuthHeader]
  );

  // 2. Listen to Firebase Authentication State
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      if (firebaseUser) {
        try {
          const idToken = await firebaseUser.getIdToken();
          const userObj: AuthUser = {
            uid: firebaseUser.uid,
            email: firebaseUser.email || '',
            displayName:
              firebaseUser.displayName ||
              (firebaseUser.email ? firebaseUser.email.split('@')[0] : 'Journal Author'),
            photoURL: firebaseUser.photoURL || undefined,
          };
          setCurrentUser(userObj);
          setCurrentToken(idToken);
          await fetchUserData(userObj, idToken);
        } catch (err) {
          console.error('Error obtaining Firebase token:', err);
        }
      } else {
        // User is unauthenticated. Clear private session state and never auto-login!
        setCurrentUser(null);
        setCurrentToken(null);
        setConversations([]);
        setActiveConversation(null);
        setMessages([]);
        setSummaries([]);
      }
      setIsAuthChecking(false);
    });

    return () => unsubscribe();
  }, [fetchUserData]);

  // 3. Automated Security Audit Runner
  const handleRunAudit = useCallback(async () => {
    setIsRunningAudit(true);
    try {
      const res = await fetch('/api/security/run-audit-suite', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setAuditReport(data);
      }
    } catch (err) {
      console.error('Audit execution failed:', err);
    } finally {
      setIsRunningAudit(false);
    }
  }, []);

  // Initial audit run
  useEffect(() => {
    handleRunAudit();
  }, [handleRunAudit]);

  // 4. Load Messages for active conversation
  const loadMessages = useCallback(
    async (conversationId: string, uid: string) => {
      setIsLoadingMessages(true);
      try {
        const res = await fetch(`/api/users/${uid}/conversations/${conversationId}/messages`, {
          headers: getAuthHeader(),
        });
        if (res.ok) {
          const data = await res.json();
          setMessages(data.messages || []);
        }
      } catch (err) {
        console.error('Failed to fetch messages:', err);
      } finally {
        setIsLoadingMessages(false);
      }
    },
    [getAuthHeader]
  );

  // Reload messages when activeConversation changes
  useEffect(() => {
    if (activeConversation && currentUser) {
      loadMessages(activeConversation.id, currentUser.uid);
    }
  }, [activeConversation, currentUser, loadMessages]);

  // Sign In with Firebase Credential
  const handleFirebaseSignInSuccess = async (user: AuthUser, idToken: string) => {
    setCurrentUser(user);
    setCurrentToken(idToken);
    await fetchUserData(user, idToken);
  };

  // Persona Sign-In: Performs real Firebase Authentication and obtains real cryptographic tokens
  const handleDemoSignIn = async (personaKey: string) => {
    setIsSwitchingUser(true);
    try {
      const demoAccount = DEMO_ACCOUNTS[personaKey] || DEMO_ACCOUNTS['usr_alice_sec'];
      let userCredential;
      try {
        userCredential = await signInWithEmailAndPassword(auth, demoAccount.email, demoAccount.pass);
      } catch (authErr: unknown) {
        const code = (authErr as { code?: string })?.code;
        if (
          code === 'auth/user-not-found' ||
          code === 'auth/invalid-credential' ||
          code === 'auth/invalid-login-credentials'
        ) {
          userCredential = await createUserWithEmailAndPassword(auth, demoAccount.email, demoAccount.pass);
        } else {
          throw authErr;
        }
      }

      const idToken = await userCredential.user.getIdToken();
      const userObj: AuthUser = {
        uid: userCredential.user.uid,
        email: userCredential.user.email || demoAccount.email,
        displayName: demoAccount.displayName,
      };
      setCurrentUser(userObj);
      setCurrentToken(idToken);
      setActiveConversation(null);
      setMessages([]);
      await fetchUserData(userObj, idToken);
    } catch (err) {
      console.error('Failed to authenticate demo persona via Firebase Auth:', err);
    } finally {
      setIsSwitchingUser(false);
    }
  };

  // Sign Out Flow: explicitly signs out of Firebase, clears all private state, remains on AuthScreen
  const handleSignOut = async () => {
    try {
      await signOut(auth);
    } catch (err) {
      console.warn('SignOut error:', err);
    }
    setCurrentUser(null);
    setCurrentToken(null);
    setConversations([]);
    setActiveConversation(null);
    setMessages([]);
    setSummaries([]);
  };

  // Handle Create Conversation
  const handleCreateConversation = async (title: string, theme: string) => {
    if (!currentUser) return;
    const res = await fetch(`/api/users/${currentUser.uid}/conversations`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...getAuthHeader(),
      },
      body: JSON.stringify({ title, theme }),
    });

    if (!res.ok) {
      const errData = await res.json();
      throw new Error(errData.error || 'Failed to create conversation');
    }

    const data = await res.json();
    setConversations((prev) => [data.conversation, ...prev]);
    setActiveConversation(data.conversation);
    setMessages([]);
  };

  // Handle Send Message (Automatic Summary Generation)
  const handleSendMessage = async (content: string, requestAi: boolean) => {
    if (!currentUser || !activeConversation) return;
    setIsSendingMessage(true);
    try {
      const res = await fetch(
        `/api/users/${currentUser.uid}/conversations/${activeConversation.id}/messages`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...getAuthHeader(),
          },
          body: JSON.stringify({ content, requestAiReflection: requestAi }),
        }
      );

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || 'Failed to record entry');
      }

      const data = await res.json();

      // Append user and assistant messages
      setMessages((prev) => {
        const next = [...prev, data.userMessage];
        if (data.assistantMessage) {
          next.push(data.assistantMessage);
        }
        return next;
      });

      // Update conversation in list
      if (data.conversation) {
        setConversations((prev) =>
          prev.map((c) => (c.id === data.conversation.id ? data.conversation : c))
        );
        setActiveConversation(data.conversation);
      }

      // If an automatic summary was synthesized, sync it immediately
      if (data.summary) {
        setSummaries((prev) => {
          const filtered = prev.filter((s) => s.id !== data.summary.id && s.conversationId !== data.summary.conversationId);
          return [data.summary, ...filtered];
        });
      }
    } finally {
      setIsSendingMessage(false);
    }
  };

  // Handle Delete Conversation
  const handleDeleteConversation = async (convId: string) => {
    if (!currentUser) return;
    const res = await fetch(`/api/users/${currentUser.uid}/conversations/${convId}`, {
      method: 'DELETE',
      headers: getAuthHeader(),
    });

    if (res.ok) {
      setConversations((prev) => {
        const filtered = prev.filter((c) => c.id !== convId);
        if (activeConversation?.id === convId) {
          setActiveConversation(filtered.length > 0 ? filtered[0] : null);
        }
        return filtered;
      });
      // Filter out deleted summaries
      setSummaries((prev) => prev.filter((s) => s.conversationId !== convId));
    }
  };

  // Handle Generate Reflection Summary Manually
  const handleGenerateSummary = async (conversationId: string) => {
    if (!currentUser) return;
    setIsGeneratingSummary(true);
    try {
      const res = await fetch(`/api/users/${currentUser.uid}/summaries`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...getAuthHeader(),
        },
        body: JSON.stringify({ conversationId }),
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || 'Failed to synthesize summary');
      }

      const data = await res.json();
      setSummaries((prev) => {
        const filtered = prev.filter((s) => s.id !== data.summary.id && s.conversationId !== data.summary.conversationId);
        return [data.summary, ...filtered];
      });
    } finally {
      setIsGeneratingSummary(false);
    }
  };

  if (isAuthChecking) {
    return (
      <div className="h-screen w-screen bg-[#050505] flex flex-col items-center justify-center text-[#e5e7eb] space-y-4 font-sans">
        <div className="w-10 h-10 bg-[#f59e0b] rounded flex items-center justify-center text-[#050505] font-bold text-xl shadow-lg select-none">
          &Sigma;
        </div>
        <div className="flex items-center space-x-2 text-xs font-mono text-[#737373] uppercase tracking-wider">
          <div className="h-2 w-2 rounded-full bg-[#10b981] animate-pulse" />
          <span>Establishing Zero-Trust Enclave...</span>
        </div>
      </div>
    );
  }

  // If no user is authenticated, render the dedicated Auth Screen
  if (!currentUser) {
    return (
      <AuthScreen
        onSignInSuccess={handleFirebaseSignInSuccess}
        onDemoSignIn={handleDemoSignIn}
      />
    );
  }

  return (
    <div className="min-h-screen bg-[#050505] text-[#e5e7eb] flex flex-col font-sans selection:bg-[#f59e0b]/20 selection:text-[#f59e0b]">
      <Header
        currentUser={currentUser}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onSwitchUser={handleDemoSignIn}
        onSignOut={handleSignOut}
        isSwitching={isSwitchingUser}
      />

      <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
        {activeTab === 'journal' && (
          <JournalView
            currentUser={currentUser}
            conversations={conversations}
            activeConversation={activeConversation}
            messages={messages}
            summaries={summaries}
            onSelectConversation={(conv) => setActiveConversation(conv)}
            onCreateConversation={handleCreateConversation}
            onSendMessage={handleSendMessage}
            onDeleteConversation={handleDeleteConversation}
            onGenerateSummary={handleGenerateSummary}
            isLoadingMessages={isLoadingMessages}
            isSendingMessage={isSendingMessage}
            isGeneratingSummary={isGeneratingSummary}
          />
        )}

        {activeTab === 'audit' && (
          <SecurityAuditView
            auditReport={auditReport}
            isRunningAudit={isRunningAudit}
            onRunAudit={handleRunAudit}
          />
        )}

        {activeTab === 'threat-model' && <ThreatModelView />}

        {activeTab === 'constitution' && <ConstitutionView />}
      </div>

      {/* Cryptographic Session Integrity Footer */}
      <footer className="h-8 bg-[#0a0a0a] border-t border-[#262626] px-4 sm:px-8 flex items-center justify-between text-[10px] text-[#525252] font-mono uppercase tracking-widest select-none shrink-0">
        <span className="truncate">Encrypted Session: AES-256-GCM (Zero-Trust Partition)</span>
        <span className="hidden md:inline">Integrity: Cloud Firestore + Server-Side Gemini</span>
        <span>UID: {currentUser?.uid || 'ANON_ENCLAVE'}</span>
      </footer>
    </div>
  );
}
