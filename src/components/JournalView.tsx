import React, { useState } from 'react';
import {
  Plus,
  Send,
  Sparkles,
  Bot,
  User,
  Shield,
  FileCheck2,
  Trash2,
  AlertCircle,
  Tag,
  Clock,
  Layers,
} from 'lucide-react';
import { AuthUser, Conversation, Message, Summary } from '../types';

interface JournalViewProps {
  currentUser: AuthUser | null;
  conversations: Conversation[];
  activeConversation: Conversation | null;
  messages: Message[];
  summaries: Summary[];
  onSelectConversation: (conv) => void;
  onCreateConversation: (title: string, theme: string) => Promise<void>;
  onSendMessage: (content: string, requestAi: boolean) => Promise<void>;
  onDeleteConversation: (convId: string) => Promise<void>;
  onGenerateSummary: (convId: string) => Promise<void>;
  isLoadingMessages: boolean;
  isSendingMessage: boolean;
  isGeneratingSummary: boolean;
}

export const JournalView: React.FC<JournalViewProps> = ({
  currentUser,
  conversations,
  activeConversation,
  messages,
  summaries,
  onSelectConversation,
  onCreateConversation,
  onSendMessage,
  onDeleteConversation,
  onGenerateSummary,
  isLoadingMessages,
  isSendingMessage,
  isGeneratingSummary,
}) => {
  const [newEntryText, setNewEntryText] = useState('');
  const [requestAi, setRequestAi] = useState(true);
  const [showNewModal, setShowNewModal] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newTheme, setNewTheme] = useState('');
  const [activeTabSub, setActiveTabSub] = useState<'entries' | 'summaries'>('entries');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;
    try {
      await onCreateConversation(newTitle.trim(), newTheme.trim() || 'General Reflection');
      setNewTitle('');
      setNewTheme('');
      setShowNewModal(false);
      setErrorMsg(null);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to create conversation');
    }
  };

  const handleSendSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newEntryText.trim() || isSendingMessage) return;
    if (newEntryText.length > 3000) {
      setErrorMsg('Input exceeds maximum allowed size of 3,000 characters.');
      return;
    }
    setErrorMsg(null);
    const content = newEntryText;
    setNewEntryText('');
    try {
      await onSendMessage(content, requestAi);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to record entry');
      setNewEntryText(content);
    }
  };

  return (
    <div className="flex flex-col lg:flex-row h-[calc(100vh-7rem)] bg-[#050505] text-[#e5e7eb] overflow-hidden">
      {/* Sidebar: Conversation Sessions */}
      <aside className="w-full lg:w-72 border-b lg:border-b-0 lg:border-r border-[#262626] flex flex-col bg-[#080808] shrink-0">
        <div className="p-4 sm:p-5 border-b border-[#262626] flex items-center justify-between">
          <div>
            <h3 className="text-[10px] uppercase tracking-[0.2em] text-[#737373] font-medium">
              Operational Nodes
            </h3>
            <p className="text-[11px] font-mono text-[#a3a3a3] truncate mt-0.5">
              users/{currentUser?.uid || '...'}/conversations
            </p>
          </div>
          <button
            id="btn-new-session"
            onClick={() => setShowNewModal(true)}
            className="w-7 h-7 rounded bg-[#f59e0b] hover:bg-[#d97706] text-[#050505] flex items-center justify-center shadow-xs transition-colors"
            title="Create New Reflection Session"
          >
            <Plus className="h-4 w-4 stroke-[2.5]" />
          </button>
        </div>

        {/* Sessions List */}
        <div className="flex-1 overflow-y-auto p-3 space-y-2">
          {conversations.length === 0 ? (
            <div className="p-6 text-center text-[#737373] text-xs">
              <Shield className="h-6 w-6 mx-auto mb-2 text-[#525252] opacity-60" />
              <p>No reflection sessions yet in this tenant partition.</p>
              <button
                onClick={() => setShowNewModal(true)}
                className="mt-3 text-xs text-[#f59e0b] hover:underline"
              >
                Start first session &rarr;
              </button>
            </div>
          ) : (
            conversations.map((conv) => {
              const isSelected = activeConversation?.id === conv.id;
              return (
                <div
                  key={conv.id}
                  onClick={() => onSelectConversation(conv)}
                  className={`group relative p-3 rounded-lg border text-left cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-[#171717] border-[#262626] shadow-xs'
                      : 'border-transparent hover:border-[#262626] hover:bg-[#171717]/60'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <div
                        className={`w-2 h-2 rounded-full shrink-0 transition-colors ${
                          isSelected ? 'bg-[#10b981]' : 'bg-[#3f3f46] group-hover:bg-[#f59e0b]'
                        }`}
                      />
                      <h4
                        className={`text-xs font-medium truncate ${
                          isSelected ? 'text-white' : 'text-[#a3a3a3] group-hover:text-white'
                        }`}
                      >
                        {conv.title}
                      </h4>
                    </div>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        if (confirm('Permanently delete this session and its messages?')) {
                          onDeleteConversation(conv.id);
                        }
                      }}
                      className="opacity-0 group-hover:opacity-100 p-1 text-[#525252] hover:text-[#ef4444] transition-opacity shrink-0"
                      title="Securely Delete Conversation"
                    >
                      <Trash2 className="h-3 w-3" />
                    </button>
                  </div>
                  <div className="mt-1.5 flex items-center justify-between text-[10px] text-[#737373] pl-4">
                    <span className="truncate">{conv.theme}</span>
                    <span className="font-mono">{conv.messageCount} msgs</span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Security Isolation Status Note */}
        <div className="p-3 bg-[#0a0a0a] border-t border-[#262626] text-[10px] text-[#737373] space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[#10b981]" />
              <span className="uppercase tracking-wider">Tenant Partition Active</span>
            </div>
            <span className="font-mono text-[#d1d5db] bg-[#171717] px-1.5 py-0.5 rounded border border-[#262626]">
              {currentUser?.uid}
            </span>
          </div>
          <div className="p-2 border border-dashed border-[#262626] rounded text-center">
            <p className="text-[9px] text-[#525252] leading-relaxed italic">
              &lsquo;Never prioritize visual polish over security boundaries.&rsquo;
            </p>
          </div>
        </div>
      </aside>

      {/* Main Journal Session Panel */}
      <main className="flex-1 flex flex-col min-w-0 bg-[#050505]">
        {activeConversation ? (
          <>
            {/* Session Top Bar */}
            <div className="h-16 border-b border-[#262626] bg-[#0a0a0a] px-4 sm:px-6 flex flex-wrap items-center justify-between gap-3 shrink-0">
              <div className="flex items-center gap-3">
                <h2 className="text-base font-serif italic text-white tracking-wide">
                  {activeConversation.title}
                </h2>
                <span className="text-[10px] uppercase tracking-wider px-2 py-0.5 rounded border border-[#262626] text-[#a3a3a3] bg-[#171717]">
                  {activeConversation.theme}
                </span>
                <span className="hidden xl:inline-flex items-center gap-1 text-[10px] text-[#10b981] bg-[#10b981]/10 px-2 py-0.5 rounded border border-[#10b981]/20 font-sans">
                  <Shield className="h-3 w-3" />
                  Private to {currentUser?.email || currentUser?.displayName}
                </span>
              </div>

              <div className="flex items-center gap-2">
                {/* Sub-view toggle: Entries vs Summaries */}
                <div className="flex gap-1.5">
                  <button
                    onClick={() => setActiveTabSub('entries')}
                    className={`px-3 py-1 rounded-full text-[10px] uppercase tracking-wider font-medium transition-all ${
                      activeTabSub === 'entries'
                        ? 'bg-white text-black font-bold shadow-xs'
                        : 'border border-[#262626] text-[#a3a3a3] hover:text-white hover:border-[#3f3f46]'
                    }`}
                  >
                    Entries ({messages.length})
                  </button>
                  <button
                    onClick={() => setActiveTabSub('summaries')}
                    className={`px-3 py-1 rounded-full text-[10px] uppercase tracking-wider font-medium transition-all ${
                      activeTabSub === 'summaries'
                        ? 'bg-white text-black font-bold shadow-xs'
                        : 'border border-[#262626] text-[#a3a3a3] hover:text-white hover:border-[#3f3f46]'
                    }`}
                  >
                    Syntheses ({summaries.filter((s) => s.conversationId === activeConversation.id).length})
                  </button>
                </div>

                <button
                  id="btn-generate-summary"
                  disabled={isGeneratingSummary || messages.length === 0}
                  onClick={() => onGenerateSummary(activeConversation.id)}
                  className="px-3 py-1 rounded-full bg-[#f59e0b] hover:bg-[#d97706] disabled:opacity-40 text-[#050505] text-[10px] uppercase tracking-wider font-bold transition-colors flex items-center gap-1.5 shadow-xs"
                >
                  <Sparkles className="h-3 w-3" />
                  <span>{isGeneratingSummary ? 'Synthesizing...' : 'Synthesize Insights'}</span>
                </button>
              </div>
            </div>

            {/* Error Notification Banner */}
            {errorMsg && (
              <div className="mx-4 sm:mx-6 mt-3 p-3 rounded-lg bg-[#ef4444]/10 border border-[#ef4444]/30 text-[#ef4444] text-xs flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <AlertCircle className="h-4 w-4 shrink-0" />
                  <span>{errorMsg}</span>
                </div>
                <button
                  onClick={() => setErrorMsg(null)}
                  className="text-[#ef4444] hover:text-white font-bold ml-2"
                >
                  &times;
                </button>
              </div>
            )}

            {/* Content Body: Entries or Summaries */}
            {activeTabSub === 'entries' ? (
              <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-4">
                {isLoadingMessages ? (
                  <div className="flex items-center justify-center h-48 text-[#737373] text-xs font-mono">
                    <Clock className="h-4 w-4 animate-spin mr-2 text-[#f59e0b]" />
                    Decrypting and loading isolated session messages...
                  </div>
                ) : messages.length === 0 ? (
                  <div className="max-w-md mx-auto my-12 text-center p-8 rounded-xl border border-[#262626] bg-[#0a0a0a]">
                    <FileCheck2 className="h-8 w-8 mx-auto text-[#10b981] mb-3 opacity-80" />
                    <h4 className="text-sm font-serif italic text-white">Start Your Protected Reflection</h4>
                    <p className="text-xs text-[#737373] mt-1.5 leading-relaxed">
                      All entries are written strictly to your user-scoped partition. Server-side prompt injection
                      delimiters ensure that even adversarial input cannot breach system boundaries.
                    </p>
                  </div>
                ) : (
                  messages.map((msg) => {
                    const isUser = msg.role === 'user';
                    return (
                      <div
                        key={msg.id}
                        className={`flex items-start gap-3 max-w-3xl ${
                          isUser ? 'ml-auto flex-row-reverse' : 'mr-auto'
                        }`}
                      >
                        {/* Avatar */}
                        <div
                          className={`w-8 h-8 rounded flex items-center justify-center shrink-0 text-xs ${
                            isUser
                              ? 'bg-[#171717] border border-[#262626] text-[#f59e0b]'
                              : 'bg-[#171717] border border-[#262626] text-[#a855f7]'
                          }`}
                        >
                          {isUser ? <User className="h-4 w-4" /> : <Bot className="h-4 w-4" />}
                        </div>

                        {/* Message Box */}
                        <div
                          className={`rounded-xl p-4 border text-xs leading-relaxed max-w-[85%] ${
                            isUser
                              ? 'bg-[#0a0a0a] border-[#262626] text-[#e5e7eb]'
                              : 'bg-[#0f0f0f] border-[#262626] text-[#e5e7eb]'
                          }`}
                        >
                          <div className="flex items-center justify-between text-[10px] text-[#737373] mb-2 pb-1.5 border-b border-[#262626]">
                            <span className="font-medium text-[#d1d5db]">
                              {isUser ? currentUser?.displayName : 'AegisReflect Companion'}
                            </span>
                            <span className="font-mono">
                              {new Date(msg.createdAt).toLocaleTimeString([], {
                                hour: '2-digit',
                                minute: '2-digit',
                              })}
                            </span>
                          </div>

                          {/* Sanitized text content */}
                          <div className="whitespace-pre-wrap font-sans text-xs text-[#d1d5db] leading-relaxed">
                            {msg.content}
                          </div>

                          {/* Tags */}
                          {msg.reflectionTags && msg.reflectionTags.length > 0 && (
                            <div className="mt-3 pt-2 border-t border-[#262626] flex flex-wrap gap-1.5">
                              {msg.reflectionTags.map((tag, idx) => (
                                <span
                                  key={idx}
                                  className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[9px] font-mono bg-[#171717] text-[#a3a3a3] border border-[#262626]"
                                >
                                  <Tag className="h-2.5 w-2.5 text-[#f59e0b]" />
                                  <span>{tag}</span>
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            ) : (
              /* Summaries Tab View */
              <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-4">
                {summaries.filter((s) => s.conversationId === activeConversation.id).length === 0 ? (
                  <div className="max-w-md mx-auto my-12 text-center p-8 rounded-xl border border-[#262626] bg-[#0a0a0a]">
                    <Sparkles className="h-8 w-8 mx-auto text-[#737373] mb-3" />
                    <h4 className="text-sm font-serif italic text-white">No Syntheses Generated Yet</h4>
                    <p className="text-xs text-[#737373] mt-1.5 leading-relaxed">
                      Click &ldquo;Synthesize Insights&rdquo; above to have server-side Gemini extract growth themes and
                      constructive self-care takeaways.
                    </p>
                  </div>
                ) : (
                  summaries
                    .filter((s) => s.conversationId === activeConversation.id)
                    .map((summary) => (
                      <div
                        key={summary.id}
                        className="rounded-xl border border-[#262626] bg-[#0a0a0a] p-5 space-y-3"
                      >
                        <div className="flex items-center justify-between border-b border-[#262626] pb-3">
                          <div className="flex items-center gap-2">
                            <Sparkles className="h-4 w-4 text-[#f59e0b]" />
                            <h3 className="text-sm font-serif italic text-white">{summary.title}</h3>
                          </div>
                          <span className="text-[10px] font-mono text-[#737373]">
                            {new Date(summary.createdAt).toLocaleString()}
                          </span>
                        </div>
                        <p className="text-xs text-[#d1d5db] leading-relaxed whitespace-pre-wrap">
                          {summary.summaryText || summary.summary}
                        </p>

                        {/* Key Points */}
                        {((summary.keyPoints && summary.keyPoints.length > 0) || (summary.insights && summary.insights.length > 0)) && (
                          <div className="pt-2 border-t border-[#262626] space-y-1.5">
                            <span className="text-[10px] uppercase tracking-wider text-[#737373] font-medium block">
                              Core Themes &amp; Breakthroughs
                            </span>
                            <div className="flex flex-wrap gap-1.5">
                              {(summary.keyPoints || summary.insights || []).map((point, i) => (
                                <span
                                  key={i}
                                  className="px-2 py-0.5 rounded text-[10px] bg-[#171717] text-[#f59e0b] border border-[#262626]"
                                >
                                  {point}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Action Items */}
                        {summary.actionItems && summary.actionItems.length > 0 && (
                          <div className="pt-2 border-t border-[#262626] space-y-1.5">
                            <span className="text-[10px] uppercase tracking-wider text-[#10b981] font-medium block">
                              Reflective Action Items &amp; Self-Care
                            </span>
                            <ul className="space-y-1">
                              {summary.actionItems.map((item, idx) => (
                                <li key={idx} className="text-xs text-[#a3a3a3] flex items-start gap-2">
                                  <span className="text-[#10b981] text-[10px] font-mono select-none">&bull;</span>
                                  <span>{item}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    ))
                )}
              </div>
            )}

            {/* Input Bar: Protected Journal Entry Input */}
            <div className="p-4 sm:p-5 border-t border-[#262626] bg-[#0a0a0a] shrink-0">
              <form onSubmit={handleSendSubmit} className="space-y-2.5">
                <div className="relative">
                  <textarea
                    id="input-journal-entry"
                    rows={3}
                    value={newEntryText}
                    onChange={(e) => setNewEntryText(e.target.value)}
                    placeholder="Write your honest thoughts, challenges, and reflections here (boxed in zero-trust delimiters)..."
                    className="w-full rounded-lg bg-[#050505] border border-[#262626] p-3 pr-24 text-xs text-[#e5e7eb] placeholder-[#525252] focus:outline-none focus:border-[#f59e0b] transition-colors resize-none font-sans"
                  />
                  <div className="absolute right-3 bottom-3 flex items-center gap-2">
                    <span
                      className={`text-[10px] font-mono ${
                        newEntryText.length > 2700 ? 'text-[#f59e0b]' : 'text-[#525252]'
                      }`}
                    >
                      {newEntryText.length}/3000
                    </span>
                    <button
                      id="btn-submit-journal-entry"
                      type="submit"
                      disabled={!newEntryText.trim() || isSendingMessage}
                      className="px-3 py-1.5 rounded bg-[#f59e0b] hover:bg-[#d97706] disabled:opacity-40 text-[#050505] text-xs font-bold transition-colors flex items-center gap-1 shadow-xs"
                      title="Record Private Journal Entry"
                    >
                      <span>Send</span>
                      <Send className="h-3 w-3" />
                    </button>
                  </div>
                </div>

                <div className="flex flex-wrap items-center justify-between text-[11px] text-[#737373] pt-0.5">
                  <label className="flex items-center gap-2 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={requestAi}
                      onChange={(e) => setRequestAi(e.target.checked)}
                      className="rounded border-[#262626] bg-[#050505] text-[#f59e0b] focus:ring-0 focus:ring-offset-0 h-3.5 w-3.5"
                    />
                    <span className="text-[#a3a3a3]">Request AI Reflective Companion response</span>
                  </label>

                  <div className="flex items-center gap-1.5 text-[#10b981] font-mono text-[10px]">
                    <Shield className="h-3 w-3" />
                    <span>Delimiter Box: &lt;&lt;&lt;USER_JOURNAL_CONTENT&gt;&gt;&gt;</span>
                  </div>
                </div>
              </form>
            </div>
          </>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center p-8 text-center bg-[#050505]">
            <div className="w-12 h-12 rounded-xl bg-[#0a0a0a] border border-[#262626] flex items-center justify-center text-[#737373] mb-3">
              <Layers className="h-6 w-6" />
            </div>
            <h3 className="text-base font-serif italic text-white">No Journal Session Selected</h3>
            <p className="text-xs text-[#737373] max-w-sm mt-1">
              Select an operational session node from the left navigation or initiate a new secure reflection workspace.
            </p>
            <button
              onClick={() => setShowNewModal(true)}
              className="mt-4 px-4 py-2 rounded-full bg-[#f59e0b] hover:bg-[#d97706] text-[#050505] text-xs font-bold transition-colors flex items-center gap-1.5 shadow-xs"
            >
              <Plus className="h-4 w-4" />
              <span>Create New Reflection Session</span>
            </button>
          </div>
        )}
      </main>

      {/* Modal: Create Session */}
      {showNewModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-xs">
          <div className="w-full max-w-md bg-[#0a0a0a] border border-[#262626] rounded-xl p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-[#262626] pb-3">
              <h3 className="text-base font-serif italic text-white">Initiate Reflective Session</h3>
              <button
                onClick={() => setShowNewModal(false)}
                className="text-[#737373] hover:text-white text-lg font-bold leading-none"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleCreateSubmit} className="space-y-4">
              <div>
                <label className="block text-[10px] uppercase tracking-wider text-[#737373] mb-1">
                  Session Title * (max 120 chars)
                </label>
                <input
                  type="text"
                  required
                  maxLength={120}
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="e.g. Navigating Team Restructuring"
                  className="w-full rounded bg-[#050505] border border-[#262626] px-3 py-2 text-xs text-[#e5e7eb] focus:outline-none focus:border-[#f59e0b]"
                />
              </div>

              <div>
                <label className="block text-[10px] uppercase tracking-wider text-[#737373] mb-1">
                  Primary Growth Theme (optional)
                </label>
                <input
                  type="text"
                  maxLength={60}
                  value={newTheme}
                  onChange={(e) => setNewTheme(e.target.value)}
                  placeholder="e.g. Resilience, Decision Making, Mindfulness"
                  className="w-full rounded bg-[#050505] border border-[#262626] px-3 py-2 text-xs text-[#e5e7eb] focus:outline-none focus:border-[#f59e0b]"
                />
              </div>

              <div className="p-3 rounded bg-[#050505] border border-[#262626] text-[10px] text-[#737373] space-y-1">
                <div className="font-mono text-[#10b981] flex items-center gap-1">
                  <Shield className="h-3 w-3" />
                  <span>Zero-Trust Invariant:</span>
                </div>
                <p>
                  Owner UID derived exclusively from verified authentication token on server. Tenant isolation
                  guarantees no other user can read or append to this session.
                </p>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowNewModal(false)}
                  className="px-3 py-1.5 rounded-full border border-[#262626] text-[#a3a3a3] hover:text-white hover:border-[#3f3f46] text-xs font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-full bg-white text-black hover:bg-[#e5e7eb] text-xs font-bold shadow-xs transition-colors"
                >
                  Create Session
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
