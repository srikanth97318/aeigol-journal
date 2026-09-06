import React, { useState } from 'react';
import { Shield, Eye, Database, Check, Copy, Layers, Search } from 'lucide-react';
import { THREAT_MODEL_MATRIX } from '../data/threatModelData';

export const ThreatModelView: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSubTab, setSelectedSubTab] = useState<'matrix' | 'firestore-rules' | 'blueprint'>('matrix');
  const [copiedRules, setCopiedRules] = useState(false);

  const filteredThreats = THREAT_MODEL_MATRIX.filter(
    (t) =>
      t.asset.toLowerCase().includes(searchTerm.toLowerCase()) ||
      t.threatActor.toLowerCase().includes(searchTerm.toLowerCase()) ||
      t.attack.toLowerCase().includes(searchTerm.toLowerCase()) ||
      t.mitigation.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const firestoreRulesText = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    
    // Global Default-Deny Catch-All Safety Net
    match /{document=**} {
      allow read, write: if false;
    }

    // Hardened Helper Primitives
    function isSignedIn() {
      return request.auth != null;
    }

    function isOwner(userId) {
      return isSignedIn() && request.auth.uid == userId;
    }

    function isValidId(id) {
      return id is string && id.size() > 0 && id.size() <= 128 && id.matches('^[a-zA-Z0-9_\\\\-]+$');
    }

    function incoming() {
      return request.resource.data;
    }

    function existing() {
      return resource.data;
    }

    function isValidConversation(data, userId) {
      return data.userId == userId &&
             data.title is string && data.title.size() >= 1 && data.title.size() <= 120 &&
             (!('theme' in data) || (data.theme is string && data.theme.size() <= 60)) &&
             (!('messageCount' in data) || (data.messageCount is number && data.messageCount >= 0)) &&
             (!('isArchived' in data) || (data.isArchived is bool));
    }

    function isValidMessage(data, userId, conversationId) {
      return data.userId == userId &&
             data.conversationId == conversationId &&
             data.role in ['user', 'assistant'] &&
             data.content is string && data.content.size() >= 1 && data.content.size() <= 3000 &&
             (!('reflectionTags' in data) || (data.reflectionTags is list && data.reflectionTags.size() <= 10));
    }

    function isValidSummary(data, userId, conversationId) {
      return data.userId == userId &&
             data.conversationId == conversationId &&
             data.title is string && data.title.size() >= 1 && data.title.size() <= 120 &&
             data.summary is string && data.summary.size() >= 1 && data.summary.size() <= 4000 &&
             (!('insights' in data) || (data.insights is list && data.insights.size() <= 10));
    }

    // User-Scoped Security Boundary
    match /users/{userId} {
      allow get: if isOwner(userId);
      allow list: if false; // Enumeration forbidden
      allow create: if isOwner(userId);
      allow update: if isOwner(userId);
      allow delete: if false;

      // Subcollection: Conversations
      match /conversations/{conversationId} {
        allow get: if isOwner(userId) && isValidId(conversationId);
        allow list: if isOwner(userId);
        
        allow create: if isOwner(userId) &&
                         isValidId(conversationId) &&
                         isValidConversation(incoming(), userId) &&
                         incoming().userId == request.auth.uid &&
                         incoming().id == conversationId;
        
        allow update: if isOwner(userId) &&
                         isValidId(conversationId) &&
                         isValidConversation(incoming(), userId) &&
                         incoming().userId == existing().userId && // Prevent ownership transfer
                         incoming().id == existing().id &&
                         incoming().diff(existing()).affectedKeys().hasOnly(['title', 'theme', 'updatedAt', 'messageCount', 'isArchived']);
        
        allow delete: if isOwner(userId) && isValidId(conversationId);

        // Subcollection: Messages
        match /messages/{messageId} {
          allow get: if isOwner(userId) && isValidId(conversationId) && isValidId(messageId);
          allow list: if isOwner(userId) && isValidId(conversationId);
          
          allow create: if isOwner(userId) &&
                           isValidId(conversationId) &&
                           isValidId(messageId) &&
                           isValidMessage(incoming(), userId, conversationId) &&
                           incoming().userId == request.auth.uid &&
                           incoming().id == messageId;
          
          allow update: if false; // Messages are immutable historical records
          allow delete: if isOwner(userId) && isValidId(conversationId) && isValidId(messageId);
        }
      }

      // Subcollection: Summaries
      match /summaries/{summaryId} {
        allow get: if isOwner(userId) && isValidId(summaryId);
        allow list: if isOwner(userId);
        
        allow create: if isOwner(userId) &&
                         isValidId(summaryId) &&
                         isValidSummary(incoming(), userId, incoming().conversationId) &&
                         incoming().userId == request.auth.uid &&
                         incoming().id == summaryId;
        
        allow update: if isOwner(userId) &&
                         isValidId(summaryId) &&
                         isValidSummary(incoming(), userId, existing().conversationId) &&
                         incoming().userId == existing().userId &&
                         incoming().diff(existing()).affectedKeys().hasOnly(['title', 'summary', 'insights', 'updatedAt']);
        
        allow delete: if isOwner(userId) && isValidId(summaryId);
      }
    }
  }
}`;

  const copyToClipboard = () => {
    navigator.clipboard.writeText(firestoreRulesText);
    setCopiedRules(true);
    setTimeout(() => setCopiedRules(false), 2000);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-8 py-8 space-y-8 bg-[#050505] text-[#e5e7eb] min-h-[calc(100vh-7rem)] overflow-y-auto">
      {/* Top Banner */}
      <div className="rounded-xl bg-[#0a0a0a] border border-[#262626] p-6 shadow-xs space-y-4">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Eye className="h-5 w-5 text-[#f59e0b]" />
              <h2 className="text-base font-serif italic text-white tracking-wide">
                Threat Modeling &amp; Zero-Trust Architecture
              </h2>
            </div>
            <p className="text-xs text-[#737373] mt-1 leading-relaxed max-w-3xl">
              Formal threat assessment satisfying Section 21 of the Security Constitution, coupled with
              mathematically hardened production Firestore Security Rules enforcing user-scoped document paths.
            </p>
          </div>

          {/* Sub-tab navigation */}
          <div className="flex gap-1.5 shrink-0">
            <button
              onClick={() => setSelectedSubTab('matrix')}
              className={`px-3 py-1 rounded-full text-[10px] uppercase tracking-wider transition-colors ${
                selectedSubTab === 'matrix'
                  ? 'bg-white text-black font-bold'
                  : 'border border-[#262626] text-[#737373] hover:text-white'
              }`}
            >
              Threat Matrix ({THREAT_MODEL_MATRIX.length})
            </button>
            <button
              onClick={() => setSelectedSubTab('firestore-rules')}
              className={`px-3 py-1 rounded-full text-[10px] uppercase tracking-wider transition-colors ${
                selectedSubTab === 'firestore-rules'
                  ? 'bg-white text-black font-bold'
                  : 'border border-[#262626] text-[#737373] hover:text-white'
              }`}
            >
              Production Rules (ABAC)
            </button>
            <button
              onClick={() => setSelectedSubTab('blueprint')}
              className={`px-3 py-1 rounded-full text-[10px] uppercase tracking-wider transition-colors ${
                selectedSubTab === 'blueprint'
                  ? 'bg-white text-black font-bold'
                  : 'border border-[#262626] text-[#737373] hover:text-white'
              }`}
            >
              Blueprint Schema (IR)
            </button>
          </div>
        </div>

        {selectedSubTab === 'matrix' && (
          <div className="relative pt-1">
            <Search className="h-4 w-4 text-[#525252] absolute left-3 top-4" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Filter threat models by asset, threat actor, attack vector, or mitigation..."
              className="w-full rounded-lg bg-[#050505] border border-[#262626] pl-9 pr-4 py-2 text-xs text-[#e5e7eb] placeholder-[#525252] focus:outline-none focus:border-[#f59e0b] font-sans"
            />
          </div>
        )}
      </div>

      {/* Subtab 1: Threat Model Matrix */}
      {selectedSubTab === 'matrix' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 gap-4">
            {filteredThreats.map((threat) => (
              <div
                key={threat.id}
                className="rounded-xl border border-[#262626] bg-[#0a0a0a] p-5 space-y-3 hover:border-[#3f3f46] transition-colors"
              >
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#262626] pb-3">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px] text-[#f59e0b] bg-[#171717] border border-[#262626] px-2 py-0.5 rounded">
                      {threat.id}
                    </span>
                    <h3 className="text-sm font-serif italic text-white">{threat.asset}</h3>
                  </div>
                  <div className="flex items-center gap-2 text-[11px] font-mono">
                    <span className="text-[#737373]">ACTOR:</span>
                    <span className="text-[#d1d5db]">{threat.threatActor}</span>
                    <span className="text-[#3f3f46]">|</span>
                    <span className="text-[#737373]">RESIDUAL RISK:</span>
                    <span
                      className={`px-2 py-0.5 rounded-full text-[10px] font-mono ${
                        threat.residualRisk === 'NEGLIGIBLE'
                          ? 'bg-[#171717] text-[#10b981] border border-[#262626]'
                          : 'bg-[#171717] text-[#60a5fa] border border-[#262626]'
                      }`}
                    >
                      {threat.residualRisk}
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  <div className="space-y-1.5 p-3.5 rounded-lg bg-[#050505] border border-[#262626]">
                    <div className="font-medium text-[#d1d5db] text-[11px] flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#ef4444]" />
                      <span>Attack &amp; Surface ({threat.attackSurface})</span>
                    </div>
                    <p className="text-[#a3a3a3] leading-relaxed text-[11px]">{threat.attack}</p>
                    <div className="pt-1 text-[10px] text-[#ef4444] font-mono">
                      Impact: {threat.impact}
                    </div>
                  </div>

                  <div className="space-y-1.5 p-3.5 rounded-lg bg-[#050505] border border-[#262626]">
                    <div className="font-medium text-[#10b981] text-[11px] flex items-center gap-1.5">
                      <Shield className="h-3.5 w-3.5 text-[#10b981]" />
                      <span>Mitigation &amp; Security Boundary</span>
                    </div>
                    <p className="text-[#d1d5db] leading-relaxed text-[11px] font-sans">
                      {threat.mitigation}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Subtab 2: Production Firestore Security Rules */}
      {selectedSubTab === 'firestore-rules' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-[#262626] bg-[#0a0a0a] p-4 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-serif italic text-white flex items-center gap-2">
                <Database className="h-4 w-4 text-[#f59e0b]" />
                <span>Production firestore.rules (Version 2)</span>
              </h3>
              <p className="text-xs text-[#737373] mt-0.5">
                Zero blanket reads, strict isValidId regex validation, immortal fields, and path-derived ABAC.
              </p>
            </div>
            <button
              onClick={copyToClipboard}
              className="px-3 py-1.5 rounded-full bg-[#171717] hover:bg-[#262626] border border-[#262626] text-[#d1d5db] hover:text-white text-[10px] uppercase tracking-wider font-medium flex items-center gap-1.5 transition-colors"
            >
              {copiedRules ? <Check className="h-3 w-3 text-[#10b981]" /> : <Copy className="h-3 w-3" />}
              <span>{copiedRules ? 'Copied' : 'Copy Rules'}</span>
            </button>
          </div>

          <pre className="p-4 rounded-xl bg-[#050505] border border-[#262626] text-[11px] font-mono text-[#10b981] overflow-x-auto leading-relaxed max-h-[600px]">
            {firestoreRulesText}
          </pre>
        </div>
      )}

      {/* Subtab 3: Blueprint IR Schema */}
      {selectedSubTab === 'blueprint' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-[#262626] bg-[#0a0a0a] p-4">
            <h3 className="text-sm font-serif italic text-white flex items-center gap-2">
              <Layers className="h-4 w-4 text-[#f59e0b]" />
              <span>Intermediate Representation: firebase-blueprint.json</span>
            </h3>
            <p className="text-xs text-[#737373] mt-0.5">
              Strict JSON schema defining entities and mapping user-scoped collections.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-5 rounded-xl bg-[#0a0a0a] border border-[#262626] space-y-2 text-xs">
              <span className="font-mono text-[#10b981] font-bold">/users/{'{userId}'}/conversations</span>
              <p className="text-[#737373] text-[11px] leading-relaxed">
                UserConversation entity with title (max 120), theme (max 60), messageCount, and timestamp tracking.
              </p>
            </div>

            <div className="p-5 rounded-xl bg-[#0a0a0a] border border-[#262626] space-y-2 text-xs">
              <span className="font-mono text-[#10b981] font-bold">.../messages/{'{messageId}'}</span>
              <p className="text-[#737373] text-[11px] leading-relaxed">
                JournalMessage entity with immutable role, content (max 3,000), reflection tags (max 10), and strict ownership checks.
              </p>
            </div>

            <div className="p-5 rounded-xl bg-[#0a0a0a] border border-[#262626] space-y-2 text-xs">
              <span className="font-mono text-[#10b981] font-bold">/users/{'{userId}'}/summaries</span>
              <p className="text-[#737373] text-[11px] leading-relaxed">
                ReflectionSummary entity with synthesized insights (max 4,000 chars) and theme tags.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
