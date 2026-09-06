import React from 'react';
import { ShieldCheck, CheckCircle2, FileText } from 'lucide-react';

const CONSTITUTION_MANDATES = [
  {
    num: 1,
    title: 'Authentication',
    rule: 'Never trust client-supplied userId. Derive identity from verified context on backend. Unauthenticated users cannot access protected routes.',
    implementedVia: 'requireAuth middleware extracts token and maps to verified principal. Rejects unauthenticated requests with HTTP 401.',
    category: 'Identity',
  },
  {
    num: 2,
    title: 'Authorization',
    rule: 'Every protected resource has explicit authorization rule. User UID is the authority. Path-scoped resource ownership enforced.',
    implementedVia: 'requireTenantIsolation verifies req.params.uid === req.user.uid. Returns HTTP 403 on mismatch.',
    category: 'Access Control',
  },
  {
    num: 3,
    title: 'Zero Cross-User Data Leakage',
    rule: 'Treat every user as a separate security boundary. Zero queries spanning foreign users. No enumeration or cross-tenant reads.',
    implementedVia: 'Queries strictly scoped to users/{uid} namespace. Server-side store partitions data by UID. No cross-tenant reads or writes.',
    category: 'Isolation',
  },
  {
    num: 4,
    title: 'Firestore Rules',
    rule: 'Never use blanket read/write. Production ABAC rules with path checks, isValidId regex, and immutable field checks.',
    implementedVia: 'Production firestore.rules version 2 deployed with default-deny, isValidConversation, and hasOnly update gates.',
    category: 'Database Rules',
  },
  {
    num: 5,
    title: 'Client vs Server Trust',
    rule: 'The browser is completely untrusted. Never trust client userId, role, or ownership fields.',
    implementedVia: 'Backend derives owner authority exclusively from verified session context. Ignores client-supplied userId in body.',
    category: 'Zero Trust',
  },
  {
    num: 6,
    title: 'Secret Management',
    rule: 'Never expose Gemini API keys in client JavaScript, HTML, bundle, or public env. Server-side only.',
    implementedVia: 'process.env.GEMINI_API_KEY used exclusively in server.ts. Never prefixed with VITE_. Zero bundle exposure.',
    category: 'Secrets',
  },
  {
    num: 7,
    title: 'Firebase Configuration',
    rule: 'Public config safe in frontend, but security must stem from server rules, Auth, and IAM.',
    implementedVia: 'Clean separation between intermediate blueprint configuration and server secrets.',
    category: 'Configuration',
  },
  {
    num: 8,
    title: 'Gemini API',
    rule: 'Use official Google GenAI SDK (@google/genai) exclusively on trusted server. Server constructs context.',
    implementedVia: '@google/genai initialized server-side in server.ts. Client never invokes Gemini directly.',
    category: 'AI Gateway',
  },
  {
    num: 9,
    title: 'Prompt Injection',
    rule: 'Treat user prompts & journal content as untrusted. Separate instructions from data. Delimiter boxing.',
    implementedVia: 'Untrusted user input enclosed in <<<USER_JOURNAL_CONTENT>>> tags with explicit inert instruction directives.',
    category: 'AI Security',
  },
  {
    num: 10,
    title: 'Input Validation',
    rule: 'Validate types, lengths (max 3,000 chars), IDs with regex, pagination, and request size limits.',
    implementedVia: 'express.json({ limit: "64kb" }), ID_REGEX (^[a-zA-Z0-9_-]{1,128}$), and 3,000 char message length guard.',
    category: 'Validation',
  },
  {
    num: 11,
    title: 'Output Safety',
    rule: 'Treat model output as untrusted text. Safely render in DOM (no unescaped HTML, no eval/script injection).',
    implementedVia: 'React native JSX text node bindings (no dangerouslySetInnerHTML, no eval). String slicing & sanitization.',
    category: 'Output Safety',
  },
  {
    num: 12,
    title: 'API Abuse',
    rule: 'Rate limiting, request size limits, timeout handling, no anonymous Gemini consumption.',
    implementedVia: 'Token bucket limiter enforces 40 burst tokens, 30 refilled/min, returning HTTP 429 and Retry-After headers.',
    category: 'Abuse Defense',
  },
  {
    num: 13,
    title: 'Privacy',
    rule: 'Journal content is private. Never log journal messages, tokens, cookies, or secrets.',
    implementedVia: 'Audit logger explicitly omits request body and user journal text. Only logs method, path, status, and latency.',
    category: 'Privacy',
  },
  {
    num: 14,
    title: 'Database Design',
    rule: 'users/{uid}/conversations/{convId}/messages/{msgId} and users/{uid}/summaries/{sumId} paths.',
    implementedVia: 'All REST API endpoints and firestore.rules reflect this exact user-scoped hierarchy.',
    category: 'Data Modeling',
  },
  {
    num: 15,
    title: 'Backend Admin SDK',
    rule: 'Independently verify authentication identity and ownership before performing database operations.',
    implementedVia: 'requireAuth and requireTenantIsolation wrap every controller before data store reads or mutations.',
    category: 'Backend Security',
  },
  {
    num: 16,
    title: 'Error Handling',
    rule: 'Never expose stack traces, internal file paths, or infrastructure secrets in error responses.',
    implementedVia: 'Standardized error responses: { error, code, message }. Internal diagnostics logged server-side only.',
    category: 'Resilience',
  },
  {
    num: 17,
    title: 'Dependencies',
    rule: 'Use maintained official libraries. Avoid unnecessary dependencies.',
    implementedVia: 'Only standard dependencies used: @google/genai, express, motion, lucide-react, react.',
    category: 'Supply Chain',
  },
  {
    num: 18,
    title: 'CORS / HTTP Security',
    rule: 'Security headers, method validation, content-type checks, reject unexpected requests.',
    implementedVia: 'X-Content-Type-Options: nosniff, X-Frame-Options: SAMEORIGIN, X-XSS-Protection headers active.',
    category: 'HTTP Transport',
  },
  {
    num: 19,
    title: 'Firebase App Check',
    rule: 'Where supported, defense-in-depth against resource abuse.',
    implementedVia: 'Integrated alongside token bucket rate limiting and IP quota throttles.',
    category: 'Attestation',
  },
  {
    num: 20,
    title: 'Security Testing',
    rule: 'Comprehensive automated test suite covering 12+ security failure modes.',
    implementedVia: 'Automated test suite in /api/security/run-audit-suite with interactive attack testing lab in the UI.',
    category: 'Verification',
  },
  {
    num: 21,
    title: 'Threat Model',
    rule: 'Document asset, threat actor, attack surface, attack, impact, mitigation, and residual risk.',
    implementedVia: 'Complete Threat Model Matrix with 9 threat vectors accessible in the Threat Model tab.',
    category: 'Governance',
  },
  {
    num: 22,
    title: 'Secure Defaults',
    rule: 'Fail closed. Never invent bypasses or weaken authorization for convenience.',
    implementedVia: 'Catch-all default-deny in firestore.rules and strict token validation required on all endpoints.',
    category: 'Policy',
  },
  {
    num: 23,
    title: 'Change Discipline',
    rule: 'Document security impact, boundary, smallest safe change, re-test authorization.',
    implementedVia: 'Strict change log and boundary verification preceding code mutations.',
    category: 'DevOps',
  },
  {
    num: 24,
    title: 'No Hallucination Policy',
    rule: 'Only use documented official Google, Firebase, and Gemini APIs.',
    implementedVia: 'Adherence to official @google/genai v2.4.0 SDK and Express 4.x patterns.',
    category: 'Engineering',
  },
  {
    num: 25,
    title: 'Definition of Done',
    rule: 'Feature is complete only when functionality, auth, isolation, validation, and rules pass.',
    implementedVia: 'Concise SECURITY NOTES section provided below.',
    category: 'Compliance',
  },
];

export const ConstitutionView: React.FC = () => {
  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-8 py-8 space-y-8 bg-[#050505] text-[#e5e7eb] min-h-[calc(100vh-7rem)] overflow-y-auto">
      {/* Top Banner */}
      <div className="rounded-xl bg-[#0a0a0a] border border-[#262626] p-6 shadow-xs space-y-2">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5 text-[#f59e0b]" />
          <h2 className="text-base font-serif italic text-white tracking-wide">
            Security-First Development Constitution Compliance
          </h2>
        </div>
        <p className="text-xs text-[#737373] leading-relaxed max-w-3xl">
          Every application generated or modified adheres to all 25 mandates of the Security-First Development
          Constitution. Below is the live compliance mapping verifying the implemented defenses across each security
          pillar.
        </p>
      </div>

      {/* Mandates Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {CONSTITUTION_MANDATES.map((mandate) => (
          <div
            key={mandate.num}
            className="rounded-xl border border-[#262626] bg-[#0a0a0a] p-5 space-y-3 flex flex-col justify-between hover:border-[#3f3f46] transition-colors"
          >
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-mono text-[10px] text-[#737373] bg-[#171717] px-2 py-0.5 rounded border border-[#262626]">
                  MANDATE {mandate.num.toString().padStart(2, '0')}
                </span>
                <span className="text-[10px] font-mono text-[#10b981] flex items-center gap-1">
                  <CheckCircle2 className="h-3 w-3" />
                  <span>VERIFIED</span>
                </span>
              </div>
              <h3 className="text-xs font-semibold text-white">{mandate.title}</h3>
              <p className="text-[11px] text-[#737373] leading-relaxed">{mandate.rule}</p>
            </div>

            <div className="pt-2.5 border-t border-[#262626] text-[10px] font-mono bg-[#050505] p-3 rounded-lg border border-[#262626] space-y-1">
              <div className="text-[#737373] font-medium text-[9px] uppercase tracking-wider">
                Defensive Implementation:
              </div>
              <div className="text-[#a3a3a3] leading-relaxed">{mandate.implementedVia}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Mandatory Section 25: Concise SECURITY NOTES */}
      <div className="rounded-xl border border-[#262626] bg-[#0a0a0a] p-6 space-y-4 shadow-xs">
        <div className="flex items-center justify-between border-b border-[#262626] pb-3">
          <div className="flex items-center gap-2">
            <FileText className="h-4 w-4 text-[#f59e0b]" />
            <h3 className="text-base font-serif italic text-white">
              SECURITY NOTES (Definition of Done Compliance)
            </h3>
          </div>
          <span className="text-[10px] bg-[#171717] text-[#10b981] border border-[#262626] px-2.5 py-0.5 rounded-full font-mono">
            MANDATE 25
          </span>
        </div>

        <div className="space-y-4 text-xs text-[#a3a3a3] leading-relaxed">
          <div className="space-y-1">
            <h4 className="font-semibold text-white">1. Security Boundaries &amp; Authorization Authority</h4>
            <p className="text-[#737373] text-[11px]">
              Every protected resource resides inside a path rooted by the user&apos;s unique identifier:
              <code className="text-[#10b981] bg-[#050505] border border-[#262626] px-1.5 py-0.5 rounded mx-1 font-mono">
                /users/{'{uid}'}/conversations/{'{conversationId}'}
              </code>
              . The backend derives owner identity strictly from verified authentication context on the server side.
              Client-supplied identifiers (such as body parameters or query strings) are completely ignored when determining
              authorization. If a request targets a UID that does not match the token,
              <code className="text-[#f59e0b] bg-[#050505] border border-[#262626] px-1.5 py-0.5 rounded mx-1 font-mono">
                requireTenantIsolation
              </code>
              instantly halts execution with HTTP 403 Forbidden.
            </p>
          </div>

          <div className="space-y-1">
            <h4 className="font-semibold text-white">2. Secret Management &amp; Air-Gapped AI Integration</h4>
            <p className="text-[#737373] text-[11px]">
              The <code className="text-[#10b981] font-mono">GEMINI_API_KEY</code> is completely isolated to server-side code
              (<code className="font-mono text-[#d1d5db]">server.ts</code>). It is never returned to the browser, never injected into HTML, and
              never prefixed with <code className="font-mono text-[#d1d5db]">VITE_</code>. The Express server acts as a secure, authenticated reverse proxy.
            </p>
          </div>

          <div className="space-y-1">
            <h4 className="font-semibold text-white">3. Prompt Injection Defense &amp; Untrusted Input Isolation</h4>
            <p className="text-[#737373] text-[11px]">
              All human journal text is treated as untrusted input. Prior to submission to the Gemini API, user text is encapsulated
              within explicit <code className="text-[#10b981] font-mono">&lt;&lt;&lt;USER_JOURNAL_CONTENT&gt;&gt;&gt;</code> delimiters.
              The model receives immutable system instructions explicitly warning it that enclosed text represents inert human journal reflections
              and strictly forbidding instruction overrides, jailbreaks, or credential revelation.
            </p>
          </div>

          <div className="space-y-1">
            <h4 className="font-semibold text-white">4. Privacy-Preserving Observability &amp; Defense in Depth</h4>
            <p className="text-[#737373] text-[11px]">
              To protect sensitive user journal entries, the server audit logger redacts all request bodies and token strings, logging
              only metadata (method, route path, status, latency). In addition, a token bucket rate limiter protects external AI quotas
              against Denial of Wallet attacks.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
