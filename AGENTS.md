# Security-First Development Constitution

These instructions are mandatory for every application generated or modified in this project.

## 1. Authentication
- Use Firebase Authentication for user identity when Firebase is specified.
- Never implement custom password storage.
- Never store passwords in Firestore.
- Never trust a user ID supplied by the browser as proof of identity.
- Always derive the authenticated identity from the verified Authentication context on the backend.
- Unauthenticated users must not be able to access protected application functionality.
- Authentication and authorization are separate controls. Always enforce both.

## 2. Authorization
- Every protected resource must have an explicit authorization rule.
- For user-owned data, the authenticated user's UID must be the authority used to determine ownership.
- Never authorize access merely because `request.auth` exists.
- Never authorize one user's resource access based solely on a client-provided `userId`.
- The backend must verify that the authenticated user owns the conversation/resource being accessed.
- For Firestore, use user-scoped document paths:
  - `users/{uid}/conversations/{conversationId}`
  - `users/{uid}/conversations/{conversationId}/messages/{messageId}`
  - `users/{uid}/summaries/{summaryId}`
- Firestore Security Rules must enforce the same ownership boundary.

## 3. Zero Cross-User Data Leakage
- Treat every user as a separate security boundary.
- A user must never be able to read, write, delete, enumerate, or retrieve another user's conversations, messages, or summaries.
- Never cause Gemini to receive another user's private data.
- Never infer another user's private data through API responses.
- Do not use collection-wide client queries that depend on security rules behaving like filters. Queries must inherently target the authenticated user's namespace.

## 4. Firestore Rules
- Never use `allow read, write: if true;` or `allow read, write: if request.auth != null;` for private user data.
- Enforce explicit ownership checks based on `request.auth.uid` and document paths.
- For create: validate that resource belongs to authenticated user.
- For update: prevent ownership transfer and enforce immutable fields (`createdAt`, `userId`).
- For delete: verify ownership.
- Validate data fields, types, and allowed ranges.
- Always provide production Firestore Security Rules rather than development/demo rules.

## 5. Client vs Server Trust
- The browser is untrusted.
- Never trust `userId`, `role`, ownership fields, conversation ownership, authorization decisions, hidden form fields, `localStorage` values, frontend route guards, disabled buttons, or client-side validation alone.
- All security-sensitive decisions must be independently enforced by the backend and/or Firestore Security Rules.

## 6. Secret Management
- Never hardcode or expose Gemini API keys, private keys, service account credentials, database credentials, or tokens.
- Never place Gemini API keys in client-side code, HTML, browser JavaScript, public environment variables, or Firestore documents.
- The Gemini API key must never be returned to the browser.
- Access Gemini exclusively from trusted server-side code.

## 7. Firebase Configuration
- Public Firebase web configuration is distinct from server secrets.
- Security must come from Authentication, Authorization, Firestore Rules, App Check, backend controls, and correct IAM.

## 8. Gemini API
- Use the official Google GenAI SDK (`@google/genai`).
- Gemini requests must originate from trusted server-side code.
- Server must construct effective conversation context from trusted application state.
- Do not allow clients to choose arbitrary backend models, system instructions, tools, or credentials unless authorized.

## 9. Prompt Injection
- Treat journal content and user prompts as untrusted data.
- Do not allow journal content to redefine application-level security instructions.
- Never expose hidden system prompts or secrets.
- Clearly separate trusted application instructions from user-provided content using delimiter boundaries.
- Never allow model-generated text to perform privileged application operations without validation.

## 10. Input Validation
- Validate all backend input: type validation, length limits, conversation ID format validation, pagination limits, request size limits.
- Reject malformed requests.

## 11. Output Safety
- Treat model output as untrusted text.
- Safely render model-generated content (no unescaped raw HTML injection, no script execution).

## 12. API Abuse
- Design for abuse: request size limits, rate limiting strategy, backoff, timeout handling, concurrency protection, quota handling.
- Do not allow anonymous users to consume Gemini resources.

## 13. Privacy
- Journal content is private user content.
- Do not log complete journal messages by default.
- Do not log API keys, auth tokens, cookies, or secrets. Redact sensitive values.

## 14. Database Design
- Structured paths: `users/{uid}/conversations/{conversationId}`, `users/{uid}/conversations/{conversationId}/messages/{messageId}`, `users/{uid}/summaries/{summaryId}`.
- Ownership derived from authenticated UID and resource path.

## 15. Backend Admin SDK
- Every backend request must independently verify identity and resource ownership before privileged operations.

## 16. Error Handling
- Do not expose stack traces, internal paths, secret names, or database internals.
- Return safe user-facing errors.

## 17. Dependencies
- Use maintained official libraries. Avoid unnecessary dependencies.

## 18. CORS / HTTP Security
- Restrict origins, validate methods and content types, reject unexpected requests.

## 19. Firebase App Check
- Use App Check where supported as defense-in-depth, not as a replacement for auth/authorization.

## 20. Security Testing
- Verify unauthenticated access, cross-tenant data access, forged owner fields, invalid IDs, oversized messages, malformed requests, prompt injection, XSS through model output, secret exposure, unauthorized backend requests.

## 21. Threat Model
- Identify assets, threat actors, attack surfaces, attacks, impact, mitigations, and residual risks.

## 22. Secure Defaults
- When ambiguous, choose the more secure implementation.

## 23. Change Discipline
- Explain security impact, identify affected boundary, implement smallest safe change, re-test authorization, re-check secret handling and rules.

## 24. No Hallucination Policy
- Only use documented official APIs for Google, Firebase, Firestore, and Gemini.

## 25. Definition of Done
- Provide a concise SECURITY NOTES section explaining security boundaries and why the implementation is safe.
