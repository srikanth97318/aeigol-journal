# Gemini & Coding Agent Constitution

See `/AGENTS.md` for the full 25-point Security-First Development Constitution.

Key directives:
1. Always enforce server-side Gemini execution (`@google/genai`). Never expose `GEMINI_API_KEY` to the browser or bundle.
2. Enforce zero cross-user leakage with user-scoped resources: `users/{uid}/conversations/{conversationId}`, `users/{uid}/conversations/{conversationId}/messages/{messageId}`, `users/{uid}/summaries/{summaryId}`.
3. Treat all user prompts and journal content as untrusted data with strict delimiter encapsulation.
4. Never trust client-side claims or user IDs. Authenticate on the backend and enforce path-based authorization.
5. Provide production-ready Firestore rules and include an interactive Security Testing Suite.
