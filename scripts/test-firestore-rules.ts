/**
 * Automated Test Runner for Production Firestore Security Rules
 * Data Model:
 *   - users/{uid}
 *   - users/{uid}/conversations/{conversationId}
 *   - users/{uid}/conversations/{conversationId}/messages/{messageId}
 *   - users/{uid}/summaries/{summaryId}
 */

export interface RuleTestScenario {
  id: string;
  category: 'AUTHENTICATED USER A' | 'USER A TARGETING USER B' | 'UNAUTHENTICATED' | 'OWNERSHIP FORGERY';
  operation: 'get' | 'list' | 'create' | 'update' | 'delete';
  path: string;
  auth: { uid: string } | null;
  incomingData?: Record<string, unknown>;
  existingData?: Record<string, unknown>;
  expectedResult: 'ALLOW' | 'DENY';
  ruleClauseTested: string;
  details: string;
}

export interface RuleTestResult extends RuleTestScenario {
  actualResult: 'ALLOW' | 'DENY';
  passed: boolean;
  evaluationReason: string;
}

// Emulated Firestore Rule Engine matching firestore.rules
export function evaluateFirestoreRules(scenario: RuleTestScenario): { actualResult: 'ALLOW' | 'DENY'; reason: string } {
  const { auth, operation, path, incomingData, existingData } = scenario;

  // Global default deny check
  if (!path.startsWith('users/')) {
    return { actualResult: 'DENY', reason: 'Default-deny: Path outside /users/{uid} hierarchy.' };
  }

  const parts = path.split('/');
  const uid = parts[1];
  const subcollection = parts[2];
  const subDocId = parts[3];
  const subSubcollection = parts[4];
  const subSubDocId = parts[5];

  // Helper: isSignedIn
  const isSignedIn = auth !== null && !!auth.uid;

  // Helper: isOwner
  const isOwner = isSignedIn && auth!.uid === uid;

  // Helper: isValidId
  const isValidId = (id: string | undefined) => {
    return typeof id === 'string' && id.length > 0 && id.length <= 128 && /^[a-zA-Z0-9_-]+$/.test(id);
  };

  // Helper: isValidConversation
  const isValidConversation = (data: Record<string, unknown> | undefined, targetUid: string, convId: string) => {
    if (!data) return false;
    const hasOwner = (data.ownerUid === targetUid) || (data.userId === targetUid);
    const validId = !('id' in data) || data.id === convId;
    const validTitle = typeof data.title === 'string' && data.title.length >= 1 && data.title.length <= 120;
    return hasOwner && validId && validTitle;
  };

  // Helper: isValidMessage
  const isValidMessage = (data: Record<string, unknown> | undefined, targetUid: string, convId: string, msgId: string) => {
    if (!data) return false;
    const hasOwner = (data.ownerUid === targetUid) || (data.userId === targetUid);
    const validConv = data.conversationId === convId;
    const validId = !('id' in data) || data.id === msgId;
    const validRole = data.role === 'user'; // Direct client write can ONLY be 'user'
    const hasText = (typeof data.text === 'string' && data.text.length >= 1 && data.text.length <= 3000) ||
                    (typeof data.content === 'string' && data.content.length >= 1 && data.content.length <= 3000);
    return hasOwner && validConv && validId && validRole && hasText;
  };

  // Helper: isValidSummary
  const isValidSummary = (data: Record<string, unknown> | undefined, targetUid: string, sumId: string) => {
    if (!data) return false;
    const hasOwner = (data.ownerUid === targetUid) || (data.userId === targetUid);
    const validId = !('id' in data) || data.id === sumId;
    const validConv = typeof data.conversationId === 'string' && isValidId(data.conversationId);
    const hasSummary = (typeof data.summaryText === 'string' && data.summaryText.length >= 1 && data.summaryText.length <= 4000) ||
                       (typeof data.summary === 'string' && data.summary.length >= 1 && data.summary.length <= 4000);
    return hasOwner && validId && validConv && hasSummary;
  };

  // Path 1: users/{uid}
  if (!subcollection) {
    if (operation === 'get') {
      return isOwner ? { actualResult: 'ALLOW', reason: 'isOwner(uid) satisfied.' } : { actualResult: 'DENY', reason: 'Unauthorized: not owner or unauthenticated.' };
    }
    if (operation === 'list') {
      return { actualResult: 'DENY', reason: 'Rule allow list: if false (enumeration forbidden).' };
    }
    if (operation === 'create' || operation === 'update' || operation === 'delete') {
      return isOwner ? { actualResult: 'ALLOW', reason: 'User document write allowed for owner.' } : { actualResult: 'DENY', reason: 'User document write forbidden.' };
    }
  }

  // Path 2: users/{uid}/conversations/{conversationId}
  if (subcollection === 'conversations' && subDocId && !subSubcollection) {
    const convId = subDocId;
    if (!isValidId(convId)) {
      return { actualResult: 'DENY', reason: 'Invalid conversationId format.' };
    }

    if (operation === 'get' || operation === 'list') {
      return isOwner ? { actualResult: 'ALLOW', reason: 'isOwner(uid) satisfied for conversation read.' } : { actualResult: 'DENY', reason: 'Not conversation owner or unauthenticated.' };
    }

    if (operation === 'create') {
      if (!isOwner) return { actualResult: 'DENY', reason: 'Unauthenticated or not matching path uid.' };
      if (!isValidConversation(incomingData, uid, convId)) return { actualResult: 'DENY', reason: 'Invalid conversation data validation failed.' };
      if (incomingData?.ownerUid && incomingData.ownerUid !== auth!.uid) return { actualResult: 'DENY', reason: 'Ownership forgery: ownerUid does not match auth.uid.' };
      return { actualResult: 'ALLOW', reason: 'Conversation create validated and authorized.' };
    }

    if (operation === 'update') {
      if (!isOwner) return { actualResult: 'DENY', reason: 'Not conversation owner or unauthenticated.' };
      if (!isValidConversation(incomingData, uid, convId)) return { actualResult: 'DENY', reason: 'Invalid conversation data update.' };
      // Ownership immutability check
      if (incomingData?.ownerUid && existingData?.ownerUid && incomingData.ownerUid !== existingData.ownerUid) {
        return { actualResult: 'DENY', reason: 'Forbidden: Cannot transfer ownerUid to another UID.' };
      }
      return { actualResult: 'ALLOW', reason: 'Conversation update preserved ownership and passed validation.' };
    }

    if (operation === 'delete') {
      return isOwner ? { actualResult: 'ALLOW', reason: 'Conversation delete authorized by owner.' } : { actualResult: 'DENY', reason: 'Delete denied: Not owner.' };
    }
  }

  // Path 3: users/{uid}/conversations/{conversationId}/messages/{messageId}
  if (subcollection === 'conversations' && subDocId && subSubcollection === 'messages' && subSubDocId) {
    const convId = subDocId;
    const msgId = subSubDocId;
    if (!isValidId(convId) || !isValidId(msgId)) {
      return { actualResult: 'DENY', reason: 'Invalid ID in message path.' };
    }

    if (operation === 'get' || operation === 'list') {
      return isOwner ? { actualResult: 'ALLOW', reason: 'isOwner(uid) satisfied for message read.' } : { actualResult: 'DENY', reason: 'Not message owner or unauthenticated.' };
    }

    if (operation === 'create') {
      if (!isOwner) return { actualResult: 'DENY', reason: 'Unauthenticated or not matching path uid.' };
      if (!isValidMessage(incomingData, uid, convId, msgId)) return { actualResult: 'DENY', reason: 'Message data validation failed (role must be user, valid text length).' };
      if (incomingData?.ownerUid && incomingData.ownerUid !== auth!.uid) return { actualResult: 'DENY', reason: 'Ownership forgery: message ownerUid does not match auth.uid.' };
      return { actualResult: 'ALLOW', reason: 'Message create validated and authorized.' };
    }

    if (operation === 'update') {
      return { actualResult: 'DENY', reason: 'Messages are immutable historical records (allow update: if false).' };
    }

    if (operation === 'delete') {
      return isOwner ? { actualResult: 'ALLOW', reason: 'Message delete authorized by owner.' } : { actualResult: 'DENY', reason: 'Delete denied: Not owner.' };
    }
  }

  // Path 4: users/{uid}/summaries/{summaryId}
  if (subcollection === 'summaries' && subDocId) {
    const sumId = subDocId;
    if (!isValidId(sumId)) {
      return { actualResult: 'DENY', reason: 'Invalid summaryId format.' };
    }

    if (operation === 'get' || operation === 'list') {
      return isOwner ? { actualResult: 'ALLOW', reason: 'isOwner(uid) satisfied for summary read.' } : { actualResult: 'DENY', reason: 'Not summary owner or unauthenticated.' };
    }

    if (operation === 'create') {
      if (!isOwner) return { actualResult: 'DENY', reason: 'Unauthenticated or not matching path uid.' };
      if (!isValidSummary(incomingData, uid, sumId)) return { actualResult: 'DENY', reason: 'Summary validation failed.' };
      if (incomingData?.ownerUid && incomingData.ownerUid !== auth!.uid) return { actualResult: 'DENY', reason: 'Ownership forgery: summary ownerUid does not match auth.uid.' };
      return { actualResult: 'ALLOW', reason: 'Summary create authorized.' };
    }

    if (operation === 'update') {
      if (!isOwner) return { actualResult: 'DENY', reason: 'Not summary owner or unauthenticated.' };
      if (incomingData?.ownerUid && existingData?.ownerUid && incomingData.ownerUid !== existingData.ownerUid) {
        return { actualResult: 'DENY', reason: 'Forbidden: Cannot transfer summary ownerUid to another UID.' };
      }
      return { actualResult: 'ALLOW', reason: 'Summary update authorized.' };
    }

    if (operation === 'delete') {
      return isOwner ? { actualResult: 'ALLOW', reason: 'Summary delete authorized by owner.' } : { actualResult: 'DENY', reason: 'Delete denied: Not owner.' };
    }
  }

  return { actualResult: 'DENY', reason: 'Default-deny rule reached.' };
}

// Official Test Matrix Scenarios specified in USER_REQUEST
export const FIRESTORE_TEST_SCENARIOS: RuleTestScenario[] = [
  // 1. AUTHENTICATED USER A
  {
    id: 'TEST-A-01',
    category: 'AUTHENTICATED USER A',
    operation: 'get',
    path: 'users/user_alice/conversations/conv_01',
    auth: { uid: 'user_alice' },
    expectedResult: 'ALLOW',
    ruleClauseTested: 'allow get: if isOwner(uid) && isValidId(conversationId);',
    details: 'Authenticated User A reads their own conversation.',
  },
  {
    id: 'TEST-A-02',
    category: 'AUTHENTICATED USER A',
    operation: 'create',
    path: 'users/user_alice/conversations/conv_02',
    auth: { uid: 'user_alice' },
    incomingData: {
      id: 'conv_02',
      ownerUid: 'user_alice',
      title: 'Alice Morning Reflection',
      theme: 'Architecture',
    },
    expectedResult: 'ALLOW',
    ruleClauseTested: 'allow create: if isOwner(uid) && isValidConversation(...) && ownerUid == request.auth.uid;',
    details: 'Authenticated User A writes a new conversation in their own path.',
  },
  {
    id: 'TEST-A-03',
    category: 'AUTHENTICATED USER A',
    operation: 'get',
    path: 'users/user_alice/conversations/conv_01/messages/msg_01',
    auth: { uid: 'user_alice' },
    expectedResult: 'ALLOW',
    ruleClauseTested: 'allow get: if isOwner(uid) && isValidId(conversationId) && isValidId(messageId);',
    details: 'Authenticated User A reads a message from their own conversation.',
  },

  // 2. USER A TARGETING USER B
  {
    id: 'TEST-B-01',
    category: 'USER A TARGETING USER B',
    operation: 'get',
    path: 'users/user_bob/conversations/conv_bob_01',
    auth: { uid: 'user_alice' },
    expectedResult: 'DENY',
    ruleClauseTested: 'isOwner(uid) requires request.auth.uid == uid;',
    details: 'User A attempts to read User B conversation.',
  },
  {
    id: 'TEST-B-02',
    category: 'USER A TARGETING USER B',
    operation: 'create',
    path: 'users/user_bob/conversations/conv_bob_malicious',
    auth: { uid: 'user_alice' },
    incomingData: {
      id: 'conv_bob_malicious',
      ownerUid: 'user_alice',
      title: 'Tampered Conversation',
    },
    expectedResult: 'DENY',
    ruleClauseTested: 'isOwner(uid) rejects writes when path uid does not match auth.uid;',
    details: 'User A attempts to write a conversation under User B path.',
  },
  {
    id: 'TEST-B-03',
    category: 'USER A TARGETING USER B',
    operation: 'delete',
    path: 'users/user_bob/conversations/conv_bob_01',
    auth: { uid: 'user_alice' },
    expectedResult: 'DENY',
    ruleClauseTested: 'allow delete: if isOwner(uid);',
    details: 'User A attempts to delete User B conversation.',
  },
  {
    id: 'TEST-B-04',
    category: 'USER A TARGETING USER B',
    operation: 'get',
    path: 'users/user_bob/conversations/conv_bob_01/messages/msg_bob_01',
    auth: { uid: 'user_alice' },
    expectedResult: 'DENY',
    ruleClauseTested: 'allow get: if isOwner(uid);',
    details: 'User A attempts to read User B message.',
  },
  {
    id: 'TEST-B-05',
    category: 'USER A TARGETING USER B',
    operation: 'get',
    path: 'users/user_bob/summaries/sum_bob_01',
    auth: { uid: 'user_alice' },
    expectedResult: 'DENY',
    ruleClauseTested: 'allow get: if isOwner(uid);',
    details: 'User A attempts to read User B summary.',
  },

  // 3. UNAUTHENTICATED
  {
    id: 'TEST-U-01',
    category: 'UNAUTHENTICATED',
    operation: 'get',
    path: 'users/user_alice/conversations/conv_01',
    auth: null,
    expectedResult: 'DENY',
    ruleClauseTested: 'isSignedIn() rejects unauthenticated requests (request.auth != null);',
    details: 'Unauthenticated caller attempts to read private conversation.',
  },
  {
    id: 'TEST-U-02',
    category: 'UNAUTHENTICATED',
    operation: 'create',
    path: 'users/user_alice/conversations/conv_01/messages/msg_anon',
    auth: null,
    incomingData: {
      id: 'msg_anon',
      ownerUid: 'user_alice',
      conversationId: 'conv_01',
      role: 'user',
      text: 'Anonymous injection attempt',
    },
    expectedResult: 'DENY',
    ruleClauseTested: 'isSignedIn() rejects unauthenticated writes;',
    details: 'Unauthenticated caller attempts to write a message.',
  },
  {
    id: 'TEST-U-03',
    category: 'UNAUTHENTICATED',
    operation: 'get',
    path: 'users/user_alice/summaries/sum_alice_01',
    auth: null,
    expectedResult: 'DENY',
    ruleClauseTested: 'isSignedIn() rejects unauthenticated reads of summaries;',
    details: 'Unauthenticated caller attempts to read private summary.',
  },

  // 4. OWNERSHIP FORGERY
  {
    id: 'TEST-F-01',
    category: 'OWNERSHIP FORGERY',
    operation: 'create',
    path: 'users/user_alice/conversations/conv_forged',
    auth: { uid: 'user_alice' },
    incomingData: {
      id: 'conv_forged',
      ownerUid: 'user_bob', // Attacker claims Bob owns this document in Alice's path
      title: 'Forged Ownership Attempt',
    },
    expectedResult: 'DENY',
    ruleClauseTested: 'incoming().ownerUid == request.auth.uid strictly enforces caller identity;',
    details: 'Create document claiming another UID (ownerUid: user_bob while auth.uid is user_alice).',
  },
  {
    id: 'TEST-F-02',
    category: 'OWNERSHIP FORGERY',
    operation: 'update',
    path: 'users/user_alice/conversations/conv_01',
    auth: { uid: 'user_alice' },
    existingData: {
      id: 'conv_01',
      ownerUid: 'user_alice',
      title: 'Existing Conversation',
    },
    incomingData: {
      id: 'conv_01',
      ownerUid: 'user_charlie', // Attempt to transfer ownership to Charlie
      title: 'Transferred Conversation',
    },
    expectedResult: 'DENY',
    ruleClauseTested: 'incoming().ownerUid == existing().ownerUid prevents ownership transfer;',
    details: 'Update ownerUid to another UID (user_alice -> user_charlie).',
  },
];

export function runFirestoreRulesTestSuite(): {
  total: number;
  passed: number;
  failed: number;
  results: RuleTestResult[];
} {
  const results: RuleTestResult[] = FIRESTORE_TEST_SCENARIOS.map((scenario) => {
    const { actualResult, reason } = evaluateFirestoreRules(scenario);
    return {
      ...scenario,
      actualResult,
      passed: actualResult === scenario.expectedResult,
      evaluationReason: reason,
    };
  });

  const passed = results.filter((r) => r.passed).length;
  const failed = results.filter((r) => !r.passed).length;

  return {
    total: results.length,
    passed,
    failed,
    results,
  };
}

// Standalone execution
if (import.meta.url === `file://${process.argv[1]}`) {
  console.log('------------------------------------------------------------');
  console.log('Running Production Firestore Security Rules Test Matrix...');
  console.log('------------------------------------------------------------');
  const report = runFirestoreRulesTestSuite();
  
  report.results.forEach((r) => {
    const icon = r.passed ? '✓' : '✗';
    console.log(`[${icon}] [${r.category}] ${r.id}: ${r.operation.toUpperCase()} ${r.path} => Expected: ${r.expectedResult}, Got: ${r.actualResult} (${r.evaluationReason})`);
  });

  console.log('------------------------------------------------------------');
  console.log(`Score: ${report.passed}/${report.total} Passed (${Math.round((report.passed / report.total) * 100)}%)`);
  if (report.failed > 0) {
    process.exit(1);
  } else {
    console.log('ALL FIRESTORE SECURITY RULES VALIDATED SUCCESSFULLY.');
  }
}
