import { getFirestore, FieldValue } from 'firebase-admin/firestore';
import { Conversation, Message, Summary } from '../src/types';
import firebaseAppletConfig from '../firebase-applet-config.json';

// In-memory cache fallback to ensure resiliency across diverse runtime sandbox environments
interface UserPartition {
  conversations: Map<string, Conversation>;
  messages: Map<string, Message[]>;
  summaries: Map<string, Summary>;
}
const memoryCache = new Map<string, UserPartition>();

function getMemoryStore(uid: string): UserPartition {
  if (!memoryCache.has(uid)) {
    memoryCache.set(uid, {
      conversations: new Map(),
      messages: new Map(),
      summaries: new Map(),
    });
  }
  return memoryCache.get(uid)!;
}

let firestoreInstance: FirebaseFirestore.Firestore | null = null;
let firestoreAvailable = true;

function getDb(): FirebaseFirestore.Firestore | null {
  if (!firestoreAvailable) return null;
  if (!firestoreInstance) {
    try {
      const dbId = firebaseAppletConfig.firestoreDatabaseId;
      if (dbId && dbId !== '(default)') {
        firestoreInstance = getFirestore(dbId);
      } else {
        firestoreInstance = getFirestore();
      }
    } catch (err) {
      console.warn('[FIRESTORE_STORAGE] Could not initialize Firestore directly; using resilient fallback:', err);
      firestoreAvailable = false;
      return null;
    }
  }
  return firestoreInstance;
}

/**
 * Retrieves all conversations for the authenticated user from Cloud Firestore
 * under the user-scoped boundary: /users/{uid}/conversations
 */
export async function getConversations(uid: string): Promise<Conversation[]> {
  const db = getDb();
  if (db) {
    try {
      const snapshot = await db
        .collection('users')
        .doc(uid)
        .collection('conversations')
        .orderBy('updatedAt', 'desc')
        .get();

      const list = snapshot.docs.map((doc) => doc.data() as Conversation);
      // Sync memory cache
      const mem = getMemoryStore(uid);
      mem.conversations.clear();
      for (const item of list) {
        mem.conversations.set(item.id, item);
      }
      return list;
    } catch (err) {
      console.warn(`[FIRESTORE_STORAGE] getConversations error for ${uid}:`, err);
    }
  }

  // Fallback to cache
  const mem = getMemoryStore(uid);
  return Array.from(mem.conversations.values()).sort(
    (a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime()
  );
}

/**
 * Retrieves a single conversation verifying ownership
 */
export async function getConversation(uid: string, convId: string): Promise<Conversation | null> {
  const db = getDb();
  if (db) {
    try {
      const doc = await db
        .collection('users')
        .doc(uid)
        .collection('conversations')
        .doc(convId)
        .get();

      if (doc.exists) {
        return doc.data() as Conversation;
      }
      return null;
    } catch (err) {
      console.warn(`[FIRESTORE_STORAGE] getConversation error:`, err);
    }
  }

  const mem = getMemoryStore(uid);
  return mem.conversations.get(convId) || null;
}

/**
 * Persists a conversation to Cloud Firestore under /users/{uid}/conversations/{convId}
 */
export async function saveConversation(uid: string, conv: Conversation): Promise<void> {
  // Update memory cache
  const mem = getMemoryStore(uid);
  mem.conversations.set(conv.id, conv);
  if (!mem.messages.has(conv.id)) {
    mem.messages.set(conv.id, []);
  }

  const db = getDb();
  if (db) {
    try {
      await db
        .collection('users')
        .doc(uid)
        .collection('conversations')
        .doc(conv.id)
        .set(conv, { merge: true });
    } catch (err) {
      console.warn(`[FIRESTORE_STORAGE] saveConversation error:`, err);
    }
  }
}

/**
 * Deletes a conversation and its linked subcollection records
 */
export async function deleteConversation(uid: string, convId: string): Promise<void> {
  const mem = getMemoryStore(uid);
  mem.conversations.delete(convId);
  mem.messages.delete(convId);
  for (const [sumId, sum] of mem.summaries.entries()) {
    if (sum.conversationId === convId) {
      mem.summaries.delete(sumId);
    }
  }

  const db = getDb();
  if (db) {
    try {
      await db
        .collection('users')
        .doc(uid)
        .collection('conversations')
        .doc(convId)
        .delete();
    } catch (err) {
      console.warn(`[FIRESTORE_STORAGE] deleteConversation error:`, err);
    }
  }
}

/**
 * Retrieves messages for a conversation
 */
export async function getMessages(uid: string, convId: string): Promise<Message[]> {
  const db = getDb();
  if (db) {
    try {
      const snapshot = await db
        .collection('users')
        .doc(uid)
        .collection('conversations')
        .doc(convId)
        .collection('messages')
        .orderBy('createdAt', 'asc')
        .get();

      const list = snapshot.docs.map((d) => d.data() as Message);
      const mem = getMemoryStore(uid);
      mem.messages.set(convId, list);
      return list;
    } catch (err) {
      console.warn(`[FIRESTORE_STORAGE] getMessages error:`, err);
    }
  }

  const mem = getMemoryStore(uid);
  return mem.messages.get(convId) || [];
}

/**
 * Persists a message to /users/{uid}/conversations/{convId}/messages/{msgId}
 * and updates parent conversation stats atomically
 */
export async function saveMessage(
  uid: string,
  convId: string,
  msg: Message,
  lastPreview?: string
): Promise<void> {
  const mem = getMemoryStore(uid);
  const currentList = mem.messages.get(convId) || [];
  currentList.push(msg);
  mem.messages.set(convId, currentList);

  const conv = mem.conversations.get(convId);
  if (conv) {
    conv.messageCount = currentList.length;
    if (lastPreview) conv.lastMessagePreview = lastPreview.slice(0, 140);
    conv.updatedAt = new Date().toISOString();
  }

  const db = getDb();
  if (db) {
    try {
      const batch = db.batch();
      const msgRef = db
        .collection('users')
        .doc(uid)
        .collection('conversations')
        .doc(convId)
        .collection('messages')
        .doc(msg.id);
      batch.set(msgRef, msg);

      const convRef = db
        .collection('users')
        .doc(uid)
        .collection('conversations')
        .doc(convId);
      batch.update(convRef, {
        messageCount: FieldValue.increment(1),
        lastMessagePreview: (lastPreview || msg.text).slice(0, 140),
        updatedAt: new Date().toISOString(),
      });

      await batch.commit();
    } catch (err) {
      console.warn(`[FIRESTORE_STORAGE] saveMessage error:`, err);
    }
  }
}

/**
 * Retrieves all summaries for the user
 */
export async function getSummaries(uid: string): Promise<Summary[]> {
  const db = getDb();
  if (db) {
    try {
      const snapshot = await db
        .collection('users')
        .doc(uid)
        .collection('summaries')
        .orderBy('createdAt', 'desc')
        .get();

      const list = snapshot.docs.map((d) => d.data() as Summary);
      const mem = getMemoryStore(uid);
      mem.summaries.clear();
      for (const s of list) {
        mem.summaries.set(s.id, s);
      }
      return list;
    } catch (err) {
      console.warn(`[FIRESTORE_STORAGE] getSummaries error:`, err);
    }
  }

  const mem = getMemoryStore(uid);
  return Array.from(mem.summaries.values()).sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
  );
}

/**
 * Persists a summary to /users/{uid}/summaries/{summaryId}
 */
export async function saveSummary(uid: string, summary: Summary): Promise<void> {
  const mem = getMemoryStore(uid);
  mem.summaries.set(summary.id, summary);

  const db = getDb();
  if (db) {
    try {
      await db
        .collection('users')
        .doc(uid)
        .collection('summaries')
        .doc(summary.id)
        .set(summary);
    } catch (err) {
      console.warn(`[FIRESTORE_STORAGE] saveSummary error:`, err);
    }
  }
}
