export interface AuthUser {
  uid: string;
  email: string;
  displayName: string;
  photoURL?: string;
  isAnonymous?: boolean;
}

export interface Conversation {
  id: string;
  ownerUid: string;
  userId?: string;
  title: string;
  theme?: string;
  lastMessagePreview?: string;
  messageCount: number;
  isArchived?: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface Message {
  id: string;
  conversationId: string;
  ownerUid: string;
  userId?: string;
  role: 'user' | 'assistant' | 'model';
  text: string;
  content?: string;
  reflectionTags?: string[];
  createdAt: string;
}

export interface Summary {
  id: string;
  conversationId: string;
  ownerUid: string;
  userId?: string;
  summaryText: string;
  summary?: string;
  keyPoints: string[];
  actionItems: string[];
  insights?: string[];
  title?: string;
  createdAt: string;
  updatedAt: string;
}

export interface SecurityTestResult {
  id: string;
  name: string;
  category: string;
  description: string;
  status: 'PASSED' | 'FAILED';
  httpStatus: number;
  expectedStatus: number;
  securityBoundary: string;
  remedyProof: string;
}

export interface AuditReport {
  timestamp: string;
  totalTests: number;
  passed: number;
  failed: number;
  complianceScore: string;
  auditResults: SecurityTestResult[];
}

export interface ThreatModelItem {
  id: string;
  asset: string;
  threatActor: string;
  attackSurface: string;
  attack: string;
  impact: string;
  mitigation: string;
  residualRisk: 'LOW' | 'MEDIUM' | 'NEGLIGIBLE';
}
