import { SecretManagerServiceClient } from '@google-cloud/secret-manager';

let cachedApiKey: string | null = null;
let secretClient: SecretManagerServiceClient | null = null;

/**
 * Lazily retrieves the Gemini API key from either:
 * 1. Environment variable (GEMINI_API_KEY)
 * 2. Google Cloud Secret Manager (projects/{project}/secrets/{secret}/versions/latest)
 *
 * Never throws an unhandled exception that could crash the server at boot.
 * Never logs or returns the secret value.
 */
export async function getGeminiApiKey(): Promise<string | null> {
  // Check cached memory first
  if (cachedApiKey) {
    return cachedApiKey;
  }

  // Check process.env first (Standard Cloud Run / Container injection)
  const envKey = process.env.GEMINI_API_KEY;
  if (envKey && envKey !== 'MY_GEMINI_API_KEY' && envKey.trim().length > 0) {
    cachedApiKey = envKey.trim();
    return cachedApiKey;
  }

  // Attempt retrieval from Google Cloud Secret Manager if project/secret is specified
  const projectId = process.env.GOOGLE_CLOUD_PROJECT || process.env.GCP_PROJECT;
  const secretName = process.env.GEMINI_SECRET_NAME || 'gemini-api-key';

  if (projectId) {
    try {
      if (!secretClient) {
        secretClient = new SecretManagerServiceClient();
      }

      const secretPath = `projects/${projectId}/secrets/${secretName}/versions/latest`;
      const [version] = await secretClient.accessSecretVersion({ name: secretPath });
      const payload = version.payload?.data?.toString();

      if (payload && payload.trim().length > 0) {
        cachedApiKey = payload.trim();
        console.log(`[SECURITY] Successfully retrieved Gemini API key from Secret Manager (${secretName})`);
        return cachedApiKey;
      }
    } catch (err: unknown) {
      // Graceful fallback; do not leak paths or error details to client
      const errMsg = err instanceof Error ? err.message : String(err);
      console.warn(`[SECRET_MANAGER] Unable to access secret '${secretName}' via Secret Manager: ${errMsg}. Falling back.`);
    }
  }

  return null;
}
