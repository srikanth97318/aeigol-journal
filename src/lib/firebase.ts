import { initializeApp, getApps, getApp, FirebaseApp } from 'firebase/app';
import {
  getAuth,
  GoogleAuthProvider,
  signInWithPopup,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signOut as firebaseSignOut,
  onAuthStateChanged,
  User,
  Auth,
} from 'firebase/auth';
import { getFirestore, Firestore } from 'firebase/firestore';
import firebaseAppletConfig from '../../firebase-applet-config.json';

// Initialize Firebase App
const app: FirebaseApp = getApps().length === 0 ? initializeApp(firebaseAppletConfig) : getApp();

export const auth: Auth = getAuth(app);
export const firestore: Firestore = getFirestore(app);
export const googleProvider = new GoogleAuthProvider();
googleProvider.setCustomParameters({
  prompt: 'select_account',
});

export {
  signInWithPopup,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  firebaseSignOut,
  firebaseSignOut as signOut,
  onAuthStateChanged,
};

export type { User };

/**
 * Retrieve the verified ID token of the active user for backend Authorization headers.
 */
export async function getActiveIdToken(): Promise<string | null> {
  const currentUser = auth.currentUser;
  if (!currentUser) return null;
  try {
    return await currentUser.getIdToken(false);
  } catch (err) {
    console.warn('Failed to retrieve ID token, retrying with force refresh', err);
    return await currentUser.getIdToken(true);
  }
}
