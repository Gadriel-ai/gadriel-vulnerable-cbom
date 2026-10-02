// Deliberately vulnerable-by-design A2 (source-API arm) fixture, TS.
// Same ARG_BASED table as JavaScript (Language::TypeScript has its own
// identical entries in crypto_source_scan.rs).
import * as crypto from 'crypto';

export function weakDigests(): void {
  crypto.createHash('md5');     // weak
  crypto.createHash('sha256');  // strong, no finding
}

export function strongCipher(key: Buffer, iv: Buffer): crypto.CipherGCM {
  return crypto.createCipheriv('aes-256-gcm', key, iv) as crypto.CipherGCM; // strong
}

export function weakCipher(key: Buffer, iv: Buffer): crypto.Decipher {
  return crypto.createDecipheriv('rc4', key, iv); // weak: RC4
}
