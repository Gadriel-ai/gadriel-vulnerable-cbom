// Deliberately vulnerable-by-design A2 (source-API arm) fixture, JS.
// Matched against crypto_source_scan.rs's ARG_BASED table for
// Language::JavaScript (crypto.createHash/createHmac/createCipheriv/
// createDecipheriv -- all argument-based on a literal string).
const crypto = require('crypto');

function weakDigests() {
  crypto.createHash('md5');     // weak
  crypto.createHash('sha1');    // weak
  crypto.createHash('sha256');  // strong, no finding
}

function weakHmac(key) {
  crypto.createHmac('sha1', key);    // weak: HMAC over SHA-1
  crypto.createHmac('sha256', key);  // strong
}

function ciphers(key, iv) {
  // Note: the Node cipher-name parser classifies this as "DES-CBC"
  // (it keys off the first hyphen-split token, "des"), not "3DES" --
  // a documented parser gap, not a 3DES-specific weak-crypto finding.
  // See docs/EXPECTED-FINDINGS.md.
  crypto.createCipheriv('des-ede3-cbc', key, iv);
  crypto.createCipheriv('aes-256-gcm', key, iv);   // strong
  crypto.createDecipheriv('rc4', key, iv);         // weak: RC4
}

module.exports = { weakDigests, weakHmac, ciphers };
