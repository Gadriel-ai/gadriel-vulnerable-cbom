// Deliberately vulnerable-by-design A2 (source-API arm) fixture, Go.
// Every call below is name-based in crypto_source_scan.rs's
// GO_NAME_BASED table -- the algorithm is the function itself, so
// these always resolve (no Unresolved case exists for this language's
// table; Go's Unresolved coverage lives in the config/IaC tiers
// instead).
package vulnbydesign

import (
	"crypto/des"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"

	"golang.org/x/crypto/bcrypt"
)

func WeakDigests() {
	_ = md5.New()      // weak
	_ = sha1.Sum(nil)  // weak
	_ = sha256.New()   // strong, no finding
}

func WeakCiphers(key []byte) {
	_, _ = des.NewCipher(key)              // weak: DES
	_, _ = des.NewTripleDESCipher(key)     // weak: 3DES
	_, _ = rc4.NewCipher(key)              // weak: RC4
}

func KeyGeneration() {
	// RSA -- quantum-vulnerable at the policy layer once resolved by
	// name; this call resolves to bare "RSA" (no size, same documented
	// receiver-chain gap as the Java fixture).
	_, _ = rsa.GenerateKey(rand.Reader, 2048)

	_, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Ed25519 key generation -- joins the cross-arm Ed25519 component
	// (A1's PEM key, A3's sshd_config ssh-ed25519 line).
	_, _, _ = ed25519.GenerateKey(nil)
}

func PasswordHashing(password []byte) {
	_, _ = bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost) // strong KDF, name-based
}
