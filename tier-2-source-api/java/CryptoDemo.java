package test.vulnbydesign.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;

/**
 * Deliberately vulnerable-by-design A2 (source-API arm) fixture.
 * Every call below is a literal-argument form the gadriel A2 scanner
 * (crypto_source_scan.rs) matches directly — see
 * docs/EXPECTED-FINDINGS.md for the expected asset/finding per line.
 */
public class CryptoDemo {

    // --- Weak hashes (CODE-W1-CRYPTO-0xx) ---
    public void weakDigests() throws Exception {
        MessageDigest md5 = MessageDigest.getInstance("MD5");                 // weak
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");               // weak
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");          // strong, no finding
        byte[] ignored = md5.digest();
        byte[] ignored2 = sha1.digest();
        byte[] ignored3 = sha256.digest();
    }

    // --- Weak + strong ciphers ---
    public void ciphers() throws Exception {
        Cipher des = Cipher.getInstance("DES/ECB/PKCS5Padding");              // weak: DES + ECB
        Cipher rc4ish3des = Cipher.getInstance("DESede/CBC/PKCS5Padding");    // weak: 3DES
        Cipher aesGcm = Cipher.getInstance("AES/GCM/NoPadding");              // strong, no finding
        Cipher rsaOaep = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"); // RSA (quantum-vulnerable family at the policy layer once resolved)
    }

    // --- MAC ---
    public void macs() throws Exception {
        Mac weak = Mac.getInstance("HmacMD5");                                // HMAC over MD5 -> family resolves, weak at the digest layer
        Mac strong = Mac.getInstance("HmacSHA256");                           // strong
    }

    // --- Key generation: receiver-chain gap (documented, not a bug) ---
    // KeyPairGenerator.getInstance("RSA") resolves to algorithm "RSA" with
    // classical_bits = None — the .initialize(2048) call is NOT correlated
    // in this increment (crypto_source_scan.rs module doc comment, "out of
    // scope"). This is an intentional advanced-tier case: it proves the
    // scanner records "RSA key generation happened" without ever guessing
    // a key size it did not actually see resolved.
    public void keyGenReceiverChainGap() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
    }

    public void symmetricKeyGen() throws Exception {
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");             // strong
    }

    // --- Password-based key derivation: weak PBE vs strong PBKDF2 ---
    public void secretKeyFactories() throws Exception {
        SecretKeyFactory weakPbe = SecretKeyFactory.getInstance("PBEWithMD5AndDES");       // legacy PBES1, weak by construction
        SecretKeyFactory strongKdf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"); // strong
    }

    // --- Signatures: weak SHA-1 vs strong SHA-256 ---
    public void signatures() throws Exception {
        Signature weakSig = Signature.getInstance("SHA1withRSA");             // weak digest component
        Signature strongSig = Signature.getInstance("SHA256withRSA");         // resolves to "RSA-SHA-256"
        Signature ed25519Sig = Signature.getInstance("Ed25519");              // resolves to bare "Ed25519" -- joins the A1/A3 Ed25519 component
    }
}
