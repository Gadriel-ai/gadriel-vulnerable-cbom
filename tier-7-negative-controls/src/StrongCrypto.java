package test.vulnbydesign.crypto.negative;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;

/**
 * False-positive guard: every call here is on the "Acceptable"/strong
 * side of the D-12 registry. A scan of this file alone must produce
 * ZERO CODE-W1-CRYPTO-* (classically weak) findings. (RSA/ECDSA/Ed25519
 * key generation still land in the quantum-vulnerable bucket when the
 * registry has a matching row -- that is a separate, correctly-firing
 * signal, not a false positive; see docs/EXPECTED-FINDINGS.md.)
 */
public class StrongCrypto {

    public void strongDigests() throws Exception {
        MessageDigest.getInstance("SHA-256");
        MessageDigest.getInstance("SHA-384");
        MessageDigest.getInstance("SHA-512");
    }

    public void strongCiphers() throws Exception {
        Cipher.getInstance("AES/GCM/NoPadding");
    }

    public void strongMac() throws Exception {
        Mac.getInstance("HmacSHA256");
        Mac.getInstance("HmacSHA384");
    }

    public void strongKeyGen() throws Exception {
        KeyPairGenerator.getInstance("Ed25519");
        KeyGenerator.getInstance("AES");
    }

    public void strongKdf() throws Exception {
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    }

    public void strongSignature() throws Exception {
        Signature.getInstance("SHA384withECDSA");
    }
}
