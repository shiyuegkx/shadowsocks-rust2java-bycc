package io.github.shadowsocks.crypto;

import io.github.shadowsocks.crypto.impl.AesGcmCipher;
import io.github.shadowsocks.crypto.impl.ChaCha20Poly1305Cipher;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for AEAD cipher implementations
 */
public class AeadCipherTest {

    @Test
    public void testAes128GcmEncryptDecrypt() throws Exception {
        CipherKind kind = CipherKind.AES_128_GCM;
        byte[] key = new byte[kind.getKeyLen()];
        new SecureRandom().nextBytes(key);

        AeadCipher cipher = new AesGcmCipher(kind, key);

        byte[] nonce = new byte[cipher.getNonceLength()];
        new SecureRandom().nextBytes(nonce);

        String plaintext = "Hello, Shadowsocks!";
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        // Encrypt
        byte[] ciphertext = cipher.encrypt(nonce, plaintextBytes, null);

        // Verify ciphertext includes tag
        assertEquals(plaintextBytes.length + cipher.getTagLength(), ciphertext.length);

        // Decrypt
        byte[] decrypted = cipher.decrypt(nonce, ciphertext, null);

        // Verify decryption
        assertArrayEquals(plaintextBytes, decrypted);
        assertEquals(plaintext, new String(decrypted, StandardCharsets.UTF_8));
    }

    @Test
    public void testAes256GcmWithAssociatedData() throws Exception {
        CipherKind kind = CipherKind.AES_256_GCM;
        byte[] key = new byte[kind.getKeyLen()];
        new SecureRandom().nextBytes(key);

        AeadCipher cipher = new AesGcmCipher(kind, key);

        byte[] nonce = new byte[cipher.getNonceLength()];
        new SecureRandom().nextBytes(nonce);

        byte[] plaintext = "Secret data".getBytes(StandardCharsets.UTF_8);
        byte[] associatedData = "metadata".getBytes(StandardCharsets.UTF_8);

        // Encrypt with AD
        byte[] ciphertext = cipher.encrypt(nonce, plaintext, associatedData);

        // Decrypt with correct AD
        byte[] decrypted = cipher.decrypt(nonce, ciphertext, associatedData);
        assertArrayEquals(plaintext, decrypted);

        // Decrypt with wrong AD should fail
        byte[] wrongAd = "wrong".getBytes(StandardCharsets.UTF_8);
        assertThrows(CryptoException.class, () ->
            cipher.decrypt(nonce, ciphertext, wrongAd)
        );
    }

    @Test
    public void testChaCha20Poly1305() throws Exception {
        CipherKind kind = CipherKind.CHACHA20_POLY1305;
        byte[] key = new byte[kind.getKeyLen()];
        new SecureRandom().nextBytes(key);

        AeadCipher cipher = new ChaCha20Poly1305Cipher(kind, key);

        byte[] nonce = new byte[cipher.getNonceLength()];
        new SecureRandom().nextBytes(nonce);

        byte[] plaintext = "ChaCha20-Poly1305 test".getBytes(StandardCharsets.UTF_8);

        // Encrypt
        byte[] ciphertext = cipher.encrypt(nonce, plaintext, null);

        // Decrypt
        byte[] decrypted = cipher.decrypt(nonce, ciphertext, null);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void testNonceIncrement() {
        byte[] nonce = new byte[12];

        // Test simple increment
        nonce[0] = 0;
        AeadCipher.incrementNonce(nonce);
        assertEquals(1, nonce[0]);

        // Test overflow
        nonce[0] = (byte) 0xFF;
        AeadCipher.incrementNonce(nonce);
        assertEquals(0, nonce[0]);
        assertEquals(1, nonce[1]);

        // Test multiple overflow
        for (int i = 0; i < 12; i++) {
            nonce[i] = (byte) 0xFF;
        }
        AeadCipher.incrementNonce(nonce);
        for (int i = 0; i < 12; i++) {
            assertEquals(0, nonce[i]);
        }
    }

    @Test
    public void testKeyDerivation() {
        String password = "test-password";
        CipherKind kind = CipherKind.AES_256_GCM;

        byte[] key1 = CipherFactory.deriveKey(password, kind);
        byte[] key2 = CipherFactory.deriveKey(password, kind);

        // Same password should produce same key
        assertArrayEquals(key1, key2);
        assertEquals(kind.getKeyLen(), key1.length);

        // Different password should produce different key
        byte[] key3 = CipherFactory.deriveKey("different", kind);
        assertFalse(java.util.Arrays.equals(key1, key3));
    }

    @Test
    public void testAuthenticationFailure() throws Exception {
        CipherKind kind = CipherKind.AES_128_GCM;
        byte[] key = new byte[kind.getKeyLen()];
        new SecureRandom().nextBytes(key);

        AeadCipher cipher = new AesGcmCipher(kind, key);

        byte[] nonce = new byte[cipher.getNonceLength()];
        new SecureRandom().nextBytes(nonce);

        byte[] plaintext = "data".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = cipher.encrypt(nonce, plaintext, null);

        // Tamper with ciphertext
        ciphertext[ciphertext.length - 1] ^= 0x01;

        // Should fail authentication
        assertThrows(CryptoException.class, () ->
            cipher.decrypt(nonce, ciphertext, null)
        );
    }
}