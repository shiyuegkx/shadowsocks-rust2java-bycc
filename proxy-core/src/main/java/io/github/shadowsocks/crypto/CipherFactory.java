package io.github.shadowsocks.crypto;

import io.github.shadowsocks.crypto.impl.AesGcmCipher;
import io.github.shadowsocks.crypto.impl.ChaCha20Poly1305Cipher;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * Factory for creating AEAD ciphers
 * Maps to shadowsocks-rust new_cipher function
 */
public class CipherFactory {

    /**
     * Create a new AEAD cipher instance
     */
    public static AeadCipher create(CipherKind kind, byte[] key) {
        switch (kind) {
            case AES_128_GCM:
            case AES_256_GCM:
                return new AesGcmCipher(kind, key);
            case CHACHA20_POLY1305:
                return new ChaCha20Poly1305Cipher(kind, key);
            case AEAD2022_BLAKE3_AES_128_GCM:
            case AEAD2022_BLAKE3_AES_256_GCM:
            case AEAD2022_BLAKE3_CHACHA20_POLY1305:
                // For 2022 ciphers, we'll need special handling
                // For now, use the base cipher
                CipherKind baseCipher = getBaseCipherKind(kind);
                return create(baseCipher, key);
            default:
                throw new UnsupportedOperationException("Cipher not supported: " + kind);
        }
    }

    /**
     * Derive key from password using EVP_BytesToKey (MD5)
     * This matches shadowsocks-rust's openssl_bytes_to_key function
     */
    public static byte[] deriveKey(String password, CipherKind kind) {
        return evpBytesToKey(password.getBytes(StandardCharsets.UTF_8), kind.getKeyLen());
    }

    /**
     * OpenSSL's EVP_BytesToKey with MD5
     * Matches shadowsocks-rust implementation
     */
    private static byte[] evpBytesToKey(byte[] password, int keyLen) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] result = new byte[keyLen];
            int resultLen = 0;
            byte[] m = null;

            while (resultLen < keyLen) {
                if (m != null) {
                    md.update(m);
                }
                md.update(password);
                m = md.digest();

                int copyLen = Math.min(m.length, keyLen - resultLen);
                System.arraycopy(m, 0, result, resultLen, copyLen);
                resultLen += copyLen;

                md.reset();
            }

            return result;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("MD5 algorithm not available", e);
        }
    }

    /**
     * Derive subkey for AEAD 2022 using HKDF-SHA256
     * Maps to shadowsocks-rust kdf::hkdf_sha256
     */
    public static byte[] deriveSubkey(byte[] key, byte[] salt, byte[] info, int length) {
        try {
            // HKDF Extract
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] prk = hmacSha256(salt != null ? salt : new byte[32], key);

            // HKDF Expand
            byte[] result = new byte[length];
            byte[] t = new byte[0];
            int pos = 0;
            byte counter = 1;

            while (pos < length) {
                sha256.reset();
                byte[] input = new byte[t.length + info.length + 1];
                System.arraycopy(t, 0, input, 0, t.length);
                System.arraycopy(info, 0, input, t.length, info.length);
                input[input.length - 1] = counter++;

                t = hmacSha256(prk, input);
                int copyLen = Math.min(t.length, length - pos);
                System.arraycopy(t, 0, result, pos, copyLen);
                pos += copyLen;
            }

            return result;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

            // HMAC implementation
            byte[] ipad = new byte[64];
            byte[] opad = new byte[64];

            // Prepare key
            byte[] k = key;
            if (k.length > 64) {
                k = sha256.digest(k);
                sha256.reset();
            }
            if (k.length < 64) {
                byte[] tmp = new byte[64];
                System.arraycopy(k, 0, tmp, 0, k.length);
                k = tmp;
            }

            // XOR with pads
            for (int i = 0; i < 64; i++) {
                ipad[i] = (byte)(k[i] ^ 0x36);
                opad[i] = (byte)(k[i] ^ 0x5c);
            }

            // Inner hash
            sha256.update(ipad);
            sha256.update(data);
            byte[] inner = sha256.digest();

            // Outer hash
            sha256.reset();
            sha256.update(opad);
            sha256.update(inner);

            return sha256.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private static CipherKind getBaseCipherKind(CipherKind kind) {
        switch (kind) {
            case AEAD2022_BLAKE3_AES_128_GCM:
                return CipherKind.AES_128_GCM;
            case AEAD2022_BLAKE3_AES_256_GCM:
                return CipherKind.AES_256_GCM;
            case AEAD2022_BLAKE3_CHACHA20_POLY1305:
                return CipherKind.CHACHA20_POLY1305;
            default:
                return kind;
        }
    }
}