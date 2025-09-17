package io.github.shadowsocks.crypto.impl;

import io.github.shadowsocks.crypto.AeadCipher;
import io.github.shadowsocks.crypto.CipherKind;
import io.github.shadowsocks.crypto.CryptoException;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * ChaCha20-Poly1305 cipher implementation (IETF variant)
 * Maps to shadowsocks-rust ChaCha20Poly1305 implementation
 */
public class ChaCha20Poly1305Cipher implements AeadCipher {
    private final CipherKind kind;
    private final byte[] key;

    public ChaCha20Poly1305Cipher(CipherKind kind, byte[] key) {
        if (kind != CipherKind.CHACHA20_POLY1305) {
            throw new IllegalArgumentException("Invalid cipher kind for ChaCha20-Poly1305: " + kind);
        }
        if (key.length != kind.getKeyLen()) {
            throw new IllegalArgumentException("Invalid key length: " + key.length + ", expected: " + kind.getKeyLen());
        }
        this.kind = kind;
        this.key = Arrays.copyOf(key, key.length);
    }

    @Override
    public byte[] encrypt(byte[] nonce, byte[] plaintext, byte[] associatedData) {
        try {
            ChaCha7539Engine chacha = new ChaCha7539Engine();
            chacha.init(true, new ParametersWithIV(new KeyParameter(key), nonce));

            // Generate Poly1305 key
            byte[] polyKey = new byte[32];
            chacha.processBytes(polyKey, 0, 32, polyKey, 0);

            // Encrypt plaintext
            byte[] ciphertext = new byte[plaintext.length];
            chacha.processBytes(plaintext, 0, plaintext.length, ciphertext, 0);

            // Calculate MAC
            byte[] mac = calculatePoly1305Mac(polyKey, associatedData, ciphertext);

            // Combine ciphertext and MAC
            byte[] result = new byte[ciphertext.length + 16];
            System.arraycopy(ciphertext, 0, result, 0, ciphertext.length);
            System.arraycopy(mac, 0, result, ciphertext.length, 16);

            return result;
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] nonce, byte[] ciphertext, byte[] associatedData) throws CryptoException {
        if (ciphertext.length < 16) {
            throw new CryptoException("Ciphertext too short");
        }

        try {
            ChaCha7539Engine chacha = new ChaCha7539Engine();
            chacha.init(false, new ParametersWithIV(new KeyParameter(key), nonce));

            // Generate Poly1305 key
            byte[] polyKey = new byte[32];
            chacha.processBytes(polyKey, 0, 32, polyKey, 0);

            // Split ciphertext and MAC
            int ctLen = ciphertext.length - 16;
            byte[] ct = Arrays.copyOf(ciphertext, ctLen);
            byte[] receivedMac = Arrays.copyOfRange(ciphertext, ctLen, ciphertext.length);

            // Verify MAC
            byte[] calculatedMac = calculatePoly1305Mac(polyKey, associatedData, ct);
            if (!constantTimeEquals(receivedMac, calculatedMac)) {
                throw new CryptoException("Authentication failed");
            }

            // Decrypt
            byte[] plaintext = new byte[ctLen];
            chacha.processBytes(ct, 0, ctLen, plaintext, 0);

            return plaintext;
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("Decryption failed", e);
        }
    }

    private byte[] calculatePoly1305Mac(byte[] key, byte[] aad, byte[] ciphertext) {
        Poly1305 poly = new Poly1305();
        poly.init(new KeyParameter(key));

        // Process AAD
        if (aad != null && aad.length > 0) {
            poly.update(aad, 0, aad.length);
            // Pad to 16 bytes
            int padLen = (16 - (aad.length % 16)) % 16;
            if (padLen > 0) {
                poly.update(new byte[padLen], 0, padLen);
            }
        }

        // Process ciphertext
        poly.update(ciphertext, 0, ciphertext.length);
        // Pad to 16 bytes
        int padLen = (16 - (ciphertext.length % 16)) % 16;
        if (padLen > 0) {
            poly.update(new byte[padLen], 0, padLen);
        }

        // Add lengths
        ByteBuffer buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        buf.putLong(aad != null ? aad.length : 0);
        buf.putLong(ciphertext.length);
        poly.update(buf.array(), 0, 16);

        // Get MAC
        byte[] mac = new byte[16];
        poly.doFinal(mac, 0);
        return mac;
    }

    private boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }

    @Override
    public CipherKind getKind() {
        return kind;
    }

    @Override
    public int getNonceLength() {
        return kind.getNonceLen();
    }

    @Override
    public int getTagLength() {
        return kind.getTagLen();
    }

    @Override
    public int getKeyLength() {
        return kind.getKeyLen();
    }
}