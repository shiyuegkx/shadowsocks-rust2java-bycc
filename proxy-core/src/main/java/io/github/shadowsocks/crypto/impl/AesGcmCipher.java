package io.github.shadowsocks.crypto.impl;

import io.github.shadowsocks.crypto.AeadCipher;
import io.github.shadowsocks.crypto.CipherKind;
import io.github.shadowsocks.crypto.CryptoException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.Arrays;

/**
 * AES-GCM cipher implementation
 * Maps to shadowsocks-rust AesGcm implementation
 */
public class AesGcmCipher implements AeadCipher {
    private final CipherKind kind;
    private final byte[] key;

    public AesGcmCipher(CipherKind kind, byte[] key) {
        if (kind != CipherKind.AES_128_GCM && kind != CipherKind.AES_256_GCM) {
            throw new IllegalArgumentException("Invalid cipher kind for AES-GCM: " + kind);
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
            GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
            AEADParameters params = new AEADParameters(
                new KeyParameter(key),
                kind.getTagLen() * 8,  // tag size in bits
                nonce,
                associatedData
            );

            cipher.init(true, params);

            byte[] ciphertext = new byte[cipher.getOutputSize(plaintext.length)];
            int len = cipher.processBytes(plaintext, 0, plaintext.length, ciphertext, 0);
            len += cipher.doFinal(ciphertext, len);

            return ciphertext;
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] nonce, byte[] ciphertext, byte[] associatedData) throws CryptoException {
        try {
            GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
            AEADParameters params = new AEADParameters(
                new KeyParameter(key),
                kind.getTagLen() * 8,  // tag size in bits
                nonce,
                associatedData
            );

            cipher.init(false, params);

            byte[] plaintext = new byte[cipher.getOutputSize(ciphertext.length)];
            int len = cipher.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0);
            len += cipher.doFinal(plaintext, len);

            return Arrays.copyOf(plaintext, len);
        } catch (Exception e) {
            throw new CryptoException("Decryption failed", e);
        }
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