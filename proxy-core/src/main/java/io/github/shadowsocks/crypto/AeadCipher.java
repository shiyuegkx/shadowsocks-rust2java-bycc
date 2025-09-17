package io.github.shadowsocks.crypto;

/**
 * AEAD Cipher interface following Shadowsocks protocol
 * Maps to shadowsocks-rust crypto traits
 */
public interface AeadCipher {
    /**
     * Encrypt plaintext with AEAD
     * @param nonce The nonce for this encryption
     * @param plaintext The plaintext to encrypt
     * @param associatedData Optional associated data (can be null)
     * @return Ciphertext with appended authentication tag
     */
    byte[] encrypt(byte[] nonce, byte[] plaintext, byte[] associatedData);

    /**
     * Decrypt ciphertext with AEAD
     * @param nonce The nonce for this decryption
     * @param ciphertext The ciphertext with appended tag
     * @param associatedData Optional associated data (can be null)
     * @return Plaintext
     * @throws CryptoException if authentication fails
     */
    byte[] decrypt(byte[] nonce, byte[] ciphertext, byte[] associatedData) throws CryptoException;

    /**
     * Get cipher kind
     */
    CipherKind getKind();

    /**
     * Get nonce length in bytes
     */
    int getNonceLength();

    /**
     * Get tag length in bytes
     */
    int getTagLength();

    /**
     * Get key length in bytes
     */
    int getKeyLength();

    /**
     * Increment nonce (used for chunk encryption)
     * @param nonce The nonce to increment
     */
    static void incrementNonce(byte[] nonce) {
        for (int i = 0; i < nonce.length; i++) {
            if (++nonce[i] != 0) {
                break;
            }
        }
    }
}