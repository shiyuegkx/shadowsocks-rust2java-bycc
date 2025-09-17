package io.github.shadowsocks.protocol;

import io.github.shadowsocks.crypto.AeadCipher;
import io.github.shadowsocks.crypto.CipherFactory;
import io.github.shadowsocks.crypto.CipherKind;
import io.github.shadowsocks.crypto.CryptoException;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * AEAD Protocol implementation following Shadowsocks specification
 * Maps to shadowsocks-rust AEAD protocol module
 *
 * Protocol structure:
 * Request stream: [salt][encrypted header chunk][encrypted payload chunks...]
 * Each chunk: [length (2 bytes)][length_tag][payload][payload_tag]
 */
public class AeadProtocol {
    // Maximum payload size per chunk (0x3FFF for v1, 0xFFFF for 2022)
    public static final int MAX_PAYLOAD_SIZE_V1 = 0x3FFF;
    public static final int MAX_PAYLOAD_SIZE_2022 = 0xFFFF;

    private final CipherKind cipherKind;
    private final byte[] key;

    public AeadProtocol(CipherKind cipherKind, byte[] key) {
        this.cipherKind = cipherKind;
        this.key = Arrays.copyOf(key, key.length);
    }

    /**
     * Create session key from salt
     * Maps to shadowsocks-rust kdf::kdf_sha1 or hkdf_sha256
     */
    public byte[] deriveSessionKey(byte[] salt) {
        String info = "ss-subkey";
        return CipherFactory.deriveSubkey(key, salt, info.getBytes(), key.length);
    }

    /**
     * Encrypt header (address)
     */
    public EncryptedHeader encryptHeader(Address address, byte[] salt) throws CryptoException {
        byte[] sessionKey = deriveSessionKey(salt);
        AeadCipher cipher = CipherFactory.create(cipherKind, sessionKey);

        // Encode address
        byte[] header = address.encode();

        // Generate nonce for header
        byte[] nonce = new byte[cipher.getNonceLength()];

        // Encrypt header length (2 bytes big-endian)
        ByteBuffer lenBuffer = ByteBuffer.allocate(2);
        lenBuffer.order(ByteOrder.BIG_ENDIAN);
        lenBuffer.putShort((short) header.length);
        byte[] encryptedLen = cipher.encrypt(nonce, lenBuffer.array(), null);

        // Increment nonce for header encryption
        AeadCipher.incrementNonce(nonce);

        // Encrypt header
        byte[] encryptedHeader = cipher.encrypt(nonce, header, null);

        return new EncryptedHeader(salt, encryptedLen, encryptedHeader);
    }

    /**
     * Decrypt header
     */
    public Address decryptHeader(ByteBuffer buffer, byte[] salt) throws CryptoException {
        byte[] sessionKey = deriveSessionKey(salt);
        AeadCipher cipher = CipherFactory.create(cipherKind, sessionKey);

        // Generate nonce
        byte[] nonce = new byte[cipher.getNonceLength()];

        // Decrypt header length
        int lenWithTag = 2 + cipher.getTagLength();
        if (buffer.remaining() < lenWithTag) {
            throw new CryptoException("Buffer too short for header length");
        }
        byte[] encryptedLen = new byte[lenWithTag];
        buffer.get(encryptedLen);
        byte[] lenBytes = cipher.decrypt(nonce, encryptedLen, null);
        int headerLen = ByteBuffer.wrap(lenBytes).order(ByteOrder.BIG_ENDIAN).getShort() & 0xFFFF;

        // Increment nonce for header decryption
        AeadCipher.incrementNonce(nonce);

        // Decrypt header
        int headerWithTag = headerLen + cipher.getTagLength();
        if (buffer.remaining() < headerWithTag) {
            throw new CryptoException("Buffer too short for header");
        }
        byte[] encryptedHeader = new byte[headerWithTag];
        buffer.get(encryptedHeader);
        byte[] header = cipher.decrypt(nonce, encryptedHeader, null);

        // Decode address
        return Address.decode(ByteBuffer.wrap(header));
    }

    /**
     * Encrypt payload chunk
     */
    public byte[] encryptChunk(byte[] data, byte[] sessionKey, byte[] nonce) {
        if (data.length > getMaxPayloadSize()) {
            throw new IllegalArgumentException("Payload too large: " + data.length);
        }

        AeadCipher cipher = CipherFactory.create(cipherKind, sessionKey);

        // Prepare length
        ByteBuffer lenBuffer = ByteBuffer.allocate(2);
        lenBuffer.order(ByteOrder.BIG_ENDIAN);
        lenBuffer.putShort((short) data.length);

        // Encrypt length
        byte[] encryptedLen = cipher.encrypt(nonce, lenBuffer.array(), null);

        // Increment nonce
        AeadCipher.incrementNonce(nonce);

        // Encrypt payload
        byte[] encryptedData = cipher.encrypt(nonce, data, null);

        // Combine [encrypted_len][encrypted_data]
        byte[] result = new byte[encryptedLen.length + encryptedData.length];
        System.arraycopy(encryptedLen, 0, result, 0, encryptedLen.length);
        System.arraycopy(encryptedData, 0, result, encryptedLen.length, encryptedData.length);

        // Increment nonce for next chunk
        AeadCipher.incrementNonce(nonce);

        return result;
    }

    /**
     * Decrypt payload chunk
     */
    public byte[] decryptChunk(ByteBuffer buffer, byte[] sessionKey, byte[] nonce) throws CryptoException {
        AeadCipher cipher = CipherFactory.create(cipherKind, sessionKey);

        // Decrypt length
        int lenWithTag = 2 + cipher.getTagLength();
        if (buffer.remaining() < lenWithTag) {
            return null; // Need more data
        }

        buffer.mark();
        byte[] encryptedLen = new byte[lenWithTag];
        buffer.get(encryptedLen);
        byte[] lenBytes = cipher.decrypt(nonce, encryptedLen, null);
        int payloadLen = ByteBuffer.wrap(lenBytes).order(ByteOrder.BIG_ENDIAN).getShort() & 0xFFFF;

        // Increment nonce
        AeadCipher.incrementNonce(nonce);

        // Check if we have full payload
        int payloadWithTag = payloadLen + cipher.getTagLength();
        if (buffer.remaining() < payloadWithTag) {
            buffer.reset();
            return null; // Need more data
        }

        // Decrypt payload
        byte[] encryptedPayload = new byte[payloadWithTag];
        buffer.get(encryptedPayload);
        byte[] payload = cipher.decrypt(nonce, encryptedPayload, null);

        // Increment nonce for next chunk
        AeadCipher.incrementNonce(nonce);

        return payload;
    }

    public int getMaxPayloadSize() {
        return cipherKind.isAead2022() ? MAX_PAYLOAD_SIZE_2022 : MAX_PAYLOAD_SIZE_V1;
    }

    /**
     * Encrypted header structure
     */
    public static class EncryptedHeader {
        public final byte[] salt;
        public final byte[] encryptedLength;
        public final byte[] encryptedHeader;

        public EncryptedHeader(byte[] salt, byte[] encryptedLength, byte[] encryptedHeader) {
            this.salt = salt;
            this.encryptedLength = encryptedLength;
            this.encryptedHeader = encryptedHeader;
        }

        public byte[] toBytes() {
            byte[] result = new byte[salt.length + encryptedLength.length + encryptedHeader.length];
            System.arraycopy(salt, 0, result, 0, salt.length);
            System.arraycopy(encryptedLength, 0, result, salt.length, encryptedLength.length);
            System.arraycopy(encryptedHeader, 0, result, salt.length + encryptedLength.length, encryptedHeader.length);
            return result;
        }
    }
}