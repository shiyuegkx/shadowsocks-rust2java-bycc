package io.github.shadowsocks.protocol;

import io.github.shadowsocks.crypto.CipherFactory;
import io.github.shadowsocks.crypto.CipherKind;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for AEAD protocol implementation
 */
public class AeadProtocolTest {

    @Test
    public void testHeaderEncryption() throws Exception {
        CipherKind kind = CipherKind.AES_256_GCM;
        String password = "test-password";
        byte[] key = CipherFactory.deriveKey(password, kind);

        AeadProtocol protocol = new AeadProtocol(kind, key);

        // Create address
        Address address = Address.fromHostPort("example.com", 443);

        // Generate salt
        byte[] salt = Salt.generate(kind.getSaltLen()).getValue();

        // Encrypt header
        AeadProtocol.EncryptedHeader encHeader = protocol.encryptHeader(address, salt);

        // Verify components exist
        assertNotNull(encHeader.salt);
        assertNotNull(encHeader.encryptedLength);
        assertNotNull(encHeader.encryptedHeader);
        assertArrayEquals(salt, encHeader.salt);

        // Convert to bytes
        byte[] headerBytes = encHeader.toBytes();
        assertTrue(headerBytes.length > salt.length);

        // Decrypt header
        ByteBuffer buffer = ByteBuffer.wrap(headerBytes);
        buffer.position(salt.length); // Skip salt (already known)

        Address decrypted = protocol.decryptHeader(buffer, salt);

        // Verify decrypted address
        assertEquals(address.getHost(), decrypted.getHost());
        assertEquals(address.getPort(), decrypted.getPort());
    }

    @Test
    public void testChunkEncryption() throws Exception {
        CipherKind kind = CipherKind.AES_128_GCM;
        byte[] key = CipherFactory.deriveKey("password", kind);

        AeadProtocol protocol = new AeadProtocol(kind, key);

        byte[] salt = Salt.generate(kind.getSaltLen()).getValue();
        byte[] sessionKey = protocol.deriveSessionKey(salt);
        byte[] nonce = new byte[12]; // GCM nonce

        // Test data
        String testData = "This is test data for chunk encryption";
        byte[] data = testData.getBytes(StandardCharsets.UTF_8);

        // Encrypt chunk
        byte[] encrypted = protocol.encryptChunk(data, sessionKey, nonce.clone());

        // Decrypt chunk
        ByteBuffer buffer = ByteBuffer.wrap(encrypted);
        byte[] decrypted = protocol.decryptChunk(buffer, sessionKey, nonce.clone());

        // Verify
        assertNotNull(decrypted);
        assertArrayEquals(data, decrypted);
        assertEquals(testData, new String(decrypted, StandardCharsets.UTF_8));
    }

    @Test
    public void testMaxPayloadSize() {
        CipherKind v1Cipher = CipherKind.AES_256_GCM;
        CipherKind v2022Cipher = CipherKind.AEAD2022_BLAKE3_AES_256_GCM;

        AeadProtocol v1Protocol = new AeadProtocol(v1Cipher, new byte[32]);
        AeadProtocol v2022Protocol = new AeadProtocol(v2022Cipher, new byte[32]);

        assertEquals(AeadProtocol.MAX_PAYLOAD_SIZE_V1, v1Protocol.getMaxPayloadSize());
        assertEquals(AeadProtocol.MAX_PAYLOAD_SIZE_2022, v2022Protocol.getMaxPayloadSize());
    }

    @Test
    public void testLargePayloadChunking() throws Exception {
        CipherKind kind = CipherKind.CHACHA20_POLY1305;
        byte[] key = CipherFactory.deriveKey("password", kind);

        AeadProtocol protocol = new AeadProtocol(kind, key);

        byte[] salt = Salt.generate(kind.getSaltLen()).getValue();
        byte[] sessionKey = protocol.deriveSessionKey(salt);
        byte[] nonce = new byte[12];

        // Create payload at max size
        int maxSize = protocol.getMaxPayloadSize();
        byte[] largeData = new byte[maxSize];
        for (int i = 0; i < maxSize; i++) {
            largeData[i] = (byte)(i % 256);
        }

        // Should succeed
        byte[] encrypted = protocol.encryptChunk(largeData, sessionKey, nonce.clone());
        assertNotNull(encrypted);

        // Decrypt and verify
        ByteBuffer buffer = ByteBuffer.wrap(encrypted);
        byte[] decrypted = protocol.decryptChunk(buffer, sessionKey, nonce.clone());
        assertArrayEquals(largeData, decrypted);
    }

    @Test
    public void testPayloadTooLarge() {
        CipherKind kind = CipherKind.AES_128_GCM;
        byte[] key = new byte[16];
        AeadProtocol protocol = new AeadProtocol(kind, key);

        byte[] sessionKey = new byte[16];
        byte[] nonce = new byte[12];

        // Create oversized payload
        byte[] oversized = new byte[protocol.getMaxPayloadSize() + 1];

        assertThrows(IllegalArgumentException.class, () ->
            protocol.encryptChunk(oversized, sessionKey, nonce)
        );
    }

    @Test
    public void testSessionKeyDerivation() {
        CipherKind kind = CipherKind.AES_256_GCM;
        byte[] key = CipherFactory.deriveKey("test", kind);
        AeadProtocol protocol = new AeadProtocol(kind, key);

        byte[] salt1 = Salt.generate(kind.getSaltLen()).getValue();
        byte[] salt2 = Salt.generate(kind.getSaltLen()).getValue();

        byte[] sessionKey1 = protocol.deriveSessionKey(salt1);
        byte[] sessionKey2 = protocol.deriveSessionKey(salt2);

        // Different salts should produce different session keys
        assertFalse(java.util.Arrays.equals(sessionKey1, sessionKey2));

        // Same salt should produce same session key
        byte[] sessionKey1Again = protocol.deriveSessionKey(salt1);
        assertArrayEquals(sessionKey1, sessionKey1Again);
    }

    @Test
    public void testIncompleteChunkDecryption() throws Exception {
        CipherKind kind = CipherKind.AES_256_GCM;
        byte[] key = CipherFactory.deriveKey("password", kind);

        AeadProtocol protocol = new AeadProtocol(kind, key);

        byte[] salt = Salt.generate(kind.getSaltLen()).getValue();
        byte[] sessionKey = protocol.deriveSessionKey(salt);
        byte[] nonce = new byte[12];

        // Create incomplete buffer (only length, no payload)
        ByteBuffer incompleteBuffer = ByteBuffer.allocate(2);
        incompleteBuffer.putShort((short)100);
        incompleteBuffer.flip();

        // Should return null (need more data)
        byte[] result = protocol.decryptChunk(incompleteBuffer, sessionKey, nonce);
        assertNull(result);
    }
}