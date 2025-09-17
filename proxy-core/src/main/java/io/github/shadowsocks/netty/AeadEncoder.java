package io.github.shadowsocks.netty;

import io.github.shadowsocks.crypto.AeadCipher;
import io.github.shadowsocks.crypto.CipherFactory;
import io.github.shadowsocks.crypto.CipherKind;
import io.github.shadowsocks.protocol.Address;
import io.github.shadowsocks.protocol.AeadProtocol;
import io.github.shadowsocks.protocol.Salt;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * Netty encoder for AEAD encrypted stream
 * Maps to shadowsocks-rust EncryptedWriter
 */
public class AeadEncoder extends MessageToByteEncoder<Object> {
    private static final Logger logger = LoggerFactory.getLogger(AeadEncoder.class);

    private final CipherKind cipherKind;
    private final byte[] key;
    private final boolean isClient;

    private boolean headerSent = false;
    private byte[] salt;
    private byte[] sessionKey;
    private byte[] nonce;
    private AeadCipher cipher;
    private AeadProtocol protocol;

    public AeadEncoder(CipherKind cipherKind, byte[] key, boolean isClient) {
        this.cipherKind = cipherKind;
        this.key = Arrays.copyOf(key, key.length);
        this.isClient = isClient;
        this.protocol = new AeadProtocol(cipherKind, key);
    }

    @Override
    protected void encode(ChannelHandlerContext ctx, Object msg, ByteBuf out) throws Exception {
        if (!headerSent) {
            // First message should contain address (for client) or just init (for server)
            if (isClient && msg instanceof AddressedMessage) {
                AddressedMessage addrMsg = (AddressedMessage) msg;
                encodeHeader(addrMsg.getAddress(), out);
                if (addrMsg.getData() != null) {
                    encodeData(addrMsg.getData(), out);
                    addrMsg.getData().release();
                }
            } else if (!isClient && msg instanceof ByteBuf) {
                // Server side: initialize encryption on first data
                initializeEncryption();
                encodeData((ByteBuf) msg, out);
                ((ByteBuf) msg).release();
            }
            headerSent = true;
        } else if (msg instanceof ByteBuf) {
            // Regular data chunk
            encodeData((ByteBuf) msg, out);
            ((ByteBuf) msg).release();
        }
    }

    private void encodeHeader(Address address, ByteBuf out) throws Exception {
        // Generate salt
        salt = Salt.generate(cipherKind.getSaltLen()).getValue();
        out.writeBytes(salt);

        // Derive session key
        sessionKey = protocol.deriveSessionKey(salt);
        cipher = CipherFactory.create(cipherKind, sessionKey);

        // Initialize nonce
        nonce = new byte[cipher.getNonceLength()];

        // Encode address
        byte[] header = address.encode();

        // Encrypt header length
        ByteBuffer lenBuffer = ByteBuffer.allocate(2);
        lenBuffer.order(ByteOrder.BIG_ENDIAN);
        lenBuffer.putShort((short) header.length);
        byte[] encryptedLen = cipher.encrypt(Arrays.copyOf(nonce, nonce.length), lenBuffer.array(), null);
        out.writeBytes(encryptedLen);

        // Increment nonce
        AeadCipher.incrementNonce(nonce);

        // Encrypt header
        byte[] encryptedHeader = cipher.encrypt(Arrays.copyOf(nonce, nonce.length), header, null);
        out.writeBytes(encryptedHeader);

        // Increment nonce for data chunks
        AeadCipher.incrementNonce(nonce);

        logger.debug("Header encoded for address: {}", address);
    }

    private void initializeEncryption() {
        if (salt == null) {
            // Server side: use received salt (should be set by decoder)
            // For now, generate one (in real impl, this would come from client)
            salt = Salt.generate(cipherKind.getSaltLen()).getValue();
            sessionKey = protocol.deriveSessionKey(salt);
            cipher = CipherFactory.create(cipherKind, sessionKey);
            nonce = new byte[cipher.getNonceLength()];
        }
    }

    private void encodeData(ByteBuf data, ByteBuf out) throws Exception {
        int maxPayloadSize = protocol.getMaxPayloadSize();

        while (data.readableBytes() > 0) {
            int chunkSize = Math.min(data.readableBytes(), maxPayloadSize);
            byte[] chunk = new byte[chunkSize];
            data.readBytes(chunk);

            // Encrypt chunk length
            ByteBuffer lenBuffer = ByteBuffer.allocate(2);
            lenBuffer.order(ByteOrder.BIG_ENDIAN);
            lenBuffer.putShort((short) chunkSize);
            byte[] encryptedLen = cipher.encrypt(Arrays.copyOf(nonce, nonce.length), lenBuffer.array(), null);
            out.writeBytes(encryptedLen);

            // Increment nonce
            AeadCipher.incrementNonce(nonce);

            // Encrypt chunk data
            byte[] encryptedChunk = cipher.encrypt(Arrays.copyOf(nonce, nonce.length), chunk, null);
            out.writeBytes(encryptedChunk);

            // Increment nonce for next chunk
            AeadCipher.incrementNonce(nonce);
        }
    }

    /**
     * Set salt for server-side encoder (from decoder)
     */
    public void setSalt(byte[] salt) {
        this.salt = Arrays.copyOf(salt, salt.length);
        this.sessionKey = protocol.deriveSessionKey(salt);
        this.cipher = CipherFactory.create(cipherKind, sessionKey);
        this.nonce = new byte[cipher.getNonceLength()];
    }

    /**
     * Message containing address and optional initial data (for client side)
     */
    public static class AddressedMessage {
        private final Address address;
        private final ByteBuf data;

        public AddressedMessage(Address address) {
            this(address, null);
        }

        public AddressedMessage(Address address, ByteBuf data) {
            this.address = address;
            this.data = data;
        }

        public Address getAddress() {
            return address;
        }

        public ByteBuf getData() {
            return data;
        }
    }
}