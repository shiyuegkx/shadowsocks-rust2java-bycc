package io.github.shadowsocks.netty;

import io.github.shadowsocks.crypto.AeadCipher;
import io.github.shadowsocks.crypto.CipherFactory;
import io.github.shadowsocks.crypto.CipherKind;
import io.github.shadowsocks.crypto.CryptoException;
import io.github.shadowsocks.protocol.Address;
import io.github.shadowsocks.protocol.AeadProtocol;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

/**
 * Netty decoder for AEAD encrypted stream
 * Maps to shadowsocks-rust DecryptedReader
 */
public class AeadDecoder extends ByteToMessageDecoder {
    private static final Logger logger = LoggerFactory.getLogger(AeadDecoder.class);

    private final CipherKind cipherKind;
    private final byte[] key;
    private final boolean isServer;

    private DecryptState state = DecryptState.WAIT_SALT;
    private byte[] salt;
    private byte[] sessionKey;
    private byte[] nonce;
    private AeadCipher cipher;
    private Address address;
    private AeadProtocol protocol;

    // Buffer for incomplete chunks
    private ByteBuf accumulator;

    enum DecryptState {
        WAIT_SALT,
        WAIT_HEADER_LENGTH,
        WAIT_HEADER,
        STREAM_CHUNK_LENGTH,
        STREAM_CHUNK_DATA
    }

    public AeadDecoder(CipherKind cipherKind, byte[] key, boolean isServer) {
        this.cipherKind = cipherKind;
        this.key = Arrays.copyOf(key, key.length);
        this.isServer = isServer;
        this.protocol = new AeadProtocol(cipherKind, key);
        this.accumulator = Unpooled.buffer();
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) throws Exception {
        accumulator.writeBytes(in);

        while (accumulator.readableBytes() > 0) {
            int startReaderIndex = accumulator.readerIndex();

            try {
                boolean decoded = false;

                switch (state) {
                    case WAIT_SALT:
                        decoded = decodeSalt();
                        break;
                    case WAIT_HEADER_LENGTH:
                        decoded = decodeHeaderLength(out);
                        break;
                    case WAIT_HEADER:
                        decoded = decodeHeader(out);
                        break;
                    case STREAM_CHUNK_LENGTH:
                    case STREAM_CHUNK_DATA:
                        decoded = decodeChunk(out);
                        break;
                }

                if (!decoded) {
                    // Need more data
                    accumulator.readerIndex(startReaderIndex);
                    break;
                }

            } catch (CryptoException e) {
                logger.error("Decryption failed", e);
                accumulator.clear();
                ctx.close();
                throw e;
            }
        }

        // Compact buffer
        accumulator.discardReadBytes();
    }

    private boolean decodeSalt() {
        int saltLen = cipherKind.getSaltLen();
        if (accumulator.readableBytes() < saltLen) {
            return false;
        }

        salt = new byte[saltLen];
        accumulator.readBytes(salt);

        // Derive session key
        sessionKey = protocol.deriveSessionKey(salt);
        cipher = CipherFactory.create(cipherKind, sessionKey);

        // Initialize nonce
        nonce = new byte[cipher.getNonceLength()];

        state = DecryptState.WAIT_HEADER_LENGTH;
        logger.debug("Salt received, transitioning to header decryption");
        return true;
    }

    private boolean decodeHeaderLength(List<Object> out) throws CryptoException {
        int lenWithTag = 2 + cipher.getTagLength();
        if (accumulator.readableBytes() < lenWithTag) {
            return false;
        }

        // Read and decrypt header length
        byte[] encryptedLen = new byte[lenWithTag];
        accumulator.readBytes(encryptedLen);

        byte[] lenBytes = cipher.decrypt(Arrays.copyOf(nonce, nonce.length), encryptedLen, null);
        int headerLen = ByteBuffer.wrap(lenBytes).getShort() & 0xFFFF;

        // Store for next state
        accumulator.markReaderIndex();
        accumulator.writeShort(headerLen); // Write decrypted length for next state

        // Increment nonce
        AeadCipher.incrementNonce(nonce);

        state = DecryptState.WAIT_HEADER;
        return true;
    }

    private boolean decodeHeader(List<Object> out) throws CryptoException {
        // Read header length from previous state
        accumulator.resetReaderIndex();
        int headerLen = accumulator.readShort() & 0xFFFF;

        int headerWithTag = headerLen + cipher.getTagLength();
        if (accumulator.readableBytes() < headerWithTag) {
            accumulator.readerIndex(accumulator.readerIndex() - 2); // Restore length
            return false;
        }

        // Read and decrypt header
        byte[] encryptedHeader = new byte[headerWithTag];
        accumulator.readBytes(encryptedHeader);

        byte[] header = cipher.decrypt(Arrays.copyOf(nonce, nonce.length), encryptedHeader, null);

        // Decode address
        address = Address.decode(ByteBuffer.wrap(header));
        logger.debug("Decoded address: {}", address);

        // Increment nonce
        AeadCipher.incrementNonce(nonce);

        // Fire address event for connection establishment
        if (isServer) {
            out.add(new AddressMessage(address));
        }

        state = DecryptState.STREAM_CHUNK_LENGTH;
        return true;
    }

    private boolean decodeChunk(List<Object> out) throws CryptoException {
        int lenWithTag = 2 + cipher.getTagLength();

        if (state == DecryptState.STREAM_CHUNK_LENGTH) {
            if (accumulator.readableBytes() < lenWithTag) {
                return false;
            }

            // Read and decrypt chunk length
            byte[] encryptedLen = new byte[lenWithTag];
            accumulator.readBytes(encryptedLen);

            byte[] lenBytes = cipher.decrypt(Arrays.copyOf(nonce, nonce.length), encryptedLen, null);
            int chunkLen = ByteBuffer.wrap(lenBytes).getShort() & 0xFFFF;

            if (chunkLen == 0) {
                // Empty chunk, continue
                AeadCipher.incrementNonce(nonce);
                return true;
            }

            // Store chunk length for next state
            accumulator.markReaderIndex();
            accumulator.writeShort(chunkLen);

            // Increment nonce
            AeadCipher.incrementNonce(nonce);

            state = DecryptState.STREAM_CHUNK_DATA;
        }

        if (state == DecryptState.STREAM_CHUNK_DATA) {
            // Read chunk length from previous state
            accumulator.resetReaderIndex();
            int chunkLen = accumulator.readShort() & 0xFFFF;

            int chunkWithTag = chunkLen + cipher.getTagLength();
            if (accumulator.readableBytes() < chunkWithTag) {
                accumulator.readerIndex(accumulator.readerIndex() - 2); // Restore length
                state = DecryptState.STREAM_CHUNK_LENGTH;
                return false;
            }

            // Read and decrypt chunk data
            byte[] encryptedChunk = new byte[chunkWithTag];
            accumulator.readBytes(encryptedChunk);

            byte[] chunk = cipher.decrypt(Arrays.copyOf(nonce, nonce.length), encryptedChunk, null);

            // Output decrypted data
            out.add(Unpooled.wrappedBuffer(chunk));

            // Increment nonce
            AeadCipher.incrementNonce(nonce);

            state = DecryptState.STREAM_CHUNK_LENGTH;
        }

        return true;
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        if (accumulator != null) {
            accumulator.release();
            accumulator = null;
        }
        super.channelInactive(ctx);
    }

    /**
     * Message containing decoded address (for server side)
     */
    public static class AddressMessage {
        private final Address address;

        public AddressMessage(Address address) {
            this.address = address;
        }

        public Address getAddress() {
            return address;
        }
    }
}