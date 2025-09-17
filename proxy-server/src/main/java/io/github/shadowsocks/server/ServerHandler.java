package io.github.shadowsocks.server;

import io.github.shadowsocks.crypto.CipherKind;
import io.github.shadowsocks.netty.AeadDecoder;
import io.github.shadowsocks.netty.AeadEncoder;
import io.github.shadowsocks.protocol.Address;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.*;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Server handler that decrypts client data and forwards to target
 * Maps to shadowsocks-rust server/tcprelay.rs
 */
public class ServerHandler extends ChannelInboundHandlerAdapter {
    private static final Logger logger = LoggerFactory.getLogger(ServerHandler.class);

    private final CipherKind cipherKind;
    private final byte[] key;

    private Channel clientChannel;
    private Channel targetChannel;
    private Address targetAddress;
    private boolean headerReceived = false;

    public ServerHandler(CipherKind cipherKind, byte[] key) {
        this.cipherKind = cipherKind;
        this.key = key;
    }

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        clientChannel = ctx.channel();

        // Add AEAD decoder/encoder
        ctx.pipeline().addFirst("aead-decoder", new AeadDecoder(cipherKind, key, true));
        ctx.pipeline().addAfter("aead-decoder", "aead-encoder", new AeadEncoder(cipherKind, key, false));
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof AeadDecoder.AddressMessage) {
            // First message contains target address
            AeadDecoder.AddressMessage addrMsg = (AeadDecoder.AddressMessage) msg;
            targetAddress = addrMsg.getAddress();
            headerReceived = true;

            logger.info("Received target address: {}", targetAddress);
            connectToTarget(ctx);

        } else if (msg instanceof ByteBuf) {
            // Regular data to forward
            if (targetChannel != null && targetChannel.isActive()) {
                targetChannel.writeAndFlush(msg).addListener((ChannelFutureListener) future -> {
                    if (!future.isSuccess()) {
                        logger.error("Failed to write to target", future.cause());
                        ctx.close();
                    }
                });
            } else {
                // Target not ready, release buffer
                ((ByteBuf) msg).release();
            }
        }
    }

    private void connectToTarget(ChannelHandlerContext ctx) {
        Bootstrap bootstrap = new Bootstrap();
        bootstrap.group(ctx.channel().eventLoop())
            .channel(NioSocketChannel.class)
            .option(ChannelOption.TCP_NODELAY, true)
            .option(ChannelOption.SO_KEEPALIVE, true)
            .handler(new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel ch) {
                    ch.pipeline().addLast(new TargetRelayHandler(clientChannel));
                }
            });

        bootstrap.connect(targetAddress.getHost(), targetAddress.getPort())
            .addListener((ChannelFutureListener) future -> {
                if (future.isSuccess()) {
                    targetChannel = future.channel();
                    logger.debug("Connected to target {}:{}", targetAddress.getHost(), targetAddress.getPort());

                    // Send response header to client (empty for AEAD protocol)
                    // The encoder will handle the response format

                    // Enable auto-read
                    clientChannel.config().setAutoRead(true);
                } else {
                    logger.error("Failed to connect to target {}", targetAddress, future.cause());
                    ctx.close();
                }
            });
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        if (targetChannel != null && targetChannel.isActive()) {
            targetChannel.close();
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        logger.error("Server handler error", cause);
        ctx.close();
        if (targetChannel != null) {
            targetChannel.close();
        }
    }

    /**
     * Handler for target->client relay
     */
    private static class TargetRelayHandler extends ChannelInboundHandlerAdapter {
        private final Channel clientChannel;

        public TargetRelayHandler(Channel clientChannel) {
            this.clientChannel = clientChannel;
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            if (clientChannel.isActive()) {
                // Data from target, encrypt and send to client
                clientChannel.writeAndFlush(msg).addListener((ChannelFutureListener) future -> {
                    if (!future.isSuccess()) {
                        logger.error("Failed to write to client", future.cause());
                        ctx.close();
                    }
                });
            } else {
                if (msg instanceof ByteBuf) {
                    ((ByteBuf) msg).release();
                }
            }
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) {
            if (clientChannel.isActive()) {
                clientChannel.close();
            }
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            logger.error("Target relay error", cause);
            ctx.close();
            clientChannel.close();
        }
    }
}