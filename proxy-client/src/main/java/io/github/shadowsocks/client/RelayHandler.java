package io.github.shadowsocks.client;

import io.github.shadowsocks.crypto.CipherKind;
import io.github.shadowsocks.netty.AeadDecoder;
import io.github.shadowsocks.netty.AeadEncoder;
import io.github.shadowsocks.protocol.Address;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Relay handler that connects to shadowsocks server and forwards data
 * Maps to shadowsocks-rust local relay implementation
 */
public class RelayHandler extends ChannelInboundHandlerAdapter {
    private static final Logger logger = LoggerFactory.getLogger(RelayHandler.class);

    private final String serverHost;
    private final int serverPort;
    private final CipherKind cipherKind;
    private final byte[] key;
    private final Address targetAddress;

    private Channel serverChannel;
    private Channel clientChannel;

    public RelayHandler(String serverHost, int serverPort, CipherKind cipherKind, byte[] key, Address targetAddress) {
        this.serverHost = serverHost;
        this.serverPort = serverPort;
        this.cipherKind = cipherKind;
        this.key = key;
        this.targetAddress = targetAddress;
    }

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        clientChannel = ctx.channel();
        connectToServer(ctx);
    }

    private void connectToServer(ChannelHandlerContext ctx) {
        Bootstrap bootstrap = new Bootstrap();
        bootstrap.group(ctx.channel().eventLoop())
            .channel(NioSocketChannel.class)
            .option(ChannelOption.TCP_NODELAY, true)
            .option(ChannelOption.SO_KEEPALIVE, true)
            .handler(new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel ch) {
                    ChannelPipeline pipeline = ch.pipeline();

                    // Add AEAD encoder/decoder
                    pipeline.addLast(new AeadDecoder(cipherKind, key, false));
                    pipeline.addLast(new AeadEncoder(cipherKind, key, true));

                    // Add server relay handler
                    pipeline.addLast(new ServerRelayHandler(clientChannel));
                }
            });

        bootstrap.connect(serverHost, serverPort).addListener((ChannelFutureListener) future -> {
            if (future.isSuccess()) {
                serverChannel = future.channel();
                logger.debug("Connected to server {}:{}", serverHost, serverPort);

                // Send target address with first data if any
                serverChannel.writeAndFlush(new AeadEncoder.AddressedMessage(targetAddress));

                // Enable auto-read
                clientChannel.config().setAutoRead(true);
            } else {
                logger.error("Failed to connect to server", future.cause());
                ctx.close();
            }
        });
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (serverChannel != null && serverChannel.isActive()) {
            // Forward data to server
            serverChannel.writeAndFlush(msg).addListener((ChannelFutureListener) future -> {
                if (!future.isSuccess()) {
                    logger.error("Failed to write to server", future.cause());
                    ctx.close();
                }
            });
        } else {
            // Server not ready, buffer the data
            if (msg instanceof ByteBuf) {
                ((ByteBuf) msg).release();
            }
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        if (serverChannel != null && serverChannel.isActive()) {
            serverChannel.close();
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        logger.error("Relay handler error", cause);
        ctx.close();
        if (serverChannel != null) {
            serverChannel.close();
        }
    }

    /**
     * Handler for server->client relay
     */
    private static class ServerRelayHandler extends ChannelInboundHandlerAdapter {
        private final Channel clientChannel;

        public ServerRelayHandler(Channel clientChannel) {
            this.clientChannel = clientChannel;
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            if (clientChannel.isActive()) {
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
            logger.error("Server relay error", cause);
            ctx.close();
            clientChannel.close();
        }
    }
}