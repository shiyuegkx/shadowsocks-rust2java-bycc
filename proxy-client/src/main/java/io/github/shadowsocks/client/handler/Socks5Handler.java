package io.github.shadowsocks.client.handler;

import io.github.shadowsocks.client.RelayHandler;
import io.github.shadowsocks.crypto.CipherKind;
import io.github.shadowsocks.protocol.Address;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.socks.SocksAddressType;
import io.netty.handler.codec.socksx.SocksMessage;
import io.netty.handler.codec.socksx.v5.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;

/**
 * SOCKS5 protocol handler for local proxy
 * Maps to shadowsocks-rust local/socks/server_impl.rs
 */
public class Socks5Handler extends SimpleChannelInboundHandler<SocksMessage> {
    private static final Logger logger = LoggerFactory.getLogger(Socks5Handler.class);

    private final String serverHost;
    private final int serverPort;
    private final CipherKind cipherKind;
    private final byte[] key;

    public Socks5Handler(String serverHost, int serverPort, CipherKind cipherKind, byte[] key) {
        this.serverHost = serverHost;
        this.serverPort = serverPort;
        this.cipherKind = cipherKind;
        this.key = key;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, SocksMessage msg) throws Exception {
        if (msg instanceof Socks5InitialRequest) {
            // Send auth method selection (NO AUTH)
            ctx.writeAndFlush(new DefaultSocks5InitialResponse(Socks5AuthMethod.NO_AUTH));
        } else if (msg instanceof Socks5CommandRequest) {
            Socks5CommandRequest req = (Socks5CommandRequest) msg;

            if (req.type() == Socks5CommandType.CONNECT) {
                handleConnect(ctx, req);
            } else {
                // Unsupported command
                ctx.writeAndFlush(new DefaultSocks5CommandResponse(
                    Socks5CommandStatus.COMMAND_UNSUPPORTED,
                    req.dstAddrType(),
                    req.dstAddr(),
                    req.dstPort()
                )).addListener(ChannelFutureListener.CLOSE);
            }
        }
    }

    private void handleConnect(ChannelHandlerContext ctx, Socks5CommandRequest request) {
        String dstAddr = request.dstAddr();
        int dstPort = request.dstPort();

        logger.debug("SOCKS5 CONNECT to {}:{}", dstAddr, dstPort);

        // Create target address
        Address targetAddress = Address.fromHostPort(dstAddr, dstPort);

        // Send success response to client
        ctx.writeAndFlush(new DefaultSocks5CommandResponse(
            Socks5CommandStatus.SUCCESS,
            request.dstAddrType(),
            dstAddr,
            dstPort
        ));

        // Remove SOCKS handlers and add relay handler
        ctx.pipeline().remove(Socks5CommandRequestDecoder.class);
        ctx.pipeline().remove(this);

        // Add relay handler to forward data to shadowsocks server
        ctx.pipeline().addLast(new RelayHandler(
            serverHost,
            serverPort,
            cipherKind,
            key,
            targetAddress
        ));
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        logger.error("SOCKS5 handler error", cause);
        ctx.close();
    }
}