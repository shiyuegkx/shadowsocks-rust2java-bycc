package io.github.shadowsocks.client.handler;

import io.github.shadowsocks.client.RelayHandler;
import io.github.shadowsocks.crypto.CipherKind;
import io.github.shadowsocks.protocol.Address;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.nio.charset.StandardCharsets;

/**
 * HTTP/HTTPS proxy handler for local proxy
 * Maps to shadowsocks-rust local/http/server.rs
 */
public class HttpProxyHandler extends SimpleChannelInboundHandler<HttpObject> {
    private static final Logger logger = LoggerFactory.getLogger(HttpProxyHandler.class);

    private final String serverHost;
    private final int serverPort;
    private final CipherKind cipherKind;
    private final byte[] key;

    private boolean isConnect = false;
    private Address targetAddress;

    public HttpProxyHandler(String serverHost, int serverPort, CipherKind cipherKind, byte[] key) {
        this.serverHost = serverHost;
        this.serverPort = serverPort;
        this.cipherKind = cipherKind;
        this.key = key;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, HttpObject msg) throws Exception {
        if (msg instanceof HttpRequest) {
            HttpRequest request = (HttpRequest) msg;

            if (request.method() == HttpMethod.CONNECT) {
                handleConnect(ctx, request);
            } else {
                handleHttpRequest(ctx, request);
            }
        }
    }

    private void handleConnect(ChannelHandlerContext ctx, HttpRequest request) {
        // CONNECT method for HTTPS tunneling
        String hostHeader = request.uri();
        String[] parts = hostHeader.split(":");
        String host = parts[0];
        int port = parts.length > 1 ? Integer.parseInt(parts[1]) : 443;

        logger.debug("HTTP CONNECT to {}:{}", host, port);

        targetAddress = Address.fromHostPort(host, port);
        isConnect = true;

        // Send 200 Connection Established
        String response = "HTTP/1.1 200 Connection Established\r\n\r\n";
        ByteBuf responseBuf = Unpooled.copiedBuffer(response, StandardCharsets.UTF_8);
        ctx.writeAndFlush(responseBuf).addListener((ChannelFutureListener) future -> {
            if (future.isSuccess()) {
                // Remove HTTP codec and add relay handler
                ctx.pipeline().remove(HttpServerCodec.class);
                ctx.pipeline().remove(HttpObjectAggregator.class);
                ctx.pipeline().remove(this);

                // Add relay handler
                ctx.pipeline().addLast(new RelayHandler(
                    serverHost,
                    serverPort,
                    cipherKind,
                    key,
                    targetAddress
                ));
            }
        });
    }

    private void handleHttpRequest(ChannelHandlerContext ctx, HttpRequest request) throws Exception {
        // Regular HTTP request
        URI uri = new URI(request.uri());

        String host;
        int port;

        if (uri.getHost() != null) {
            // Absolute URI
            host = uri.getHost();
            port = uri.getPort() != -1 ? uri.getPort() : 80;
        } else {
            // Relative URI, get host from Host header
            String hostHeader = request.headers().get(HttpHeaderNames.HOST);
            if (hostHeader == null) {
                sendError(ctx, HttpResponseStatus.BAD_REQUEST);
                return;
            }

            String[] parts = hostHeader.split(":");
            host = parts[0];
            port = parts.length > 1 ? Integer.parseInt(parts[1]) : 80;
        }

        logger.debug("HTTP request to {}:{}", host, port);

        targetAddress = Address.fromHostPort(host, port);

        // Convert request to raw bytes
        ByteBuf requestBuf = encodeHttpRequest(request);

        // Remove HTTP handlers
        ctx.pipeline().remove(HttpServerCodec.class);
        ctx.pipeline().remove(HttpObjectAggregator.class);
        ctx.pipeline().remove(this);

        // Add relay handler with initial data
        RelayHandler relayHandler = new RelayHandler(
            serverHost,
            serverPort,
            cipherKind,
            key,
            targetAddress
        );
        ctx.pipeline().addLast(relayHandler);

        // Send the HTTP request through the relay
        ctx.fireChannelRead(requestBuf);
    }

    private ByteBuf encodeHttpRequest(HttpRequest request) {
        StringBuilder sb = new StringBuilder();

        // Request line
        sb.append(request.method()).append(" ");
        sb.append(request.uri()).append(" ");
        sb.append(request.protocolVersion()).append("\r\n");

        // Headers
        for (String name : request.headers().names()) {
            for (String value : request.headers().getAll(name)) {
                sb.append(name).append(": ").append(value).append("\r\n");
            }
        }

        sb.append("\r\n");

        return Unpooled.copiedBuffer(sb.toString(), StandardCharsets.UTF_8);
    }

    private void sendError(ChannelHandlerContext ctx, HttpResponseStatus status) {
        FullHttpResponse response = new DefaultFullHttpResponse(
            HttpVersion.HTTP_1_1,
            status,
            Unpooled.copiedBuffer(status.toString(), StandardCharsets.UTF_8)
        );
        response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=UTF-8");
        response.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, response.content().readableBytes());

        ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        logger.error("HTTP proxy handler error", cause);
        ctx.close();
    }
}