package io.github.shadowsocks.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.github.shadowsocks.client.handler.HttpProxyHandler;
import io.github.shadowsocks.client.handler.Socks5Handler;
import io.github.shadowsocks.config.ServerConfig;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.socksx.v5.Socks5CommandRequestDecoder;
import io.netty.handler.codec.socksx.v5.Socks5InitialRequestDecoder;
import io.netty.handler.codec.socksx.v5.Socks5ServerEncoder;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

/**
 * Shadowsocks client main entry point
 * Maps to shadowsocks-rust sslocal
 */
public class ShadowsocksClient {
    private static final Logger logger = LoggerFactory.getLogger(ShadowsocksClient.class);

    private final ServerConfig config;
    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;

    public ShadowsocksClient(ServerConfig config) {
        this.config = config;
        config.initialize();
    }

    public void start() throws InterruptedException {
        bossGroup = new NioEventLoopGroup(1);
        workerGroup = new NioEventLoopGroup();

        try {
            // Start SOCKS5 proxy
            startSocks5Proxy();

            // Start HTTP proxy on different port if configured
            if (config.getLocalPort() != 1080) {
                startHttpProxy();
            }

            logger.info("Shadowsocks client started");
            logger.info("SOCKS5 proxy listening on {}:1080", config.getLocalAddress());
            logger.info("HTTP proxy listening on {}:{}", config.getLocalAddress(), config.getLocalPort());

            // Wait until shutdown
            Thread.currentThread().join();
        } finally {
            shutdown();
        }
    }

    private void startSocks5Proxy() throws InterruptedException {
        ServerBootstrap bootstrap = new ServerBootstrap();
        bootstrap.group(bossGroup, workerGroup)
            .channel(NioServerSocketChannel.class)
            .option(ChannelOption.SO_BACKLOG, 128)
            .childOption(ChannelOption.SO_KEEPALIVE, true)
            .childOption(ChannelOption.TCP_NODELAY, true)
            .handler(new LoggingHandler(LogLevel.INFO))
            .childHandler(new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel ch) {
                    ChannelPipeline pipeline = ch.pipeline();

                    // SOCKS5 protocol handlers
                    pipeline.addLast(Socks5ServerEncoder.DEFAULT);
                    pipeline.addLast(new Socks5InitialRequestDecoder());
                    pipeline.addLast(new Socks5CommandRequestDecoder());
                    pipeline.addLast(new Socks5Handler(
                        config.getServer(),
                        config.getServerPort(),
                        config.getCipherKind(),
                        config.getKey()
                    ));
                }
            });

        ChannelFuture future = bootstrap.bind(config.getLocalAddress(), 1080).sync();
        if (!future.isSuccess()) {
            throw new RuntimeException("Failed to bind SOCKS5 port", future.cause());
        }
    }

    private void startHttpProxy() throws InterruptedException {
        ServerBootstrap bootstrap = new ServerBootstrap();
        bootstrap.group(bossGroup, workerGroup)
            .channel(NioServerSocketChannel.class)
            .option(ChannelOption.SO_BACKLOG, 128)
            .childOption(ChannelOption.SO_KEEPALIVE, true)
            .childOption(ChannelOption.TCP_NODELAY, true)
            .handler(new LoggingHandler(LogLevel.INFO))
            .childHandler(new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel ch) {
                    ChannelPipeline pipeline = ch.pipeline();

                    // HTTP protocol handlers
                    pipeline.addLast(new HttpServerCodec());
                    pipeline.addLast(new HttpObjectAggregator(1024 * 1024)); // 1MB max
                    pipeline.addLast(new HttpProxyHandler(
                        config.getServer(),
                        config.getServerPort(),
                        config.getCipherKind(),
                        config.getKey()
                    ));
                }
            });

        ChannelFuture future = bootstrap.bind(config.getLocalAddress(), config.getLocalPort()).sync();
        if (!future.isSuccess()) {
            throw new RuntimeException("Failed to bind HTTP port", future.cause());
        }
    }

    public void shutdown() {
        if (bossGroup != null) {
            bossGroup.shutdownGracefully();
        }
        if (workerGroup != null) {
            workerGroup.shutdownGracefully();
        }
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java -jar proxy-client.jar <config.yaml>");
            System.exit(1);
        }

        try {
            // Load configuration
            ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
            ServerConfig config = mapper.readValue(new File(args[0]), ServerConfig.class);
            config.setMode("client");

            // Start client
            ShadowsocksClient client = new ShadowsocksClient(config);
            client.start();
        } catch (Exception e) {
            logger.error("Failed to start client", e);
            System.exit(1);
        }
    }
}