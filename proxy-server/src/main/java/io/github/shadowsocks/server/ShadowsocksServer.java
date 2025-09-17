package io.github.shadowsocks.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.github.shadowsocks.config.ServerConfig;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.timeout.IdleStateHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.concurrent.TimeUnit;

/**
 * Shadowsocks server main entry point
 * Maps to shadowsocks-rust ssserver
 */
public class ShadowsocksServer {
    private static final Logger logger = LoggerFactory.getLogger(ShadowsocksServer.class);

    private final ServerConfig config;
    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;

    public ShadowsocksServer(ServerConfig config) {
        this.config = config;
        config.initialize();
    }

    public void start() throws InterruptedException {
        bossGroup = new NioEventLoopGroup(1);
        workerGroup = new NioEventLoopGroup();

        try {
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

                        // Add idle handler for timeout
                        pipeline.addLast(new IdleStateHandler(
                            config.getTimeout(),
                            config.getTimeout(),
                            0,
                            TimeUnit.SECONDS
                        ));

                        // Add server handler
                        pipeline.addLast(new ServerHandler(
                            config.getCipherKind(),
                            config.getKey()
                        ));
                    }
                });

            String bindAddr = config.getServer() != null ? config.getServer() : "0.0.0.0";
            ChannelFuture future = bootstrap.bind(bindAddr, config.getServerPort()).sync();

            if (future.isSuccess()) {
                logger.info("Shadowsocks server started on {}:{}", bindAddr, config.getServerPort());
                logger.info("Using cipher: {}", config.getMethod());

                // Wait until shutdown
                future.channel().closeFuture().sync();
            } else {
                throw new RuntimeException("Failed to bind server port", future.cause());
            }
        } finally {
            shutdown();
        }
    }

    public void shutdown() {
        if (bossGroup != null) {
            bossGroup.shutdownGracefully();
        }
        if (workerGroup != null) {
            workerGroup.shutdownGracefully();
        }
        logger.info("Shadowsocks server shutdown");
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java -jar proxy-server.jar <config.yaml>");
            System.exit(1);
        }

        try {
            // Load configuration
            ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
            ServerConfig config = mapper.readValue(new File(args[0]), ServerConfig.class);
            config.setMode("server");

            // Start server
            ShadowsocksServer server = new ShadowsocksServer(config);

            // Add shutdown hook
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                logger.info("Shutting down server...");
                server.shutdown();
            }));

            server.start();
        } catch (Exception e) {
            logger.error("Failed to start server", e);
            System.exit(1);
        }
    }
}