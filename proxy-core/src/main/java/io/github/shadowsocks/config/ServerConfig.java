package io.github.shadowsocks.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.github.shadowsocks.crypto.CipherFactory;
import io.github.shadowsocks.crypto.CipherKind;

/**
 * Server configuration
 * Maps to shadowsocks-rust ServerConfig
 */
public class ServerConfig {
    @JsonProperty("server")
    private String server;

    @JsonProperty("server_port")
    private int serverPort;

    @JsonProperty("local_address")
    private String localAddress = "127.0.0.1";

    @JsonProperty("local_port")
    private int localPort;

    @JsonProperty("password")
    private String password;

    @JsonProperty("method")
    private String method = "aes-256-gcm";

    @JsonProperty("timeout")
    private int timeout = 300; // seconds

    @JsonProperty("mode")
    private String mode; // "client" or "server"

    // Derived fields
    private CipherKind cipherKind;
    private byte[] key;

    public void initialize() {
        this.cipherKind = CipherKind.fromName(method);
        this.key = CipherFactory.deriveKey(password, cipherKind);
    }

    // Getters and setters
    public String getServer() {
        return server;
    }

    public void setServer(String server) {
        this.server = server;
    }

    public int getServerPort() {
        return serverPort;
    }

    public void setServerPort(int serverPort) {
        this.serverPort = serverPort;
    }

    public String getLocalAddress() {
        return localAddress;
    }

    public void setLocalAddress(String localAddress) {
        this.localAddress = localAddress;
    }

    public int getLocalPort() {
        return localPort;
    }

    public void setLocalPort(int localPort) {
        this.localPort = localPort;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public CipherKind getCipherKind() {
        return cipherKind;
    }

    public byte[] getKey() {
        return key;
    }
}