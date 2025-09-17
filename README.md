# Shadowsocks Java Implementation

A complete Java+Netty implementation of the Shadowsocks protocol, strictly following shadowsocks-rust v1.23.5 specifications.

## Overview

This project is a full rewrite of shadowsocks-rust in Java, providing both client (local proxy) and server (remote proxy) functionality with complete AEAD encryption support.

## Features

- **Full AEAD Protocol Support**: Implements Shadowsocks AEAD protocol with proper chunked encryption
- **Multiple Cipher Support**:
  - AES-128-GCM
  - AES-256-GCM
  - ChaCha20-Poly1305 (IETF variant)
- **Client Features**:
  - SOCKS5 proxy (port 1080)
  - HTTP/HTTPS proxy (configurable port)
  - CONNECT tunnel support for HTTPS
- **Server Features**:
  - Full AEAD stream decryption
  - Target connection forwarding
  - Bidirectional relay

## Architecture

```
relay-proxy-parent/
├── proxy-core/          # Core library: crypto, protocol, codecs
├── proxy-client/        # Local proxy implementation
└── proxy-server/        # Remote proxy implementation
```

## Building

Requirements:
- Java 17+
- Maven 3.6+

```bash
# Build all modules
mvn clean package

# This creates:
# - proxy-client/target/proxy-client-1.0.0-shaded.jar
# - proxy-server/target/proxy-server-1.0.0-shaded.jar
```

## Running

### Client (Local Proxy)

```bash
java -jar proxy-client/target/proxy-client-1.0.0-shaded.jar client.yaml
```

Client configuration (`client.yaml`):
```yaml
server: "your-server.com"
server_port: 8388
local_address: "127.0.0.1"
local_port: 8080              # HTTP proxy port
password: "your-password"
method: "aes-256-gcm"
timeout: 300
```

After starting:
- SOCKS5 proxy: `127.0.0.1:1080`
- HTTP proxy: `127.0.0.1:8080`

### Server (Remote Proxy)

```bash
java -jar proxy-server/target/proxy-server-1.0.0-shaded.jar server.yaml
```

Server configuration (`server.yaml`):
```yaml
server: "0.0.0.0"
server_port: 8388
password: "your-password"
method: "aes-256-gcm"
timeout: 300
```

## Testing

### Unit Tests

```bash
mvn test
```

### Integration Testing

Test with curl:
```bash
# HTTP through proxy
curl -x http://127.0.0.1:8080 http://httpbin.org/ip

# HTTPS through proxy
curl -x http://127.0.0.1:8080 https://httpbin.org/get

# SOCKS5 proxy
curl --socks5 127.0.0.1:1080 http://httpbin.org/ip
```

## Implementation Mapping

| Shadowsocks-Rust Module | Java Implementation |
|------------------------|-------------------|
| `shadowsocks-crypto` | `io.github.shadowsocks.crypto` |
| `crypto::v1::Cipher` | `AeadCipher` interface + implementations |
| `relay::socks5` | `io.github.shadowsocks.protocol.Address` |
| `relay::tcprelay::aead` | `io.github.shadowsocks.protocol.AeadProtocol` |
| `relay::tcprelay::crypto_io` | `io.github.shadowsocks.netty.Aead{Encoder,Decoder}` |
| `local::socks::server` | `io.github.shadowsocks.client.handler.Socks5Handler` |
| `local::http::server` | `io.github.shadowsocks.client.handler.HttpProxyHandler` |
| `server::tcprelay` | `io.github.shadowsocks.server.ServerHandler` |
| `config::ServerConfig` | `io.github.shadowsocks.config.ServerConfig` |

## Protocol Implementation Details

### AEAD Stream Format

Following SIP022/AEAD specification:

**Request Stream:**
```
[salt][encrypted_header_length][length_tag][encrypted_header][header_tag]
[encrypted_chunk_length][length_tag][encrypted_chunk][chunk_tag]...
```

- Salt: Random bytes for session key derivation
- Header: SOCKS5 address format (type + addr + port)
- Chunks: Data split into max 0x3FFF (v1) or 0xFFFF (2022) byte chunks
- Each encryption uses incrementing nonce

### Key Derivation

- Password → Key: EVP_BytesToKey with MD5 (matches OpenSSL/shadowsocks-rust)
- Session Key: HKDF-SHA256 with salt (for AEAD 2022)

### Nonce Management

- Start with zero nonce
- Increment after each encrypt/decrypt operation
- Separate nonce counters for header and data chunks

## Interoperability

This implementation is designed to be compatible with shadowsocks-rust v1.23.5. The AEAD protocol implementation strictly follows the specification to ensure:

- Java client ↔ Java server: ✅ Fully tested
- Java client ↔ Rust server: ✅ Compatible
- Rust client ↔ Java server: ✅ Compatible

## Performance Considerations

- Uses Netty's zero-copy ByteBuf for efficient data handling
- Connection pooling for server connections
- Chunked encryption/decryption to handle large streams
- Configurable timeout for idle connections

## Security Notes

- Always use strong passwords
- Recommended ciphers: AES-256-GCM or ChaCha20-Poly1305
- Salt is randomly generated for each connection
- Authentication tags prevent tampering

## Limitations

Current implementation focuses on TCP relay. UDP relay is not implemented.

## License

This implementation follows the same principles as shadowsocks-rust for educational and defensive security purposes.

## Contributing

Pull requests for bug fixes and improvements are welcome. Please ensure:
- All tests pass
- Code follows existing style
- Protocol compatibility is maintained