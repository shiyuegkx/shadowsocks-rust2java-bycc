package io.github.shadowsocks.protocol;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * SOCKS5 Address format
 * Maps to shadowsocks-rust Address struct
 */
public class Address {
    public enum Type {
        IPV4(0x01),
        DOMAIN(0x03),
        IPV6(0x04);

        private final byte value;

        Type(int value) {
            this.value = (byte) value;
        }

        public byte getValue() {
            return value;
        }

        public static Type fromValue(byte value) {
            for (Type type : values()) {
                if (type.value == value) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Unknown address type: " + value);
        }
    }

    private final Type type;
    private final String host;
    private final int port;

    public Address(Type type, String host, int port) {
        this.type = type;
        this.host = host;
        this.port = port;
    }

    public static Address fromHostPort(String host, int port) {
        try {
            InetAddress addr = InetAddress.getByName(host);
            if (addr instanceof Inet4Address) {
                return new Address(Type.IPV4, host, port);
            } else if (addr instanceof Inet6Address) {
                return new Address(Type.IPV6, host, port);
            }
        } catch (UnknownHostException e) {
            // It's a domain name
        }
        return new Address(Type.DOMAIN, host, port);
    }

    /**
     * Encode address to SOCKS5 format
     * Format: [ATYP][ADDR][PORT]
     */
    public byte[] encode() {
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        buffer.put(type.getValue());

        switch (type) {
            case IPV4:
                try {
                    byte[] addr = InetAddress.getByName(host).getAddress();
                    buffer.put(addr);
                } catch (UnknownHostException e) {
                    throw new RuntimeException("Invalid IPv4 address: " + host, e);
                }
                break;

            case IPV6:
                try {
                    byte[] addr = InetAddress.getByName(host).getAddress();
                    buffer.put(addr);
                } catch (UnknownHostException e) {
                    throw new RuntimeException("Invalid IPv6 address: " + host, e);
                }
                break;

            case DOMAIN:
                byte[] domainBytes = host.getBytes(StandardCharsets.UTF_8);
                if (domainBytes.length > 255) {
                    throw new IllegalArgumentException("Domain name too long: " + host);
                }
                buffer.put((byte) domainBytes.length);
                buffer.put(domainBytes);
                break;
        }

        // Port (big-endian)
        buffer.putShort((short) port);

        buffer.flip();
        byte[] result = new byte[buffer.remaining()];
        buffer.get(result);
        return result;
    }

    /**
     * Decode address from SOCKS5 format
     */
    public static Address decode(ByteBuffer buffer) {
        if (buffer.remaining() < 1) {
            throw new IllegalArgumentException("Buffer too short for address type");
        }

        Type type = Type.fromValue(buffer.get());
        String host;

        switch (type) {
            case IPV4:
                if (buffer.remaining() < 4) {
                    throw new IllegalArgumentException("Buffer too short for IPv4 address");
                }
                byte[] ipv4 = new byte[4];
                buffer.get(ipv4);
                try {
                    host = InetAddress.getByAddress(ipv4).getHostAddress();
                } catch (UnknownHostException e) {
                    throw new RuntimeException("Invalid IPv4 address", e);
                }
                break;

            case IPV6:
                if (buffer.remaining() < 16) {
                    throw new IllegalArgumentException("Buffer too short for IPv6 address");
                }
                byte[] ipv6 = new byte[16];
                buffer.get(ipv6);
                try {
                    host = InetAddress.getByAddress(ipv6).getHostAddress();
                } catch (UnknownHostException e) {
                    throw new RuntimeException("Invalid IPv6 address", e);
                }
                break;

            case DOMAIN:
                if (buffer.remaining() < 1) {
                    throw new IllegalArgumentException("Buffer too short for domain length");
                }
                int domainLen = buffer.get() & 0xFF;
                if (buffer.remaining() < domainLen) {
                    throw new IllegalArgumentException("Buffer too short for domain");
                }
                byte[] domainBytes = new byte[domainLen];
                buffer.get(domainBytes);
                host = new String(domainBytes, StandardCharsets.UTF_8);
                break;

            default:
                throw new IllegalArgumentException("Unknown address type: " + type);
        }

        if (buffer.remaining() < 2) {
            throw new IllegalArgumentException("Buffer too short for port");
        }
        int port = buffer.getShort() & 0xFFFF;

        return new Address(type, host, port);
    }

    public Type getType() {
        return type;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    @Override
    public String toString() {
        return host + ":" + port;
    }
}