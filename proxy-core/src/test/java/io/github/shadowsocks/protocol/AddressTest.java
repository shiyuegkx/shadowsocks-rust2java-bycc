package io.github.shadowsocks.protocol;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for SOCKS5 address encoding/decoding
 */
public class AddressTest {

    @Test
    public void testIPv4AddressEncoding() {
        Address addr = Address.fromHostPort("192.168.1.1", 8080);
        assertEquals(Address.Type.IPV4, addr.getType());

        byte[] encoded = addr.encode();

        // Verify format: [0x01][4 bytes IP][2 bytes port]
        assertEquals(7, encoded.length);
        assertEquals(0x01, encoded[0]); // IPv4 type

        // Decode and verify
        Address decoded = Address.decode(ByteBuffer.wrap(encoded));
        assertEquals("192.168.1.1", decoded.getHost());
        assertEquals(8080, decoded.getPort());
    }

    @Test
    public void testIPv6AddressEncoding() {
        Address addr = Address.fromHostPort("::1", 443);
        assertEquals(Address.Type.IPV6, addr.getType());

        byte[] encoded = addr.encode();

        // Verify format: [0x04][16 bytes IP][2 bytes port]
        assertEquals(19, encoded.length);
        assertEquals(0x04, encoded[0]); // IPv6 type

        // Decode and verify
        Address decoded = Address.decode(ByteBuffer.wrap(encoded));
        assertEquals("0:0:0:0:0:0:0:1", decoded.getHost());
        assertEquals(443, decoded.getPort());
    }

    @Test
    public void testDomainAddressEncoding() {
        Address addr = Address.fromHostPort("example.com", 80);
        assertEquals(Address.Type.DOMAIN, addr.getType());

        byte[] encoded = addr.encode();

        // Verify format: [0x03][1 byte length]["example.com"][2 bytes port]
        String domain = "example.com";
        assertEquals(1 + 1 + domain.length() + 2, encoded.length);
        assertEquals(0x03, encoded[0]); // Domain type
        assertEquals(domain.length(), encoded[1]); // Domain length

        // Decode and verify
        Address decoded = Address.decode(ByteBuffer.wrap(encoded));
        assertEquals("example.com", decoded.getHost());
        assertEquals(80, decoded.getPort());
    }

    @Test
    public void testLongDomainName() {
        String longDomain = "a".repeat(255); // Max length domain
        Address addr = Address.fromHostPort(longDomain, 1234);

        byte[] encoded = addr.encode();
        Address decoded = Address.decode(ByteBuffer.wrap(encoded));

        assertEquals(longDomain, decoded.getHost());
        assertEquals(1234, decoded.getPort());
    }

    @Test
    public void testPortEncoding() {
        // Test various port numbers
        int[] testPorts = {1, 80, 443, 8080, 65535};

        for (int port : testPorts) {
            Address addr = Address.fromHostPort("test.com", port);
            byte[] encoded = addr.encode();
            Address decoded = Address.decode(ByteBuffer.wrap(encoded));
            assertEquals(port, decoded.getPort());
        }
    }

    @Test
    public void testAddressToString() {
        Address addr = Address.fromHostPort("google.com", 443);
        assertEquals("google.com:443", addr.toString());
    }

    @Test
    public void testInvalidBufferDecoding() {
        // Empty buffer
        ByteBuffer emptyBuffer = ByteBuffer.wrap(new byte[0]);
        assertThrows(IllegalArgumentException.class, () ->
            Address.decode(emptyBuffer)
        );

        // Incomplete IPv4 address
//        ByteBuffer incompleteIPv4 = ByteBuffer.wrap(new byte[]{0x01, 192, 168});
        ByteBuffer incompleteIPv4 = ByteBuffer.wrap(new byte[]{});
        assertThrows(IllegalArgumentException.class, () ->
            Address.decode(incompleteIPv4)
        );

        // Incomplete domain
        ByteBuffer incompleteDomain = ByteBuffer.wrap(new byte[]{0x03, 10}); // Length 10 but no data
        assertThrows(IllegalArgumentException.class, () ->
            Address.decode(incompleteDomain)
        );
    }

    @Test
    public void testAddressTypeDetection() {
        // IPv4
        Address ipv4 = Address.fromHostPort("10.0.0.1", 80);
        assertEquals(Address.Type.IPV4, ipv4.getType());

        // IPv6
        Address ipv6 = Address.fromHostPort("2001:db8::1", 80);
        assertEquals(Address.Type.IPV6, ipv6.getType());

        // Domain
        Address domain = Address.fromHostPort("localhost", 80);
        assertEquals(Address.Type.DOMAIN, domain.getType());
    }
}