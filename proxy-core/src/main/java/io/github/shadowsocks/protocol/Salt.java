package io.github.shadowsocks.protocol;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Salt generation and management
 * Maps to shadowsocks-rust Salt struct
 */
public class Salt {
    private static final SecureRandom RANDOM = new SecureRandom();

    private final byte[] value;

    public Salt(byte[] value) {
        this.value = Arrays.copyOf(value, value.length);
    }

    /**
     * Generate a new random salt
     */
    public static Salt generate(int length) {
        byte[] salt = new byte[length];
        RANDOM.nextBytes(salt);
        return new Salt(salt);
    }

    public byte[] getValue() {
        return Arrays.copyOf(value, value.length);
    }

    public int length() {
        return value.length;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        Salt salt = (Salt) obj;
        return Arrays.equals(value, salt.value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }
}