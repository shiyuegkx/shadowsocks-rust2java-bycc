package io.github.shadowsocks.crypto;

/**
 * Cipher types supported by Shadowsocks
 * Maps to shadowsocks-rust CipherKind enum
 */
public enum CipherKind {
    // AEAD Ciphers (v1)
    AES_128_GCM("aes-128-gcm", 16, 16, 12, 16),
    AES_256_GCM("aes-256-gcm", 32, 32, 12, 16),
    CHACHA20_POLY1305("chacha20-ietf-poly1305", 32, 32, 12, 16),

    // AEAD Ciphers (2022 edition)
    AEAD2022_BLAKE3_AES_128_GCM("2022-blake3-aes-128-gcm", 16, 16, 12, 16),
    AEAD2022_BLAKE3_AES_256_GCM("2022-blake3-aes-256-gcm", 32, 32, 12, 16),
    AEAD2022_BLAKE3_CHACHA20_POLY1305("2022-blake3-chacha20-poly1305", 32, 32, 12, 16);

    private final String name;
    private final int keyLen;
    private final int saltLen;
    private final int nonceLen;
    private final int tagLen;

    CipherKind(String name, int keyLen, int saltLen, int nonceLen, int tagLen) {
        this.name = name;
        this.keyLen = keyLen;
        this.saltLen = saltLen;
        this.nonceLen = nonceLen;
        this.tagLen = tagLen;
    }

    public String getName() {
        return name;
    }

    public int getKeyLen() {
        return keyLen;
    }

    public int getSaltLen() {
        return saltLen;
    }

    public int getNonceLen() {
        return nonceLen;
    }

    public int getTagLen() {
        return tagLen;
    }

    public boolean isAead2022() {
        return name.startsWith("2022-");
    }

    public static CipherKind fromName(String name) {
        for (CipherKind kind : values()) {
            if (kind.name.equalsIgnoreCase(name)) {
                return kind;
            }
        }
        throw new IllegalArgumentException("Unknown cipher: " + name);
    }
}