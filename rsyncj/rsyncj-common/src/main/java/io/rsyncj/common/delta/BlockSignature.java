package io.rsyncj.common.delta;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Signature of one block of an existing file: its index, the rolling (weak)
 * checksum and a truncated SHA-256 (strong) checksum.
 */
public record BlockSignature(int index, int weak, byte[] strong) {

    /** Strong checksums are truncated to 16 bytes: collision probability is negligible here. */
    public static final int STRONG_LENGTH = 16;

    public static byte[] strongHash(byte[] data, int off, int len) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(data, off, len);
            return Arrays.copyOf(md.digest(), STRONG_LENGTH);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
