package io.rsyncj.common.util;

import java.util.HexFormat;

/** Hex helpers (lower-case, no separators). */
public final class Hex {

    private static final HexFormat HEX = HexFormat.of();

    private Hex() {
    }

    public static String encode(byte[] bytes) {
        return HEX.formatHex(bytes);
    }

    public static byte[] decode(String hex) {
        return HEX.parseHex(hex);
    }

    /** Formats a SHA-256 fingerprint as colon separated upper-case bytes (SSH style). */
    public static String colon(byte[] bytes) {
        String plain = HEX.formatHex(bytes).toUpperCase();
        StringBuilder sb = new StringBuilder(plain.length() + plain.length() / 2);
        for (int i = 0; i < plain.length(); i += 2) {
            if (i > 0) {
                sb.append(':');
            }
            sb.append(plain, i, i + 2);
        }
        return sb.toString();
    }
}
