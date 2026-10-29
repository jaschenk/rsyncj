package io.rsyncj.common.crypto;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * SCRAM-SHA-256 style mutual authentication.
 *
 * <p>The server never stores the user's password, only a salted PBKDF2-derived
 * {@code StoredKey}. The client proves knowledge of the password with an HMAC over a
 * client/server nonce pair, and the server proves it knows the derived key back, so both
 * directions are authenticated. Combined with TLS this prevents credential replay and
 * server impersonation.</p>
 */
public final class Scram {

    public static final String VERSION = "rsyncj-auth-v1";
    public static final int DEFAULT_ITERATIONS = 210_000;
    public static final int KEY_BITS = 256;

    private static final SecureRandom RANDOM = new SecureRandom();

    private Scram() {
    }

    /**
     * What the server persists per user. Neither value allows impersonating the user:
     * {@code storedKey} verifies the client proof and {@code serverKey} signs the server
     * proof. The password itself is never stored.
     */
    public record UserEntry(byte[] salt, int iterations, byte[] storedKey, byte[] serverKey) {
    }

    public static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    public static String randomToken(int length) {
        return Base64.getEncoder().encodeToString(randomBytes(length));
    }

    public static UserEntry newUser(char[] password) {
        byte[] salt = randomBytes(16);
        byte[] salted = saltedPassword(password, salt, DEFAULT_ITERATIONS);
        return new UserEntry(salt, DEFAULT_ITERATIONS, storedKey(clientKey(salted)), serverKey(salted));
    }

    public static byte[] saltedPassword(char[] password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PBKDF2 unavailable", e);
        } finally {
            spec.clearPassword();
        }
    }

    public static byte[] clientKey(byte[] saltedPassword) {
        return hmac(saltedPassword, "Client Key".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    public static byte[] storedKey(byte[] clientKey) {
        return sha256(clientKey);
    }

    public static byte[] serverKey(byte[] saltedPassword) {
        return hmac(saltedPassword, "Server Key".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    public static byte[] proof(byte[] storedKey, String authMessage) {
        return hmac(storedKey, authMessage.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    public static byte[] serverSignature(byte[] serverKey, String authMessage) {
        return hmac(serverKey, authMessage.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    public static String authMessage(String user, String clientNonceB64, String serverNonceB64) {
        return VERSION + "," + user + "," + clientNonceB64 + "," + serverNonceB64;
    }

    public static byte[] hmac(byte[] key, byte[] message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(message);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC unavailable", e);
        }
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }
}
