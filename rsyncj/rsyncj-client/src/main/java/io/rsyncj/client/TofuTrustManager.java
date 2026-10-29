package io.rsyncj.client;

import io.rsyncj.common.crypto.Scram;
import io.rsyncj.common.util.Hex;

import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Trust-on-first-use certificate pinning, modelled on OpenSSH's known_hosts.
 *
 * <p>The server uses a self-signed certificate, so instead of a CA chain the client pins
 * the SHA-256 fingerprint of the leaf certificate per {@code host:port}. A changed
 * fingerprint is a hard failure (possible MITM) unless the user explicitly pins the new
 * value with {@code --fingerprint}.</p>
 */
public final class TofuTrustManager implements X509TrustManager {

    private final String host;
    private final int port;
    private final Path knownHosts;
    private final boolean acceptNew;
    private final String pinnedFingerprint;

    public TofuTrustManager(ClientConfig config) {
        this.host = config.host();
        this.port = config.port();
        this.knownHosts = config.knownHosts();
        this.acceptNew = config.acceptNewHostKey();
        this.pinnedFingerprint = config.pinnedFingerprint();
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        throw new CertificateException("Client certificates are not used");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("Server presented no certificate");
        }
        String fingerprint;
        try {
            fingerprint = Hex.encode(Scram.sha256(chain[0].getEncoded()));
        } catch (Exception e) {
            throw new CertificateException("Could not hash server certificate", e);
        }

        if (pinnedFingerprint != null && !pinnedFingerprint.isBlank()) {
            if (!normalise(pinnedFingerprint).equalsIgnoreCase(fingerprint)) {
                throw new CertificateException("Server certificate does not match the pinned fingerprint\n"
                        + "  expected " + normalise(pinnedFingerprint) + "\n  actual   " + fingerprint);
            }
            return;
        }

        String key = host + ":" + port;
        String known = lookup(key);
        if (known != null) {
            if (!known.equalsIgnoreCase(fingerprint)) {
                throw new CertificateException("HOST KEY MISMATCH for " + key + "\n"
                        + "  known  " + known + "\n  actual " + fingerprint + "\n"
                        + "This could indicate a man-in-the-middle attack. If the server key really "
                        + "changed, remove the entry from " + knownHosts + " or pass --fingerprint.");
            }
            return;
        }

        if (!acceptNew) {
            throw new CertificateException("Unknown host key for " + key + "\n"
                    + "  fingerprint " + fingerprint + "\n"
                    + "Re-run with --accept-new to trust it, or pass --fingerprint " + fingerprint);
        }
        store(key, fingerprint);
        System.err.println("Warning: permanently added '" + key + "' (SHA-256 " + fingerprint + ") to " + knownHosts);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

    private String lookup(String key) throws CertificateException {
        if (!Files.exists(knownHosts)) {
            return null;
        }
        try {
            List<String> lines = Files.readAllLines(knownHosts, StandardCharsets.UTF_8);
            for (String line : lines) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                String[] parts = trimmed.split("\\s+");
                if (parts.length >= 2 && parts[0].equals(key)) {
                    return normalise(parts[1]);
                }
            }
            return null;
        } catch (IOException e) {
            throw new CertificateException("Could not read " + knownHosts, e);
        }
    }

    private void store(String key, String fingerprint) throws CertificateException {
        try {
            Path parent = knownHosts.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            String line = key + " " + fingerprint + "\n";
            Files.writeString(knownHosts, line, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new CertificateException("Could not update " + knownHosts, e);
        }
    }

    private static String normalise(String fingerprint) {
        return fingerprint.replace(":", "").replace(" ", "").toLowerCase();
    }
}
