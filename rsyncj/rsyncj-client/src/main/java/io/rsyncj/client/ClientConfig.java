package io.rsyncj.client;

import java.nio.file.Path;

/** Client connection settings. */
public record ClientConfig(
        String host,
        int port,
        String user,
        char[] password,
        boolean acceptNewHostKey,
        Path knownHosts,
        String pinnedFingerprint,
        int connectTimeoutMs,
        int readTimeoutMs) {

    public static Path defaultKnownHosts() {
        return Path.of(System.getProperty("user.home"), ".rsyncj", "known_hosts");
    }

    public static ClientConfig create(String host, int port, String user, char[] password) {
        return new ClientConfig(host, port, user, password, true, defaultKnownHosts(), null, 15_000, 300_000);
    }

    public ClientConfig withHostKeyPolicy(boolean acceptNew, Path knownHostsFile, String fingerprint) {
        return new ClientConfig(host, port, user, password, acceptNew, knownHostsFile, fingerprint,
                connectTimeoutMs, readTimeoutMs);
    }

    public ClientConfig withTimeouts(int connectMs, int readMs) {
        return new ClientConfig(host, port, user, password, acceptNewHostKey, knownHosts, pinnedFingerprint,
                connectMs, readMs);
    }
}
