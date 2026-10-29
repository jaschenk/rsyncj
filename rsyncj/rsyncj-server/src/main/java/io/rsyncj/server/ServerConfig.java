package io.rsyncj.server;

import java.nio.file.Path;

/** Immutable server configuration. */
public record ServerConfig(
        Path root,
        String bind,
        int port,
        int statsPort,
        boolean statsHttpEnabled,
        Path stateDir,
        Path keystore,
        char[] keystorePassword,
        Path usersFile,
        Path statsFile,
        Path tokenFile,
        long maxFileSize) {

    public static final long DEFAULT_MAX_FILE_SIZE = 8L * 1024 * 1024 * 1024; // 8 GiB

    public static ServerConfig defaults(Path root, Path stateDir) {
        return new ServerConfig(
                root.toAbsolutePath().normalize(),
                "0.0.0.0",
                8443,
                8444,
                true,
                stateDir.toAbsolutePath().normalize(),
                stateDir.resolve("keystore.p12").toAbsolutePath().normalize(),
                "changeit".toCharArray(),
                stateDir.resolve("users.json").toAbsolutePath().normalize(),
                stateDir.resolve("stats.json").toAbsolutePath().normalize(),
                stateDir.resolve("stats-token").toAbsolutePath().normalize(),
                DEFAULT_MAX_FILE_SIZE);
    }

    public ServerConfig withRoot(Path newRoot) {
        return new ServerConfig(newRoot.toAbsolutePath().normalize(), bind, port, statsPort, statsHttpEnabled,
                stateDir, keystore, keystorePassword, usersFile, statsFile, tokenFile, maxFileSize);
    }

    public ServerConfig withPorts(String newBind, int newPort, int newStatsPort, boolean httpEnabled) {
        return new ServerConfig(root, newBind, newPort, newStatsPort, httpEnabled,
                stateDir, keystore, keystorePassword, usersFile, statsFile, tokenFile, maxFileSize);
    }

    public ServerConfig withStateDir(Path newStateDir) {
        Path dir = newStateDir.toAbsolutePath().normalize();
        return new ServerConfig(root, bind, port, statsPort, statsHttpEnabled,
                dir, dir.resolve("keystore.p12"), keystorePassword,
                dir.resolve("users.json"), dir.resolve("stats.json"), dir.resolve("stats-token"),
                maxFileSize);
    }
}
