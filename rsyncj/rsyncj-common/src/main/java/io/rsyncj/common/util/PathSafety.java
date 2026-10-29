package io.rsyncj.common.util;

import io.rsyncj.common.protocol.ProtocolException;

import java.nio.file.Path;

/**
 * Confines every remote path to the server's configured root.
 *
 * <p>Remote paths are always interpreted relative to the root, even if they start with
 * {@code /} (so {@code /projects/app} maps to {@code <root>/projects/app}). Any path that
 * escapes the root, contains {@code ..}, or uses NUL bytes is rejected.</p>
 */
public final class PathSafety {

    private PathSafety() {
    }

    public static Path resolve(Path root, String remotePath) {
        if (remotePath == null || remotePath.isBlank()) {
            throw new ProtocolException("Empty remote path");
        }
        if (remotePath.indexOf('\0') >= 0) {
            throw new ProtocolException("Illegal character in remote path");
        }
        String normalised = remotePath.replace('\\', '/');
        while (normalised.startsWith("/")) {
            normalised = normalised.substring(1);
        }
        if (normalised.isEmpty()) {
            throw new ProtocolException("Remote path must not be the root itself");
        }
        for (String segment : normalised.split("/")) {
            if (segment.equals("..")) {
                throw new ProtocolException("Path traversal rejected: " + remotePath);
            }
        }
        Path base = root.toAbsolutePath().normalize();
        Path resolved = base.resolve(normalised).normalize();
        if (!resolved.startsWith(base)) {
            throw new ProtocolException("Path escapes server root: " + remotePath);
        }
        return resolved;
    }

    /** Converts a path inside the root back to a '/'-separated relative path. */
    public static String relativise(Path root, Path path) {
        Path base = root.toAbsolutePath().normalize();
        Path normalised = path.toAbsolutePath().normalize();
        if (!normalised.startsWith(base)) {
            throw new ProtocolException("Path escapes server root: " + path);
        }
        return base.relativize(normalised).toString().replace('\\', '/');
    }
}
