package io.rsyncj.client;

import java.nio.file.Path;

/** A request to synchronise a local file or directory to the server. */
public record SyncRequest(
        Path source,
        String remotePath,
        boolean delete,
        boolean dryRun,
        boolean verbose,
        ProgressListener listener) {

    public interface ProgressListener {
        void onFile(String remotePath, long size, long bytesReceived, long bytesReused, boolean skipped);

        ProgressListener NONE = (path, size, received, reused, skipped) -> {
        };
    }

    public SyncRequest {
        if (source == null) {
            throw new IllegalArgumentException("source is required");
        }
        if (remotePath == null || remotePath.isBlank()) {
            throw new IllegalArgumentException("remotePath is required");
        }
        if (listener == null) {
            listener = ProgressListener.NONE;
        }
    }

    public static SyncRequest of(Path source, String remotePath) {
        return new SyncRequest(source, remotePath, false, false, false, ProgressListener.NONE);
    }

    public SyncRequest withDelete(boolean value) {
        return new SyncRequest(source, remotePath, value, dryRun, verbose, listener);
    }

    public SyncRequest withDryRun(boolean value) {
        return new SyncRequest(source, remotePath, delete, value, verbose, listener);
    }

    public SyncRequest withVerbose(boolean value) {
        return new SyncRequest(source, remotePath, delete, dryRun, value, listener);
    }

    public SyncRequest withListener(ProgressListener value) {
        return new SyncRequest(source, remotePath, delete, dryRun, verbose, value);
    }
}
