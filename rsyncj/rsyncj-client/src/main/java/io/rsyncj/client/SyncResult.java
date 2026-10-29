package io.rsyncj.client;

/** Aggregate outcome of one synchronisation. */
public record SyncResult(
        long files,
        long skipped,
        long bytesReceived,
        long bytesReused,
        long deleted,
        long durationMs,
        boolean dryRun) {

    /** Fraction of the new data that was served from blocks the server already had. */
    public double deltaEfficiency() {
        long total = bytesReceived + bytesReused;
        return total == 0 ? 0.0 : (double) bytesReused / total;
    }
}
