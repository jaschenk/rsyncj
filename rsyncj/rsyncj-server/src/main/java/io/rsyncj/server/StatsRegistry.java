package io.rsyncj.server;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.rsyncj.common.Version;
import io.rsyncj.common.json.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * In-memory counters with periodic JSON persistence. All values exposed through
 * {@link #snapshot()} are read atomically enough for monitoring purposes.
 */
public final class StatsRegistry {

    public record FileStat(String path, long size, long mtime, Instant lastSyncAt,
                           String sha256, long bytesReceived, long bytesReused, long durationMs) {
    }

    private final Instant startedAt = Instant.now();
    private final Path statsFile;
    private final String root;
    private final String bind;
    private final int port;

    private final AtomicLong sessionsTotal = new AtomicLong();
    private final AtomicLong sessionsActive = new AtomicLong();
    private final AtomicLong authFailures = new AtomicLong();
    private final AtomicLong syncsTotal = new AtomicLong();
    private final AtomicLong filesSynced = new AtomicLong();
    private final AtomicLong filesSkipped = new AtomicLong();
    private final AtomicLong bytesReceived = new AtomicLong();
    private final AtomicLong bytesReused = new AtomicLong();
    private final AtomicLong bytesSent = new AtomicLong();
    private final AtomicLong errors = new AtomicLong();
    private final AtomicLong filesDeleted = new AtomicLong();
    private volatile Instant lastSyncAt;

    private final Map<String, FileStat> files = new ConcurrentHashMap<>();

    public StatsRegistry(Path statsFile, String root, String bind, int port) {
        this.statsFile = statsFile;
        this.root = root;
        this.bind = bind;
        this.port = port;
    }

    public void sessionOpened() {
        sessionsTotal.incrementAndGet();
        sessionsActive.incrementAndGet();
    }

    public void sessionClosed() {
        sessionsActive.decrementAndGet();
    }

    public void authFailed() {
        authFailures.incrementAndGet();
    }

    public void error() {
        errors.incrementAndGet();
    }

    public void syncStarted() {
        syncsTotal.incrementAndGet();
    }

    public void syncFinished() {
        lastSyncAt = Instant.now();
    }

    public void outbound(long bytes) {
        bytesSent.addAndGet(bytes);
    }

    public void fileSynced(FileStat stat, boolean skipped) {
        files.put(stat.path(), stat);
        if (skipped) {
            filesSkipped.incrementAndGet();
        } else {
            filesSynced.incrementAndGet();
        }
        bytesReceived.addAndGet(stat.bytesReceived());
        bytesReused.addAndGet(stat.bytesReused());
    }

    public void filesDeleted(long count) {
        filesDeleted.addAndGet(count);
    }

    public void removeFile(String path) {
        files.remove(path);
    }

    public ObjectNode snapshot() {
        ObjectNode rootNode = Json.MAPPER.createObjectNode();
        ObjectNode server = rootNode.putObject("server");
        server.put("product", Version.PRODUCT);
        server.put("protocol", Version.PROTOCOL);
        server.put("root", root);
        server.put("bind", bind);
        server.put("port", port);
        server.put("startedAt", startedAt.toString());
        server.put("generatedAt", Instant.now().toString());
        server.put("uptimeSeconds", Duration.between(startedAt, Instant.now()).toSeconds());

        ObjectNode sessions = rootNode.putObject("sessions");
        sessions.put("total", sessionsTotal.get());
        sessions.put("active", sessionsActive.get());
        sessions.put("authFailures", authFailures.get());

        long received = bytesReceived.get();
        long reused = bytesReused.get();
        long total = received + reused;
        ObjectNode syncs = rootNode.putObject("syncs");
        syncs.put("total", syncsTotal.get());
        syncs.put("filesSynced", filesSynced.get());
        syncs.put("filesSkipped", filesSkipped.get());
        syncs.put("filesDeleted", filesDeleted.get());
        syncs.put("bytesReceived", received);
        syncs.put("bytesReused", reused);
        syncs.put("bytesSent", bytesSent.get());
        syncs.put("deltaEfficiency", total == 0 ? 0.0 : Math.round((reused * 10000.0) / total) / 10000.0);
        syncs.put("errors", errors.get());
        if (lastSyncAt != null) {
            syncs.put("lastSyncAt", lastSyncAt.toString());
        } else {
            syncs.putNull("lastSyncAt");
        }

        ObjectNode storage = rootNode.putObject("storage");
        storage.put("files", files.size());
        storage.put("bytes", files.values().stream().mapToLong(FileStat::size).sum());

        List<FileStat> sorted = new ArrayList<>(files.values());
        sorted.sort(Comparator.comparing(FileStat::path));
        ArrayNode filesNode = rootNode.putArray("files");
        for (FileStat stat : sorted) {
            ObjectNode node = filesNode.addObject();
            node.put("path", stat.path());
            node.put("size", stat.size());
            node.put("mtime", Instant.ofEpochMilli(stat.mtime()).toString());
            node.put("lastSyncAt", stat.lastSyncAt().toString());
            node.put("sha256", stat.sha256());
            node.put("bytesReceived", stat.bytesReceived());
            node.put("bytesReused", stat.bytesReused());
            node.put("durationMs", stat.durationMs());
        }
        return rootNode;
    }

    public synchronized void persist() {
        try {
            ObjectNode rootNode = snapshot();
            Path parent = statsFile.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Path temp = Files.createTempFile(parent, ".stats-", ".tmp");
            Files.write(temp, Json.MAPPER.writerWithDefaultPrettyPrinter().writeValueAsBytes(rootNode));
            Files.move(temp, statsFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            System.getLogger("rsyncj").log(System.Logger.Level.WARNING, "Could not persist stats: " + e.getMessage());
        }
    }

    /** Restores cumulative counters and per-file data from a previous run. */
    public void restore() {
        if (!Files.exists(statsFile)) {
            return;
        }
        try {
            var rootNode = Json.MAPPER.readTree(Files.readAllBytes(statsFile));
            var syncs = rootNode.path("syncs");
            sessionsTotal.set(rootNode.path("sessions").path("total").asLong(0));
            authFailures.set(rootNode.path("sessions").path("authFailures").asLong(0));
            syncsTotal.set(syncs.path("total").asLong(0));
            filesSynced.set(syncs.path("filesSynced").asLong(0));
            filesSkipped.set(syncs.path("filesSkipped").asLong(0));
            filesDeleted.set(syncs.path("filesDeleted").asLong(0));
            bytesReceived.set(syncs.path("bytesReceived").asLong(0));
            bytesReused.set(syncs.path("bytesReused").asLong(0));
            bytesSent.set(syncs.path("bytesSent").asLong(0));
            errors.set(syncs.path("errors").asLong(0));
            if (syncs.hasNonNull("lastSyncAt")) {
                lastSyncAt = Instant.parse(syncs.path("lastSyncAt").asText());
            }
            for (var node : rootNode.path("files")) {
                FileStat stat = new FileStat(
                        node.path("path").asText(),
                        node.path("size").asLong(),
                        Instant.parse(node.path("mtime").asText()).toEpochMilli(),
                        Instant.parse(node.path("lastSyncAt").asText()),
                        node.path("sha256").asText(),
                        node.path("bytesReceived").asLong(),
                        node.path("bytesReused").asLong(),
                        node.path("durationMs").asLong());
                files.put(stat.path(), stat);
            }
        } catch (Exception e) {
            System.getLogger("rsyncj").log(System.Logger.Level.WARNING, "Could not restore stats: " + e.getMessage());
        }
    }
}
