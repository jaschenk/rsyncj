package io.rsyncj.server;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.rsyncj.common.Version;
import io.rsyncj.common.crypto.Scram;
import io.rsyncj.common.delta.BlockSignature;
import io.rsyncj.common.delta.RollingChecksum;
import io.rsyncj.common.json.Json;
import io.rsyncj.common.protocol.FrameIO;
import io.rsyncj.common.protocol.FrameType;
import io.rsyncj.common.protocol.Messages;
import io.rsyncj.common.protocol.ProtocolException;
import io.rsyncj.common.util.Hex;
import io.rsyncj.common.util.PathSafety;

import javax.net.ssl.SSLSocket;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/** Handles one authenticated client connection. */
final class SessionHandler implements Runnable {

    private static final System.Logger LOG = System.getLogger("rsyncj.session");
    private static final Map<String, ReentrantLock> PATH_LOCKS = new ConcurrentHashMap<>();

    private final SSLSocket socket;
    private final ServerConfig config;
    private final UserStore users;
    private final StatsRegistry stats;
    private final Path root;

    private InputStream in;
    private OutputStream out;
    private FrameIO.Reader reader;
    private String user = "<anonymous>";
    private String sessionId;
    private boolean errorSent;

    private SyncContext sync;

    SessionHandler(SSLSocket socket, ServerConfig config, UserStore users, StatsRegistry stats) {
        this.socket = socket;
        this.config = config;
        this.users = users;
        this.stats = stats;
        this.root = config.root();
    }

    @Override
    public void run() {
        stats.sessionOpened();
        try {
            socket.setSoTimeout(180_000);
            socket.setTcpNoDelay(true);
            in = new BufferedInputStream(socket.getInputStream(), 128 * 1024);
            out = new BufferedOutputStream(socket.getOutputStream(), 128 * 1024);
            reader = new FrameIO.Reader(in);

            authenticate();
            commandLoop();
        } catch (ProtocolException e) {
            stats.error();
            sendErrorOnce("protocol_error", e.getMessage());
            LOG.log(System.Logger.Level.WARNING, "Session " + sessionId + " protocol error: " + e.getMessage());
        } catch (EOFException e) {
            LOG.log(System.Logger.Level.DEBUG, "Client disconnected: " + user);
        } catch (IOException e) {
            stats.error();
            LOG.log(System.Logger.Level.WARNING, "Session " + sessionId + " I/O error: " + e.getMessage());
        } catch (Exception e) {
            stats.error();
            LOG.log(System.Logger.Level.ERROR, "Session " + sessionId + " failed", e);
        } finally {
            try {
                socket.close();
            } catch (IOException ignored) {
                // closing
            }
            stats.sessionClosed();
            stats.persist();
        }
    }

    // ------------------------------------------------------------------ auth

    private void authenticate() throws Exception {
        FrameIO.Frame frame = reader.read();
        if (frame == null) {
            throw new ProtocolException("Connection closed before hello");
        }
        ObjectNode hello = Messages.parse(frame);
        if (!"hello".equals(Messages.typeOf(hello))) {
            throw new ProtocolException("Expected hello");
        }
        int protocol = hello.path("version").asInt(-1);
        if (protocol != Version.PROTOCOL) {
            sendErrorOnce("version_mismatch", "Server speaks protocol " + Version.PROTOCOL);
            throw new ProtocolException("Protocol mismatch: " + protocol);
        }
        user = hello.path("user").asText("");
        if (user.isEmpty() || user.length() > 64) {
            throw new ProtocolException("Invalid user name");
        }

        Scram.UserEntry entry = users.get(user).orElse(null);
        // Always issue a challenge so that unknown users are indistinguishable from bad passwords.
        byte[] salt = entry != null ? entry.salt() : Scram.randomBytes(16);
        int iterations = entry != null ? entry.iterations() : Scram.DEFAULT_ITERATIONS;
        byte[] storedKey = entry != null ? entry.storedKey() : Scram.randomBytes(32);
        byte[] serverKey = entry != null ? entry.serverKey() : Scram.randomBytes(32);
        String serverNonce = Scram.randomToken(24);

        sendJson(Messages.of("challenge")
                .put("salt", Base64.getEncoder().encodeToString(salt))
                .put("iterations", iterations)
                .put("nonce", serverNonce));

        FrameIO.Frame authFrame = reader.read();
        if (authFrame == null) {
            throw new ProtocolException("Connection closed during authentication");
        }
        ObjectNode auth = Messages.parse(authFrame);
        if (!"auth".equals(Messages.typeOf(auth))) {
            throw new ProtocolException("Expected auth");
        }
        String clientNonce = auth.path("clientNonce").asText("");
        byte[] proof;
        try {
            proof = Base64.getDecoder().decode(auth.path("proof").asText(""));
        } catch (IllegalArgumentException e) {
            proof = new byte[0];
        }
        String authMessage = Scram.authMessage(user, clientNonce, serverNonce);
        byte[] expected = Scram.proof(storedKey, authMessage);
        if (entry == null || !Scram.constantTimeEquals(expected, proof)) {
            stats.authFailed();
            sendErrorOnce("auth_failed", "Authentication failed");
            throw new ProtocolException("Authentication failed for user " + user);
        }

        sessionId = Scram.randomToken(9);
        sendJson(Messages.of("auth_ok")
                .put("sessionId", sessionId)
                .put("serverSignature", Base64.getEncoder().encodeToString(Scram.serverSignature(serverKey, authMessage)))
                .put("serverTime", Instant.now().toString())
                .put("product", Version.PRODUCT)
                .put("protocol", Version.PROTOCOL));
        LOG.log(System.Logger.Level.INFO, "Authenticated user=" + user + " session=" + sessionId);
    }

    // --------------------------------------------------------------- command

    private void commandLoop() throws IOException {
        while (true) {
            FrameIO.Frame frame = reader.read();
            if (frame == null) {
                return;
            }
            ObjectNode message = Messages.parse(frame);
            switch (Messages.typeOf(message)) {
                case "sync_begin" -> beginSync(message);
                case "file_begin" -> receiveFile(message);
                case "dir_begin" -> receiveDirectory(message);
                case "sync_end" -> endSync(message);
                case "stats" -> sendStats();
                case "ping" -> sendJson(Messages.of("pong").put("serverTime", Instant.now().toString()));
                case "quit" -> {
                    sendJson(Messages.of("bye"));
                    return;
                }
                default -> throw new ProtocolException("Unknown command: " + Messages.typeOf(message));
            }
        }
    }

    private void beginSync(ObjectNode message) throws IOException {
        String targetPath = requireText(message, "target");
        String kind = message.path("kind").asText("dir");
        if (!kind.equals("dir") && !kind.equals("file")) {
            throw new ProtocolException("Invalid sync kind: " + kind);
        }
        boolean delete = message.path("delete").asBoolean(false);
        boolean dryRun = message.path("dryRun").asBoolean(false);

        Path target = PathSafety.resolve(root, targetPath);
        if (kind.equals("dir")) {
            if (Files.exists(target) && !Files.isDirectory(target)) {
                throw new ProtocolException("Target exists and is not a directory: " + targetPath);
            }
            if (!dryRun) {
                Files.createDirectories(target);
            }
        } else {
            if (Files.isDirectory(target)) {
                throw new ProtocolException("Target is a directory: " + targetPath);
            }
            Path parent = target.getParent();
            if (parent != null && !dryRun) {
                Files.createDirectories(parent);
            }
        }

        sync = new SyncContext(target, kind, delete && kind.equals("dir"), dryRun);
        stats.syncStarted();
        sendJson(Messages.of("sync_ready")
                .put("target", PathSafety.relativise(root, target))
                .put("kind", kind)
                .put("dryRun", dryRun));
    }

    private void receiveDirectory(ObjectNode message) throws IOException {
        requireSync();
        Path directory = PathSafety.resolve(root, requireText(message, "path"));
        if (Files.exists(directory) && !Files.isDirectory(directory)) {
            throw new ProtocolException("Path exists and is not a directory: " + message.path("path").asText());
        }
        if (!sync.dryRun) {
            Files.createDirectories(directory);
        }
        long mtime = message.path("mtime").asLong(0);
        int mode = message.path("mode").asInt(0755);
        if (!sync.dryRun) {
            IncomingFile.applyMetadata(directory, mtime, mode);
        }
        String relative = PathSafety.relativise(root, directory);
        sync.received.add(relative);
        sendJson(Messages.of("dir_done").put("path", relative));
    }

    private void receiveFile(ObjectNode message) throws IOException {
        requireSync();
        String relativePath = requireText(message, "path");
        Path target = PathSafety.resolve(root, relativePath);
        if (Files.isDirectory(target)) {
            throw new ProtocolException("Target is a directory: " + relativePath);
        }
        long size = message.path("size").asLong(-1);
        if (size < 0 || size > config.maxFileSize()) {
            throw new ProtocolException("File size out of range: " + size);
        }
        int blockSize = message.path("blockSize").asInt(0);
        if (blockSize < 1024 || blockSize > 1024 * 1024) {
            throw new ProtocolException("Illegal block size: " + blockSize);
        }
        long mtime = message.path("mtime").asLong(System.currentTimeMillis());
        int mode = message.path("mode").asInt(0644);
        String relative = PathSafety.relativise(root, target);

        ReentrantLock lock = PATH_LOCKS.computeIfAbsent(relative, k -> new ReentrantLock());
        lock.lock();
        long started = System.nanoTime();
        try {
            boolean exists = Files.isRegularFile(target) && !Files.isSymbolicLink(target);
            long oldSize = exists ? Files.size(target) : 0;
            List<BlockSignature> signatures = exists ? signatures(target, blockSize) : List.of();

            ObjectNode signatureMessage = Messages.of("signatures")
                    .put("exists", exists)
                    .put("blockSize", blockSize)
                    .put("size", oldSize);
            ArrayNode blocks = signatureMessage.putArray("blocks");
            for (BlockSignature signature : signatures) {
                ArrayNode block = blocks.addArray();
                block.add(signature.index());
                block.add(signature.weak());
                block.add(Base64.getEncoder().encodeToString(signature.strong()));
            }
            sendJson(signatureMessage);

            boolean changed;
            long dataBytes;
            long reusedBytes;
            String sha256;
            try (IncomingFile incoming = new IncomingFile(target, blockSize, oldSize, exists, sync.dryRun)) {
                while (true) {
                    FrameIO.Frame frame = reader.read();
                    if (frame == null) {
                        throw new ProtocolException("Connection closed during file transfer");
                    }
                    if (frame.type() == FrameType.DATA) {
                        incoming.data(frame.payload(), 0, frame.payload().length);
                        continue;
                    }
                    ObjectNode control = Messages.parse(frame);
                    String type = Messages.typeOf(control);
                    if (type.equals("copy")) {
                        incoming.copy(control.path("block").asLong(-1));
                    } else if (type.equals("file_end")) {
                        sha256 = control.path("sha256").asText("");
                        long declaredSize = control.path("size").asLong(-1);
                        if (declaredSize != size) {
                            throw new ProtocolException("Declared size changed during transfer");
                        }
                        dataBytes = incoming.dataBytes();
                        reusedBytes = incoming.reusedBytes();
                        changed = incoming.finish(sha256, size, mtime, mode);
                        break;
                    } else {
                        throw new ProtocolException("Unexpected message during transfer: " + type);
                    }
                }
            }

            long durationMs = (System.nanoTime() - started) / 1_000_000;
            sync.files++;
            sync.bytesReceived += dataBytes;
            sync.bytesReused += reusedBytes;
            sync.received.add(relative);
            if (!changed) {
                sync.skipped++;
            }
            stats.fileSynced(new StatsRegistry.FileStat(relative, size, mtime, Instant.now(),
                    sha256, dataBytes, reusedBytes, durationMs), !changed);
            sendJson(Messages.of("file_done")
                    .put("path", relative)
                    .put("size", size)
                    .put("bytesReceived", dataBytes)
                    .put("bytesReused", reusedBytes)
                    .put("skipped", !changed)
                    .put("sha256", sha256));
        } finally {
            lock.unlock();
        }
    }

    private void endSync(ObjectNode message) throws IOException {
        requireSync();
        long deleted = 0;
        if (sync.delete && !sync.dryRun) {
            deleted = deleteExtraneous(sync.target, sync.received);
            stats.filesDeleted(deleted);
        }
        stats.syncFinished();
        sendJson(Messages.of("sync_result")
                .put("files", sync.files)
                .put("skipped", sync.skipped)
                .put("bytesReceived", sync.bytesReceived)
                .put("bytesReused", sync.bytesReused)
                .put("deleted", deleted)
                .put("dryRun", sync.dryRun)
                .put("durationMs", sync.durationMs()));
        sync = null;
    }

    private void sendStats() throws IOException {
        sendJson(Messages.of("stats_result").set("stats", stats.snapshot()));
    }

    // --------------------------------------------------------------- helpers

    private long deleteExtraneous(Path target, Set<String> keep) throws IOException {
        List<Path> files = new ArrayList<>();
        List<Path> directories = new ArrayList<>();
        Files.walkFileTree(target, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                files.add(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc) {
                if (!dir.equals(target)) {
                    directories.add(dir);
                }
                return FileVisitResult.CONTINUE;
            }
        });
        long deleted = 0;
        for (Path file : files) {
            String relative = PathSafety.relativise(root, file);
            if (!keep.contains(relative) && Files.deleteIfExists(file)) {
                deleted++;
                stats.removeFile(relative);
            }
        }
        for (Path directory : directories) {
            String relative = PathSafety.relativise(root, directory);
            if (!keep.contains(relative)) {
                try (var entries = Files.list(directory)) {
                    if (entries.findAny().isEmpty()) {
                        Files.delete(directory);
                        deleted++;
                    }
                }
            }
        }
        return deleted;
    }

    private static List<BlockSignature> signatures(Path file, int blockSize) throws IOException {
        List<BlockSignature> result = new ArrayList<>();
        try (InputStream input = new BufferedInputStream(Files.newInputStream(file), 128 * 1024)) {
            byte[] buffer = new byte[blockSize];
            int index = 0;
            while (true) {
                int read = readFully(input, buffer, blockSize);
                if (read <= 0) {
                    break;
                }
                RollingChecksum checksum = new RollingChecksum();
                checksum.reset(buffer, 0, read);
                result.add(new BlockSignature(index++, checksum.value(),
                        BlockSignature.strongHash(buffer, 0, read)));
                if (read < blockSize) {
                    break;
                }
            }
        }
        return result;
    }

    private static int readFully(InputStream in, byte[] buffer, int length) throws IOException {
        int total = 0;
        while (total < length) {
            int read = in.read(buffer, total, length - total);
            if (read < 0) {
                break;
            }
            total += read;
        }
        return total;
    }

    private void sendErrorOnce(String code, String message) {
        if (errorSent) {
            return;
        }
        errorSent = true;
        Messages.sendError(out, code, message);
    }

    private void sendJson(ObjectNode message) throws IOException {
        byte[] payload = Json.MAPPER.writeValueAsBytes(message);
        FrameIO.write(out, FrameType.JSON, payload);
        out.flush();
        stats.outbound(payload.length + 5L);
    }

    private void requireSync() {
        if (sync == null) {
            throw new ProtocolException("No sync in progress");
        }
    }

    private static String requireText(ObjectNode message, String field) {
        JsonNode node = message.get(field);
        if (node == null || !node.isTextual() || node.asText().isEmpty()) {
            throw new ProtocolException("Missing field: " + field);
        }
        return node.asText();
    }

    private static final class SyncContext {
        final Path target;
        final String kind;
        final boolean delete;
        final boolean dryRun;
        final Set<String> received = new HashSet<>();
        final long started = System.nanoTime();
        long files;
        long skipped;
        long bytesReceived;
        long bytesReused;

        SyncContext(Path target, String kind, boolean delete, boolean dryRun) {
            this.target = target;
            this.kind = kind;
            this.delete = delete;
            this.dryRun = dryRun;
        }

        long durationMs() {
            return (System.nanoTime() - started) / 1_000_000;
        }
    }
}
