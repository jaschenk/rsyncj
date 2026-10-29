package io.rsyncj.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.rsyncj.common.Version;
import io.rsyncj.common.crypto.Scram;
import io.rsyncj.common.delta.BlockSignature;
import io.rsyncj.common.delta.DeltaEncoder;
import io.rsyncj.common.json.Json;
import io.rsyncj.common.protocol.FrameIO;
import io.rsyncj.common.protocol.FrameType;
import io.rsyncj.common.protocol.Messages;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Programmatic client API.
 *
 * <pre>{@code
 * ClientConfig config = ClientConfig.create("server.example", 8443, "alice", password);
 * try (RsyncClient client = new RsyncClient(config)) {
 *     SyncResult result = client.sync(SyncRequest.of(Path.of("src"), "/backups/src"));
 *     JsonNode stats = client.getStats();
 * }
 * }</pre>
 */
public final class RsyncClient implements AutoCloseable {

    private final ClientConfig config;

    public RsyncClient(ClientConfig config) {
        this.config = config;
    }

    public SyncResult sync(SyncRequest request) throws IOException {
        Path source = request.source().toAbsolutePath().normalize();
        boolean directory = Files.isDirectory(source);
        if (!directory && !Files.isRegularFile(source)) {
            throw new IOException("Source does not exist or is not a regular file/directory: " + source);
        }
        String kind = directory ? "dir" : "file";
        String effectiveTarget = directory
                ? request.remotePath()
                : fileTarget(request.remotePath(), source.getFileName().toString());

        try (Session session = open()) {
            session.sendJson(Messages.of("sync_begin")
                    .put("target", effectiveTarget)
                    .put("kind", kind)
                    .put("delete", request.delete())
                    .put("dryRun", request.dryRun()));
            ObjectNode ready = session.readJson();
            expect(ready, "sync_ready");

            long started = System.nanoTime();
            long files = 0;
            long skipped = 0;
            long bytesReceived = 0;
            long bytesReused = 0;

            if (directory) {
                List<Path> directories = new ArrayList<>();
                List<Path> regularFiles = new ArrayList<>();
                Files.walkFileTree(source, new SimpleFileVisitor<>() {
                    @Override
                    public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                        directories.add(dir);
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                        if (attrs.isRegularFile()) {
                            regularFiles.add(file);
                        } else if (request.verbose()) {
                            System.err.println("skipping non-regular file: " + file);
                        }
                        return FileVisitResult.CONTINUE;
                    }
                });
                directories.sort(Comparator.comparing(path -> relative(source, path)));
                regularFiles.sort(Comparator.comparing(path -> relative(source, path)));

                for (Path directoryPath : directories) {
                    String relative = relative(source, directoryPath);
                    if (relative.isEmpty()) {
                        continue;
                    }
                    session.sendJson(Messages.of("dir_begin")
                            .put("path", join(request.remotePath(), relative))
                            .put("mtime", Files.getLastModifiedTime(directoryPath).toMillis())
                            .put("mode", mode(directoryPath, 0755)));
                    expect(session.readJson(), "dir_done");
                }

                for (Path file : regularFiles) {
                    ObjectNode done = syncFile(session, file, join(request.remotePath(), relative(source, file)), request);
                    files++;
                    if (done.path("skipped").asBoolean()) {
                        skipped++;
                    }
                    bytesReceived += done.path("bytesReceived").asLong();
                    bytesReused += done.path("bytesReused").asLong();
                    request.listener().onFile(done.path("path").asText(), done.path("size").asLong(),
                            done.path("bytesReceived").asLong(), done.path("bytesReused").asLong(),
                            done.path("skipped").asBoolean());
                }
            } else {
                ObjectNode done = syncFile(session, source, effectiveTarget, request);
                files++;
                if (done.path("skipped").asBoolean()) {
                    skipped++;
                }
                bytesReceived += done.path("bytesReceived").asLong();
                bytesReused += done.path("bytesReused").asLong();
                request.listener().onFile(done.path("path").asText(), done.path("size").asLong(),
                        done.path("bytesReceived").asLong(), done.path("bytesReused").asLong(),
                        done.path("skipped").asBoolean());
            }

            session.sendJson(Messages.of("sync_end")
                    .put("delete", request.delete())
                    .put("dryRun", request.dryRun()));
            ObjectNode result = session.readJson();
            expect(result, "sync_result");
            long durationMs = (System.nanoTime() - started) / 1_000_000;
            return new SyncResult(result.path("files").asLong(files),
                    result.path("skipped").asLong(skipped),
                    result.path("bytesReceived").asLong(bytesReceived),
                    result.path("bytesReused").asLong(bytesReused),
                    result.path("deleted").asLong(0),
                    durationMs,
                    request.dryRun());
        }
    }

    /** Fetches the server's statistics document over the authenticated protocol channel. */
    public JsonNode getStats() throws IOException {
        try (Session session = open()) {
            session.sendJson(Messages.of("stats"));
            ObjectNode response = session.readJson();
            expect(response, "stats_result");
            return response.path("stats");
        }
    }

    public String ping() throws IOException {
        try (Session session = open()) {
            session.sendJson(Messages.of("ping"));
            ObjectNode response = session.readJson();
            expect(response, "pong");
            return response.path("serverTime").asText();
        }
    }

    private ObjectNode syncFile(Session session, Path file, String remotePath, SyncRequest request) throws IOException {
        long size = Files.size(file);
        int blockSize = DeltaEncoder.blockSizeFor(size);
        session.sendJson(Messages.of("file_begin")
                .put("path", remotePath)
                .put("size", size)
                .put("mtime", Files.getLastModifiedTime(file).toMillis())
                .put("mode", mode(file, 0644))
                .put("blockSize", blockSize));

        ObjectNode signatureMessage = session.readJson();
        expect(signatureMessage, "signatures");
        Map<Integer, List<BlockSignature>> table = new HashMap<>();
        for (JsonNode block : signatureMessage.path("blocks")) {
            int index = block.get(0).asInt();
            int weak = block.get(1).asInt();
            byte[] strong = Base64.getDecoder().decode(block.get(2).asText());
            table.computeIfAbsent(weak, key -> new ArrayList<>())
                    .add(new BlockSignature(index, weak, strong));
        }

        String sha256;
        try (InputStream input = new BufferedInputStream(Files.newInputStream(file), 128 * 1024)) {
            sha256 = DeltaEncoder.encode(input, signatureMessage.path("size").asLong(), blockSize, table, new DeltaEncoder.Sink() {
                @Override
                public void copy(long blockIndex) throws IOException {
                    session.sendJson(Messages.of("copy").put("block", blockIndex));
                }

                @Override
                public void literal(byte[] buffer, int offset, int length) throws IOException {
                    session.sendData(buffer, offset, length);
                }
            });
        }
        session.sendJson(Messages.of("file_end").put("sha256", sha256).put("size", size));
        ObjectNode done = session.readJson();
        expect(done, "file_done");
        return done;
    }

    private Session open() throws IOException {
        if (config.password() == null) {
            throw new IOException("A password is required");
        }
        try {
            TofuTrustManager trustManager = new TofuTrustManager(config);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[]{trustManager}, new SecureRandom());

            SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket();
            try {
                socket.connect(new InetSocketAddress(config.host(), config.port()), config.connectTimeoutMs());
            } catch (java.net.ConnectException e) {
                socket.close();
                throw new IOException("Cannot connect to " + config.host() + ":" + config.port() + " ("
                        + e.getMessage() + "). Is the server running and is the port correct? "
                        + "Use user@host:PORT:/path, user@host:PORT/path or --port.", e);
            } catch (java.net.SocketTimeoutException e) {
                socket.close();
                throw new IOException("Timed out connecting to " + config.host() + ":" + config.port()
                        + " - check firewall rules and the port number", e);
            } catch (java.net.UnknownHostException e) {
                socket.close();
                throw new IOException("Cannot resolve host '" + config.host() + "'", e);
            }
            socket.setSoTimeout(config.readTimeoutMs());
            socket.setTcpNoDelay(true);
            SSLParameters parameters = socket.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm(null); // pinning replaces hostname verification
            socket.setSSLParameters(parameters);
            socket.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
            socket.startHandshake();

            Session session = new Session(socket);
            session.authenticate();
            return session;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Could not connect to " + config.host() + ":" + config.port() + ": " + e.getMessage(), e);
        }
    }

    private final class Session implements AutoCloseable {
        private final SSLSocket socket;
        private final InputStream in;
        private final OutputStream out;
        private final FrameIO.Reader reader;

        Session(SSLSocket socket) throws IOException {
            this.socket = socket;
            this.in = new BufferedInputStream(socket.getInputStream(), 128 * 1024);
            this.out = new BufferedOutputStream(socket.getOutputStream(), 128 * 1024);
            this.reader = new FrameIO.Reader(in);
        }

        void authenticate() throws IOException {
            sendJson(Messages.of("hello")
                    .put("version", Version.PROTOCOL)
                    .put("user", config.user())
                    .put("clientId", Scram.randomToken(9)));
            ObjectNode challenge = readJson();
            expect(challenge, "challenge");

            byte[] salt = Base64.getDecoder().decode(challenge.path("salt").asText());
            int iterations = challenge.path("iterations").asInt(Scram.DEFAULT_ITERATIONS);
            String serverNonce = challenge.path("nonce").asText();

            byte[] salted = Scram.saltedPassword(config.password(), salt, iterations);
            byte[] clientKey = Scram.clientKey(salted);
            byte[] storedKey = Scram.storedKey(clientKey);
            byte[] serverKey = Scram.serverKey(salted);

            String clientNonce = Scram.randomToken(24);
            String authMessage = Scram.authMessage(config.user(), clientNonce, serverNonce);
            byte[] proof = Scram.proof(storedKey, authMessage);

            sendJson(Messages.of("auth")
                    .put("clientNonce", clientNonce)
                    .put("proof", Base64.getEncoder().encodeToString(proof)));

            ObjectNode ok = readJson();
            expect(ok, "auth_ok");
            byte[] expected = Scram.serverSignature(serverKey, authMessage);
            byte[] actual;
            try {
                actual = Base64.getDecoder().decode(ok.path("serverSignature").asText());
            } catch (IllegalArgumentException e) {
                throw new IOException("Server sent an invalid signature");
            }
            if (!Scram.constantTimeEquals(expected, actual)) {
                throw new IOException("Server failed authentication (possible impersonation)");
            }
        }

        void sendJson(ObjectNode message) throws IOException {
            FrameIO.write(out, FrameType.JSON, Json.MAPPER.writeValueAsBytes(message));
            out.flush();
        }

        void sendData(byte[] buffer, int offset, int length) throws IOException {
            FrameIO.write(out, FrameType.DATA, buffer, offset, length);
        }

        ObjectNode readJson() throws IOException {
            FrameIO.Frame frame = reader.read();
            if (frame == null) {
                throw new EOFException("Server closed the connection");
            }
            ObjectNode node = Messages.parse(frame);
            if ("error".equals(Messages.typeOf(node))) {
                throw new IOException("Server error [" + node.path("code").asText() + "]: "
                        + node.path("message").asText());
            }
            return node;
        }

        @Override
        public void close() {
            try {
                socket.close();
            } catch (IOException ignored) {
                // closing
            }
        }
    }

    private static void expect(ObjectNode message, String type) throws IOException {
        String actual = Messages.typeOf(message);
        if (!actual.equals(type)) {
            throw new IOException("Protocol error: expected " + type + " but got " + actual);
        }
    }

    private static String relative(Path root, Path path) {
        return root.relativize(path).toString().replace('\\', '/');
    }

    private static String join(String base, String relative) {
        String normalised = base;
        while (normalised.endsWith("/") && normalised.length() > 1) {
            normalised = normalised.substring(0, normalised.length() - 1);
        }
        if (normalised.isEmpty()) {
            return relative;
        }
        if (normalised.equals("/")) {
            return "/" + relative;
        }
        return normalised + "/" + relative;
    }

    private static String fileTarget(String remotePath, String fileName) {
        if (remotePath.isEmpty() || remotePath.endsWith("/") || remotePath.endsWith("/.")) {
            return join(remotePath, fileName);
        }
        return remotePath;
    }

    private static int mode(Path path, int fallback) {
        try {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path);
            int mode = 0;
            for (PosixFilePermission permission : permissions) {
                mode |= switch (permission) {
                    case OWNER_READ -> 0400;
                    case OWNER_WRITE -> 0200;
                    case OWNER_EXECUTE -> 0100;
                    case GROUP_READ -> 0040;
                    case GROUP_WRITE -> 0020;
                    case GROUP_EXECUTE -> 0010;
                    case OTHERS_READ -> 0004;
                    case OTHERS_WRITE -> 0002;
                    case OTHERS_EXECUTE -> 0001;
                };
            }
            return mode;
        } catch (IOException | UnsupportedOperationException e) {
            return fallback;
        }
    }

    @Override
    public void close() {
        // Connections are short-lived and closed per operation.
    }

    /** Exposed for the CLI: current time on the server. */
    public Instant serverTime() throws IOException {
        return Instant.parse(ping());
    }
}
