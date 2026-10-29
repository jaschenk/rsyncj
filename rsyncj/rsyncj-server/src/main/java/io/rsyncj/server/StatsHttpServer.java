package io.rsyncj.server;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import io.rsyncj.common.json.Json;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.Executors;

/**
 * Read-only HTTPS JSON API for monitoring.
 *
 * <ul>
 *   <li>{@code GET /health} – unauthenticated liveness probe</li>
 *   <li>{@code GET /api/stats} – full statistics document</li>
 *   <li>{@code GET /api/stats/files} – per-file statistics only</li>
 * </ul>
 * All stats endpoints require {@code Authorization: Bearer <stats-token>}. The token is
 * generated on first start and stored with {@code 0600} permissions.
 */
public final class StatsHttpServer implements AutoCloseable {

    private final HttpsServer server;
    private final StatsRegistry stats;
    private final byte[] token;

    public StatsHttpServer(ServerConfig config, SSLContext sslContext, StatsRegistry stats) throws IOException {
        this.stats = stats;
        this.token = loadOrCreateToken(config.tokenFile());
        this.server = HttpsServer.create(new InetSocketAddress(config.bind(), config.statsPort()), 0);
        this.server.setHttpsConfigurator(new HttpsConfigurator(sslContext));
        this.server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        this.server.createContext("/health", this::handleHealth);
        this.server.createContext("/api/stats", this::handleStats);
        this.server.createContext("/api/stats/files", this::handleFiles);
    }

    public void start() {
        server.start();
    }

    public String token() {
        return new String(token, StandardCharsets.UTF_8);
    }

    private void handleHealth(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            respond(exchange, 405, Json.MAPPER.createObjectNode().put("error", "method_not_allowed"));
            return;
        }
        respond(exchange, 200, Json.MAPPER.createObjectNode().put("status", "ok"));
    }

    private void handleStats(HttpExchange exchange) throws IOException {
        if (!authorised(exchange)) {
            return;
        }
        if (!"GET".equals(exchange.getRequestMethod())) {
            respond(exchange, 405, Json.MAPPER.createObjectNode().put("error", "method_not_allowed"));
            return;
        }
        respond(exchange, 200, stats.snapshot());
    }

    private void handleFiles(HttpExchange exchange) throws IOException {
        if (!authorised(exchange)) {
            return;
        }
        if (!"GET".equals(exchange.getRequestMethod())) {
            respond(exchange, 405, Json.MAPPER.createObjectNode().put("error", "method_not_allowed"));
            return;
        }
        respond(exchange, 200, stats.snapshot().path("files"));
    }

    private boolean authorised(HttpExchange exchange) throws IOException {
        String header = exchange.getRequestHeaders().getFirst("Authorization");
        String supplied = header != null && header.startsWith("Bearer ") ? header.substring(7) : "";
        if (!MessageDigest.isEqual(supplied.getBytes(StandardCharsets.UTF_8), token)) {
            respond(exchange, 401, Json.MAPPER.createObjectNode().put("error", "unauthorized"));
            return false;
        }
        return true;
    }

    private static void respond(HttpExchange exchange, int status, Object body) throws IOException {
        byte[] payload = Json.MAPPER.writerWithDefaultPrettyPrinter().writeValueAsBytes(body);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(status, payload.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(payload);
        }
    }

    private static byte[] loadOrCreateToken(Path file) throws IOException {
        if (Files.exists(file)) {
            return Files.readString(file).trim().getBytes(StandardCharsets.UTF_8);
        }
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        byte[] token = Base64.getUrlEncoder().withoutPadding().encodeToString(random).getBytes(StandardCharsets.UTF_8);
        Path parent = file.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.write(file, token);
        try {
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            // non-POSIX filesystem
        }
        return token;
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
