package io.rsyncj.server;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.rsyncj.common.crypto.Scram;
import io.rsyncj.common.json.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

/** Persistent user database holding SCRAM verifiers only. */
public final class UserStore {

    private static final int FORMAT_VERSION = 1;

    private final Path file;
    private final Map<String, Scram.UserEntry> users = new ConcurrentHashMap<>();

    private UserStore(Path file) {
        this.file = file;
    }

    public static UserStore load(Path file) throws IOException {
        UserStore store = new UserStore(file);
        if (Files.exists(file)) {
            JsonNode root = Json.MAPPER.readTree(Files.readAllBytes(file));
            JsonNode usersNode = root.path("users");
            if (usersNode.isObject()) {
                usersNode.properties().forEach(entry -> {
                    JsonNode value = entry.getValue();
                    store.users.put(entry.getKey(), new Scram.UserEntry(
                            Base64.getDecoder().decode(value.path("salt").asText()),
                            value.path("iterations").asInt(Scram.DEFAULT_ITERATIONS),
                            Base64.getDecoder().decode(value.path("storedKey").asText()),
                            Base64.getDecoder().decode(value.path("serverKey").asText())));
                });
            }
        }
        return store;
    }

    public Optional<Scram.UserEntry> get(String user) {
        return Optional.ofNullable(users.get(user));
    }

    public Set<String> names() {
        return new TreeSet<>(users.keySet());
    }

    public void addUser(String user, char[] password) throws IOException {
        if (user == null || !user.matches("[A-Za-z0-9._-]{1,64}")) {
            throw new IllegalArgumentException("Invalid user name (allowed: A-Z a-z 0-9 . _ -, max 64 chars)");
        }
        if (password == null || password.length < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters");
        }
        users.put(user, Scram.newUser(password));
        save();
    }

    public void removeUser(String user) throws IOException {
        if (users.remove(user) != null) {
            save();
        }
    }

    public void save() throws IOException {
        ObjectNode root = Json.MAPPER.createObjectNode();
        root.put("version", FORMAT_VERSION);
        ObjectNode usersNode = root.putObject("users");
        users.forEach((name, entry) -> {
            ObjectNode node = usersNode.putObject(name);
            node.put("salt", Base64.getEncoder().encodeToString(entry.salt()));
            node.put("iterations", entry.iterations());
            node.put("storedKey", Base64.getEncoder().encodeToString(entry.storedKey()));
            node.put("serverKey", Base64.getEncoder().encodeToString(entry.serverKey()));
        });
        Path parent = file.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Path temp = Files.createTempFile(parent, ".users-", ".tmp");
        Files.write(temp, Json.MAPPER.writerWithDefaultPrettyPrinter().writeValueAsBytes(root));
        try {
            Files.setPosixFilePermissions(temp, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            // non-POSIX filesystem
        }
        Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
}
