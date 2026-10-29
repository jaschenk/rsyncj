package io.rsyncj.client;

import com.fasterxml.jackson.databind.JsonNode;
import io.rsyncj.common.json.Json;
import io.rsyncj.common.util.Hex;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Command line entry point for the client. */
public final class Main {

    private static final String USAGE = """
            rsyncj client

            Usage:
              rsyncj sync <source> <remote> [options]
              rsyncj stats <user@host[:port]> [options]
              rsyncj fingerprint <host[:port]>

            Remote forms (default port 8443):
              user@host:/path   user@host:9443:/path   user@host:9443/path
              rsyncj://user@host:9443/path

            Sync options:
              -p, --port <n>        Server port (overrides the port in <remote>)
              --delete              Delete remote files that no longer exist locally
              --dry-run             Compute the delta but do not write anything
              --verbose             Print one line per file
              --password <pw>       Password (otherwise RSYNCJ_PASSWORD or a prompt)
              --accept-new          Trust an unknown server key on first use (default)
              --no-accept-new       Refuse unknown server keys
              --fingerprint <hex>   Pin the server certificate SHA-256 fingerprint
              --known-hosts <file>  known_hosts location (default ~/.rsyncj/known_hosts)

            Stats options:
              --json                Print raw JSON
              --http                Use the HTTPS stats endpoint instead of the sync protocol
              --stats-port <n>      HTTPS stats port (default 8444)
              --token <token>       Bearer token for the HTTPS stats endpoint
              --password <pw>       Password for the protocol based stats call
              -h, --help            Show this help
            """;

    public static void main(String[] args) {
        try {
            int code = run(args);
            System.exit(code);
        } catch (IllegalArgumentException e) {
            System.err.println("error: " + e.getMessage());
            System.err.println();
            System.err.println(USAGE);
            System.exit(2);
        } catch (Exception e) {
            System.err.println("error: " + e.getMessage());
            if (System.getenv("RSYNCJ_DEBUG") != null) {
                e.printStackTrace(System.err);
            }
            System.exit(1);
        }
    }

    private static int run(String[] args) throws Exception {
        if (args.length == 0 || args[0].equals("-h") || args[0].equals("--help")) {
            System.out.println(USAGE);
            return 0;
        }
        String command = args[0];
        Options options = Options.parse(args, 1);
        switch (command) {
            case "sync" -> {
                return sync(options);
            }
            case "stats" -> {
                return stats(options);
            }
            case "fingerprint" -> {
                return fingerprint(options);
            }
            default -> throw new IllegalArgumentException("Unknown command: " + command);
        }
    }

    private static int sync(Options options) throws Exception {
        String sourceArg = options.positional(0, "sync requires a source path");
        RemoteTarget target = options.apply(RemoteTarget.parse(options.positional(1, "sync requires user@host:path")));
        if (options.verbose) {
            System.err.println("connecting to " + target.host() + ":" + target.port()
                    + " as " + target.user() + ", remote path " + target.path());
        }

        ClientConfig config = options.toConfig(target);
        Path source = Path.of(sourceArg);
        SyncRequest request = new SyncRequest(source, target.path(), options.delete, options.dryRun,
                options.verbose, options.verbose ? Main::printFile : SyncRequest.ProgressListener.NONE);

        try (RsyncClient client = new RsyncClient(config)) {
            SyncResult result = client.sync(request);
            printSummary(result);
        }
        return 0;
    }

    private static int stats(Options options) throws Exception {
        RemoteTarget target = options.apply(RemoteTarget.parseHost(options.positional(0, "stats requires user@host")));
        if (options.http) {
            String token = options.token != null ? options.token : System.getenv("RSYNCJ_STATS_TOKEN");
            if (token == null || token.isBlank()) {
                throw new IllegalArgumentException("--http requires --token or RSYNCJ_STATS_TOKEN");
            }
            JsonNode stats = fetchHttpStats(target, options, token);
            System.out.println(Json.PRETTY.writeValueAsString(stats));
            return 0;
        }
        ClientConfig config = options.toConfig(target);
        try (RsyncClient client = new RsyncClient(config)) {
            JsonNode stats = client.getStats();
            System.out.println(Json.PRETTY.writeValueAsString(stats));
        }
        return 0;
    }

    private static int fingerprint(Options options) throws Exception {
        RemoteTarget target = options.apply(RemoteTarget.parseHost(options.positional(0, "fingerprint requires host[:port]")));
        X509Certificate[] captured = new X509Certificate[1];
        TrustManager capture = new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                captured[0] = chain[0];
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[]{capture}, new SecureRandom());
        try (SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket()) {
            socket.connect(new InetSocketAddress(target.host(), target.port()), 15_000);
            socket.startHandshake();
            if (captured[0] == null) {
                throw new IOException("Server presented no certificate");
            }
            byte[] hash = io.rsyncj.common.crypto.Scram.sha256(captured[0].getEncoded());
            System.out.println("SHA256:" + Hex.colon(hash));
            System.out.println("pin with --fingerprint " + Hex.encode(hash));
        }
        return 0;
    }

    private static JsonNode fetchHttpStats(RemoteTarget target, Options options, String token) throws Exception {
        TofuTrustManager trustManager = new TofuTrustManager(
                options.toConfig(target).withTimeouts(15_000, 30_000));
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[]{trustManager}, new SecureRandom());
        URI uri = URI.create("https://" + target.host() + ":" + options.statsPort + "/api/stats");
        HttpsURLConnection connection = (HttpsURLConnection) uri.toURL().openConnection();
        connection.setSSLSocketFactory(context.getSocketFactory());
        connection.setRequestProperty("Authorization", "Bearer " + token);
        connection.setRequestProperty("Accept", "application/json");
        connection.setConnectTimeout(15_000);
        connection.setReadTimeout(30_000);
        int status = connection.getResponseCode();
        try (var stream = status >= 400 ? connection.getErrorStream() : connection.getInputStream()) {
            if (stream == null) {
                throw new IOException("Empty response from stats endpoint (HTTP " + status + ")");
            }
            String body = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
            if (status >= 400) {
                throw new IOException("Stats endpoint returned HTTP " + status + ": " + body);
            }
            return Json.MAPPER.readTree(body);
        }
    }

    private static void printFile(String path, long size, long received, long reused, boolean skipped) {
        String status = skipped ? "unchanged" : "updated";
        System.out.printf(Locale.ROOT, "  %-48s %10s  sent %9s  reused %9s  %s%n",
                path, human(size), human(received), human(reused), status);
    }

    private static void printSummary(SyncResult result) {
        System.out.printf(Locale.ROOT, "%s %d file(s) (%d unchanged) in %d ms%n",
                result.dryRun() ? "Would sync" : "Synced",
                result.files(), result.skipped(), result.durationMs());
        System.out.printf(Locale.ROOT, "  data sent : %s%n  reused    : %s%n  efficiency: %.1f%%%n",
                human(result.bytesReceived()), human(result.bytesReused()), result.deltaEfficiency() * 100);
        if (result.deleted() > 0) {
            System.out.println("  deleted   : " + result.deleted());
        }
    }

    private static String human(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        double value = bytes;
        String[] units = {"KiB", "MiB", "GiB", "TiB"};
        int unit = -1;
        while (value >= 1024 && unit < units.length - 1) {
            value /= 1024;
            unit++;
        }
        return String.format(Locale.ROOT, "%.1f %s", value, units[unit]);
    }

    record RemoteTarget(String user, String host, int port, String path) {

        static final int DEFAULT_PORT = 8443;

        /** rsyncj://[user@]host[:port]/path */
        private static final Pattern URL_PATTERN =
                Pattern.compile("^rsyncj://(?:([^@/]+)@)?([^:/@]+)(?::(\\d+))?(/.*)?$");
        /** [user@]host:port:path or [user@]host:port/path (port present). */
        private static final Pattern WITH_PORT =
                Pattern.compile("^(?:([^@/]+)@)?([^:/@]+):(\\d+)(?::(.*)|(/.*))$");
        /** [user@]host:path (no port). */
        private static final Pattern NO_PORT =
                Pattern.compile("^(?:([^@/]+)@)?([^:/@]+):(.*)$");
        private static final Pattern HOST_PATTERN =
                Pattern.compile("^(?:rsyncj://)?(?:([^@/]+)@)?([^:/@]+)(?::(\\d+))?/?$");

        /**
         * Parses a sync target. Accepted forms:
         * <pre>
         *   user@host:/path            (default port 8443)
         *   user@host:9443:/path
         *   user@host:9443/path
         *   rsyncj://user@host:9443/path
         * </pre>
         */
        static RemoteTarget parse(String value) {
            Matcher m = URL_PATTERN.matcher(value);
            if (m.matches()) {
                String path = m.group(4) == null ? "" : m.group(4);
                return build(value, m.group(1), m.group(2), m.group(3), path);
            }
            m = WITH_PORT.matcher(value);
            if (m.matches()) {
                String path = m.group(4) != null ? m.group(4) : m.group(5);
                return build(value, m.group(1), m.group(2), m.group(3), path);
            }
            m = NO_PORT.matcher(value);
            if (m.matches()) {
                String path = m.group(3);
                if (path.matches("\\d+")) {
                    throw new IllegalArgumentException("Ambiguous remote '" + value + "': '" + path
                            + "' looks like a port but no remote path was given. Use "
                            + m.group(2) + ":" + path + ":/path or " + m.group(2) + ":" + path + "/path");
                }
                return build(value, m.group(1), m.group(2), null, path);
            }
            throw new IllegalArgumentException("Invalid remote '" + value
                    + "', expected [user@]host[:port]:path, [user@]host:port/path or rsyncj://[user@]host[:port]/path");
        }

        static RemoteTarget parseHost(String value) {
            Matcher m = HOST_PATTERN.matcher(value);
            if (!m.matches()) {
                throw new IllegalArgumentException("Invalid remote '" + value + "', expected [user@]host[:port]");
            }
            return new RemoteTarget(user(m.group(1)), m.group(2), port(value, m.group(3)), "");
        }

        RemoteTarget withPort(int newPort) {
            return new RemoteTarget(user, host, newPort, path);
        }

        private static RemoteTarget build(String value, String user, String host, String port, String path) {
            if (path == null || path.isEmpty()) {
                throw new IllegalArgumentException("Remote path is empty in '" + value + "'");
            }
            return new RemoteTarget(user(user), host, port(value, port), path);
        }

        private static String user(String user) {
            return user != null ? user : System.getProperty("user.name");
        }

        private static int port(String value, String port) {
            if (port == null) {
                return DEFAULT_PORT;
            }
            int p = Integer.parseInt(port);
            if (p < 1 || p > 65535) {
                throw new IllegalArgumentException("Invalid port " + p + " in '" + value + "'");
            }
            return p;
        }
    }

    private static final class Options {
        private final java.util.List<String> positional = new java.util.ArrayList<>();
        private boolean delete;
        private boolean dryRun;
        private boolean verbose;
        private boolean http;
        private String password;
        private String token;
        private String fingerprint;
        private boolean acceptNew = true;
        private Path knownHosts = ClientConfig.defaultKnownHosts();
        private int statsPort = 8444;
        private Integer port;

        static Options parse(String[] args, int start) {
            Options options = new Options();
            for (int i = start; i < args.length; i++) {
                String arg = args[i];
                switch (arg) {
                    case "--delete" -> options.delete = true;
                    case "--dry-run" -> options.dryRun = true;
                    case "--verbose", "-v" -> options.verbose = true;
                    case "--json" -> options.verbose = false;
                    case "--http" -> options.http = true;
                    case "--accept-new" -> options.acceptNew = true;
                    case "--no-accept-new" -> options.acceptNew = false;
                    case "--password" -> options.password = requireValue(args, ++i, arg);
                    case "--token" -> options.token = requireValue(args, ++i, arg);
                    case "--fingerprint" -> options.fingerprint = requireValue(args, ++i, arg);
                    case "--known-hosts" -> options.knownHosts = Path.of(requireValue(args, ++i, arg));
                    case "--port", "-p" -> options.port = Integer.parseInt(requireValue(args, ++i, arg));
                    case "--stats-port" -> options.statsPort = Integer.parseInt(requireValue(args, ++i, arg));
                    case "-h", "--help" -> {
                        System.out.println(USAGE);
                        System.exit(0);
                    }
                    default -> {
                        if (arg.startsWith("--")) {
                            throw new IllegalArgumentException("Unknown option: " + arg);
                        }
                        options.positional.add(arg);
                    }
                }
            }
            return options;
        }

        RemoteTarget apply(RemoteTarget target) {
            return port != null ? target.withPort(port) : target;
        }

        ClientConfig toConfig(RemoteTarget target) {
            return new ClientConfig(target.host(), target.port(), target.user(), password(),
                    acceptNew, knownHosts, fingerprint, 15_000, 300_000);
        }

        String positional(int index, String message) {
            if (index >= positional.size()) {
                throw new IllegalArgumentException(message);
            }
            return positional.get(index);
        }

        char[] password() {
            if (password != null) {
                return password.toCharArray();
            }
            String env = System.getenv("RSYNCJ_PASSWORD");
            if (env != null && !env.isEmpty()) {
                return env.toCharArray();
            }
            Console console = System.console();
            if (console != null) {
                char[] value = console.readPassword("Password: ");
                if (value == null) {
                    throw new IllegalArgumentException("No password supplied");
                }
                return value;
            }
            try {
                System.out.print("Password: ");
                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
                String line = reader.readLine();
                if (line == null || line.isEmpty()) {
                    throw new IllegalArgumentException("No password supplied (use --password or RSYNCJ_PASSWORD)");
                }
                return line.toCharArray();
            } catch (IOException e) {
                throw new IllegalArgumentException("Could not read password", e);
            }
        }

        private static String requireValue(String[] args, int index, String option) {
            if (index >= args.length) {
                throw new IllegalArgumentException(option + " requires a value");
            }
            return args[index];
        }
    }

    private Main() {
    }
}
