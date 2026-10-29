package io.rsyncj.server;

import io.rsyncj.common.crypto.Scram;

import java.io.BufferedReader;
import java.io.Console;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Arrays;

/** Command line entry point for the server. */
public final class Main {

    private static final String USAGE = """
            rsyncj server

            Usage:
              rsyncj-server serve [options]
              rsyncj-server add-user <name> [--password <password>] [options]
              rsyncj-server remove-user <name> [options]
              rsyncj-server fingerprint [options]

            Options:
              --root <dir>          Directory that may be written to (default ./rsyncj-data)
              --bind <address>      Listen address (default 0.0.0.0)
              --port <n>            TLS sync port (default 8443)
              --stats-port <n>      HTTPS stats port (default 8444)
              --no-stats-http       Disable the HTTPS stats endpoint
              --state <dir>         State directory for keys/users/stats (default ./rsyncj-state)
              --max-file-size <n>   Maximum accepted file size in bytes
              -h, --help            Show this help
            """;

    public static void main(String[] args) {
        try {
            run(args);
        } catch (IllegalArgumentException e) {
            System.err.println("error: " + e.getMessage());
            System.err.println();
            System.err.println(USAGE);
            System.exit(2);
        } catch (Exception e) {
            System.err.println("fatal: " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(1);
        }
    }

    private static void run(String[] args) throws Exception {
        if (args.length == 0 || args[0].equals("-h") || args[0].equals("--help")) {
            System.out.println(USAGE);
            return;
        }
        String command = args[0];
        Options options = Options.parse(args, 1);
        ServerConfig config = options.toConfig();

        switch (command) {
            case "serve" -> {
                RsyncServer server = RsyncServer.create(config);
                server.start();
            }
            case "add-user" -> {
                String name = options.positional(0, "add-user requires a user name");
                char[] password = options.password();
                UserStore store = UserStore.load(config.usersFile());
                store.addUser(name, password);
                Arrays.fill(password, '\0');
                System.out.println("User '" + name + "' added to " + config.usersFile());
            }
            case "remove-user" -> {
                String name = options.positional(0, "remove-user requires a user name");
                UserStore store = UserStore.load(config.usersFile());
                store.removeUser(name);
                System.out.println("User '" + name + "' removed from " + config.usersFile());
            }
            case "fingerprint" -> {
                KeyStore keyStore = CertManager.loadOrCreate(config.keystore(), config.keystorePassword());
                System.out.println(io.rsyncj.common.util.Hex.colon(
                        io.rsyncj.common.util.Hex.decode(CertManager.fingerprint(keyStore))));
            }
            default -> throw new IllegalArgumentException("Unknown command: " + command);
        }
    }

    private static final class Options {
        private final java.util.List<String> positional = new java.util.ArrayList<>();
        private Path root = Path.of("rsyncj-data");
        private Path state = Path.of("rsyncj-state");
        private String bind = "0.0.0.0";
        private int port = 8443;
        private int statsPort = 8444;
        private boolean statsHttp = true;
        private long maxFileSize = ServerConfig.DEFAULT_MAX_FILE_SIZE;
        private String password;

        static Options parse(String[] args, int start) {
            Options options = new Options();
            for (int i = start; i < args.length; i++) {
                String arg = args[i];
                switch (arg) {
                    case "--root" -> options.root = Path.of(requireValue(args, ++i, arg));
                    case "--state" -> options.state = Path.of(requireValue(args, ++i, arg));
                    case "--bind" -> options.bind = requireValue(args, ++i, arg);
                    case "--port" -> options.port = parseInt(requireValue(args, ++i, arg), arg);
                    case "--stats-port" -> options.statsPort = parseInt(requireValue(args, ++i, arg), arg);
                    case "--max-file-size" -> options.maxFileSize = Long.parseLong(requireValue(args, ++i, arg));
                    case "--no-stats-http" -> options.statsHttp = false;
                    case "--password" -> options.password = requireValue(args, ++i, arg);
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

        ServerConfig toConfig() {
            ServerConfig config = ServerConfig.defaults(root, state)
                    .withPorts(bind, port, statsPort, statsHttp);
            return new ServerConfig(config.root(), config.bind(), config.port(), config.statsPort(),
                    config.statsHttpEnabled(), config.stateDir(), config.keystore(),
                    config.keystorePassword(), config.usersFile(), config.statsFile(),
                    config.tokenFile(), maxFileSize);
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
                char[] first = console.readPassword("Password for user: ");
                char[] second = console.readPassword("Repeat password: ");
                if (!Arrays.equals(first, second)) {
                    throw new IllegalArgumentException("Passwords do not match");
                }
                return first;
            }
            try {
                System.out.print("Password: ");
                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
                String line = reader.readLine();
                if (line == null || line.isEmpty()) {
                    throw new IllegalArgumentException("No password supplied");
                }
                return line.toCharArray();
            } catch (java.io.IOException e) {
                throw new IllegalArgumentException("Could not read password", e);
            }
        }

        private static String requireValue(String[] args, int index, String option) {
            if (index >= args.length) {
                throw new IllegalArgumentException(option + " requires a value");
            }
            return args[index];
        }

        private static int parseInt(String value, String option) {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(option + " requires an integer");
            }
        }
    }

    private Main() {
    }
}
