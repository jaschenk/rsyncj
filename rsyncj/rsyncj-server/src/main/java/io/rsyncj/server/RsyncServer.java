package io.rsyncj.server;

import io.rsyncj.common.Version;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/** Accepts TLS connections and dispatches each to a virtual thread. */
public final class RsyncServer implements AutoCloseable {

    private static final System.Logger LOG = System.getLogger("rsyncj.server");

    private final ServerConfig config;
    private final StatsRegistry stats;
    private final UserStore users;
    private final SSLServerSocket serverSocket;
    private final StatsHttpServer httpServer;
    private final String fingerprint;
    private final ScheduledExecutorService housekeeping;
    private volatile boolean running = true;

    private RsyncServer(ServerConfig config, StatsRegistry stats, UserStore users,
                        SSLServerSocket serverSocket, StatsHttpServer httpServer, String fingerprint) {
        this.config = config;
        this.stats = stats;
        this.users = users;
        this.serverSocket = serverSocket;
        this.httpServer = httpServer;
        this.fingerprint = fingerprint;
        this.housekeeping = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "rsyncj-housekeeping");
            thread.setDaemon(true);
            return thread;
        });
    }

    public static RsyncServer create(ServerConfig config) throws Exception {
        Files.createDirectories(config.root());
        Files.createDirectories(config.stateDir());

        KeyStore keyStore = CertManager.loadOrCreate(config.keystore(), config.keystorePassword());
        SSLContext sslContext = CertManager.sslContext(keyStore, config.keystorePassword());
        UserStore users = UserStore.load(config.usersFile());
        StatsRegistry stats = new StatsRegistry(config.statsFile(),
                config.root().toString(), config.bind(), config.port());
        stats.restore();

        SSLServerSocket serverSocket = (SSLServerSocket) sslContext.getServerSocketFactory()
                .createServerSocket();
        serverSocket.setReuseAddress(true);
        serverSocket.bind(new InetSocketAddress(InetAddress.getByName(config.bind()), config.port()), 128);
        serverSocket.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});

        StatsHttpServer httpServer = config.statsHttpEnabled()
                ? new StatsHttpServer(config, sslContext, stats)
                : null;

        return new RsyncServer(config, stats, users, serverSocket, httpServer,
                CertManager.fingerprint(keyStore));
    }

    public void start() throws IOException {
        if (httpServer != null) {
            httpServer.start();
        }
        housekeeping.scheduleWithFixedDelay(stats::persist, 15, 15, TimeUnit.SECONDS);
        Runtime.getRuntime().addShutdownHook(new Thread(this::close, "rsyncj-shutdown"));

        System.out.println(Version.PRODUCT + " server");
        System.out.println("  root          : " + config.root());
        System.out.println("  listening     : " + config.bind() + ":" + config.port() + " (TLS)");
        if (httpServer != null) {
            System.out.println("  stats api     : https://" + config.bind() + ":" + config.statsPort() + "/api/stats");
            System.out.println("  stats token   : " + httpServer.token());
        }
        System.out.println("  users         : " + users.names());
        System.out.println("  fingerprint   : " + fingerprint);
        System.out.println();

        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            while (running) {
                try {
                    SSLSocket socket = (SSLSocket) serverSocket.accept();
                    executor.submit(new SessionHandler(socket, config, users, stats));
                } catch (IOException e) {
                    if (running) {
                        LOG.log(System.Logger.Level.WARNING, "Accept failed: " + e.getMessage());
                    }
                }
            }
        }
    }

    @Override
    public void close() {
        running = false;
        try {
            serverSocket.close();
        } catch (IOException ignored) {
            // shutting down
        }
        if (httpServer != null) {
            httpServer.close();
        }
        housekeeping.shutdownNow();
        stats.persist();
    }
}
