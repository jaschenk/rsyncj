# rsyncj

A secure, rsync-style file synchroniser for Java 25.

`rsyncj` copies a local file or directory tree to a remote server and only sends the
parts of each file that the server does not already have. Unlike a naive upload it uses
the classic rsync rolling-checksum algorithm, so inserting bytes at the start of a large
file does not force the whole file to be transferred again. Everything runs over TLS with
mutual authentication, and the server exposes live JSON statistics that the client can
query through its API.

```
$ rsyncj sync ./website alice@backup.example.com:8443:/srv/www --delete
Synced 1 284 file(s) (1 190 unchanged) in 842 ms
  data sent : 4.1 MiB
  reused    : 812.6 MiB
  efficiency: 99.5%
```

---

## Contents

1. [Features](#features)
2. [Requirements and build](#requirements-and-build)
3. [Quick start](#quick-start)
4. [Command line reference](#command-line-reference)
5. [How the delta transfer works](#how-the-delta-transfer-works)
6. [Security model](#security-model)
7. [Statistics API](#statistics-api)
8. [Java client API](#java-client-api)
9. [Project layout](#project-layout)
10. [Testing](#testing)
11. [Operational notes and limitations](#operational-notes-and-limitations)

---

## Features

* **Delta synchronisation** – per-block weak (rolling Adler) and strong (truncated
  SHA-256) checksums; only literal bytes that the server cannot reconstruct are sent.
* **Files or directory trees** – recursive directory sync, empty directories, POSIX
  permissions and modification times, optional deletion of extraneous remote files.
* **Dry-run mode** – compute and report the delta without writing anything.
* **TLS 1.3 / 1.2** with a self-signed server certificate and SSH-style
  trust-on-first-use fingerprint pinning (or explicit `--fingerprint` pinning).
* **SCRAM-SHA-256 mutual authentication** – the server stores only PBKDF2-derived
  verifier keys, never passwords, and the client also verifies the server.
* **Path confinement** – every remote path is resolved inside the configured root;
  traversal, absolute escapes and NUL bytes are rejected.
* **Integrity and atomicity** – every file is rebuilt in a temporary file, verified
  against the client's SHA-256 and size, then atomically renamed into place.
* **JSON statistics** – cumulative counters and per-file records, available over the
  authenticated protocol *and* an HTTPS endpoint protected by a bearer token.
* **Persistent stats** – counters survive server restarts.
* **Java 25** – records, sealed-style switch expressions, virtual threads per
  connection, and a small, dependency-light codebase.

## Requirements and build

* JDK 25 (`java -version` must report 25)
* Maven 3.9+

```bash
mvn clean package
```

This produces two runnable fat jars:

```
rsyncj-server/target/rsyncj-server.jar
rsyncj-client/target/rsyncj-client.jar
```

Run the unit tests with `mvn test`. A full end-to-end test (server, TLS, auth, delta
transfer, deletion, stats) is available as `scripts/e2e-test.sh`.

## Quick start

### 1. Create a user on the server

```bash
java -jar rsyncj-server/target/rsyncj-server.jar add-user alice \
     --state ./server-state
# prompts for a password (or use --password / RSYNCJ_PASSWORD)
```

The state directory holds `keystore.p12` (TLS key), `users.json` (SCRAM verifiers),
`stats.json` and `stats-token`. All are created with `0600` permissions where the
filesystem supports it.

### 2. Start the server

```bash
java -jar rsyncj-server/target/rsyncj-server.jar serve \
     --root /srv/rsyncj-data \
     --state ./server-state \
     --port 8443 \
     --stats-port 8444
```

```
rsyncj/1.0.0 server
  root          : /srv/rsyncj-data
  listening     : 0.0.0.0:8443 (TLS)
  stats api     : https://0.0.0.0:8444/api/stats
  stats token   : 3Yk... (also stored in server-state/stats-token)
  users         : [alice]
  fingerprint   : 38171a2123a40bfb15a4e01f4c71915f7c2546bcb0e349dd33b71b267dbf87ff
```

On first connection the client prints the fingerprint and stores it in
`~/.rsyncj/known_hosts`. Later connections fail if the server key changes.

### 3. Synchronise

```bash
export RSYNCJ_PASSWORD='correct horse battery staple'

# directory: contents of ./site are mirrored into <root>/www
java -jar rsyncj-client/target/rsyncj-client.jar sync ./site alice@server:8443:/www

# single file
java -jar rsyncj-client/target/rsyncj-client.jar sync ./report.pdf alice@server:8443:/docs/report.pdf

# mirror + delete remote files that no longer exist locally
java -jar rsyncj-client/target/rsyncj-client.jar sync ./site alice@server:8443:/www --delete

# preview only
java -jar rsyncj-client/target/rsyncj-client.jar sync ./site alice@server:8443:/www --dry-run --verbose
```

Remote paths are always relative to the server root, even when written with a leading
slash: `/www` means `<root>/www`. A trailing slash on a single-file target means "copy
into this directory":

```bash
rsyncj sync ./a.txt alice@server:8443:/inbox/     # -> <root>/inbox/a.txt
```

## Command line reference

### Server

```
rsyncj-server serve [options]
rsyncj-server add-user <name> [--password <pw>] [options]
rsyncj-server remove-user <name> [options]
rsyncj-server fingerprint [options]

  --root <dir>          Writable root (default ./rsyncj-data)
  --bind <address>      Listen address (default 0.0.0.0)
  --port <n>            TLS sync port (default 8443)
  --stats-port <n>      HTTPS stats port (default 8444)
  --no-stats-http       Disable the HTTPS stats endpoint
  --state <dir>         State directory (default ./rsyncj-state)
  --max-file-size <n>   Maximum accepted file size in bytes (default 8 GiB)
```

### Client

```
rsyncj sync <source> <user@host[:port]:remotePath> [options]
rsyncj stats <user@host[:port]> [options]
rsyncj fingerprint <host[:port]>

Sync options
  --delete              Delete remote files that no longer exist locally
  --dry-run             Compute the delta but write nothing
  --verbose             One line per file
  --password <pw>       Password (else RSYNCJ_PASSWORD or an interactive prompt)
  --accept-new          Trust an unknown server key on first use (default)
  --no-accept-new       Refuse unknown server keys
  --fingerprint <hex>   Pin the server certificate SHA-256 fingerprint
  --known-hosts <file>  known_hosts location (default ~/.rsyncj/known_hosts)

Stats options
  --json                Print raw JSON
  --http                Use the HTTPS stats endpoint instead of the sync protocol
  --stats-port <n>      HTTPS stats port (default 8444)
  --token <token>       Bearer token for the HTTPS endpoint
```

Exit codes: `0` success, `1` runtime/transfer error, `2` usage error.

## How the delta transfer works

For every file the client and server perform a miniature rsync session:

1. The client announces the file, its size, mode, mtime and a block size derived from
   the file size (`4096` bytes, doubled until the signature table has at most ~32 768
   entries, capped at 1 MiB).
2. If the server already has the file, it reads it block by block and returns a
   **signature table**: for each block, its index, a 32-bit rolling checksum and a
   16-byte truncated SHA-256.
3. The client walks the new file with a rolling window of one block. At each position
   it looks up the rolling checksum in the table. On a hit it verifies the strong
   checksum and emits a `COPY <blockIndex>` operation; otherwise it emits one literal
   byte and rolls the window forward by one byte. Both steps are O(1), so the whole
   file is processed in linear time.
4. Literal bytes are streamed in `DATA` frames (64 KiB each); copy operations are tiny
   JSON control messages. The server reconstructs the file by reading the referenced
   blocks from the old file and appending literal bytes.
5. The client computes SHA-256 while streaming and sends it with the final size. The
   server verifies both before replacing the destination atomically.

Because the rolling checksum is position-independent, inserting or deleting bytes
anywhere in a file only invalidates the blocks around the edit. A 2 GiB file with 100 KiB
inserted at the front transfers roughly 100 KiB plus one block.

If the destination is byte-identical, every block is a `COPY`, no `DATA` is sent, and
the server reports the file as *unchanged* without touching it.

## Security model

| Threat | Mitigation |
| --- | --- |
| Eavesdropping | TLS 1.3 (1.2 fallback), modern cipher suites from the JDK. |
| Server impersonation | Self-signed certificate pinned by SHA-256 fingerprint in `known_hosts`; a changed key is a hard failure. `--fingerprint` allows explicit out-of-band pinning. |
| Client impersonation | SCRAM-SHA-256 challenge/response. The password never crosses the wire; the server stores only PBKDF2 verifiers. |
| Replay | Fresh 24-byte server and client nonces per connection are bound into the HMAC transcript. |
| Password theft from server disk | `users.json` contains `salt`, `iterations`, `storedKey` and `serverKey` only. Neither key can be used to authenticate as the client. |
| Path traversal | `PathSafety` strips leading `/`, rejects `..` segments and NUL bytes, normalises, and verifies the result still starts with the root. |
| Symlink escape | Symlinks are never followed during traversal or deletion; incoming files are written with `CREATE`/`TRUNCATE` to a fresh temp file. |
| Partial/corrupt files | SHA-256 + size verification, `fsync`, then atomic `rename`. A failed transfer leaves the old file untouched. |
| Memory exhaustion | Hard 16 MiB frame cap, 1 MiB block cap, configurable maximum file size, bounded signature tables. |
| Stats data leakage | HTTPS endpoint requires `Authorization: Bearer <token>` (32 random bytes, `0600` file, constant-time compare). The protocol endpoint requires a full SCRAM session. |
| User enumeration | Unknown users receive a random challenge indistinguishable from a wrong password, and the same `auth_failed` error. |

The server also enforces a 180-second socket idle timeout and validates every field of
every control message (sizes, block indexes, block sizes, path lengths).

**Key management.** The TLS key pair is generated on first start with the JDK's
BouncyCastle provider (EC P-256, SHA-256 self-signature, 10-year validity) and stored in
a PKCS#12 keystore. Back up `keystore.p12` and `users.json` together; losing the
keystore changes the fingerprint and requires clients to re-trust the server.

## Statistics API

The server keeps cumulative counters and a per-file record of the last synchronisation.
They are persisted to `stats.json` every 15 seconds and on shutdown, and restored at
startup.

### Over the authenticated protocol (client API)

```bash
java -jar rsyncj-client/target/rsyncj-client.jar stats alice@server:8443
```

```json
{
  "server": {
    "product": "rsyncj/1.0.0",
    "protocol": 1,
    "root": "/srv/rsyncj-data",
    "bind": "0.0.0.0",
    "port": 8443,
    "startedAt": "2026-10-29T11:03:28.313916918Z",
    "generatedAt": "2026-10-29T11:04:38.990826444Z",
    "uptimeSeconds": 70
  },
  "sessions": { "total": 6, "active": 1, "authFailures": 0 },
  "syncs": {
    "total": 2,
    "filesSynced": 9,
    "filesSkipped": 1,
    "filesDeleted": 0,
    "bytesReceived": 2001200,
    "bytesReused": 1998848,
    "bytesSent": 25747,
    "deltaEfficiency": 0.4997,
    "errors": 0,
    "lastSyncAt": "2026-10-29T11:03:41.424129680Z"
  },
  "storage": { "files": 5, "bytes": 2000024 },
  "files": [
    {
      "path": "backup/big.bin",
      "size": 2000000,
      "mtime": "2026-10-29T11:02:55Z",
      "lastSyncAt": "2026-10-29T11:03:41.421Z",
      "sha256": "9f2c…",
      "bytesReceived": 1024,
      "bytesReused": 1998848,
      "durationMs": 118
    }
  ]
}
```

### Over HTTPS

```bash
TOKEN=$(cat server-state/stats-token)
curl -sk -H "Authorization: Bearer $TOKEN" https://server:8444/api/stats | jq
curl -sk -H "Authorization: Bearer $TOKEN" https://server:8444/api/stats/files | jq
curl -sk https://server:8444/health
```

`GET /health` is unauthenticated and returns `{"status":"ok"}`. All other endpoints
return `401` without a valid bearer token and `405` for non-GET methods.

## Java client API

The client is a library as well as a CLI:

```java
import io.rsyncj.client.*;
import java.nio.file.Path;

char[] password = System.getenv("RSYNCJ_PASSWORD").toCharArray();

ClientConfig config = ClientConfig.create("backup.example.com", 8443, "alice", password)
        .withHostKeyPolicy(true, Path.of("/home/alice/.rsyncj/known_hosts"), null);

try (RsyncClient client = new RsyncClient(config)) {
    SyncResult result = client.sync(
            SyncRequest.of(Path.of("site"), "/www")
                    .withDelete(true)
                    .withListener((path, size, sent, reused, skipped) ->
                            System.out.printf("%s sent=%d reused=%d%n", path, sent, reused)));

    System.out.printf("sent %d bytes, reused %d bytes (%.1f%%)%n",
            result.bytesReceived(), result.bytesReused(), result.deltaEfficiency() * 100);

    var stats = client.getStats();          // Jackson JsonNode, same document as above
    System.out.println(stats.path("syncs").path("deltaEfficiency").asDouble());
}
```

`SyncRequest` is immutable; `withDelete`, `withDryRun`, `withVerbose` and `withListener`
return modified copies. `SyncResult` exposes `files`, `skipped`, `bytesReceived`,
`bytesReused`, `deleted`, `durationMs`, `dryRun` and `deltaEfficiency()`.

## Project layout

```
rsyncj/
├── pom.xml                     parent POM (Java 25, Jackson, BouncyCastle, JUnit 5)
├── rsyncj-common/              protocol, delta algorithm, crypto, path safety
│   ├── protocol/               frame codec and control messages
│   ├── delta/                  RollingChecksum, BlockSignature, DeltaEncoder
│   ├── crypto/                 SCRAM-SHA-256
│   └── util/                   PathSafety, Hex
├── rsyncj-server/              TLS listener, sessions, receiver, stats, CLI
├── rsyncj-client/              TLS client, delta sender, stats client, CLI
├── scripts/e2e-test.sh         full end-to-end test
└── docs/PROTOCOL.md            wire protocol specification
```

## Testing

```bash
mvn test                 # unit tests: rolling checksum, delta round-trip, path safety
scripts/e2e-test.sh      # builds, starts a real server, exercises the whole feature set
```

The end-to-end script verifies: initial directory sync, byte-for-byte equality,
delta reuse after a large insertion, unchanged re-sync (zero data), `--delete`,
single-file sync, dry-run, wrong-password rejection, path-traversal rejection,
host-key mismatch detection, HTTPS stats with and without a token, and stats
persistence across a restart.

## Operational notes and limitations

* **Not a drop-in rsync replacement.** The wire protocol is rsync-*inspired*, not
  compatible with `rsync(1)` or its daemon.
* **Regular files and directories only.** Symlinks, devices, sockets and sparse files
  are skipped (and reported in verbose mode). Extended attributes and ACLs are not
  transferred.
* **Whole-file locking is per path**, not per root; two concurrent syncs writing the
  same file are serialised, but a sync and an unrelated local process are not.
* **Deletion is opt-in** (`--delete`) and confined to the sync target subtree.
* **Stats grow with the number of distinct paths.** For very large trees consider
  capping or rotating `stats.json`.
* **TLS trust is pinned, not CA-based.** That is deliberate for a self-hosted tool; if
  you terminate TLS in a reverse proxy, disable the built-in listener and adapt the
  client accordingly.
* **Password handling.** Prefer `RSYNCJ_PASSWORD` or the interactive prompt over
  `--password`, which is visible in the process list.
* **Firewall.** Expose only the sync port (default 8443) and, if needed, the stats port
  (8444). The stats port is read-only but still requires the bearer token.

## License

MIT.
