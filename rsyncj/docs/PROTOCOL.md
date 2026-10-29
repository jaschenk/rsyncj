# rsyncj wire protocol (version 1)

The protocol runs inside a TLS 1.3 (or 1.2) connection. All control messages are UTF-8
JSON objects with a `type` field. File bytes travel in separate binary frames. The
connection is strictly sequential: one request/response exchange at a time, with file
data streamed between `file_begin` and `file_end`.

## Framing

```
+----------------+------------+------------------+
| uint32 length  | uint8 type | payload[length]  |
+----------------+------------+------------------+
```

* `length` is the payload length in bytes (big-endian, 0 .. 16 MiB).
* `type` is `1` for JSON and `2` for raw file data.
* A frame larger than 16 MiB, or an unknown type, terminates the session.

## Handshake

```
client                                server
  |  hello {version, user, clientId}  ->
  |                                   <- challenge {salt, iterations, nonce}
  |  auth {clientNonce, proof}        ->
  |                                   <- auth_ok {sessionId, serverSignature, ...}
```

* `salt` is 16 random bytes, base64. `iterations` is the PBKDF2 iteration count
  (currently 210 000). `nonce` is 24 random bytes, base64.
* `saltedPassword = PBKDF2-HMAC-SHA256(password, salt, iterations, 256 bits)`
* `clientKey      = HMAC-SHA256(saltedPassword, "Client Key")`
* `storedKey      = SHA256(clientKey)`
* `serverKey      = HMAC-SHA256(saltedPassword, "Server Key")`
* `authMessage    = "rsyncj-auth-v1," + user + "," + clientNonce + "," + serverNonce`
* `proof          = HMAC-SHA256(storedKey, authMessage)`
* `serverSignature= HMAC-SHA256(serverKey, authMessage)`

The server stores `salt`, `iterations`, `storedKey` and `serverKey`. The client verifies
`serverSignature`; a mismatch aborts the connection. Unknown users receive a random
challenge and the same `auth_failed` error as a wrong password.

## Synchronisation

```
sync_begin {target, kind: "dir"|"file", delete, dryRun}
  <- sync_ready {target, kind, dryRun}

  for each directory:
    dir_begin {path, mtime, mode}
      <- dir_done {path}

  for each file:
    file_begin {path, size, mtime, mode, blockSize}
      <- signatures {exists, blockSize, size, blocks: [[index, weak, strongB64], ...]}
    (DATA frames and copy messages, in any order)
    file_end {sha256, size}
      <- file_done {path, size, bytesReceived, bytesReused, skipped, sha256}

sync_end {delete, dryRun}
  <- sync_result {files, skipped, bytesReceived, bytesReused, deleted, dryRun, durationMs}
```

Other commands: `stats` → `stats_result {stats}`, `ping` → `pong`, `quit` → `bye`.

Any failure produces `error {code, message}` and the server closes the connection.
Codes include `auth_failed`, `version_mismatch`, `protocol_error`.

### Delta stream

Between `file_begin` and `file_end` the client sends, in file order:

* `DATA` frames containing literal bytes (up to 64 KiB each), and
* `copy {block}` JSON messages meaning "append block `block` of the existing file".

The server reads block `i` at offset `i * blockSize` with length
`min(blockSize, oldSize - i * blockSize)`. Block indexes outside the old file are
rejected. The concatenation of all literal bytes and copied blocks must equal the new
file exactly; this is verified by size and SHA-256 before the file is moved into place.

### Signature table

For each block of the existing file:

* `weak` – 32-bit rolling checksum: `a = Σ x_i mod 65536`,
  `b = Σ (n-i)·x_i mod 65536`, value `(b << 16) | a`.
* `strong` – the first 16 bytes of SHA-256 over the block, base64 encoded.

The block size is chosen by the client: start at 4096 and double while
`size / blockSize > 32768`, capped at 1 MiB. This bounds the signature table to roughly
1.5 MiB of JSON.

## Limits

| Item | Limit |
| --- | --- |
| Frame payload | 16 MiB |
| Block size | 1 KiB .. 1 MiB |
| File size | configurable, default 8 GiB |
| Control string fields | validated (non-empty, bounded) |
| Socket idle timeout | 180 s |

## Paths

Remote paths are always relative to the server root, even if they begin with `/`.
Leading slashes are stripped, `..` segments and NUL bytes are rejected, and the
normalised result must remain inside the root. `sync_begin` with `kind: "file"` targets
a file path; with `kind: "dir"` it targets a directory that is created if missing.
