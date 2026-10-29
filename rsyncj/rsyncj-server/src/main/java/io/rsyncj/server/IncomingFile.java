package io.rsyncj.server;

import io.rsyncj.common.delta.DeltaEncoder;
import io.rsyncj.common.protocol.ProtocolException;
import io.rsyncj.common.util.Hex;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Set;

/**
 * Reconstructs a file from a delta stream (COPY references + literal bytes) into a
 * temporary file, verifies its SHA-256 and size, then atomically replaces the target.
 * A failed transfer can never leave a partially written destination file.
 */
final class IncomingFile implements AutoCloseable {

    private final Path target;
    private final Path temp;
    private final FileChannel out;
    private final FileChannel oldChannel;
    private final MessageDigest digest;
    private final boolean dryRun;
    private final boolean existed;
    private final int blockSize;
    private final long oldSize;

    private long written;
    private long dataBytes;
    private long reusedBytes;
    private boolean closed;

    IncomingFile(Path target, int blockSize, long oldSize, boolean existed, boolean dryRun) throws IOException {
        this.target = target;
        this.blockSize = blockSize;
        this.oldSize = oldSize;
        this.existed = existed;
        this.dryRun = dryRun;
        this.digest = sha256();
        if (dryRun) {
            this.temp = null;
            this.out = null;
        } else {
            Path parent = target.toAbsolutePath().getParent();
            Files.createDirectories(parent);
            this.temp = Files.createTempFile(parent, ".rsyncj-", ".part");
            this.out = FileChannel.open(temp, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
        }
        this.oldChannel = oldSize > 0 && Files.isRegularFile(target)
                ? FileChannel.open(target, StandardOpenOption.READ)
                : null;
    }

    void data(byte[] buffer, int offset, int length) throws IOException {
        digest.update(buffer, offset, length);
        write(buffer, offset, length);
        written += length;
        dataBytes += length;
    }

    void copy(long blockIndex) throws IOException {
        DeltaEncoder.validateBlockIndex(blockIndex, oldSize, blockSize);
        if (oldChannel == null) {
            throw new ProtocolException("Server has no source blocks to copy");
        }
        long position = blockIndex * blockSize;
        int length = (int) Math.min(blockSize, oldSize - position);
        ByteBuffer buffer = ByteBuffer.allocate(length);
        while (buffer.hasRemaining()) {
            int read = oldChannel.read(buffer, position + buffer.position());
            if (read < 0) {
                throw new ProtocolException("Short read while copying block " + blockIndex);
            }
        }
        digest.update(buffer.array(), 0, length);
        write(buffer.array(), 0, length);
        written += length;
        reusedBytes += length;
    }

    /**
     * @return {@code true} if the destination content changed (or would change in dry-run mode)
     */
    boolean finish(String expectedSha256, long expectedSize, long mtime, int mode) throws IOException {
        if (written != expectedSize) {
            throw new ProtocolException("Size mismatch for " + target + ": expected " + expectedSize + " got " + written);
        }
        String actual = Hex.encode(digest.digest());
        if (!actual.equalsIgnoreCase(expectedSha256)) {
            throw new ProtocolException("SHA-256 mismatch for " + target);
        }
        boolean unchanged = existed && dataBytes == 0 && written == oldSize;
        closeChannels();
        if (dryRun || unchanged) {
            deleteTemp();
            return !unchanged;
        }
        Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        applyMetadata(target, mtime, mode);
        return true;
    }

    long dataBytes() {
        return dataBytes;
    }

    long reusedBytes() {
        return reusedBytes;
    }

    private void write(byte[] buffer, int offset, int length) throws IOException {
        if (out == null) {
            return;
        }
        ByteBuffer byteBuffer = ByteBuffer.wrap(buffer, offset, length);
        while (byteBuffer.hasRemaining()) {
            out.write(byteBuffer);
        }
    }

    private void closeChannels() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        if (out != null) {
            out.force(true);
            out.close();
        }
        if (oldChannel != null) {
            oldChannel.close();
        }
    }

    private void deleteTemp() throws IOException {
        if (temp != null) {
            Files.deleteIfExists(temp);
        }
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        try {
            if (out != null) {
                out.close();
            }
            if (oldChannel != null) {
                oldChannel.close();
            }
            deleteTemp();
        } catch (IOException ignored) {
            // best effort cleanup
        }
    }

    static void applyMetadata(Path path, long mtime, int mode) {
        try {
            Files.setLastModifiedTime(path, FileTime.fromMillis(mtime));
        } catch (IOException ignored) {
            // not fatal
        }
        try {
            Files.setPosixFilePermissions(path, permissions(mode));
        } catch (IOException | UnsupportedOperationException ignored) {
            // non-POSIX filesystem or permission denied: not fatal
        }
    }

    static Set<PosixFilePermission> permissions(int mode) {
        int[] bits = {0400, 0200, 0100, 0040, 0020, 0010, 0004, 0002, 0001};
        char[] letters = {'r', 'w', 'x', 'r', 'w', 'x', 'r', 'w', 'x'};
        char[] value = new char[9];
        for (int i = 0; i < 9; i++) {
            value[i] = (mode & bits[i]) != 0 ? letters[i] : '-';
        }
        return PosixFilePermissions.fromString(new String(value));
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
