package io.rsyncj.common.delta;

import io.rsyncj.common.protocol.ProtocolException;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Client-side rsync delta encoder.
 *
 * <p>Walks the new file with a rolling window of {@code blockSize} bytes. Whenever the
 * weak checksum matches a signature of the old file, the strong checksum is verified and
 * the block is emitted as a {@code COPY} reference. Otherwise a single literal byte is
 * emitted and the window rolls forward. This yields a stream of copy/literal operations
 * that reconstructs the new file on the server from blocks it already has.</p>
 */
public final class DeltaEncoder {

    /** Receives the delta operations. */
    public interface Sink {
        void copy(long blockIndex) throws IOException;

        void literal(byte[] buffer, int offset, int length) throws IOException;
    }

    private static final int LITERAL_BUFFER = 64 * 1024;

    private DeltaEncoder() {
    }

    /**
     * Encodes {@code in} against the supplied signature table and returns the hex SHA-256
     * of the complete new file (computed while streaming).
     */
    public static String encode(InputStream in,
                                long oldSize,
                                int blockSize,
                                Map<Integer, List<BlockSignature>> signatures,
                                Sink sink) throws IOException {
        if (blockSize <= 0) {
            throw new IllegalArgumentException("blockSize must be positive");
        }
        MessageDigest digest = sha256();
        byte[] ring = new byte[blockSize];
        byte[] window = new byte[blockSize];
        LiteralBuffer literals = new LiteralBuffer(sink);

        int head = 0;
        int length = readIntoRing(in, ring, 0, blockSize);
        RollingChecksum rolling = new RollingChecksum();
        if (length > 0) {
            rolling.resetRing(ring, 0, length);
        }

        while (length == blockSize) {
            List<BlockSignature> candidates = signatures.get(rolling.value());
            BlockSignature match = null;
            if (candidates != null && !candidates.isEmpty()) {
                copyWindow(ring, head, blockSize, window);
                byte[] strong = BlockSignature.strongHash(window, 0, blockSize);
                for (BlockSignature candidate : candidates) {
                    if (Arrays.equals(candidate.strong(), strong)) {
                        match = candidate;
                        break;
                    }
                }
            }
            if (match != null) {
                literals.flush();
                sink.copy(match.index());
                digest.update(window, 0, blockSize);
                int read = readIntoRing(in, ring, head, blockSize);
                if (read < blockSize) {
                    length = read;
                    if (read > 0) {
                        rolling.resetRing(ring, head, read);
                    }
                } else {
                    rolling.resetRing(ring, head, blockSize);
                }
            } else {
                byte outgoing = ring[head];
                literals.write(outgoing);
                digest.update(outgoing);
                int next = in.read();
                if (next < 0) {
                    head = (head + 1) % blockSize;
                    length--;
                    if (length > 0) {
                        rolling.resetRing(ring, head, length);
                    }
                } else {
                    // The vacated slot is exactly where the new trailing byte belongs.
                    ring[head] = (byte) next;
                    head = (head + 1) % blockSize;
                    rolling.roll(outgoing, (byte) next);
                }
            }
        }

        // The final partial block can also be reused if the old file has a block of
        // exactly this length with the same strong checksum.
        if (length > 0) {
            List<BlockSignature> candidates = signatures.get(rolling.value());
            if (candidates != null) {
                copyWindow(ring, head, length, window);
                byte[] strong = BlockSignature.strongHash(window, 0, length);
                for (BlockSignature candidate : candidates) {
                    if (blockLength(candidate.index(), oldSize, blockSize) == length
                            && Arrays.equals(candidate.strong(), strong)) {
                        literals.flush();
                        sink.copy(candidate.index());
                        digest.update(window, 0, length);
                        length = 0;
                        break;
                    }
                }
            }
        }

        for (int i = 0; i < length; i++) {
            byte value = ring[(head + i) % blockSize];
            literals.write(value);
            digest.update(value);
        }
        literals.flush();
        return io.rsyncj.common.util.Hex.encode(digest.digest());
    }

    private static int blockLength(int index, long oldSize, int blockSize) {
        long offset = (long) index * blockSize;
        if (offset >= oldSize) {
            return 0;
        }
        return (int) Math.min(blockSize, oldSize - offset);
    }

    /** Chooses a block size that keeps the signature table bounded (~32k entries). */
    public static int blockSizeFor(long fileSize) {
        int blockSize = 4096;
        while (fileSize / blockSize > 32_768 && blockSize < 1024 * 1024) {
            blockSize <<= 1;
        }
        return blockSize;
    }

    private static int readIntoRing(InputStream in, byte[] ring, int head, int length) throws IOException {
        int total = 0;
        while (total < length) {
            int index = (head + total) % ring.length;
            int chunk = Math.min(length - total, ring.length - index);
            int read = in.read(ring, index, chunk);
            if (read < 0) {
                break;
            }
            total += read;
        }
        return total;
    }

    private static void copyWindow(byte[] ring, int head, int length, byte[] target) {
        int first = Math.min(length, ring.length - head);
        System.arraycopy(ring, head, target, 0, first);
        if (first < length) {
            System.arraycopy(ring, 0, target, first, length - first);
        }
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static final class LiteralBuffer {
        private final Sink sink;
        private final byte[] buffer = new byte[LITERAL_BUFFER];
        private int count;

        LiteralBuffer(Sink sink) {
            this.sink = sink;
        }

        void write(byte value) throws IOException {
            if (count == buffer.length) {
                flush();
            }
            buffer[count++] = value;
        }

        void flush() throws IOException {
            if (count > 0) {
                sink.literal(buffer, 0, count);
                count = 0;
            }
        }
    }

    /** Validates that a copy index is within the old file's block count. */
    public static void validateBlockIndex(long index, long oldSize, int blockSize) {
        long blocks = oldSize <= 0 ? 0 : (oldSize + blockSize - 1) / blockSize;
        if (index < 0 || index >= blocks) {
            throw new ProtocolException("Invalid copy block index " + index);
        }
    }
}
