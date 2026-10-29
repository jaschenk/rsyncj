package io.rsyncj.common.protocol;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Length-prefixed framing: {@code [int32 payloadLength][uint8 type][payload]}.
 * A hard cap on frame size prevents memory exhaustion attacks from a hostile peer.
 */
public final class FrameIO {

    /** 16 MiB: large enough for a full block-signature table, small enough to bound memory. */
    public static final int MAX_FRAME = 16 * 1024 * 1024;

    private FrameIO() {
    }

    public record Frame(FrameType type, byte[] payload) {
    }

    public static void write(OutputStream out, FrameType type, byte[] payload) throws IOException {
        write(out, type, payload, 0, payload.length);
    }

    public static void write(OutputStream out, FrameType type, byte[] payload, int offset, int length) throws IOException {
        if (length > MAX_FRAME) {
            throw new ProtocolException("Frame too large: " + length + " bytes");
        }
        byte[] header = new byte[5];
        header[0] = (byte) (length >>> 24);
        header[1] = (byte) (length >>> 16);
        header[2] = (byte) (length >>> 8);
        header[3] = (byte) length;
        header[4] = (byte) type.code();
        out.write(header);
        out.write(payload, offset, length);
    }

    /** Blocking frame reader. Not thread safe; one reader per connection. */
    public static final class Reader {
        private final InputStream in;

        public Reader(InputStream in) {
            this.in = in;
        }

        /** Returns {@code null} on a clean end of stream before any header byte. */
        public Frame read() throws IOException {
            byte[] header = new byte[5];
            int first = in.read();
            if (first < 0) {
                return null;
            }
            header[0] = (byte) first;
            int off = 1;
            while (off < 5) {
                int n = in.read(header, off, 5 - off);
                if (n < 0) {
                    throw new EOFException("Truncated frame header");
                }
                off += n;
            }
            int length = ((header[0] & 0xff) << 24)
                    | ((header[1] & 0xff) << 16)
                    | ((header[2] & 0xff) << 8)
                    | (header[3] & 0xff);
            if (length < 0 || length > MAX_FRAME) {
                throw new ProtocolException("Illegal frame length: " + length);
            }
            FrameType type = FrameType.of(header[4] & 0xff);
            byte[] payload = in.readNBytes(length);
            if (payload.length != length) {
                throw new EOFException("Truncated frame payload");
            }
            return new Frame(type, payload);
        }
    }
}
