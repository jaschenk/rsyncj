package io.rsyncj.common.delta;

/**
 * rsync's weak rolling checksum (a 16-bit Adler variant):
 * <pre>
 *   a = sum(x_i)                  mod 65536
 *   b = sum((n - i) * x_i)        mod 65536
 *   value = (b &lt;&lt; 16) | a
 * </pre>
 * The checksum can be rolled one byte at a time in O(1), which is what makes the
 * rsync delta algorithm linear in the file size.
 */
public final class RollingChecksum {

    private static final int MOD = 65536;

    private int a;
    private int b;
    private int window;

    public void reset(byte[] data, int off, int len) {
        int sa = 0;
        int sb = 0;
        for (int i = 0; i < len; i++) {
            sa += data[off + i] & 0xff;
            sb += sa;
        }
        this.a = sa % MOD;
        this.b = sb % MOD;
        this.window = len;
    }

    /** Reset over a (possibly wrapped) ring buffer window. */
    public void resetRing(byte[] ring, int head, int len) {
        int sa = 0;
        int sb = 0;
        int mask = ring.length;
        for (int i = 0; i < len; i++) {
            sa += ring[(head + i) % mask] & 0xff;
            sb += sa;
        }
        this.a = sa % MOD;
        this.b = sb % MOD;
        this.window = len;
    }

    public int value() {
        return ((b & 0xffff) << 16) | (a & 0xffff);
    }

    public void roll(byte outgoing, byte incoming) {
        a = (a - (outgoing & 0xff) + (incoming & 0xff)) & 0xffff;
        b = (b - window * (outgoing & 0xff) + a) & 0xffff;
    }
}
