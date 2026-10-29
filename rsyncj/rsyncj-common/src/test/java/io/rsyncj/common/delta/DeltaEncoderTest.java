package io.rsyncj.common.delta;

import io.rsyncj.common.util.Hex;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DeltaEncoderTest {

    @Test
    void rollingChecksumMatchesDirectComputation() {
        byte[] data = new byte[100];
        new Random(7).nextBytes(data);
        RollingChecksum rolling = new RollingChecksum();
        rolling.reset(data, 10, 32);
        int direct = directWeak(data, 10, 32);
        assertEquals(direct, rolling.value());

        for (int i = 0; i < 40; i++) {
            rolling.roll(data[10 + i], data[42 + i]);
            assertEquals(directWeak(data, 11 + i, 32), rolling.value(), "roll " + i);
        }
    }

    @Test
    void deltaRoundTripReusesUnchangedBlocks() throws Exception {
        Random random = new Random(42);
        byte[] oldData = new byte[300_000];
        random.nextBytes(oldData);

        // New file: 50k prefix inserted, one block changed, tail removed.
        byte[] inserted = new byte[50_000];
        random.nextBytes(inserted);
        byte[] newData = new byte[oldData.length + inserted.length - 20_000];
        System.arraycopy(inserted, 0, newData, 0, inserted.length);
        System.arraycopy(oldData, 0, newData, inserted.length, oldData.length - 20_000);
        for (int i = 100_000; i < 104_096; i++) {
            newData[i] ^= 0x5a;
        }

        int blockSize = 4096;
        List<BlockSignature> signatures = signatures(oldData, blockSize);
        Map<Integer, List<BlockSignature>> table = new HashMap<>();
        for (BlockSignature signature : signatures) {
            table.computeIfAbsent(signature.weak(), k -> new ArrayList<>()).add(signature);
        }

        ByteArrayOutputStream rebuilt = new ByteArrayOutputStream();
        long[] reused = {0};
        String sha = DeltaEncoder.encode(new ByteArrayInputStream(newData), oldData.length, blockSize, table, new DeltaEncoder.Sink() {
            @Override
            public void copy(long blockIndex) {
                int offset = (int) blockIndex * blockSize;
                int length = Math.min(blockSize, oldData.length - offset);
                rebuilt.write(oldData, offset, length);
                reused[0] += length;
            }

            @Override
            public void literal(byte[] buffer, int offset, int length) {
                rebuilt.write(buffer, offset, length);
            }
        });

        assertArrayEquals(newData, rebuilt.toByteArray());
        assertEquals(Hex.encode(MessageDigest.getInstance("SHA-256").digest(newData)), sha);
        assertTrue(reused[0] > newData.length / 2, "expected most blocks to be reused, got " + reused[0]);
    }

    @Test
    void emptyAndTinyFiles() throws Exception {
        int blockSize = 4096;
        for (byte[] data : new byte[][]{{}, {1}, new byte[4095], new byte[4096], new byte[4097]}) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            String sha = DeltaEncoder.encode(new ByteArrayInputStream(data), data.length, blockSize, Map.of(), new DeltaEncoder.Sink() {
                @Override
                public void copy(long blockIndex) {
                    throw new AssertionError("no copies expected");
                }

                @Override
                public void literal(byte[] buffer, int offset, int length) {
                    out.write(buffer, offset, length);
                }
            });
            assertArrayEquals(data, out.toByteArray());
            assertEquals(Hex.encode(MessageDigest.getInstance("SHA-256").digest(data)), sha);
        }
    }

    @Test
    void rejectsOutOfRangeCopyIndex() {
        assertThrows(RuntimeException.class, () -> DeltaEncoder.validateBlockIndex(5, 100, 4096));
        DeltaEncoder.validateBlockIndex(0, 100, 4096);
    }

    private static List<BlockSignature> signatures(byte[] data, int blockSize) {
        List<BlockSignature> result = new ArrayList<>();
        int index = 0;
        for (int offset = 0; offset < data.length; offset += blockSize, index++) {
            int length = Math.min(blockSize, data.length - offset);
            RollingChecksum checksum = new RollingChecksum();
            checksum.reset(data, offset, length);
            result.add(new BlockSignature(index, checksum.value(),
                    BlockSignature.strongHash(data, offset, length)));
        }
        return result;
    }

    private static int directWeak(byte[] data, int offset, int length) {
        int a = 0;
        int b = 0;
        for (int i = 0; i < length; i++) {
            a += data[offset + i] & 0xff;
            b += a;
        }
        return ((b & 0xffff) << 16) | (a & 0xffff);
    }

    @Test
    void blockSizeStaysBounded() {
        assertEquals(4096, DeltaEncoder.blockSizeFor(0));
        assertEquals(4096, DeltaEncoder.blockSizeFor(10_000_000));
        assertTrue(DeltaEncoder.blockSizeFor(10L * 1024 * 1024 * 1024) > 4096);
        assertTrue(DeltaEncoder.blockSizeFor(Long.MAX_VALUE / 2) <= 1024 * 1024);
    }

    @Test
    void signaturesAreStable() {
        byte[] block = "hello rsyncj".getBytes();
        assertArrayEquals(BlockSignature.strongHash(block, 0, block.length),
                Arrays.copyOf(BlockSignature.strongHash(block, 0, block.length), BlockSignature.STRONG_LENGTH));
    }
}
