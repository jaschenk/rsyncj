package io.rsyncj.common.util;

import io.rsyncj.common.protocol.ProtocolException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PathSafetyTest {

    @Test
    void resolvesRelativeAndAbsoluteStylePaths(@TempDir Path root) {
        assertEquals(root.resolve("a/b").toAbsolutePath().normalize(),
                PathSafety.resolve(root, "a/b"));
        assertEquals(root.resolve("a/b").toAbsolutePath().normalize(),
                PathSafety.resolve(root, "/a/b"));
    }

    @Test
    void rejectsTraversal(@TempDir Path root) {
        assertThrows(ProtocolException.class, () -> PathSafety.resolve(root, "../etc/passwd"));
        assertThrows(ProtocolException.class, () -> PathSafety.resolve(root, "a/../../etc"));
        assertThrows(ProtocolException.class, () -> PathSafety.resolve(root, ".."));
        assertThrows(ProtocolException.class, () -> PathSafety.resolve(root, ""));
        assertThrows(ProtocolException.class, () -> PathSafety.resolve(root, "a\0b"));
    }

    @Test
    void relativiseRoundTrips(@TempDir Path root) {
        Path target = PathSafety.resolve(root, "x/y.txt");
        assertEquals("x/y.txt", PathSafety.relativise(root, target));
    }
}
