package io.rsyncj.client;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RemoteTargetTest {

    @Test
    void hostPortSlashPath() {
        // The form that was previously mis-parsed as host "host" port 8443 path "9443/GWMigration".
        Main.RemoteTarget t = Main.RemoteTarget.parse("js33110@nvlasddpl001vd.spr.bz:9443/GWMigration");
        assertEquals("js33110", t.user());
        assertEquals("nvlasddpl001vd.spr.bz", t.host());
        assertEquals(9443, t.port());
        assertEquals("/GWMigration", t.path());
    }

    @Test
    void hostPortColonPath() {
        Main.RemoteTarget t = Main.RemoteTarget.parse("alice@example.com:9443:/backup/dir");
        assertEquals("example.com", t.host());
        assertEquals(9443, t.port());
        assertEquals("/backup/dir", t.path());

        Main.RemoteTarget relative = Main.RemoteTarget.parse("alice@example.com:9443:backup");
        assertEquals(9443, relative.port());
        assertEquals("backup", relative.path());
    }

    @Test
    void hostPathDefaultPort() {
        Main.RemoteTarget t = Main.RemoteTarget.parse("alice@example.com:/backup");
        assertEquals(8443, t.port());
        assertEquals("/backup", t.path());

        Main.RemoteTarget relative = Main.RemoteTarget.parse("alice@example.com:backup");
        assertEquals(8443, relative.port());
        assertEquals("backup", relative.path());
    }

    @Test
    void urlForm() {
        Main.RemoteTarget t = Main.RemoteTarget.parse("rsyncj://alice@example.com:9443/data/x");
        assertEquals("alice", t.user());
        assertEquals(9443, t.port());
        assertEquals("/data/x", t.path());

        assertEquals(8443, Main.RemoteTarget.parse("rsyncj://example.com/data").port());
    }

    @Test
    void portWithoutPathIsRejectedWithHint() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> Main.RemoteTarget.parse("alice@example.com:9443"));
        assertEquals(true, e.getMessage().contains("looks like a port"));
    }

    @Test
    void invalidInputs() {
        assertThrows(IllegalArgumentException.class, () -> Main.RemoteTarget.parse("example.com"));
        assertThrows(IllegalArgumentException.class, () -> Main.RemoteTarget.parse("alice@example.com:"));
        assertThrows(IllegalArgumentException.class, () -> Main.RemoteTarget.parse("alice@example.com:70000:/x"));
    }

    @Test
    void hostOnly() {
        Main.RemoteTarget t = Main.RemoteTarget.parseHost("alice@example.com:9443");
        assertEquals(9443, t.port());
        assertEquals(8443, Main.RemoteTarget.parseHost("example.com").port());
        assertEquals(9443, Main.RemoteTarget.parseHost("rsyncj://alice@example.com:9443").port());
    }

    @Test
    void portOverride() {
        Main.RemoteTarget t = Main.RemoteTarget.parse("alice@example.com:/x").withPort(9443);
        assertEquals(9443, t.port());
        assertEquals("/x", t.path());
    }
}
