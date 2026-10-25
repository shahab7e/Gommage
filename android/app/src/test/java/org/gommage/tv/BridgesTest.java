package org.gommage.tv;

import static org.junit.Assert.*;

import java.util.Arrays;

import org.junit.Test;

public class BridgesTest {
    static final String OBFS4 = "obfs4 1.2.3.4:443 " + "A".repeat(40) + " cert=" + "x".repeat(70) + " iat-mode=0";
    static final String WT = "webtunnel [2001:db8::1]:443 " + "B".repeat(40) + " url=https://ex.com/p ver=0.0.3";

    @Test
    public void parseValidateTarget() {
        assertEquals(Arrays.asList(OBFS4, WT), Bridges.clean("Bridge " + OBFS4 + "\n\n# c\n" + WT + "\n" + OBFS4));
        assertTrue(Bridges.VALID.matcher(OBFS4).matches());
        assertTrue(Bridges.VALID.matcher(WT).matches());
        assertFalse(Bridges.VALID.matcher(OBFS4 + " evil=1").matches());
        assertArrayEquals(new String[]{"1.2.3.4", "443", ""}, Bridges.target(OBFS4));
        assertArrayEquals(new String[]{"ex.com", "443", "tls"}, Bridges.target(WT));
        assertNull(Bridges.target("snowflake 192.0.2.3:80 " + "C".repeat(40)));
        assertEquals("A".repeat(40), Bridges.fingerprint(OBFS4));
    }
}
