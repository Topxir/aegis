package org.aegis.messenger.net

import org.aegis.messenger.net.Bridges.Mode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class BridgesTest {
    private val webtunnel = "webtunnel [2001:db8:3d87:60f1:6b2:5c2a:a1a7:4d5e]:443 4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A url=https://example.com/aBcD ver=0.0.1"
    private val ports = mapOf("obfs4" to 47001, "meek_lite" to 47002, "webtunnel" to 47003, "snowflake" to 47004)
    private fun rc(mode: Mode, custom: String) = Bridges.torrc(mode, custom) { ports[it] }

    private fun invalid(text: String): Bridges.Invalid {
        try {
            Bridges.check(Mode.Custom, text)
        } catch (e: Bridges.Invalid) {
            return e
        }
        fail("accepted: $text")
        throw IllegalStateException()
    }

    @Test
    fun offWritesNoBridgeOptions() {
        assertEquals("", rc(Mode.Off, webtunnel))
        assertEquals(Mode.Off, Mode.parse("off"))
        assertNull(Mode.parse("garbage"))
    }

    @Test
    fun snowflakeUsesTheBuiltinListAndItsLocalPort() {
        val lines = rc(Mode.Snowflake, "").trimEnd('\n').split('\n')
        assertEquals("UseBridges 1", lines[0])
        assertEquals("ClientTransportPlugin snowflake socks5 127.0.0.1:47004", lines[1])
        assertEquals(2 + Bridges.SNOWFLAKE.size, lines.size)
        for ((l, b) in lines.drop(2).zip(Bridges.SNOWFLAKE)) assertEquals("Bridge $b", l)
        val o = Bridges.options(Bridges.SNOWFLAKE, "snowflake")
        assertTrue(o.getValue("url").startsWith("https://"))
        assertTrue(o.getValue("ice").startsWith("stun:"))
    }

    @Test
    fun obfs4UsesTheBuiltinList() {
        val rc = rc(Mode.Obfs4, "")
        assertTrue(rc.startsWith("UseBridges 1\nClientTransportPlugin obfs4 socks5 127.0.0.1:47001\nBridge obfs4 "))
        assertFalse(rc.contains("snowflake"))
        assertEquals(Bridges.OBFS4.size, rc.split("\nBridge obfs4 ").size - 1)
        for (b in Bridges.OBFS4 + Bridges.SNOWFLAKE) assertEquals(b, Bridges.parseLine(b))
        assertEquals(listOf("obfs4"), Bridges.transports(Bridges.OBFS4))
    }

    @Test
    fun customLinesAreCheckedAndNormalized() {
        val text = "  Bridge $webtunnel\r\n\n# comment\n198.51.100.7:9001\t0123456789ABCDEF0123456789ABCDEF01234567\n$webtunnel\n"
        val stored = Bridges.check(Mode.Custom, text)
        assertEquals("$webtunnel\n198.51.100.7:9001 0123456789ABCDEF0123456789ABCDEF01234567", stored)
        assertEquals(
            "UseBridges 1\nClientTransportPlugin webtunnel socks5 127.0.0.1:47003\nBridge $webtunnel\nBridge 198.51.100.7:9001 0123456789ABCDEF0123456789ABCDEF01234567\n",
            rc(Mode.Custom, stored),
        )
        // Plain relays as bridges need no transport.
        assertEquals("UseBridges 1\nBridge 203.0.113.5:443\n", rc(Mode.Custom, "203.0.113.5:443"))
        // A transport that did not start leaves its bridges out instead of failing open.
        assertEquals("", Bridges.torrc(Mode.Obfs4, "") { null })
    }

    @Test
    fun badLinesAreRefusedWithTheirNumber() {
        for ((text, n) in listOf(
            "obfs4 1.2.3.4 cert=x" to 1,
            "\nobfs5 1.2.3.4:443" to 2,
            "obfs4 1.2.3.4:0 cert=x" to 1,
            "obfs4 example.com:443 cert=x" to 1,
            "obfs4 1.2.3.4:443 cert" to 1,
            "obfs4 1.2.3.4:443 =x" to 1,
            "UseBridges 0" to 1,
            "Socks5Proxy 127.0.0.1:1" to 1,
            "1.2.3.4:443 key=value" to 1,
            "obfs4 1.2.3.4:443 cert=\u007f" to 1,
            "obfs4 1.2.3.4:443 cert=\u0000x" to 1,
            "obfs4 1.2.3.4:443 cert=\u0442" to 1,
            "obfs4 [example.com]:443 cert=x" to 1,
        )) {
            assertEquals(text, n, invalid(text).line)
        }
        assertTrue(invalid("  \n# only a comment").empty)
        assertTrue(invalid((0..Bridges.MAX_LINES).joinToString("") { "203.0.113.$it:443\n" }).tooMany)
        assertNull(Bridges.parseLine("obfs4 1.2.3.4:443 cert=" + "a".repeat(Bridges.MAX_LINE)))
    }

    @Test
    fun storedTextCannotInjectTorrcOptions() {
        val evil = "obfs4 1.2.3.4:443 cert=x\nSocksPort 0.0.0.0:9050\nobfs4 1.2.3.4:443 cert=x\rExitNodes {ru}\nBridge 5.6.7.8:443\n%include C:\\x"
        val rc = rc(Mode.Custom, evil)
        for (line in rc.trimEnd('\n').split('\n')) {
            assertTrue(line, line == "UseBridges 1" || line.startsWith("ClientTransportPlugin ") || line.startsWith("Bridge "))
        }
        assertFalse(rc.contains("SocksPort") || rc.contains("ExitNodes") || rc.contains("%include"))
        assertTrue(rc.contains("Bridge 5.6.7.8:443\n"))
    }
}
