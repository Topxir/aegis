package org.aegis.messenger.net

import org.aegis.messenger.core.AegisException
import org.aegis.messenger.core.Hex
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class RouteTest {
    private class Memory : KeyPins {
        val m = HashMap<String, ByteArray>()
        override fun get(origin: String): ByteArray? = m[origin]
        override fun put(origin: String, key: ByteArray) { m[origin] = key }
        override fun remove(origin: String) { m.remove(origin) }
    }

    @Test
    fun torOnSendsTheDefaultServerToItsOnionAddress() {
        for (e in listOf(Endpoint.DEFAULT, Endpoint.ONION, "https://FreeOasis.space/")) {
            val r = Route.plan(true, e, "")
            assertEquals(Endpoint.ONION, r.endpoint)
            assertTrue(r.viaTor)
            assertEquals("", r.proxy)
        }
    }

    @Test
    fun torOnIgnoresTheManualProxyAndKeepsCustomServers() {
        val r = Route.plan(true, "https://chat.example.org", "127.0.0.1:9050")
        assertEquals("https://chat.example.org", r.endpoint)
        assertEquals("", r.proxy)
        assertTrue(r.viaTor)
    }

    @Test
    fun torOffGoesToClearnetAndNeverToTheOnion() {
        for (e in listOf(Endpoint.DEFAULT, Endpoint.ONION)) {
            val r = Route.plan(false, e, "")
            assertEquals(Endpoint.DEFAULT, r.endpoint)
            assertFalse(r.viaTor)
        }
        assertEquals("127.0.0.1:9050", Route.plan(false, Endpoint.DEFAULT, "127.0.0.1:9050").proxy)
    }

    @Test
    fun theOnionParsesAsPlainHttpOnTheDefaultPort() {
        val ep = Endpoint.parse(Endpoint.ONION)
        assertTrue(ep.isOnion)
        assertFalse(ep.https)
        assertEquals(80, ep.port)
        assertEquals(Endpoint.ONION, ep.origin)
    }

    @Test
    fun onionAndDefaultShareTheCompiledKey() {
        assertArrayEquals(Endpoint.DEFAULT_SERVER_X_PK, Endpoint.builtInKey(Endpoint.ONION))
        assertArrayEquals(Endpoint.DEFAULT_SERVER_X_PK, Endpoint.builtInKey(Endpoint.DEFAULT))
        assertNull(Endpoint.builtInKey("http://other.onion"))
        assertNull(Endpoint.builtInKey("https://chat.example.org"))
    }

    @Test
    fun aDifferentKeyOnTheOnionIsRefusedAndNotPinned() {
        val pins = Memory()
        val fake = ByteArray(32) { 9 }
        val inner = object : Transport {
            override fun request(ep: Endpoint, method: String, pathQuery: String, body: ByteArray?, contentType: String?): Response =
                if (method == "GET" && pathQuery.contains("key")) Response(200, ("{\"x\":\"" + Hex.encode(fake) + "\"}").toByteArray()) else Response(500, ByteArray(0))
        }
        try {
            SealedTransport(inner, pins).request(Endpoint.parse(Endpoint.ONION), "GET", "/health", null, null)
            fail()
        } catch (e: AegisException.ServerKeyChanged) {
        }
        assertNull(pins.get(Endpoint.ONION))
    }
}
