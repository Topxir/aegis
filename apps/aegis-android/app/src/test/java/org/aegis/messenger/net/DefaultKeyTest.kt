package org.aegis.messenger.net

import org.aegis.messenger.core.AegisException
import org.aegis.messenger.core.Hex
import org.junit.Assert.assertEquals
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.fail
import org.junit.Test

class DefaultKeyTest {
    private class Memory : KeyPins {
        val m = HashMap<String, ByteArray>()
        override fun get(origin: String): ByteArray? = m[origin]
        override fun put(origin: String, key: ByteArray) { m[origin] = key }
        override fun remove(origin: String) { m.remove(origin) }
    }

    @Test
    fun theCompiledKeyIsTheDefaultServers() {
        assertEquals("8e5b9b5c709ec893f16624d00d410dc697887d4dee434d5bcf5f705a35062860", Hex.encode(Endpoint.DEFAULT_SERVER_X_PK!!))
    }

    @Test
    fun aDifferentKeyOnTheDefaultEndpointIsRefused() {
        val pins = Memory()
        val fake = ByteArray(32) { 7 }
        val inner = object : Transport {
            override fun request(ep: Endpoint, method: String, pathQuery: String, body: ByteArray?, contentType: String?): Response =
                if (method == "GET" && pathQuery.contains("key")) Response(200, ("{\"x\":\"" + Hex.encode(fake) + "\"}").toByteArray()) else Response(500, ByteArray(0))
        }
        val t = SealedTransport(inner, pins)
        try {
            t.request(Endpoint.parse(Endpoint.DEFAULT), "GET", "/health", null, null)
            fail()
        } catch (e: AegisException.ServerKeyChanged) {
        }
        assertEquals(null, pins.get(Endpoint.DEFAULT))
    }
}
