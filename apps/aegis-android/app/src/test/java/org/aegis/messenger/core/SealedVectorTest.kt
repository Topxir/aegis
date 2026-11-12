package org.aegis.messenger.core

import org.aegis.messenger.net.Sealed
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import java.io.File

class SealedVectorTest {
    @Test
    fun sealedTransport() {
        val path = System.getProperty("aegis.vectors") ?: error("aegis.vectors not set")
        @Suppress("UNCHECKED_CAST")
        val m = Json.parseObject(File(path).readText(Charsets.UTF_8))["sealed_transport"] as Map<String, Any?>
        fun h(k: String) = Hex.decode(m[k] as String)
        assertEquals(m["srv_pk"], Hex.encode(Crypto.x25519Public(h("srv_sk"))))
        val body = Text.utf8(m["body_text"] as String)
        val r = Sealed.sealRequestWith(h("e_sk"), h("srv_pk"), m["method"] as String, m["target"] as String, body)
        assertEquals(m["request"], Hex.encode(r.outer))
        assertEquals((m["request_len"] as Long).toInt(), r.outer.size)
        assertEquals(m["k_resp"], Hex.encode(r.kResp))
        val inner = Text.utf8(m["response_body_text"] as String)
        val resp = Sealed.sealResponseWith(h("response_nonce"), r.kResp, (m["response_status"] as Long).toInt(), inner)
        assertEquals(m["response"], Hex.encode(resp))
        assertEquals((m["response_len"] as Long).toInt(), resp.size)
        val o = Sealed.openResponse(r.kResp, resp)
        assertEquals((m["response_status"] as Long).toInt(), o.code)
        assertArrayEquals(inner, o.body)
    }

    @Test
    fun requestCarriesTheClockAfterTheMethod() {
        val srv = Crypto.x25519Public(ByteArray(32) { 9 })
        val r = Sealed.sealRequestAt(ByteArray(32) { 5 }, srv, "GET", "/api/v2/key", ByteArray(0), 1700000000L)
        val plain = Sealed.sealRequestAt(ByteArray(32) { 5 }, srv, "GET", "/api/v2/key", ByteArray(0), null)
        assertEquals(plain.outer.size, r.outer.size)
        assertFalse(Hex.encode(plain.outer) == Hex.encode(r.outer))
        assertEquals(Hex.encode(Sealed.sealRequestWith(ByteArray(32) { 5 }, srv, "GET", "/api/v2/key", ByteArray(0)).outer), Hex.encode(plain.outer))
    }

    @Test
    fun padRules() {
        assertEquals(1024, Sealed.pad(ByteArray(0)).size)
        assertEquals(1024, Sealed.pad(ByteArray(1020)).size)
        assertEquals(4096, Sealed.pad(ByteArray(1021)).size)
        val p = Sealed.pad(byteArrayOf(1))
        p[1023] = 1
        try { Sealed.unpad(p); throw AssertionError() } catch (_: AegisException) {}
    }
}
