package org.aegis.messenger.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.BeforeClass
import org.junit.Test
import java.io.File

/** Disappearing-message timer: ttl/gttl envelopes and local expiry (spec section 5.2). */
class TimerTest {
    companion object {
        lateinit var v: Map<String, Any?>

        @BeforeClass
        @JvmStatic
        fun load() {
            val path = System.getProperty("aegis.vectors") ?: error("aegis.vectors not set")
            v = Json.parseObject(File(path).readText(Charsets.UTF_8))
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun obj(m: Map<String, Any?>, k: String) = m[k] as Map<String, Any?>

    @Suppress("UNCHECKED_CAST")
    private fun list(m: Map<String, Any?>, k: String) = m[k] as List<Map<String, Any?>>

    private fun s(m: Map<String, Any?>, k: String) = m[k] as String
    private fun h(m: Map<String, Any?>, k: String) = Hex.decode(s(m, k))
    private fun n(m: Map<String, Any?>, k: String) = m[k] as Long

    private fun ttlEnv(ttlS: Long, kind: Kind = Kind.Ttl, groupId: String = "", body: String = "") = Envelope(
        kind, "00112233445566778899aabbccddeeff", "alice", "Alice", ByteArray(32) { 7 },
        1_700_000_000_123, ttlS, groupId, body,
    )

    @Test
    fun vectorsMatchTheRustCore() {
        val t = obj(v, "timer")
        @Suppress("UNCHECKED_CAST")
        assertEquals(Expiry.TTL_CHOICES, t["choices"] as List<Long>)
        for (k in listOf("ttl_envelope", "gttl_envelope")) {
            val j = obj(t, k)
            val e = Envelope.decode(h(j, "encoded"))
            assertEquals(s(j, "kind"), e.kind.wire)
            assertEquals(n(j, "ttl_s"), e.ttlS)
            assertEquals(s(j, "encoded"), Hex.encode(e.encode()))
            val built = Envelope(
                e.kind, s(j, "msg_id"), s(j, "sender"), s(j, "sender_name_text"), h(j, "sender_ed"),
                n(j, "ts_ms"), n(j, "ttl_s"), s(j, "group_id"), s(j, "body_text"),
            )
            assertEquals(s(j, "encoded"), Hex.encode(built.encode()))
        }
        val g = h(t, "g")
        val chain = SendChain.createWith(h(t, "chain_id"), h(t, "ck"), n(t, "now"))
        val gttl = Envelope.decode(h(obj(t, "gttl_envelope"), "encoded"))
        val alice = Identity(ByteArray(32) { (0x10 + it).toByte() }, ByteArray(32) { (0x20 + it).toByte() })
        val frame = chain.encryptWith(h(t, "hnonce"), SkScope.Group, g, alice.edSecret, gttl)
        assertEquals(s(t, "gttl_frame"), Hex.encode(frame))
        val set = RecvSet(SkScope.Group, g, null)
        set.addFromSkey(Envelope.decode(h(obj(t, "skey_envelope"), "encoded")), n(t, "now"))
        val out = set.decrypt(frame, n(t, "now"))
        assertEquals(Kind.Gttl, out.kind)
        assertEquals(30L, out.ttlS)
        for (c in list(t, "expiry")) {
            assertEquals(c["expired"] as Boolean, Expiry.isExpired(n(c, "base_ms"), n(c, "ttl_s"), n(c, "now_ms")))
        }
    }

    @Test
    fun choicesAndBounds() {
        for (t in Expiry.TTL_CHOICES) assertTrue(Expiry.allowed(t))
        for (t in listOf(1L, 29L, 60L, 7200L, 604_801L, -1L)) assertFalse(Expiry.allowed(t))
        assertFalse(Expiry.isExpired(1000, 0, Long.MAX_VALUE))
        assertFalse(Expiry.isExpired(1000, 30, 30_999))
        assertTrue(Expiry.isExpired(1000, 30, 31_000))
        assertFalse(Expiry.isExpired(Long.MAX_VALUE - 10, Long.MAX_VALUE, Long.MAX_VALUE - 1))
    }

    @Test
    fun ttlEnvelopesRejectExtraFields() {
        val g = "ab".repeat(32)
        for (t in Expiry.TTL_CHOICES) {
            val e = ttlEnv(t)
            assertEquals(Hex.encode(e.encode()), Hex.encode(Envelope.decode(e.encode()).encode()))
        }
        ttlEnv(30, Kind.Gttl, g).encode()
        for (bad in listOf(ttlEnv(30, body = "x"), ttlEnv(30, groupId = g), ttlEnv(30, Kind.Gttl))) {
            try { bad.encode(); fail() } catch (_: AegisException) {}
        }
        try { Seal.sealDm(ByteArray(32) { 1 }, ByteArray(32) { 2 }, ttlEnv(30, Kind.Gttl, g)); fail() } catch (_: AegisException) {}
    }
}
