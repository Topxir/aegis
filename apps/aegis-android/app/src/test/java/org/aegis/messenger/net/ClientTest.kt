package org.aegis.messenger.net

import org.aegis.messenger.core.Hex
import org.aegis.messenger.core.Pin
import org.aegis.messenger.core.Pow
import org.aegis.messenger.core.Text
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Client behaviour against a scripted transport. */
class ClientTest {
    private class Req(val method: String, val path: String, val body: ByteArray?, val type: String?)

    private class Fake(private val answers: ArrayDeque<Response>) : Transport {
        val seen = ArrayList<Req>()
        override fun request(ep: Endpoint, method: String, pathQuery: String, body: ByteArray?, contentType: String?): Response {
            seen.add(Req(method, pathQuery, body, contentType))
            return answers.removeFirst()
        }
    }

    private fun json(code: Int, s: String) = Response(code, s.toByteArray())
    private fun client(vararg a: Response): Pair<Client, Fake> {
        val f = Fake(ArrayDeque(a.toList()))
        return Client(Endpoint.parse("http://127.0.0.1:8080"), f) to f
    }

    private fun query(path: String) = path.substringAfter('?').split('&').associate { it.substringBefore('=') to it.substringAfter('=') }
    private fun form(body: ByteArray?) = String(body!!, Charsets.UTF_8).split('&').associate { it.substringBefore('=') to it.substringAfter('=') }

    @Test
    fun sendRetriesOnceWithTheBitsFrom429() {
        val (c, f) = client(json(429, """{"bits":20}"""), json(200, """{"seq":7}"""))
        val q = ByteArray(16) { it.toByte() }
        assertEquals(7L, c.send(q, ByteArray(40)))
        assertEquals(2, f.seen.size)
        val second = f.seen[1]
        val p = query(second.path)
        assertEquals(Hex.encode(q), p["q"])
        val hash = Pow.bodyHashHex(second.body!!)
        assertTrue(Pow.verify(Hex.encode(q), p["ts"]!!.toLong(), hash, p["pow"]!!.toULong(), 20))
    }

    @Test
    fun sendIgnoresBitsOutOfRangeAndNeverLoops() {
        val (c, f) = client(json(429, """{"bits":29}"""))
        try { c.send(ByteArray(16), ByteArray(10)); error("expected failure") } catch (e: org.aegis.messenger.core.AegisException.Http) { assertEquals(429, e.code) }
        assertEquals(1, f.seen.size)
        val (c2, f2) = client(json(429, """{"bits":20}"""), json(429, """{"bits":24}"""))
        try { c2.send(ByteArray(16), ByteArray(10)); error("expected failure") } catch (e: org.aegis.messenger.core.AegisException.Http) { assertEquals(429, e.code) }
        assertEquals(2, f2.seen.size)
    }

    private fun page(vararg seqs: Long, more: Boolean, next: Long) =
        json(200, """{"frames":[""" + seqs.joinToString(",") { """{"seq":$it,"d":"00ff"}""" } + """],"next":$next,"has_more":$more}""")

    @Test
    fun hasMoreIsReportedAndCursorAdvances() {
        val (c, f) = client(page(1, 2, more = true, next = 2), page(3, more = false, next = 3))
        val q = ByteArray(16)
        var after = 0L
        var total = 0
        do {
            val r = c.poll(q, after)
            total += r.frames.size
            after = r.next
            val more = r.hasMore
        } while (more)
        assertEquals(3, total)
        assertEquals(3L, after)
        assertEquals(2, f.seen.size)
        assertTrue(f.seen[1].path.endsWith("after=2"))
    }

    @Test
    fun pollRejectsOutOfOrderSequence() {
        val (c, _) = client(page(2, 2, more = false, next = 2))
        try { c.poll(ByteArray(16), 0); error("expected failure") } catch (e: org.aegis.messenger.core.AegisException.BadResponse) { }
    }

    @Test
    fun pinEndpointForms() {
        val slot = ByteArray(16) { 1 }
        val v = ByteArray(32) { 2 }
        val s = ByteArray(32) { 3 }
        val sl = Hex.encode(slot)
        val (c, f) = client(json(200, "{}"), json(200, """{"s":"${Hex.encode(s)}"}"""), json(200, "{}"))
        c.pinCreate(slot, v, s)
        val open = c.pinOpen(slot, v)
        assertTrue(open is PinOpen.Ok)
        assertArrayEquals(s, (open as PinOpen.Ok).s)
        c.pinDelete(slot, v)
        val paths = f.seen.map { it.path }
        assertEquals(listOf("/api/v2/pin/create", "/api/v2/pin/open", "/api/v2/pin/delete"), paths)
        for (r in f.seen) {
            assertEquals("POST", r.method)
            assertEquals("application/x-www-form-urlencoded", r.type)
        }
        val create = form(f.seen[0].body)
        assertEquals(listOf("slot", "v", "s", "ts", "pow"), String(f.seen[0].body!!).split('&').map { it.substringBefore('=') })
        assertEquals(sl, create["slot"])
        assertEquals(Hex.encode(v), create["v"])
        assertEquals(Hex.encode(s), create["s"])
        assertTrue(Pow.verify(Pin.powScope(sl), create["ts"]!!.toLong(), Pow.bodyHashHex(Text.utf8(Pin.createHashInput(sl, Hex.encode(v), Hex.encode(s)))), create["pow"]!!.toULong(), Client.POW_BITS))
        assertEquals(listOf("slot", "v", "ts", "pow"), String(f.seen[1].body!!).split('&').map { it.substringBefore('=') })
        val open2 = form(f.seen[1].body)
        assertTrue(Pow.verify(Pin.powScope(sl), open2["ts"]!!.toLong(), Pow.bodyHashHex(Text.utf8(Pin.openHashInput(sl, Hex.encode(v)))), open2["pow"]!!.toULong(), Client.POW_BITS))
        assertEquals(listOf("slot", "v", "ts", "pow"), String(f.seen[2].body!!).split('&').map { it.substringBefore('=') })
    }

    @Test
    fun pinOpenAnswers() {
        val slot = ByteArray(16)
        val v = ByteArray(32)
        val (c, _) = client(json(403, """{"left":2}"""), json(404, "{}"))
        val w = c.pinOpen(slot, v)
        assertEquals(2, (w as PinOpen.Wrong).left)
        assertTrue(c.pinOpen(slot, v) === PinOpen.Gone)
        val (c2, f2) = client(json(404, "{}"))
        c2.pinDelete(slot, v)
        assertEquals(1, f2.seen.size)
    }

    @Test
    fun nopBodyAndRequest() {
        val (c, f) = client(Response(200, ByteArray(300)))
        assertEquals(300, c.nop(1024, 300))
        val r = f.seen[0]
        assertEquals("/api/v2/nop", r.path)
        assertEquals("application/octet-stream", r.type)
        assertEquals(1024, r.body!!.size)
        assertEquals(300L, org.aegis.messenger.core.Bytes.be32(r.body!!, 0))
        val tiny = org.aegis.messenger.core.Cover.nopBody(1, 10)
        assertEquals(4, tiny.size)
        val capped = org.aegis.messenger.core.Cover.nopBody(256, 1_000_000)
        assertEquals(256, capped.size)
        assertEquals(org.aegis.messenger.core.Cover.maxRespLen(256).toLong(), org.aegis.messenger.core.Bytes.be32(capped, 0))
        assertFalse(capped.isEmpty())
    }

    @Test
    fun observerSeesRealTrafficOnly() {
        val (c, _) = client(json(200, """{"seq":1}"""), page(1, more = false, next = 1), Response(200, ByteArray(10)))
        val seen = ArrayList<Pair<Int, Int>>()
        c.observe = { a, b -> seen.add(a to b) }
        c.send(ByteArray(16), ByteArray(10))
        c.poll(ByteArray(16), 0)
        c.nop(64, 10)
        assertEquals(2, seen.size)
        assertEquals(-1, seen[1].first)
    }
}
