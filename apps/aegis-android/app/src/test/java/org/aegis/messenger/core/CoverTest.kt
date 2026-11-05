package org.aegis.messenger.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CoverTest {
    @Test
    fun rateMatchesMeanAndMinimum() {
        for ((m, mean) in listOf(CoverMode.Standard to 30_000.0, CoverMode.High to 12_000.0)) {
            val rng = SeededCoverRng(7)
            val s = CoverScheduler(m, 0, rng)
            val times = ArrayList<Long>()
            var now = 0L
            while (times.size < 30_000) {
                when (val t = s.tick(now, 0, false, rng)) {
                    is CoverTick.Wait -> now = t.untilMs
                    is CoverTick.Slot -> { assertTrue(t.slot is CoverSlot.Dummy); times.add(now) }
                    CoverTick.Off -> error("off")
                }
            }
            val gaps = times.zipWithNext { a, b -> b - a }
            assertTrue(gaps.all { it >= Cover.MIN_GAP_MS })
            val avg = gaps.sum().toDouble() / gaps.size
            assertTrue("$m $avg", Math.abs(avg / mean - 1.0) < 0.03)
        }
    }

    @Test
    fun slotOrderAndSizes() {
        val rng = SeededCoverRng(1)
        val s = CoverScheduler(CoverMode.High, 0, rng)
        s.recordRequest(300)
        s.recordResponse(100_000)
        var now = s.nextSlotMs()!!
        assertTrue((s.tick(now, 2, true, rng) as CoverTick.Slot).slot is CoverSlot.Real)
        assertEquals(now + Cover.MIN_GAP_MS, s.nextSlotMs())
        now = s.nextSlotMs()!!
        assertTrue((s.tick(now, 0, true, rng) as CoverTick.Slot).slot is CoverSlot.Poll)
        now = s.nextSlotMs()!!
        val d = (s.tick(now, 0, false, rng) as CoverTick.Slot).slot as CoverSlot.Dummy
        assertEquals(300, d.reqLen)
        assertEquals(4096, d.respLen)
        assertEquals(4096, Cover.maxRespLen(300).coerceAtMost(4096))
        assertEquals(65536, Cover.maxRespLen(20_000))
        val body = Cover.nopBody(d.reqLen, d.respLen)
        assertEquals(300, body.size)
        assertEquals(4096L, Bytes.be32(body, 0))
    }

    @Test
    fun offAndEarlySlot() {
        val rng = SeededCoverRng(3)
        val off = CoverScheduler(CoverMode.Off, 0, rng)
        assertTrue(off.tick(1_000_000, 0, false, rng) is CoverTick.Off)
        val s = CoverScheduler(CoverMode.Standard, 0, rng)
        val before = s.nextSlotMs()!!
        s.earlySlot(0)
        if (before > Cover.MIN_GAP_MS) assertEquals(0L, s.nextSlotMs())
    }
}
