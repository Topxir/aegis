package org.aegis.messenger.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class SlotGateTest {
    private fun waitQueued(g: SlotGate, n: Int) {
        val end = System.currentTimeMillis() + 3000
        while (g.queued() < n && System.currentTimeMillis() < end) Thread.sleep(5)
        assertEquals(n, g.queued())
    }

    @Test
    fun passesThroughWhenInactive() {
        val g = SlotGate({ false }, {})
        assertEquals(5, g.pass { 5 })
    }

    @Test
    fun oneRequestPerSlot() {
        val g = SlotGate({ true }, {})
        val done = AtomicInteger()
        val threads = (1..3).map { Thread { g.pass { done.incrementAndGet() } }.also { it.start() } }
        waitQueued(g, 3)
        assertEquals(0, done.get())
        assertTrue(g.grantReal())
        Thread.sleep(100)
        assertEquals(1, done.get())
        assertEquals(2, g.queued())
        assertTrue(g.grantReal())
        assertTrue(g.grantReal())
        threads.forEach { it.join(3000) }
        assertEquals(3, done.get())
        assertFalse(g.grantReal())
    }

    @Test
    fun aPollCycleTakesOneSlotPerRequest() {
        val g = SlotGate({ true }, {})
        val done = AtomicInteger()
        g.grantPollStart()
        val t = Thread {
            g.asPoll { repeat(3) { g.pass { done.incrementAndGet() } } }
        }
        t.start()
        waitQueued(g, 1)
        assertEquals(1, done.get())
        assertTrue(g.grantReal())
        waitQueued(g, 1)
        assertEquals(2, done.get())
        assertTrue(g.grantReal())
        t.join(3000)
        assertEquals(3, done.get())
        assertFalse(g.takeCredit())
    }

    @Test
    fun resetFailsWaiters() {
        val g = SlotGate({ true }, {})
        val failed = CountDownLatch(1)
        Thread {
            try { g.pass { 1 } } catch (e: AegisException.Network) { failed.countDown() }
        }.start()
        waitQueued(g, 1)
        g.reset()
        assertTrue(failed.await(3, TimeUnit.SECONDS))
    }
}
