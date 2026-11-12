package org.aegis.messenger.core

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Lets exactly one network request through per cover slot (spec section 26). While [active], every
 * request waits for a slot; the runner grants them one at a time. Requests made from the poll
 * thread are marked with [asPoll] so a poll cycle never takes more than one request per slot.
 */
class SlotGate(
    private val active: () -> Boolean,
    private val wake: () -> Unit,
    private val waitMs: Long = 20_000L,
) {
    private class Waiter(val poll: Boolean) {
        val latch = CountDownLatch(1)
        @Volatile var granted = false
    }

    private val lock = Any()
    private val waiters = ArrayList<Waiter>()
    private var credit = 0
    private val pollThread = ThreadLocal<Boolean>()

    /** Runs [f] with requests counted as part of a poll cycle. */
    fun <T> asPoll(f: () -> T): T {
        pollThread.set(true)
        try { return f() } finally { pollThread.set(false) }
    }

    /** Requests waiting for a slot, real and poll. */
    fun queued(): Int = synchronized(lock) { waiters.size }

    /** Runs [call] (one request) in the next slot when cover traffic is on, at once otherwise. */
    fun <T> pass(call: () -> T): T {
        if (!active()) return call()
        val poll = pollThread.get() == true
        val w = Waiter(poll)
        synchronized(lock) {
            if (poll && credit > 0) {
                credit--
                w.granted = true
            } else {
                waiters.add(w)
            }
        }
        if (!w.granted) {
            wake()
            val ok = w.latch.await(waitMs, TimeUnit.MILLISECONDS)
            if (!ok) {
                synchronized(lock) { waiters.remove(w) }
                if (!w.granted) throw AegisException.Network("no slot")
            }
            if (!w.granted) throw AegisException.Network("cancelled")
        }
        return call()
    }

    /** A real slot: the oldest user-driven request goes, else the oldest poll request. False when nobody waits. */
    fun grantReal(): Boolean = synchronized(lock) {
        val w = waiters.firstOrNull { !it.poll } ?: waiters.firstOrNull() ?: return false
        waiters.remove(w)
        w.granted = true
        w.latch.countDown()
        true
    }

    /** A poll slot: the first request of a new poll cycle may use it. */
    fun grantPollStart() { synchronized(lock) { credit++ } }

    /** Takes back an unused poll slot; true if there was one. */
    fun takeCredit(): Boolean = synchronized(lock) { if (credit > 0) { credit--; true } else false }

    /** Fails every waiting request (the vault locked). */
    fun reset() {
        synchronized(lock) {
            credit = 0
            for (w in waiters) w.latch.countDown()
            waiters.clear()
        }
    }
}
