package org.aegis.messenger.core

import org.aegis.messenger.net.Sealed
import kotlin.math.ln

/** Cover traffic scheduler (spec section 26). Pure logic: the caller owns the clock, the timer and the network. */
enum class CoverMode { Off, Standard, High }

interface CoverRng {
    /** Uniform in the open interval (0, 1). */
    fun unit(): Double

    /** Uniform in 0 until n (n > 0). */
    fun below(n: Long): Long
}

class OsCoverRng : CoverRng {
    private val r = java.security.SecureRandom()
    override fun unit(): Double = unitFrom(r.nextLong())
    override fun below(n: Long): Long = java.lang.Long.remainderUnsigned(r.nextLong(), maxOf(n, 1))
}

/** Seeded generator (SplitMix64) for tests. */
class SeededCoverRng(private var state: Long) : CoverRng {
    private fun next(): Long {
        state += -0x61c8864680b583ebL
        var z = state
        z = (z xor (z ushr 30)) * -0x40a7b892e31b1a47L
        z = (z xor (z ushr 27)) * -0x6b2fb644ecceee15L
        return z xor (z ushr 31)
    }

    override fun unit(): Double = unitFrom(next())
    override fun below(n: Long): Long = java.lang.Long.remainderUnsigned(next(), maxOf(n, 1))
}

private fun unitFrom(x: Long): Double = ((x ushr 11).toDouble() + 0.5) / (1L shl 53).toDouble()

sealed class CoverSlot {
    object Real : CoverSlot()
    object Poll : CoverSlot()
    class Dummy(val reqLen: Int, val respLen: Int) : CoverSlot()
}

sealed class CoverTick {
    object Off : CoverTick()
    class Wait(val untilMs: Long) : CoverTick()
    class Slot(val slot: CoverSlot) : CoverTick()
}

object Cover {
    const val MIN_GAP_MS = 2000L
    const val SIZE_HISTORY = 16
    const val DEFAULT_SIZE = 1024
    const val MAX_RESP_LEN = 65536

    /** Mean gap on Android in milliseconds; null when off. */
    fun meanGapMs(mode: CoverMode): Long? = when (mode) {
        CoverMode.Off -> null
        CoverMode.Standard -> 30_000L
        CoverMode.High -> 12_000L
    }

    /** Largest resp_len the server answers for a nop with a body of reqLen bytes. */
    fun maxRespLen(reqLen: Int): Int {
        val bucket = try { Sealed.bucketFor(reqLen) } catch (e: AegisException) { Sealed.BUCKETS[6] }
        return minOf(bucket.toLong() * 4, MAX_RESP_LEN.toLong()).toInt()
    }

    /** Body of POST /api/v2/nop: BE32(resp_len) followed by random bytes, reqLen bytes in total. */
    fun nopBody(reqLen: Int, respLen: Int): ByteArray {
        val total = maxOf(reqLen, 4)
        val body = Crypto.randomBytes(total)
        Bytes.putBe32(body, 0, minOf(respLen, maxRespLen(total)).toLong())
        return body
    }
}

class CoverScheduler(mode: CoverMode, nowMs: Long, rng: CoverRng) {
    var mode: CoverMode = mode
        private set
    private var nextMs = nowMs
    private var lastMs: Long? = null
    private var displacedMs: Long? = null
    private val reqs = ArrayDeque<Int>()
    private val resps = ArrayDeque<Int>()

    init {
        scheduleFrom(nowMs, rng)
    }

    fun setMode(m: CoverMode, nowMs: Long, rng: CoverRng) {
        mode = m
        displacedMs = null
        scheduleFrom(nowMs, rng)
    }

    /** Time of the next slot, or null when off. */
    fun nextSlotMs(): Long? = if (mode == CoverMode.Off) null else nextMs

    /** 2 s + Exp(mean - 2 s): the mean gap is the configured mean. */
    fun gapMs(rng: CoverRng): Long {
        val mean = Cover.meanGapMs(mode) ?: return 0
        val extra = -ln(rng.unit()) * (mean - Cover.MIN_GAP_MS).toDouble()
        return Cover.MIN_GAP_MS + extra.toLong()
    }

    private fun scheduleFrom(base: Long, rng: CoverRng) {
        if (mode != CoverMode.Off) nextMs = base + gapMs(rng)
    }

    fun tick(nowMs: Long, queueLen: Int, pollDue: Boolean, rng: CoverRng): CoverTick {
        if (mode == CoverMode.Off) return CoverTick.Off
        if (nowMs < nextMs) return CoverTick.Wait(nextMs)
        val slot: CoverSlot = if (queueLen > 0) {
            CoverSlot.Real
        } else if (pollDue) {
            CoverSlot.Poll
        } else {
            val req = maxOf(sample(reqs, rng), 4)
            val resp = minOf(sample(resps, rng), Cover.maxRespLen(req))
            CoverSlot.Dummy(req, resp)
        }
        val base = displacedMs ?: nowMs
        displacedMs = null
        val gap = if (queueLen > 1) Cover.MIN_GAP_MS else gapMs(rng)
        nextMs = maxOf(base + gap, nowMs + Cover.MIN_GAP_MS)
        lastMs = nowMs
        return CoverTick.Slot(slot)
    }

    private fun earliest(nowMs: Long): Long = lastMs?.let { maxOf(nowMs, it + Cover.MIN_GAP_MS) } ?: nowMs

    /** A user-visible action needs the network now: the next slot moves up and the one it replaced is skipped. */
    fun earlySlot(nowMs: Long) {
        if (mode == CoverMode.Off || nextMs <= nowMs + Cover.MIN_GAP_MS) return
        val e = earliest(nowMs)
        if (e < nextMs) {
            if (displacedMs == null) displacedMs = nextMs
            nextMs = e
        }
    }

    /** Call after queueing a request: with more than one queued, slots run at the minimum gap. */
    fun queueGrew(nowMs: Long, queueLen: Int) {
        if (mode == CoverMode.Off || queueLen < 2) return
        nextMs = minOf(nextMs, earliest(nowMs))
    }

    fun recordRequest(bodyLen: Int) = push(reqs, bodyLen)
    fun recordResponse(bodyLen: Int) = push(resps, bodyLen)

    private fun sample(q: ArrayDeque<Int>, rng: CoverRng): Int =
        if (q.isEmpty()) Cover.DEFAULT_SIZE else q[rng.below(q.size.toLong()).toInt()]

    private fun push(q: ArrayDeque<Int>, len: Int) {
        q.addLast(len)
        while (q.size > Cover.SIZE_HISTORY) q.removeFirst()
    }
}
