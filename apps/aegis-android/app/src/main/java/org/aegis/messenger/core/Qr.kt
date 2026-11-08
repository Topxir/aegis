package org.aegis.messenger.core

/**
 * QR code (ISO/IEC 18004) in byte mode at error correction level M, versions 1 to 9.
 * Enough for invite links; no other library is pulled in for it.
 */
object Qr {
    /** EC codewords per block and the data codewords of each block, for level M. */
    private val EC = intArrayOf(10, 16, 26, 18, 24, 16, 18, 22, 22)
    private val BLOCKS = arrayOf(
        intArrayOf(16), intArrayOf(28), intArrayOf(44), intArrayOf(32, 32), intArrayOf(43, 43),
        intArrayOf(27, 27, 27, 27), intArrayOf(31, 31, 31, 31), intArrayOf(38, 38, 39, 39),
        intArrayOf(36, 36, 36, 37, 37),
    )
    private val ALIGN = arrayOf(
        intArrayOf(), intArrayOf(6, 18), intArrayOf(6, 22), intArrayOf(6, 26), intArrayOf(6, 30),
        intArrayOf(6, 34), intArrayOf(6, 22, 38), intArrayOf(6, 24, 42), intArrayOf(6, 26, 46),
    )

    /** A square of modules; `true` is dark. */
    class Code(val size: Int, private val dark: Array<BooleanArray>) {
        operator fun get(x: Int, y: Int): Boolean = dark[y][x]
    }

    /** Encodes [data] with the mask of lowest penalty. */
    fun encode(data: ByteArray): Code = (0..7).map { encode(data, it) }.minBy { penalty(it) }

    /** Encodes [data] with a fixed [mask] (0 to 7). */
    fun encode(data: ByteArray, mask: Int): Code {
        val v = (1..9).firstOrNull { BLOCKS[it - 1].sum() >= data.size + 2 } ?: throw AegisException.Length()
        val m = Matrix(v)
        m.functionPatterns()
        m.place(codewords(data, v))
        m.applyMask(mask)
        m.format(mask)
        return Code(m.size, m.dark)
    }

    private fun codewords(data: ByteArray, v: Int): ByteArray {
        val blocks = BLOCKS[v - 1]
        val cap = blocks.sum()
        val bits = ArrayList<Boolean>()
        fun put(value: Int, n: Int) { for (i in n - 1 downTo 0) bits.add((value ushr i) and 1 == 1) }
        put(0b0100, 4)
        put(data.size, 8)
        for (b in data) put(b.toInt() and 0xFF, 8)
        repeat(minOf(4, cap * 8 - bits.size)) { bits.add(false) }
        while (bits.size % 8 != 0) bits.add(false)
        val out = ByteArray(cap)
        for (i in 0 until bits.size / 8) {
            var b = 0
            for (j in 0 until 8) b = (b shl 1) or (if (bits[i * 8 + j]) 1 else 0)
            out[i] = b.toByte()
        }
        for (i in bits.size / 8 until cap) out[i] = if ((i - bits.size / 8) % 2 == 0) 0xEC.toByte() else 0x11
        val ec = EC[v - 1]
        val gen = generator(ec)
        val split = ArrayList<ByteArray>()
        var off = 0
        for (n in blocks) { split.add(out.copyOfRange(off, off + n)); off += n }
        val ecs = split.map { remainder(it, gen) }
        val res = ArrayList<Byte>()
        for (i in 0 until blocks.max()) for (b in split) if (i < b.size) res.add(b[i])
        for (i in 0 until ec) for (e in ecs) res.add(e[i].toByte())
        return res.toByteArray()
    }

    private fun mul(a: Int, b: Int): Int {
        var x = a
        var y = b
        var r = 0
        while (y != 0) {
            if (y and 1 != 0) r = r xor x
            x = x shl 1
            if (x and 0x100 != 0) x = x xor 0x11D
            y = y ushr 1
        }
        return r
    }

    /** Coefficients of prod (x - 2^i), highest degree first without the leading 1. */
    private fun generator(n: Int): IntArray {
        val g = IntArray(n)
        g[n - 1] = 1
        var root = 1
        for (i in 0 until n) {
            for (j in 0 until n) {
                g[j] = mul(g[j], root)
                if (j + 1 < n) g[j] = g[j] xor g[j + 1]
            }
            root = mul(root, 2)
        }
        return g
    }

    private fun remainder(data: ByteArray, gen: IntArray): IntArray {
        val r = IntArray(gen.size)
        for (b in data) {
            val f = (b.toInt() and 0xFF) xor r[0]
            System.arraycopy(r, 1, r, 0, r.size - 1)
            r[r.size - 1] = 0
            for (i in r.indices) r[i] = r[i] xor mul(gen[i], f)
        }
        return r
    }

    private class Matrix(val version: Int) {
        val size = version * 4 + 17
        val dark = Array(size) { BooleanArray(size) }
        val fixed = Array(size) { BooleanArray(size) }

        fun set(x: Int, y: Int, on: Boolean) {
            dark[y][x] = on
            fixed[y][x] = true
        }

        fun functionPatterns() {
            for (i in 0 until size) {
                set(6, i, i % 2 == 0)
                set(i, 6, i % 2 == 0)
            }
            finder(3, 3)
            finder(size - 4, 3)
            finder(3, size - 4)
            val a = ALIGN[version - 1]
            for (i in a.indices) for (j in a.indices) {
                if ((i == 0 && j == 0) || (i == 0 && j == a.size - 1) || (i == a.size - 1 && j == 0)) continue
                for (dy in -2..2) for (dx in -2..2) set(a[i] + dx, a[j] + dy, maxOf(Math.abs(dx), Math.abs(dy)) != 1)
            }
            format(0)
            if (version >= 7) {
                var rem = version
                repeat(12) { rem = (rem shl 1) xor ((rem ushr 11) * 0x1F25) }
                val bits = (version shl 12) or rem
                for (i in 0 until 18) {
                    val on = (bits ushr i) and 1 == 1
                    val p = size - 11 + i % 3
                    val q = i / 3
                    set(p, q, on)
                    set(q, p, on)
                }
            }
        }

        private fun finder(cx: Int, cy: Int) {
            for (dy in -4..4) for (dx in -4..4) {
                val x = cx + dx
                val y = cy + dy
                if (x !in 0 until size || y !in 0 until size) continue
                val d = maxOf(Math.abs(dx), Math.abs(dy))
                set(x, y, d != 2 && d != 4)
            }
        }

        fun format(mask: Int) {
            val data = mask
            var rem = data
            repeat(10) { rem = (rem shl 1) xor ((rem ushr 9) * 0x537) }
            val bits = ((data shl 10) or rem) xor 0x5412
            fun bit(i: Int) = (bits ushr i) and 1 == 1
            for (i in 0..5) set(8, i, bit(i))
            set(8, 7, bit(6))
            set(8, 8, bit(7))
            set(7, 8, bit(8))
            for (i in 9 until 15) set(14 - i, 8, bit(i))
            for (i in 0 until 8) set(size - 1 - i, 8, bit(i))
            for (i in 8 until 15) set(8, size - 15 + i, bit(i))
            set(8, size - 8, true)
        }

        fun place(words: ByteArray) {
            var i = 0
            var right = size - 1
            while (right >= 1) {
                if (right == 6) right = 5
                for (vert in 0 until size) for (j in 0..1) {
                    val x = right - j
                    val y = if ((right + 1) and 2 == 0) size - 1 - vert else vert
                    if (fixed[y][x]) continue
                    if (i < words.size * 8) dark[y][x] = (words[i ushr 3].toInt() ushr (7 - (i and 7))) and 1 == 1
                    i++
                }
                right -= 2
            }
        }

        fun applyMask(mask: Int) {
            for (y in 0 until size) for (x in 0 until size) {
                if (fixed[y][x]) continue
                val flip = when (mask) {
                    0 -> (x + y) % 2 == 0
                    1 -> y % 2 == 0
                    2 -> x % 3 == 0
                    3 -> (x + y) % 3 == 0
                    4 -> (x / 3 + y / 2) % 2 == 0
                    5 -> x * y % 2 + x * y % 3 == 0
                    6 -> (x * y % 2 + x * y % 3) % 2 == 0
                    else -> ((x + y) % 2 + x * y % 3) % 2 == 0
                }
                if (flip) dark[y][x] = !dark[y][x]
            }
        }
    }

    /** Penalty rules N1 to N4; only used to pick between masks. */
    private fun penalty(c: Code): Int {
        val n = c.size
        var p = 0
        for (horizontal in listOf(true, false)) for (a in 0 until n) {
            var run = 1
            val line = BooleanArray(n) { b -> if (horizontal) c[b, a] else c[a, b] }
            for (b in 1..n) {
                if (b < n && line[b] == line[b - 1]) { run++; continue }
                if (run >= 5) p += run - 2
                run = 1
            }
            for (b in 0..n - 7) {
                if (line[b] && !line[b + 1] && line[b + 2] && line[b + 3] && line[b + 4] && !line[b + 5] && line[b + 6]) {
                    val before = (b - 4 until b).all { it < 0 || !line[it] }
                    val after = (b + 7 until b + 11).all { it >= n || !line[it] }
                    if (before || after) p += 40
                }
            }
        }
        for (y in 0 until n - 1) for (x in 0 until n - 1) {
            val k = c[x, y]
            if (c[x + 1, y] == k && c[x, y + 1] == k && c[x + 1, y + 1] == k) p += 3
        }
        var darkCount = 0
        for (y in 0 until n) for (x in 0 until n) if (c[x, y]) darkCount++
        p += Math.abs(darkCount * 20 - n * n * 10) / (n * n) * 10
        return p
    }
}
