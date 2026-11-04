package org.aegis.messenger.core

/** Usernames, account keys and safety numbers (spec sections 2 and 8). */
object Names {
    fun isValidUsername(u: String): Boolean =
        u.length in 3..24 && u.all { it in 'a'..'z' || it in '0'..'9' || it == '_' }

    /** ASCII-only folding, like Rust's to_ascii_lowercase; other characters stay and fail validation. */
    private fun asciiLower(s: String): String =
        String(CharArray(s.length) { val c = s[it]; if (c in 'A'..'Z') c + 32 else c })

    fun normalizeUsername(u: String): String {
        val l = asciiLower(u.trim())
        if (!isValidUsername(l)) throw AegisException.InvalidUsername()
        return l
    }
}

class Identity(xSk: ByteArray, edSk: ByteArray) {
    val xSecret: ByteArray = xSk.copyOf()
    val edSecret: ByteArray = edSk.copyOf()
    val xPublic: ByteArray = Crypto.x25519Public(xSk)
    val edPublic: ByteArray = Crypto.ed25519Public(edSk)

    fun sign(msg: ByteArray): ByteArray = Crypto.ed25519Sign(edSecret, msg)

    fun wipe() {
        xSecret.fill(0)
        edSecret.fill(0)
    }

    override fun toString(): String = "Identity(..)"

    companion object {
        fun generate(): Identity {
            val x = Crypto.randomBytes(32)
            val e = Crypto.randomBytes(32)
            val id = Identity(x, e)
            x.fill(0)
            e.fill(0)
            return id
        }
    }
}

object Safety {
    private fun cmp(a: ByteArray, b: ByteArray): Int {
        for (i in a.indices) {
            val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (d != 0) return d
        }
        return 0
    }

    /** Six groups of five digits for two users, each given as ed_pk and x_pk. */
    fun number(aEd: ByteArray, aX: ByteArray, bEd: ByteArray, bX: ByteArray): String {
        val ka = aEd + aX
        val kb = bEd + bX
        val (lo, hi) = if (cmp(ka, kb) <= 0) ka to kb else kb to ka
        val h = Crypto.sha256("aegis-v2 safety".toByteArray(Charsets.UTF_8), lo, hi)
        return (0 until 6).joinToString(" ") { i ->
            var v = 0L
            for (j in 0 until 5) v = (v shl 8) or (h[i * 5 + j].toLong() and 0xFF)
            (v % 100000L).toString().padStart(5, '0')
        }
    }
}
