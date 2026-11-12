package org.aegis.messenger.core

/**
 * Minimal strict JSON reader/writer. Values: Map<String, Any?>, List<Any?>, String, Long, Double,
 * Boolean, null. Used for server replies and the vault payload, so it avoids android.* classes.
 */
object Json {
    class ParseException(message: String) : Exception(message)

    private const val MAX_DEPTH = 32

    fun parse(text: String): Any? {
        val p = Parser(text)
        p.skipWs()
        val v = p.value(0)
        p.skipWs()
        if (!p.atEnd()) throw ParseException("trailing data")
        return v
    }

    @Suppress("UNCHECKED_CAST")
    fun parseObject(text: String): Map<String, Any?> =
        parse(text) as? Map<String, Any?> ?: throw ParseException("object expected")

    private class Parser(val s: String) {
        var i = 0
        fun atEnd() = i >= s.length
        fun skipWs() {
            while (i < s.length && (s[i] == ' ' || s[i] == '\n' || s[i] == '\r' || s[i] == '\t')) i++
        }

        fun value(depth: Int): Any? {
            if (depth > MAX_DEPTH) throw ParseException("too deep")
            if (atEnd()) throw ParseException("unexpected end")
            return when (val c = s[i]) {
                '{' -> obj(depth)
                '[' -> arr(depth)
                '"' -> str()
                't' -> lit("true", true)
                'f' -> lit("false", false)
                'n' -> lit("null", null)
                else -> if (c == '-' || c in '0'..'9') num() else throw ParseException("bad value")
            }
        }

        fun lit(word: String, v: Any?): Any? {
            if (!s.startsWith(word, i)) throw ParseException("bad literal")
            i += word.length
            return v
        }

        fun num(): Any {
            val st = i
            if (s[i] == '-') i++
            while (i < s.length && s[i] in '0'..'9') i++
            var isInt = true
            if (i < s.length && s[i] == '.') {
                isInt = false
                i++
                while (i < s.length && s[i] in '0'..'9') i++
            }
            if (i < s.length && (s[i] == 'e' || s[i] == 'E')) {
                isInt = false
                i++
                if (i < s.length && (s[i] == '+' || s[i] == '-')) i++
                while (i < s.length && s[i] in '0'..'9') i++
            }
            val t = s.substring(st, i)
            if (isInt) return t.toLongOrNull() ?: throw ParseException("number out of range")
            return t.toDoubleOrNull() ?: throw ParseException("bad number")
        }

        fun str(): String {
            i++
            val sb = StringBuilder()
            while (true) {
                if (atEnd()) throw ParseException("unterminated string")
                val c = s[i++]
                when {
                    c == '"' -> return sb.toString()
                    c == '\\' -> {
                        if (atEnd()) throw ParseException("bad escape")
                        when (val e = s[i++]) {
                            '"' -> sb.append('"')
                            '\\' -> sb.append('\\')
                            '/' -> sb.append('/')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                if (i + 4 > s.length) throw ParseException("bad escape")
                                val n = s.substring(i, i + 4).toIntOrNull(16) ?: throw ParseException("bad escape")
                                sb.append(n.toChar())
                                i += 4
                            }
                            else -> throw ParseException("bad escape $e")
                        }
                    }
                    c < ' ' -> throw ParseException("control character in string")
                    else -> sb.append(c)
                }
            }
        }

        fun arr(depth: Int): List<Any?> {
            i++
            val out = ArrayList<Any?>()
            skipWs()
            if (i < s.length && s[i] == ']') { i++; return out }
            while (true) {
                skipWs()
                out.add(value(depth + 1))
                skipWs()
                if (atEnd()) throw ParseException("unterminated array")
                when (s[i++]) {
                    ',' -> continue
                    ']' -> return out
                    else -> throw ParseException("bad array")
                }
            }
        }

        fun obj(depth: Int): Map<String, Any?> {
            i++
            val out = LinkedHashMap<String, Any?>()
            skipWs()
            if (i < s.length && s[i] == '}') { i++; return out }
            while (true) {
                skipWs()
                if (atEnd() || s[i] != '"') throw ParseException("key expected")
                val k = str()
                skipWs()
                if (atEnd() || s[i++] != ':') throw ParseException("colon expected")
                skipWs()
                if (out.containsKey(k)) throw ParseException("duplicate key")
                out[k] = value(depth + 1)
                skipWs()
                if (atEnd()) throw ParseException("unterminated object")
                when (s[i++]) {
                    ',' -> continue
                    '}' -> return out
                    else -> throw ParseException("bad object")
                }
            }
        }
    }

    fun write(v: Any?): String = StringBuilder().also { write(it, v) }.toString()

    private fun write(sb: StringBuilder, v: Any?) {
        when (v) {
            null -> sb.append("null")
            is String -> quote(sb, v)
            is Boolean -> sb.append(v)
            is Int, is Long -> sb.append(v.toString())
            is Double -> sb.append(v.toString())
            is Map<*, *> -> {
                sb.append('{')
                var first = true
                for ((k, x) in v) {
                    if (!first) sb.append(',')
                    first = false
                    quote(sb, k as String)
                    sb.append(':')
                    write(sb, x)
                }
                sb.append('}')
            }
            is List<*> -> {
                sb.append('[')
                for ((n, x) in v.withIndex()) {
                    if (n > 0) sb.append(',')
                    write(sb, x)
                }
                sb.append(']')
            }
            else -> throw IllegalArgumentException("unsupported json value")
        }
    }

    private fun quote(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) {
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c == '\n' -> sb.append("\\n")
                c == '\r' -> sb.append("\\r")
                c == '\t' -> sb.append("\\t")
                c < ' ' -> sb.append("\\u").append(c.code.toString(16).padStart(4, '0'))
                else -> sb.append(c)
            }
        }
        sb.append('"')
    }
}
