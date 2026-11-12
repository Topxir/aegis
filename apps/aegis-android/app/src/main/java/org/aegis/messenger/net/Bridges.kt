package org.aegis.messenger.net

/**
 * Tor bridges for networks that block Tor, the same rules as the desktop app. The built-in lists are
 * the ones Tor Browser ships (`bridges.torproject.org/moat/circumvention/builtin`); pasted lines are
 * checked here before anything reaches the torrc.
 */
object Bridges {
    enum class Mode(val code: String) {
        Off("off"), Snowflake("snowflake"), Obfs4("obfs4"), Custom("custom");

        companion object {
            fun parse(s: String): Mode? = entries.firstOrNull { it.code == s.trim() }
        }
    }

    val OBFS4: List<String> = listOf(
        "obfs4 37.218.245.14:38224 D9A82D2F9C2F65A18407B1D2B764F130847F8B5D cert=bjRaMrr1BRiAW8IE9U5z27fQaYgOhX1UCmOpg2pFpoMvo6ZgQMzLsaTzzQNTlm7hNcb+Sg iat-mode=0",
        "obfs4 209.148.46.65:443 74FAD13168806246602538555B5521A0383A1875 cert=ssH+9rP8dG2NLDN2XuFw63hIO/9MNNinLmxQDpVa+7kTOa9/m+tGWT1SmSYpQ9uTBGa6Hw iat-mode=0",
        "obfs4 146.57.248.225:22 10A6CD36A537FCE513A322361547444B393989F0 cert=K1gDtDAIcUfeLqbstggjIw2rtgIKqdIhUlHp82XRqNSq/mtAjp1BIC9vHKJ2FAEpGssTPw iat-mode=0",
        "obfs4 45.145.95.6:27015 C5B7CD6946FF10C5B3E89691A7D3F2C122D2117C cert=TD7PbUO0/0k6xYHMPW3vJxICfkMZNdkRrb63Zhl5j9dW3iRGiCx0A7mPhe5T2EDzQ35+Zw iat-mode=0",
        "obfs4 51.222.13.177:80 5EDAC3B810E12B01F6FD8050D2FD3E277B289A08 cert=2uplIpLQ0q9+0qMFrK5pkaYRDOe460LL9WHBvatgkuRr/SL31wBOEupaMMJ6koRE6Ld0ew iat-mode=0",
        "obfs4 212.83.43.95:443 BFE712113A72899AD685764B211FACD30FF52C31 cert=ayq0XzCwhpdysn5o0EyDUbmSOx3X/oTEbzDMvczHOdBJKlvIdHHLJGkZARtT4dcBFArPPg iat-mode=1",
        "obfs4 212.83.43.74:443 39562501228A4D5E27FCA4C0C81A01EE23AE3EE4 cert=PBwr+S8JTVZo6MPdHnkTwXJPILWADLqfMGoVvhZClMq/Urndyd42BwX9YFJHZnBB3H0XCw iat-mode=1",
    )

    val SNOWFLAKE: List<String> = listOf(
        "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=app.datapacket.com,www.datapacket.com ice=stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478,stun:stun.fitauto.ru:3478,stun:stun.m-online.net:3478 utls-imitate=hellorandomizedalpn",
        "snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://1098762253.rsc.cdn77.org/ fronts=app.datapacket.com,www.datapacket.com ice=stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478,stun:stun.fitauto.ru:3478,stun:stun.m-online.net:3478 utls-imitate=hellorandomizedalpn",
    )

    /** Transports the pluggable transport library provides. */
    val TRANSPORTS = listOf("meek_lite", "obfs4", "webtunnel", "snowflake")

    const val MAX_LINES = 32
    const val MAX_LINE = 2048

    /** Pasted text that is not usable; [line] is the 1-based number of the bad line, 0 for the whole text. */
    class Invalid(val line: Int, val tooMany: Boolean = false, val empty: Boolean = false) : Exception("bad bridge line $line")

    private val V4 = Regex("^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$")
    private val V6 = Regex("^[0-9a-fA-F:.]{2,45}$")

    /** `a.b.c.d:port` or `[v6]:port`, no names; port 1..65535. */
    fun validAddr(s: String): Boolean {
        val colon = s.lastIndexOf(':')
        if (colon <= 0) return false
        val port = s.substring(colon + 1).takeIf { it.length in 1..5 && it.all { c -> c in '0'..'9' } }?.toInt() ?: return false
        if (port !in 1..65535) return false
        val host = s.substring(0, colon)
        if (host.startsWith('[') && host.endsWith(']')) {
            val h = host.substring(1, host.length - 1)
            // A literal with ':' is never looked up by name.
            return ':' in h && V6.matches(h) && runCatching { java.net.InetAddress.getByName(h) is java.net.Inet6Address }.getOrDefault(false)
        }
        return V4.matches(host)
    }

    private fun isHex40(t: String) = t.length == 40 && t.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }

    /** One bridge line as `transport addr [fingerprint] [k=v ...]` (no `Bridge` keyword), or null. */
    fun parseLine(raw: String): String? {
        val s = raw.trim()
        if (s.length > MAX_LINE || !s.all { it == '\t' || it.code in 0x20 until 0x7f }) return null
        val toks = s.split(' ', '\t').filter { it.isNotEmpty() }.toMutableList()
        if (toks.firstOrNull()?.equals("bridge", ignoreCase = true) == true) toks.removeAt(0)
        val first = toks.firstOrNull() ?: return null
        var i = 1
        val transport = when {
            validAddr(first) -> null
            first in TRANSPORTS -> { if (toks.size < 2 || !validAddr(toks[1])) return null; i = 2; first }
            else -> return null
        }
        if (i < toks.size && isHex40(toks[i])) i++
        while (i < toks.size) {
            val t = toks[i++]
            val eq = t.indexOf('=')
            if (eq < 0) return null
            val k = t.substring(0, eq)
            val keyOk = k.isNotEmpty() && k.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-' || it == '_' }
            if (transport == null || !keyOk || eq == t.length - 1) return null
        }
        return toks.joinToString(" ")
    }

    /** Pasted text: one bridge per line, empty lines and `#` comments skipped. */
    fun parseLines(text: String): List<String> {
        val out = ArrayList<String>()
        for ((n, raw) in text.split('\n').withIndex()) {
            val t = raw.trim()
            if (t.isEmpty() || t.startsWith('#')) continue
            val line = parseLine(t) ?: throw Invalid(n + 1)
            if (line !in out) out.add(line)
            if (out.size > MAX_LINES) throw Invalid(0, tooMany = true)
        }
        return out
    }

    /** Checks a choice before it is stored; returns the text to keep for custom bridges. */
    fun check(mode: Mode, text: String): String {
        val lines = parseLines(text)
        if (mode == Mode.Custom && lines.isEmpty()) throw Invalid(0, empty = true)
        return lines.joinToString("\n")
    }

    /** Bridge lines for a mode; stored custom text is checked again here. */
    fun linesFor(mode: Mode, custom: String): List<String> = when (mode) {
        Mode.Off -> emptyList()
        Mode.Snowflake -> SNOWFLAKE
        Mode.Obfs4 -> OBFS4
        Mode.Custom -> custom.split('\n').mapNotNull { parseLine(it) }.distinct().take(MAX_LINES)
    }

    private fun transportOf(line: String): String? = line.substringBefore(' ').takeIf { !validAddr(it) }

    /** Transports the lines need, in a fixed order. */
    fun transports(lines: List<String>): List<String> {
        val used = lines.mapNotNull { transportOf(it) }.toSet()
        return TRANSPORTS.filter { it in used }
    }

    /** `key=value` options of the first line for [transport], used to configure that client. */
    fun options(lines: List<String>, transport: String): Map<String, String> {
        val l = lines.firstOrNull { transportOf(it) == transport } ?: return emptyMap()
        return l.split(' ').mapNotNull { t -> t.indexOf('=').takeIf { it > 0 }?.let { t.substring(0, it) to t.substring(it + 1) } }.toMap()
    }

    /**
     * The torrc for the bridge settings. Each transport runs in-process and listens on a local
     * SOCKS port given by [port]; a transport without a port leaves its bridges out.
     */
    fun torrc(mode: Mode, custom: String, port: (String) -> Int?): String {
        val ports = HashMap<String, Int>()
        val lines = linesFor(mode, custom).filter { l ->
            val t = transportOf(l) ?: return@filter true
            val p = ports[t] ?: port(t)?.takeIf { it in 1..65535 } ?: return@filter false
            ports[t] = p
            true
        }
        if (lines.isEmpty()) return ""
        val sb = StringBuilder("UseBridges 1\n")
        for (t in TRANSPORTS) ports[t]?.let { sb.append("ClientTransportPlugin ").append(t).append(" socks5 127.0.0.1:").append(it).append('\n') }
        for (l in lines) sb.append("Bridge ").append(l).append('\n')
        return sb.toString()
    }
}
