package org.aegis.messenger.net

import org.aegis.messenger.core.AegisException

/** Server endpoint: https anywhere, http only for loopback, the emulator host and onion services. */
class Endpoint private constructor(val https: Boolean, val host: String, val port: Int) {
    val isOnion: Boolean get() = host.endsWith(".onion")

    val origin: String
        get() {
            val def = if (https) 443 else 80
            return (if (https) "https://" else "http://") + host + if (port == def) "" else ":$port"
        }

    override fun toString(): String = origin

    companion object {
        const val DEFAULT = "https://freeoasis.space"
        private val HOST = Regex("^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
        private val PLAIN_HOSTS = setOf("127.0.0.1", "localhost")

        fun isPlainHttpHost(h: String): Boolean = h in PLAIN_HOSTS || h.endsWith(".onion")

        fun parse(input: String): Endpoint {
            val s = input.trim().lowercase()
            val https = when {
                s.startsWith("https://") -> true
                s.startsWith("http://") -> false
                else -> throw AegisException.InvalidEndpoint()
            }
            val rest = s.substring(if (https) 8 else 7).trimEnd('/')
            if (rest.isEmpty() || rest.any { it == '/' || it == '?' || it == '#' || it == '@' || it == '\\' || it.isWhitespace() }) {
                throw AegisException.InvalidEndpoint()
            }
            val colon = rest.lastIndexOf(':')
            val host = if (colon >= 0) rest.substring(0, colon) else rest
            val port = if (colon >= 0) {
                rest.substring(colon + 1).takeIf { it.length in 1..5 && it.all { c -> c in '0'..'9' } }?.toInt()
                    ?: throw AegisException.InvalidEndpoint()
            } else if (https) 443 else 80
            if (port !in 1..65535 || !HOST.matches(host) || ".." in host) throw AegisException.InvalidEndpoint()
            if (!https && !isPlainHttpHost(host)) throw AegisException.InvalidEndpoint()
            return Endpoint(https, host, port)
        }
    }
}

/** SOCKS5 proxy address. Only IPv4 literals and "localhost" are accepted so the proxy itself needs no DNS lookup. */
class ProxyAddr(val host: String, val port: Int) {
    override fun toString(): String = "$host:$port"

    companion object {
        private val V4 = Regex("^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$")

        fun parse(input: String): ProxyAddr {
            val s = input.trim().lowercase()
            val colon = s.lastIndexOf(':')
            if (colon <= 0) throw AegisException.InvalidEndpoint()
            val host = s.substring(0, colon)
            val port = s.substring(colon + 1).takeIf { it.length in 1..5 && it.all { c -> c in '0'..'9' } }?.toInt()
                ?: throw AegisException.InvalidEndpoint()
            if (port !in 1..65535 || !(host == "localhost" || V4.matches(host))) throw AegisException.InvalidEndpoint()
            return ProxyAddr(host, port)
        }
    }
}
