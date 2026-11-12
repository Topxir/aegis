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

        /** Onion service of the default server; it answers with the same transport key as [DEFAULT]. */
        const val ONION = "http://axwvmhfhymxuwwzegl4k3o4xfmlwfflaeunsnn557tjyiuy2wetlx7ad.onion"

        /** Transport key of the default server, compiled in: the default endpoint is never pinned from the network. */
        val DEFAULT_SERVER_X_PK: ByteArray? = ByteArray(32) { ("8e5b9b5c709ec893f16624d00d410dc697887d4dee434d5bcf5f705a35062860".substring(it * 2, it * 2 + 2)).toInt(16).toByte() }

        /** Compiled-in key for [origin], or null when the origin has to be pinned on first use. */
        fun builtInKey(origin: String): ByteArray? = if (origin == DEFAULT || origin == ONION) DEFAULT_SERVER_X_PK else null

        private val HOST = Regex("^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
        private val PLAIN_HOSTS = setOf("127.0.0.1", "localhost")

        fun isPlainHttpHost(h: String): Boolean = h in PLAIN_HOSTS || h.endsWith(".onion")

        /** Whether [endpoint] is the clearnet entry of the default server (behind Cloudflare) or a name below it. */
        fun isClearnetEntry(endpoint: String): Boolean {
            val base = parse(DEFAULT).host
            val host = try { parse(endpoint).host } catch (_: AegisException) { return false }
            return host == base || host.endsWith(".$base")
        }

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

/** Where a request goes: the settings endpoint and proxy, adjusted for the Tor switch. */
class Route(val endpoint: String, val proxy: String, val viaTor: Boolean) {
    companion object {
        /**
         * With Tor on the default server is reached at its onion address through the embedded Tor and a custom
         * server goes through it too. With Tor off the onion address maps back to the default clearnet endpoint.
         * Nothing is ever rerouted to a different transport than the switch says, and with Tor on any other name
         * under the clearnet domain is refused.
         */
        fun plan(tor: Boolean, endpoint: String, proxy: String): Route {
            val origin = Endpoint.parse(endpoint).origin
            val isDefault = origin == Endpoint.DEFAULT || origin == Endpoint.ONION
            if (tor && !isDefault && Endpoint.isClearnetEntry(origin)) throw AegisException.Network("clearnet entry")
            return if (tor) Route(if (isDefault) Endpoint.ONION else origin, "", true)
            else Route(if (isDefault) Endpoint.DEFAULT else origin, proxy, false)
        }
    }
}
