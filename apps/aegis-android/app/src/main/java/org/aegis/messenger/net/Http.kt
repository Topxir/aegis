package org.aegis.messenger.net

import org.aegis.messenger.core.AegisException
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

class Response(val code: Int, val body: ByteArray)

/** One HTTP exchange against [Endpoint]; direct, or through a SOCKS5 proxy with remote name resolution. */
interface Transport {
    fun request(ep: Endpoint, method: String, pathQuery: String, body: ByteArray?, contentType: String?): Response
}

const val MAX_RESPONSE = 1 shl 20
private const val TIMEOUT_MS = 20_000

/** Direct connection through the platform stack; never uses a system proxy. */
class DirectTransport : Transport {
    override fun request(ep: Endpoint, method: String, pathQuery: String, body: ByteArray?, contentType: String?): Response {
        // Onion hosts cannot be resolved locally; refuse instead of leaking the name to the system resolver.
        if (ep.isOnion) throw AegisException.Network("onion endpoints need a SOCKS5 proxy")
        var conn: HttpURLConnection? = null
        try {
            conn = URL(ep.origin + pathQuery).openConnection(Proxy.NO_PROXY) as HttpURLConnection
            if (ep.https != (conn is HttpsURLConnection)) throw AegisException.Network("scheme")
            conn.requestMethod = method
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            conn.instanceFollowRedirects = false
            conn.useCaches = false
            conn.setRequestProperty("Accept", "application/json")
            if (body != null) {
                conn.doOutput = true
                conn.setFixedLengthStreamingMode(body.size)
                if (contentType != null) conn.setRequestProperty("Content-Type", contentType)
                conn.outputStream.use { it.write(body) }
            }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val data = stream?.use { readCapped(it, MAX_RESPONSE) } ?: ByteArray(0)
            return Response(code, data)
        } catch (e: javax.net.ssl.SSLException) {
            throw AegisException.Network("tls")
        } catch (e: java.io.IOException) {
            throw AegisException.Network("io")
        } finally {
            conn?.disconnect()
        }
    }
}

internal fun readCapped(input: InputStream, cap: Int): ByteArray {
    val out = ByteArrayOutputStream()
    val buf = ByteArray(8192)
    while (true) {
        val n = input.read(buf)
        if (n < 0) break
        if (out.size() + n > cap) throw AegisException.BadResponse()
        out.write(buf, 0, n)
    }
    return out.toByteArray()
}

/**
 * SOCKS5 with the destination sent as a domain name (ATYP 3), so the proxy resolves it.
 * TLS runs over the proxied socket with SNI and hostname verification.
 */
class SocksTransport(private val proxy: ProxyAddr) : Transport {
    override fun request(ep: Endpoint, method: String, pathQuery: String, body: ByteArray?, contentType: String?): Response {
        val raw = Socket()
        try {
            raw.soTimeout = TIMEOUT_MS
            raw.connect(InetSocketAddress(proxy.host, proxy.port), TIMEOUT_MS)
            connectThroughProxy(raw, ep.host, ep.port)
            val sock: Socket = if (ep.https) wrapTls(raw, ep.host, ep.port) else raw
            val out = sock.getOutputStream()
            val head = StringBuilder()
                .append(method).append(' ').append(pathQuery).append(" HTTP/1.1\r\n")
                .append("Host: ").append(ep.host).append("\r\n")
                .append("Accept: application/json\r\n")
                .append("Connection: close\r\n")
            if (body != null) {
                if (contentType != null) head.append("Content-Type: ").append(contentType).append("\r\n")
                head.append("Content-Length: ").append(body.size).append("\r\n")
            }
            head.append("\r\n")
            out.write(head.toString().toByteArray(Charsets.US_ASCII))
            if (body != null) out.write(body)
            out.flush()
            return readResponse(sock.getInputStream())
        } catch (e: javax.net.ssl.SSLException) {
            throw AegisException.Network("tls")
        } catch (e: java.io.IOException) {
            throw AegisException.Network("io")
        } finally {
            try { raw.close() } catch (_: java.io.IOException) {}
        }
    }

    private fun connectThroughProxy(s: Socket, host: String, port: Int) {
        val out = s.getOutputStream()
        val inp = s.getInputStream()
        out.write(byteArrayOf(5, 1, 0))
        out.flush()
        val g = readFully(inp, 2)
        if (g[0].toInt() != 5 || g[1].toInt() != 0) throw AegisException.Network("proxy auth")
        val name = host.toByteArray(Charsets.US_ASCII)
        if (name.isEmpty() || name.size > 255) throw AegisException.InvalidEndpoint()
        val req = ByteArray(7 + name.size)
        req[0] = 5; req[1] = 1; req[2] = 0; req[3] = 3; req[4] = name.size.toByte()
        System.arraycopy(name, 0, req, 5, name.size)
        req[5 + name.size] = (port ushr 8).toByte()
        req[6 + name.size] = port.toByte()
        out.write(req)
        out.flush()
        val r = readFully(inp, 4)
        if (r[0].toInt() != 5 || r[1].toInt() != 0) throw AegisException.Network("proxy refused")
        val skip = when (r[3].toInt()) {
            1 -> 4
            4 -> 16
            3 -> (readFully(inp, 1)[0].toInt() and 0xFF)
            else -> throw AegisException.Network("proxy reply")
        }
        readFully(inp, skip + 2)
    }

    private fun wrapTls(raw: Socket, host: String, port: Int): Socket {
        val f = SSLSocketFactory.getDefault() as SSLSocketFactory
        val ssl = f.createSocket(raw, host, port, true) as SSLSocket
        val p = ssl.sslParameters
        p.endpointIdentificationAlgorithm = "HTTPS"
        ssl.sslParameters = p
        ssl.startHandshake()
        if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, ssl.session)) {
            throw javax.net.ssl.SSLPeerUnverifiedException("hostname")
        }
        return ssl
    }
}

private fun readFully(i: InputStream, n: Int): ByteArray {
    val b = ByteArray(n)
    var off = 0
    while (off < n) {
        val r = i.read(b, off, n - off)
        if (r < 0) throw java.io.EOFException()
        off += r
    }
    return b
}

private fun readLine(i: InputStream): String {
    val sb = StringBuilder()
    while (true) {
        val c = i.read()
        if (c < 0) throw java.io.EOFException()
        if (c == '\n'.code) break
        if (c != '\r'.code) sb.append(c.toChar())
        if (sb.length > 8192) throw AegisException.BadResponse()
    }
    return sb.toString()
}

/** Minimal HTTP/1.1 response reader: status, then content-length, chunked, or until close; body capped. */
internal fun readResponse(i: InputStream): Response {
    val status = readLine(i).split(' ')
    if (status.size < 2 || !status[0].startsWith("HTTP/1.")) throw AegisException.BadResponse()
    val code = status[1].toIntOrNull() ?: throw AegisException.BadResponse()
    var length = -1L
    var chunked = false
    var n = 0
    while (true) {
        val line = readLine(i)
        if (line.isEmpty()) break
        if (++n > 100) throw AegisException.BadResponse()
        val c = line.indexOf(':')
        if (c <= 0) throw AegisException.BadResponse()
        val k = line.substring(0, c).trim().lowercase()
        val v = line.substring(c + 1).trim()
        if (k == "content-length") length = v.toLongOrNull()?.takeIf { it >= 0 } ?: throw AegisException.BadResponse()
        if (k == "transfer-encoding" && v.lowercase().contains("chunked")) chunked = true
    }
    val body = when {
        chunked -> readChunked(i)
        length >= 0 -> {
            if (length > MAX_RESPONSE) throw AegisException.BadResponse()
            readFully(i, length.toInt())
        }
        else -> readCapped(i, MAX_RESPONSE)
    }
    return Response(code, body)
}

private fun readChunked(i: InputStream): ByteArray {
    val out = ByteArrayOutputStream()
    while (true) {
        val line = readLine(i).substringBefore(';').trim()
        val size = line.toIntOrNull(16)?.takeIf { it >= 0 } ?: throw AegisException.BadResponse()
        if (size == 0) {
            while (readLine(i).isNotEmpty()) { /* trailers */ }
            return out.toByteArray()
        }
        if (out.size() + size > MAX_RESPONSE) throw AegisException.BadResponse()
        out.write(readFully(i, size))
        if (readLine(i).isNotEmpty()) throw AegisException.BadResponse()
    }
}
