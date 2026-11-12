package org.aegis.messenger.core

/** Encrypted local storage file (spec section 9). */
object Vault {
    private val MAGIC = byteArrayOf('A'.code.toByte(), 'G'.code.toByte(), 'V'.code.toByte(), '2'.code.toByte())
    private const val AAD_LEN = 32
    private const val HEADER_LEN = AAD_LEN + 12
    private const val MAX_M_KIB = 1L shl 18
    private const val MAX_T = 16L
    private const val MAX_P = 16L

    class Params(val mKib: Int, val t: Int, val p: Int) {
        fun validate() {
            val ok = p in 1..MAX_P && t in 1..MAX_T && mKib.toLong() in (8L * p)..MAX_M_KIB
            if (!ok) throw AegisException.VaultParams()
        }
    }

    val ANDROID = Params(19456, 2, 1)

    /** Derived key with its header inputs; lets the app rewrite the file with a fresh nonce without re-running Argon2. */
    class Keyed internal constructor(val params: Params, private val salt: ByteArray, private val key: ByteArray) {
        fun seal(data: ByteArray): ByteArray = sealWith(Crypto.randomBytes(12), data)

        internal fun sealWith(nonce: ByteArray, data: ByteArray): ByteArray {
            val header = ByteArray(AAD_LEN)
            System.arraycopy(MAGIC, 0, header, 0, 4)
            Bytes.putBe32(header, 4, params.mKib.toLong())
            Bytes.putBe32(header, 8, params.t.toLong())
            Bytes.putBe32(header, 12, params.p.toLong())
            System.arraycopy(salt, 0, header, 16, 16)
            val ct = Crypto.aeadSeal(key, nonce, header, data)
            return Bytes.concat(header, nonce, ct)
        }

        /** Copy of the derived key, for wrapping with a PIN (spec section 20). The caller wipes it. */
        fun exportKey(): ByteArray = key.copyOf()

        fun wipe() {
            key.fill(0)
        }
    }

    class Opened(val data: ByteArray, val keyed: Keyed)

    private fun derive(password: String, salt: ByteArray, params: Params): ByteArray {
        params.validate()
        val pw = Text.utf8(password)
        try {
            return Crypto.argon2id(pw, salt, params.mKib, params.t, params.p)
        } catch (_: OutOfMemoryError) {
            throw AegisException.VaultParams()
        } finally {
            pw.fill(0)
        }
    }

    fun newKeyed(password: String, params: Params): Keyed = newKeyedWith(password, params, Crypto.randomBytes(16))

    fun newKeyedWith(password: String, params: Params, salt: ByteArray): Keyed =
        Keyed(params, salt, derive(password, salt, params))

    fun encrypt(password: String, params: Params, data: ByteArray): ByteArray =
        newKeyed(password, params).let { k -> k.seal(data).also { k.wipe() } }

    /** Deterministic variant of [encrypt] with injected salt and nonce. */
    fun encryptWith(password: String, params: Params, salt: ByteArray, nonce: ByteArray, data: ByteArray): ByteArray {
        val k = newKeyedWith(password, params, salt)
        return k.sealWith(nonce, data).also { k.wipe() }
    }

    /** A wrong password and a damaged file are indistinguishable. */
    fun decrypt(password: String, file: ByteArray): Opened {
        if (file.size < HEADER_LEN + 16 || !Bytes.eq(file.copyOfRange(0, 4), MAGIC)) {
            throw AegisException.VaultFormat()
        }
        val m = Bytes.be32(file, 4)
        val t = Bytes.be32(file, 8)
        val p = Bytes.be32(file, 12)
        // Compare as unsigned 32-bit values before narrowing to Int.
        if (p !in 1..MAX_P || t !in 1..MAX_T || m !in (8 * p)..MAX_M_KIB) throw AegisException.VaultParams()
        val params = Params(m.toInt(), t.toInt(), p.toInt())
        val salt = file.copyOfRange(16, 32)
        val nonce = file.copyOfRange(AAD_LEN, HEADER_LEN)
        val key = derive(password, salt, params)
        try {
            val data = Crypto.aeadOpen(key, nonce, file.copyOfRange(0, AAD_LEN), file.copyOfRange(HEADER_LEN, file.size))
            return Opened(data, Keyed(params, salt, key))
        } catch (e: AegisException.Decrypt) {
            key.fill(0)
            throw AegisException.VaultDecrypt()
        }
    }

    /** Opens a file with the already derived 32-byte key (PIN unlock). The key is copied. */
    fun decryptWithKey(keyBytes: ByteArray, file: ByteArray): Opened {
        if (file.size < HEADER_LEN + 16 || !Bytes.eq(file.copyOfRange(0, 4), MAGIC)) throw AegisException.VaultFormat()
        val m = Bytes.be32(file, 4)
        val t = Bytes.be32(file, 8)
        val p = Bytes.be32(file, 12)
        if (p !in 1..MAX_P || t !in 1..MAX_T || m !in (8 * p)..MAX_M_KIB) throw AegisException.VaultParams()
        val params = Params(m.toInt(), t.toInt(), p.toInt())
        val salt = file.copyOfRange(16, 32)
        val nonce = file.copyOfRange(AAD_LEN, HEADER_LEN)
        val key = keyBytes.copyOf()
        try {
            val data = Crypto.aeadOpen(key, nonce, file.copyOfRange(0, AAD_LEN), file.copyOfRange(HEADER_LEN, file.size))
            return Opened(data, Keyed(params, salt, key))
        } catch (e: AegisException.Decrypt) {
            key.fill(0)
            throw AegisException.VaultDecrypt()
        }
    }

    /** First 32 hex chars of SHA256("aegis-v2 vault-name\n" || username) plus ".vault". */
    fun fileName(username: String): String =
        Hex.encode(Crypto.sha256(Text.utf8("aegis-v2 vault-name\n"), Text.utf8(username))).substring(0, 32) + ".vault"
}
