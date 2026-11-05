package org.aegis.messenger.core

import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.SecureRandom

/** Thin wrappers over BouncyCastle lightweight primitives. No primitive is implemented here. */
object Crypto {
    private val rng = SecureRandom()

    fun randomBytes(n: Int): ByteArray = ByteArray(n).also { rng.nextBytes(it) }

    fun sha256(vararg parts: ByteArray): ByteArray {
        val d = SHA256Digest()
        for (p in parts) d.update(p, 0, p.size)
        val out = ByteArray(32)
        d.doFinal(out, 0)
        return out
    }

    /** HKDF-SHA256 to 32 bytes; an empty [salt] means no salt. */
    fun hkdf32(ikm: ByteArray, salt: ByteArray, info: ByteArray): ByteArray {
        val g = HKDFBytesGenerator(SHA256Digest())
        g.init(HKDFParameters(ikm, if (salt.isEmpty()) null else salt, info))
        val out = ByteArray(32)
        g.generateBytes(out, 0, 32)
        return out
    }

    /** HKDF-SHA256 to [len] bytes; an empty [salt] means no salt. */
    fun hkdfN(ikm: ByteArray, salt: ByteArray, info: ByteArray, len: Int): ByteArray {
        val g = HKDFBytesGenerator(SHA256Digest())
        g.init(HKDFParameters(ikm, if (salt.isEmpty()) null else salt, info))
        val out = ByteArray(len)
        g.generateBytes(out, 0, len)
        return out
    }

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val m = org.bouncycastle.crypto.macs.HMac(SHA256Digest())
        m.init(KeyParameter(key))
        m.update(data, 0, data.size)
        val out = ByteArray(32)
        m.doFinal(out, 0)
        return out
    }

    fun aeadSeal(key: ByteArray, nonce: ByteArray, aad: ByteArray, pt: ByteArray): ByteArray {
        val c = ChaCha20Poly1305()
        c.init(true, AEADParameters(KeyParameter(key), 128, nonce, aad))
        val out = ByteArray(c.getOutputSize(pt.size))
        var n = c.processBytes(pt, 0, pt.size, out, 0)
        n += c.doFinal(out, n)
        return if (n == out.size) out else out.copyOf(n)
    }

    fun aeadOpen(key: ByteArray, nonce: ByteArray, aad: ByteArray, ct: ByteArray): ByteArray {
        if (ct.size < 16) throw AegisException.Decrypt()
        try {
            val c = ChaCha20Poly1305()
            c.init(false, AEADParameters(KeyParameter(key), 128, nonce, aad))
            val out = ByteArray(c.getOutputSize(ct.size))
            var n = c.processBytes(ct, 0, ct.size, out, 0)
            n += c.doFinal(out, n)
            return if (n == out.size) out else out.copyOf(n)
        } catch (_: InvalidCipherTextException) {
            throw AegisException.Decrypt()
        } catch (_: IllegalArgumentException) {
            throw AegisException.Decrypt()
        }
    }

    fun x25519Public(sk: ByteArray): ByteArray =
        X25519PrivateKeyParameters(sk, 0).generatePublicKey().encoded

    /** X25519 with an all-zero result rejected. */
    fun dh(sk: ByteArray, pk: ByteArray): ByteArray {
        try {
            val a = X25519Agreement()
            a.init(X25519PrivateKeyParameters(sk, 0))
            val out = ByteArray(32)
            a.calculateAgreement(X25519PublicKeyParameters(pk, 0), out, 0)
            if (out.all { it.toInt() == 0 }) throw AegisException.ZeroSharedSecret()
            return out
        } catch (_: IllegalStateException) {
            throw AegisException.ZeroSharedSecret()
        } catch (_: IllegalArgumentException) {
            throw AegisException.ZeroSharedSecret()
        }
    }

    fun ed25519Public(sk: ByteArray): ByteArray =
        Ed25519PrivateKeyParameters(sk, 0).generatePublicKey().encoded

    fun ed25519Sign(sk: ByteArray, msg: ByteArray): ByteArray {
        val s = Ed25519Signer()
        s.init(true, Ed25519PrivateKeyParameters(sk, 0))
        s.update(msg, 0, msg.size)
        return s.generateSignature()
    }

    private val P25519 = java.math.BigInteger.ONE.shiftLeft(255).subtract(java.math.BigInteger.valueOf(19))
    private val GROUP_L = java.math.BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989")
    private val ORDER8_Y = java.math.BigInteger("7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7", 16)
    private val SMALL_ORDER_Y = setOf(
        java.math.BigInteger.ZERO, java.math.BigInteger.ONE, P25519.subtract(java.math.BigInteger.ONE),
        ORDER8_Y, P25519.subtract(ORDER8_Y),
    )

    private fun leToBig(b: ByteArray, off: Int, len: Int): java.math.BigInteger {
        val r = ByteArray(len)
        for (i in 0 until len) r[len - 1 - i] = b[off + i]
        return java.math.BigInteger(1, r)
    }

    /** True for the eight points of order dividing 8, in any encoding (sign bit ignored, y reduced mod p). */
    fun isSmallOrder(enc: ByteArray, off: Int = 0): Boolean {
        val y = leToBig(enc, off, 32).clearBit(255).mod(P25519)
        return y in SMALL_ORDER_Y
    }

    /** Ed25519 with the strictness of Rust verify_strict: S canonical, A and R not small order. */
    fun ed25519Verify(pk: ByteArray, msg: ByteArray, sig: ByteArray): Boolean {
        if (pk.size != 32 || sig.size != 64) return false
        if (isSmallOrder(pk) || isSmallOrder(sig, 0)) return false
        if (leToBig(sig, 32, 32) >= GROUP_L) return false
        return try {
            val s = Ed25519Signer()
            s.init(false, Ed25519PublicKeyParameters(pk, 0))
            s.update(msg, 0, msg.size)
            s.verifySignature(sig)
        } catch (_: RuntimeException) {
            false
        }
    }

    /** Argon2id v0x13 to 32 bytes. */
    fun argon2id(password: ByteArray, salt: ByteArray, mKib: Int, t: Int, p: Int): ByteArray {
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(t)
            .withMemoryAsKB(mKib)
            .withParallelism(p)
            .withSalt(salt)
            .build()
        val g = Argon2BytesGenerator()
        g.init(params)
        val out = ByteArray(32)
        g.generateBytes(password, out, 0, 32)
        return out
    }
}
