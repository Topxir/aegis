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

    fun ed25519Verify(pk: ByteArray, msg: ByteArray, sig: ByteArray): Boolean {
        if (pk.size != 32 || sig.size != 64) return false
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
