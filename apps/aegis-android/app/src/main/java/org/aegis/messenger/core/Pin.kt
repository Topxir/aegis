package org.aegis.messenger.core

/** Argon2id cost for the PIN. */
class PinParams(val mKib: Int, val t: Int, val p: Int) {
    companion object {
        val DEFAULT = PinParams(19456, 2, 1)
    }
}

/** PIN unlock, client side (spec sections 20 and 25). */
object Pin {
    const val PIN_FILE_LEN = 4 + 16 + 32 + 12 + 32 + 16
    const val DURESS_FILE_LEN = 4 + 16 + 32 + 32
    private val MAGIC = Text.utf8("AGP1")
    private val DURESS_MAGIC = Text.utf8("AGD1")

    fun isValidPin(pin: String): Boolean = (pin.length == 4 || pin.length == 6) && pin.all { it in '0'..'9' }

    fun createHashInput(slotHex: String, vHex: String, sHex: String) = "$slotHex\n$vHex\n$sHex"
    fun openHashInput(slotHex: String, vHex: String) = "$slotHex\n$vHex"
    fun powScope(slotHex: String) = "pin:$slotHex"

    /** Key derived from the PIN and the stored salt: T = Argon2id(pin, salt). */
    class PinKey private constructor(val t: ByteArray, private val slot: ByteArray) {
        fun verifier(): ByteArray = Crypto.hkdf32(t, slot, Text.utf8("aegis-v2 pin-verify"))

        fun wrapKey(s: ByteArray): ByteArray = Crypto.hkdf32(Bytes.concat(t, s), slot, Text.utf8("aegis-v2 pin-wrap"))

        fun wipe() = t.fill(0)

        companion object {
            fun derive(pin: String, salt: ByteArray, slot: ByteArray, params: PinParams = PinParams.DEFAULT): PinKey {
                if (!isValidPin(pin)) throw AegisException.InvalidEnvelope("pin")
                val t = Crypto.argon2id(Text.utf8(pin), salt, params.mKib, params.t, params.p)
                return PinKey(t, slot.copyOf())
            }
        }
    }

    private fun aad(salt: ByteArray, slot: ByteArray) = Bytes.concat(MAGIC, salt, slot)

    class PinFile(val salt: ByteArray, val slot: ByteArray, val nonce: ByteArray, private val ct: ByteArray) {
        fun slotHex(): String = Hex.encode(slot)

        fun encode(): ByteArray = Bytes.concat(MAGIC, salt, slot, nonce, ct)

        fun derive(pin: String): PinKey = PinKey.derive(pin, salt, slot)

        /** Recovers the vault key with the PIN key and the secret returned by the server. */
        fun unwrap(key: PinKey, s: ByteArray): ByteArray {
            val wrap = key.wrapKey(s)
            try {
                val pt = Crypto.aeadOpen(wrap, nonce, aad(salt, slot), ct)
                if (pt.size != 32) throw AegisException.Length()
                return pt
            } finally {
                wrap.fill(0)
            }
        }

        companion object {
            fun parse(b: ByteArray): PinFile {
                if (b.size != PIN_FILE_LEN || !Bytes.eq(b.copyOfRange(0, 4), MAGIC)) throw AegisException.VaultFormat()
                return PinFile(b.copyOfRange(4, 20), b.copyOfRange(20, 52), b.copyOfRange(52, 64), b.copyOfRange(64, b.size))
            }
        }
    }

    class PinSetup(val file: PinFile, val verifier: ByteArray, val s: ByteArray)

    fun setup(pin: String, vaultKey: ByteArray): PinSetup = setupWith(
        pin, vaultKey, PinParams.DEFAULT,
        Crypto.randomBytes(16), Crypto.randomBytes(32), Crypto.randomBytes(32), Crypto.randomBytes(12),
    )

    fun setupWith(
        pin: String, vaultKey: ByteArray, params: PinParams,
        salt: ByteArray, slot: ByteArray, s: ByteArray, nonce: ByteArray,
    ): PinSetup {
        val key = PinKey.derive(pin, salt, slot, params)
        val wrap = key.wrapKey(s)
        val ct = Crypto.aeadSeal(wrap, nonce, aad(salt, slot), vaultKey)
        val v = key.verifier()
        key.wipe(); wrap.fill(0)
        return PinSetup(PinFile(salt, slot, nonce, ct), v, s.copyOf())
    }

    /** Local record of the duress PIN; a match means wipe. It has no server slot. */
    class DuressRecord(val salt: ByteArray, val slot: ByteArray, private val verifier: ByteArray) {
        fun matches(pin: String, params: PinParams = PinParams.DEFAULT): Boolean {
            val key = PinKey.derive(pin, salt, slot, params)
            val v = key.verifier()
            key.wipe()
            return Bytes.eq(v, verifier)
        }

        fun encode(): ByteArray = Bytes.concat(DURESS_MAGIC, salt, slot, verifier)

        companion object {
            fun create(pin: String, params: PinParams = PinParams.DEFAULT): DuressRecord =
                createWith(pin, params, Crypto.randomBytes(16), Crypto.randomBytes(32))

            fun createWith(pin: String, params: PinParams, salt: ByteArray, slot: ByteArray): DuressRecord {
                val key = PinKey.derive(pin, salt, slot, params)
                val v = key.verifier()
                key.wipe()
                return DuressRecord(salt, slot, v)
            }

            fun parse(b: ByteArray): DuressRecord {
                if (b.size != DURESS_FILE_LEN || !Bytes.eq(b.copyOfRange(0, 4), DURESS_MAGIC)) throw AegisException.VaultFormat()
                return DuressRecord(b.copyOfRange(4, 20), b.copyOfRange(20, 52), b.copyOfRange(52, 84))
            }
        }
    }
}
