package org.aegis.messenger.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PinUnlockTest {
    private val small = PinParams(64, 1, 1)

    @Test
    fun pinFileOpensVaultFile() {
        val vault = Vault.newKeyedWith("a long password", Vault.Params(64, 1, 1), ByteArray(16) { 3 })
        val key = vault.exportKey()
        val file = vault.seal("hello".toByteArray())

        val salt = ByteArray(16) { 1 }
        val slot = ByteArray(32) { 2 }
        val s = ByteArray(32) { 4 }
        val setup = Pin.setupWith("1234", key, small, salt, slot, s, ByteArray(12) { 5 })
        val parsed = Pin.PinFile.parse(setup.file.encode())

        val pk = PinKey(parsed, "1234")
        assertArrayEquals(setup.verifier, pk.verifier)
        val vk = parsed.unwrap(pk.key, s)
        assertArrayEquals(key, vk)
        val opened = Vault.decryptWithKey(vk, file)
        assertArrayEquals("hello".toByteArray(), opened.data)
        // The reopened key can seal again.
        val again = Vault.decryptWithKey(vk, opened.keyed.seal("x".toByteArray()))
        assertArrayEquals("x".toByteArray(), again.data)
    }

    @Test
    fun wrongPinFailsToUnwrap() {
        val key = ByteArray(32) { 9 }
        val s = ByteArray(32) { 4 }
        val setup = Pin.setupWith("1234", key, small, ByteArray(16), ByteArray(32), s, ByteArray(12))
        val k = Pin.PinKey.derive("4321", setup.file.salt, setup.file.slot, small)
        try {
            setup.file.unwrap(k, s)
            org.junit.Assert.fail("opened")
        } catch (_: AegisException) {
        }
    }

    @Test
    fun duressRecordMatchesOnlyItsPin() {
        val r = Pin.DuressRecord.parse(Pin.DuressRecord.createWith("0000", small, ByteArray(16) { 7 }, ByteArray(32) { 8 }).encode())
        assertTrue(r.matches("0000", small))
        assertFalse(r.matches("0001", small))
    }

    private class PinKey(f: Pin.PinFile, pin: String) {
        val key = Pin.PinKey.derive(pin, f.salt, f.slot, PinParams(64, 1, 1))
        val verifier: ByteArray = key.verifier()
    }
}
