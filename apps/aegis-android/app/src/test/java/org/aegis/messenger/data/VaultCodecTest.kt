package org.aegis.messenger.data

import org.aegis.messenger.core.Json
import org.aegis.messenger.core.Text
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Timer, app lock and notification fields in the vault, and vaults saved before them. */
class VaultCodecTest {
    private fun sample(): VaultData {
        val bob = Contact("bob", "Bob", ByteArray(32) { 1 }, ByteArray(32) { 2 }, ttlS = 300, ttlTs = 1_700_000_000_500)
        val g = Group("ab".repeat(16), ByteArray(32) { 3 }, "Team", listOf("alice", "bob"), 30, "alice", 1_700_000_000_900)
        val msgs = listOf(
            Message("01".repeat(16), false, "bob", "Bob", 1_700_000_000_000, 1_700_000_000_100, 300, "hi"),
            Message("02".repeat(16), true, "alice", "Alice", 1_700_000_000_500, 1_700_000_000_500, 0, "", timer = 300),
        )
        return VaultData(
            "alice", ByteArray(32) { 4 }, ByteArray(32) { 5 },
            contacts = listOf(bob), groups = listOf(g), chats = mapOf(dmKey("bob") to Chat(msgs, 1)),
            settings = Settings(appLock = false, showContent = true),
        )
    }

    @Test
    fun roundTrip() {
        val d = VaultCodec.decode(VaultCodec.encode(sample()))
        assertEquals(1_700_000_000_500, d.contact("bob")!!.ttlTs)
        assertEquals(1_700_000_000_900, d.groups[0].ttlTs)
        val msgs = d.chat(dmKey("bob")).messages
        assertNull(msgs[0].timer)
        assertEquals(300L, msgs[1].timer)
        assertFalse(d.settings.appLock)
        assertTrue(d.settings.showContent)
    }

    @Test
    @Suppress("UNCHECKED_CAST")
    fun olderVaultGetsDefaults() {
        val m = Json.parseObject(Text.utf8Strict(VaultCodec.encode(sample()))).toMutableMap()
        m["contacts"] = (m["contacts"] as List<Map<String, Any?>>).map { it - "ttl_ts" }
        m["groups"] = (m["groups"] as List<Map<String, Any?>>).map { it - "ttl_ts" }
        m["settings"] = (m["settings"] as Map<String, Any?>) - "app_lock" - "show_content"
        m["chats"] = (m["chats"] as Map<String, Map<String, Any?>>).mapValues { (_, c) ->
            c + ("msgs" to (c["msgs"] as List<Map<String, Any?>>).map { it - "timer" })
        }
        val d = VaultCodec.decode(Text.utf8(Json.write(m)))
        assertEquals(0L, d.contact("bob")!!.ttlTs)
        assertEquals(0L, d.groups[0].ttlTs)
        assertTrue(d.chat(dmKey("bob")).messages.all { it.timer == null })
        assertTrue(d.settings.appLock)
        assertFalse(d.settings.showContent)
    }
}
