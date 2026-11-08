package org.aegis.messenger.data

import org.aegis.messenger.core.Json
import org.aegis.messenger.core.Text
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LookTest {
    private fun roundTrip(l: Look): Look {
        @Suppress("UNCHECKED_CAST")
        val m = Json.parse(Json.write(l.toJson())) as Map<String, Any?>
        return Look.fromJson(m)
    }

    @Test
    fun defaultsAreCalm() {
        val d = Look()
        assertEquals("mono", d.theme)
        assertEquals("subtle", d.motion)
        assertFalse(d.depth)
        assertFalse(d.animated)
        assertEquals("left", d.list)
        assertEquals("comfortable", d.density)
        assertEquals("rounded", d.bubble)
        assertEquals(Look.RADIUS_DEFAULT, d.radius)
        assertEquals(Look.FONT_DEFAULT, d.font)
        assertEquals("none", d.wall)
        assertEquals("circle", d.avatar)
        assertEquals(d, d.sanitize())
    }

    @Test
    fun missingLookGivesDefaults() {
        assertEquals(Look(), Look.fromJson(null))
        assertEquals(Look(), Look.fromJson(emptyMap()))
        assertEquals(Look(depth = true), Look.fromJson(mapOf("depth" to true)))
    }

    @Test
    fun roundTripKeepsEverything() {
        val l = Look(
            theme = "custom", custom = listOf(0x112233, 0xABCDEF, 0x00FF00), animated = true, motion = "full",
            depth = true, list = "top", density = "compact", bubble = "minimal", radius = 5, font = 19,
            wall = "gradient", avatar = "square",
        )
        assertEquals(l, roundTrip(l))
        assertEquals(Look(theme = "dusk"), roundTrip(Look(theme = "dusk")))
        assertEquals(listOf("#112233", "#abcdef", "#00ff00"), l.toJson()["custom"])
    }

    @Test
    fun brokenValuesAreSanitized() {
        val l = Look.fromJson(
            mapOf(
                "theme" to "neon", "custom" to listOf("#12", 7, "#zzzzzz"), "animated" to "yes", "motion" to 3L,
                "depth" to null, "list" to "bottom", "density" to "tight", "bubble" to "", "radius" to 900L,
                "font" to -4L, "wall" to listOf(1), "avatar" to "hexagon",
            ),
        )
        assertEquals(Look(radius = Look.RADIUS_MAX, font = Look.FONT_MIN), l)
        // A custom theme needs two or three valid stops.
        assertEquals("mono", Look.fromJson(mapOf("theme" to "custom", "custom" to listOf("#112233"))).theme)
        assertEquals(listOf(1, 2, 3), Look(theme = "custom", custom = listOf(1, 2, 3, 4)).sanitize().custom)
        assertEquals(Look(), Look.fromJson(mapOf("radius" to 1e300, "font" to Long.MAX_VALUE)).copy(radius = Look.RADIUS_DEFAULT, font = Look.FONT_DEFAULT))
    }

    @Test
    fun presetsMatchDesktop() {
        assertEquals(listOf("mono", "ocean", "dusk", "aurora", "ember", "slate"), Look.PRESETS.keys.toList())
        assertEquals(listOf(0xF4F4F6, 0xCFD0D6), Look.PRESETS["mono"])
        assertEquals(listOf(0x2563EB, 0x0EA5B7), Look.PRESETS["ocean"])
        assertEquals(listOf(0x6D4AFF, 0xD9467E), Look.PRESETS["dusk"])
        assertEquals(listOf(0x0F9F7A, 0x2B6FE0, 0x7C4DFF), Look.PRESETS["aurora"])
        assertEquals(listOf(0xF0662E, 0xD42F4F), Look.PRESETS["ember"])
        assertEquals(listOf(0x8FA3C2, 0x5D6F8C), Look.PRESETS["slate"])
        assertEquals(listOf(0x2C2D32, 0x222327), Look(theme = "mono").bubbleStops())
        assertEquals(listOf(0x4B5A73, 0x2D3646), Look(theme = "slate").bubbleStops())
        assertEquals(Look.PRESETS["ocean"], Look(theme = "ocean").bubbleStops())
        assertEquals(listOf(5, 6), Look(theme = "custom", custom = listOf(5, 6)).stops())
    }

    @Test
    fun inkFollowsBrightness() {
        assertTrue(Look.darkInk(Look(theme = "mono").stops()))
        assertFalse(Look.darkInk(Look(theme = "ocean").stops()))
        assertFalse(Look.darkInk(Look(theme = "mono").bubbleStops()))
        assertEquals(0x0EA5B7, Look.parseHex("#0ea5b7"))
        assertEquals(null, Look.parseHex("0ea5b7"))
        assertEquals("#00000a", Look.hex(10))
    }

    @Test
    fun placement() {
        val left = Look()
        assertEquals("single", left.placement(wide = false, chatOpen = false))
        assertEquals("single", left.placement(wide = true, chatOpen = false))
        assertEquals("single", left.placement(wide = false, chatOpen = true))
        assertEquals("left", left.placement(wide = true, chatOpen = true))
        val right = Look(list = "right")
        assertEquals("right", right.placement(wide = true, chatOpen = true))
        assertEquals("single", right.placement(wide = false, chatOpen = true))
        val top = Look(list = "top")
        assertEquals("strip", top.placement(wide = false, chatOpen = true))
        assertEquals("strip", top.placement(wide = true, chatOpen = true))
        assertEquals("single", top.placement(wide = true, chatOpen = false))
    }

    @Test
    fun vaultKeepsLookAndReadsOldVaults() {
        val look = Look(theme = "aurora", motion = "off", list = "right", font = 18)
        val v = VaultData("alice", ByteArray(32) { 1 }, ByteArray(32) { 2 }, mediaKey = ByteArray(32) { 3 }, look = look)
        val bytes = VaultCodec.encode(v)
        assertEquals(look, VaultCodec.decode(bytes).look)

        // A vault written before the look existed has no "look" key.
        val m = LinkedHashMap(Json.parseObject(Text.utf8Strict(bytes)))
        m.remove("look")
        val old = VaultCodec.decode(Text.utf8(Json.write(m)))
        assertEquals(Look(), old.look)
        assertEquals("alice", old.username)
    }
}
