package org.aegis.messenger.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NoteTextTest {
    private val dm = NoteText.Incoming("Alice", null, "see you at 7")
    private val grp = NoteText.Incoming("Team", "Bob", "done")
    private val generic = NoteText.Note("Aegis", "New message")

    private fun note(locked: Boolean, show: Boolean, m: NoteText.Incoming?) = NoteText.note(locked, show, "Aegis", "New message", m)

    @Test
    fun hiddenByDefaultAndWhileLocked() {
        assertEquals(generic, note(false, false, dm))
        assertEquals(generic, note(true, false, dm))
        assertEquals(generic, note(true, true, dm))
        assertEquals(generic, note(true, true, grp))
        assertEquals(generic, note(false, true, null))
    }

    @Test
    fun contentWhenAllowed() {
        assertEquals(NoteText.Note("Alice", "see you at 7"), note(false, true, dm))
        assertEquals(NoteText.Note("Team", "Bob: done"), note(false, true, grp))
    }

    @Test
    fun cleansAndShortens() {
        val n = note(false, true, NoteText.Incoming("  Al\u202Eice\n", null, "a\n\nb\u0007 c"))
        assertEquals("Alice", n.title)
        assertEquals("a b c", n.body)
        assertEquals(generic.body, note(false, true, NoteText.Incoming("", null, " \n ")).body)
        assertEquals("Aegis", note(false, true, NoteText.Incoming("", null, "x")).title)
        val long = note(false, true, NoteText.Incoming("A", null, "x".repeat(500))).body
        assertEquals(NoteText.MAX_BODY, long.codePointCount(0, long.length))
        assertTrue(long.endsWith("\u2026"))
    }
}
