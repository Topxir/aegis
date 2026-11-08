package org.aegis.messenger.app

import org.aegis.messenger.core.Text

/** What a new-message notification may show. Nothing here touches the system. */
object NoteText {
    /** Longest notification text, in characters. */
    const val MAX_BODY = 120

    data class Note(val title: String, val body: String)

    /**
     * The message a notification is about: [chat] is the contact, group or channel name, [sender] the
     * author inside a group (null in direct chats), [text] the message text or the attachment label.
     */
    data class Incoming(val chat: String, val sender: String?, val text: String)

    /**
     * The notification for [m]. Unless content is allowed and the app is unlocked it is the same for
     * every message: the app name and [generic], with no sender and no text.
     */
    fun note(locked: Boolean, showContent: Boolean, app: String, generic: String, m: Incoming?): Note {
        if (locked || !showContent || m == null) return Note(app, generic)
        val text = oneLine(m.text)
        val body = if (m.sender != null) "${oneLine(m.sender)}: $text" else text
        val title = oneLine(m.chat)
        return Note(
            if (title.isEmpty()) app else title,
            if (text.isEmpty()) generic else shorten(body),
        )
    }

    private fun oneLine(s: String): String =
        Text.sanitizeBody(s).split(' ', '\n', '\t').filter { it.isNotEmpty() }.joinToString(" ")

    private fun shorten(s: String): String {
        if (s.codePointCount(0, s.length) <= MAX_BODY) return s
        return s.substring(0, s.offsetByCodePoints(0, MAX_BODY - 1)) + "\u2026"
    }
}
