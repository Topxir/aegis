package org.aegis.messenger.core

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class ValidationTest {
    private val particles = Particles.None

    private fun rejectsProfile(name: String, about: String = "") {
        try {
            Profile(name, about, particles).encode()
            fail("accepted")
        } catch (_: AegisException) {
        }
    }

    @Test
    fun profileRejectsSpoofingChars() {
        for (cp in listOf(0x200B, 0x200F, 0x202A, 0x202E, 0x2060, 0x2064, 0x2066, 0x2069, 0xFEFF)) {
            rejectsProfile("a" + String(Character.toChars(cp)) + "b")
            rejectsProfile("ok", "x" + String(Character.toChars(cp)))
        }
        Profile("Anna", "hello", particles).encode()
    }

    private fun desc(caption: String, w: Long = 10, h: Long = 10, d: Long = 0) = AttachmentDescriptor(
        MediaKind.Image, 100, ByteArray(32), ByteArray(32), w, h, d, listOf(ByteArray(16)), caption,
    )

    private fun rejectsAttach(f: () -> AttachmentDescriptor) {
        try {
            f().encode()
            fail("accepted")
        } catch (_: AegisException.Media) {
        }
    }

    @Test
    fun attachLimits() {
        desc("fine", 16384, 16384).encode()
        rejectsAttach { desc("x", 16385) }
        rejectsAttach { desc("x", h = 16385) }
        rejectsAttach { desc("a‮b") }
        rejectsAttach { desc("a​b") }
        rejectsAttach { desc("a\nb") }
        desc("a".repeat(1024)).encode()
        rejectsAttach { desc("a".repeat(1025)) }
        assertEquals(86_400_000L, Attach.MAX_DURATION_MS)
    }

    @Test
    fun videoDurationLimit() {
        val v = { d: Long ->
            AttachmentDescriptor(MediaKind.Video, 100, ByteArray(32), ByteArray(32), 1, 1, d, listOf(ByteArray(16)), "")
        }
        v(86_400_000L).encode()
        rejectsAttach { v(86_400_001L) }
    }
}
