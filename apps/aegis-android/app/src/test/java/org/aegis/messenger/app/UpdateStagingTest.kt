package org.aegis.messenger.app

import org.aegis.messenger.core.AegisException
import org.aegis.messenger.core.Update
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream
import java.io.File

class UpdateStagingTest {
    @get:Rule val tmp = TemporaryFolder()

    private fun artifact(data: ByteArray, name: String = "aegis.apk") =
        Update.Artifact(name, data.size.toLong(), Update.hash(ByteArrayInputStream(data)).first, "0.3.0", "0.1.0", 3)

    private fun refused(why: String, block: () -> Unit) {
        try {
            block()
        } catch (e: AegisException.Update) {
            assertEquals(why, e.why)
            return
        }
        fail("accepted, expected $why")
    }

    @Test
    fun onlyAMatchingFileIsKept() {
        val dir = File(tmp.root, "update")
        val body = ByteArray(3 * 1000) { (it % 251).toByte() }
        val a = artifact(body)
        refused("file hash") { stageUpdate(dir, a) { off -> ByteArray(body.size - off.toInt()) } }
        refused("file size") { stageUpdate(dir, a) { ByteArray(body.size + 1) } }
        assertEquals(0, dir.listFiles()!!.size)

        val f = stageUpdate(dir, a) { off -> body.copyOfRange(off.toInt(), minOf(body.size, off.toInt() + 1000)) }
        assertArrayEquals(body, f.readBytes())
        assertEquals(listOf("aegis.apk"), dir.list()!!.toList())
        assertTrue(isStaged(f, a))
        // Already staged: not fetched again.
        assertEquals(f, stageUpdate(dir, a) { throw AegisException.BadResponse() })
        // A changed file on disk is not trusted.
        f.writeBytes(body.copyOf().also { it[0] = 1 })
        refused("file hash") { stageUpdate(dir, a) { off -> ByteArray(body.size - off.toInt()) } }
        assertEquals(0, dir.listFiles()!!.size)
    }

    @Test
    fun namesCannotLeaveTheUpdateDir() {
        val dir = File(tmp.root, "update")
        for (name in listOf("../evil.apk", "a/b.apk", "..", "", ".hidden.apk", "C:x.apk")) {
            refused("file name") { stageUpdate(dir, artifact(byteArrayOf(1), name)) { byteArrayOf(1) } }
        }
        assertEquals(0, tmp.root.list()!!.size)
    }

    @Test
    fun oversizedArtifactsAreRefusedBeforeDownload() {
        val big = Update.Artifact("aegis.apk", Update.MAX_FILE + 1, ByteArray(32), "0.3.0", "0.1.0", 3)
        refused("file size") { stageUpdate(File(tmp.root, "update"), big) { fail("fetched"); ByteArray(0) } }
    }
}
