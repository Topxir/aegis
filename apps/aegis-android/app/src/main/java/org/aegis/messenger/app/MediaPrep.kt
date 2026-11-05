package org.aegis.messenger.app

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.ImageDecoder
import android.net.Uri
import org.aegis.messenger.core.AegisException
import org.aegis.messenger.core.Attach
import org.aegis.messenger.core.Jpeg
import org.aegis.messenger.core.MediaKind
import org.aegis.messenger.core.Mp4Clean
import java.io.ByteArrayOutputStream

/** Sanitized media ready to be sealed (spec section 16). */
class Prepared(val kind: MediaKind, val bytes: ByteArray, val width: Long, val height: Long, val durationMs: Long)

/** Turns a picked item into sanitized bytes. The original is read into memory only. */
object MediaPrep {
    const val MAX_SIDE = 2560
    const val JPEG_QUALITY = 85

    fun fromUri(ctx: Context, uri: Uri): Prepared {
        val type = ctx.contentResolver.getType(uri) ?: ""
        return if (type.startsWith("video/")) video(ctx, uri) else image(ctx, uri)
    }

    private fun readCapped(ctx: Context, uri: Uri, cap: Int): ByteArray {
        val input = ctx.contentResolver.openInputStream(uri) ?: throw AegisException.Media("unreadable")
        input.use {
            val out = ByteArrayOutputStream()
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = it.read(buf)
                if (n < 0) break
                if (out.size() + n > cap) throw AegisException.Media("too large")
                out.write(buf, 0, n)
            }
            return out.toByteArray()
        }
    }

    private fun video(ctx: Context, uri: Uri): Prepared {
        val raw = readCapped(ctx, uri, Mp4Clean.MAX_VIDEO)
        val v = Mp4Clean.sanitize(raw)
        return Prepared(MediaKind.Video, v.bytes, v.width, v.height, v.durationMs)
    }

    private fun image(ctx: Context, uri: Uri): Prepared {
        // ImageDecoder applies the EXIF orientation. Re-encoding writes no metadata at all.
        val src = ImageDecoder.createSource(ctx.contentResolver, uri)
        var bmp = try {
            ImageDecoder.decodeBitmap(src) { decoder, info, _ ->
                decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
                val w = info.size.width
                val h = info.size.height
                val big = maxOf(w, h)
                if (big > MAX_SIDE) {
                    val f = MAX_SIDE.toDouble() / big
                    decoder.setTargetSize(maxOf(1, (w * f).toInt()), maxOf(1, (h * f).toInt()))
                }
            }
        } catch (e: java.io.IOException) {
            throw AegisException.Media("decode")
        }
        if (bmp.hasAlpha()) {
            val flat = Bitmap.createBitmap(bmp.width, bmp.height, Bitmap.Config.ARGB_8888)
            val c = Canvas(flat)
            c.drawColor(0xFFFFFFFF.toInt())
            c.drawBitmap(bmp, 0f, 0f, null)
            bmp.recycle()
            bmp = flat
        }
        val out = ByteArrayOutputStream()
        val ok = bmp.compress(Bitmap.CompressFormat.JPEG, JPEG_QUALITY, out)
        val w = bmp.width.toLong()
        val h = bmp.height.toLong()
        bmp.recycle()
        if (!ok) throw AegisException.Media("encode")
        val jpeg = Jpeg.stripMetadata(out.toByteArray())
        if (jpeg.size > Attach.MAX_SIZE) throw AegisException.Media("too large")
        return Prepared(MediaKind.Image, jpeg, w, h, 0)
    }
}
