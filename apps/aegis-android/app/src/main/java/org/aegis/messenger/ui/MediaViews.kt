package org.aegis.messenger.ui

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.SurfaceTexture
import android.media.MediaDataSource
import android.media.MediaMetadataRetriever
import android.media.MediaPlayer
import android.view.Surface
import android.view.TextureView
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Icon
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.aegis.messenger.app.Session
import org.aegis.messenger.core.MediaKind
import org.aegis.messenger.data.Media

/** Plays a video straight from memory, so no plaintext file exists. */
private class MemorySource(private val bytes: ByteArray) : MediaDataSource() {
    override fun readAt(position: Long, buffer: ByteArray, offset: Int, size: Int): Int {
        if (position >= bytes.size) return -1
        val n = minOf(size, bytes.size - position.toInt())
        System.arraycopy(bytes, position.toInt(), buffer, offset, n)
        return n
    }

    override fun getSize(): Long = bytes.size.toLong()
    override fun close() {}
}

private fun decodeScaled(bytes: ByteArray, maxSide: Int): Bitmap? {
    val o = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    BitmapFactory.decodeByteArray(bytes, 0, bytes.size, o)
    var sample = 1
    while (maxOf(o.outWidth, o.outHeight) / sample > maxSide) sample *= 2
    return BitmapFactory.decodeByteArray(bytes, 0, bytes.size, BitmapFactory.Options().apply { inSampleSize = sample })
}

private fun videoFrame(bytes: ByteArray): Bitmap? {
    val r = MediaMetadataRetriever()
    return try {
        r.setDataSource(MemorySource(bytes))
        r.getFrameAtTime(0)
    } catch (e: Exception) {
        null
    } finally {
        r.release()
    }
}

/** Decrypts in memory and decodes a preview. Plaintext never touches storage. */
@Composable
fun rememberPreview(session: Session, media: Media, maxSide: Int = 1280): ImageBitmap? {
    val state = produceState<ImageBitmap?>(null, media.file) {
        value = withContext(Dispatchers.IO) {
            val bytes = session.loadMedia(media) ?: return@withContext null
            try {
                (if (media.kind == MediaKind.Video) videoFrame(bytes) else decodeScaled(bytes, maxSide))?.asImageBitmap()
            } finally {
                bytes.fill(0)
            }
        }
    }
    return state.value
}

fun durationLabel(ms: Long): String {
    val s = (ms / 1000).toInt()
    return "%d:%02d".format(s / 60, s % 60)
}

/** Photo or video thumbnail; the ratio follows the stored size. */
@Composable
fun MediaThumb(session: Session, media: Media, modifier: Modifier = Modifier, square: Boolean = false, onClick: () -> Unit) {
    val img = rememberPreview(session, media, if (square) 400 else 1080)
    val ratio = if (square || media.width <= 0 || media.height <= 0) 1f else (media.width.toFloat() / media.height).coerceIn(0.6f, 1.8f)
    Box(modifier.aspectRatio(ratio).background(Ui.surface2).clickable(onClick = onClick), contentAlignment = Alignment.Center) {
        if (img != null) Image(img, null, Modifier.fillMaxSize(), contentScale = ContentScale.Crop)
        if (media.kind == MediaKind.Video) {
            Box(Modifier.size(44.dp).clip(CircleShape).background(Color(0x99000000)), contentAlignment = Alignment.Center) {
                Icon(AegisIcons.Play, null, tint = Color.White, modifier = Modifier.size(22.dp))
            }
        }
    }
}

/** Full-screen viewer for a photo or a video. */
@Composable
fun MediaViewer(session: Session, media: Media, onClose: () -> Unit) {
    Dialog(onClose, DialogProperties(usePlatformDefaultWidth = false, securePolicy = securePolicy())) {
        Box(Modifier.fillMaxSize().background(Color.Black).clickable(onClick = onClose), contentAlignment = Alignment.Center) {
            if (media.kind == MediaKind.Video) VideoPlayer(session, media) else {
                val img = rememberPreview(session, media, 2560)
                if (img != null) Image(img, null, Modifier.fillMaxWidth(), contentScale = ContentScale.Fit)
            }
        }
    }
}

@Composable
private fun VideoPlayer(session: Session, media: Media) {
    var holder by remember { mutableStateOf<ByteArray?>(null) }
    val player = remember { MediaPlayer() }
    DisposableEffect(media.file) {
        val bytes = session.loadMedia(media)
        holder = bytes
        onDispose {
            try { player.release() } catch (_: Exception) {}
            bytes?.fill(0)
        }
    }
    val bytes = holder ?: return
    AndroidView(
        modifier = Modifier.fillMaxWidth().aspectRatio(if (media.width > 0 && media.height > 0) media.width.toFloat() / media.height else 1f),
        factory = { ctx ->
            TextureView(ctx).apply {
                surfaceTextureListener = object : TextureView.SurfaceTextureListener {
                    override fun onSurfaceTextureAvailable(st: SurfaceTexture, w: Int, h: Int) {
                        try {
                            player.setSurface(Surface(st))
                            player.setDataSource(MemorySource(bytes))
                            player.isLooping = true
                            player.setOnPreparedListener { it.start() }
                            player.prepareAsync()
                        } catch (_: Exception) {}
                    }

                    override fun onSurfaceTextureSizeChanged(st: SurfaceTexture, w: Int, h: Int) {}
                    override fun onSurfaceTextureDestroyed(st: SurfaceTexture): Boolean = true
                    override fun onSurfaceTextureUpdated(st: SurfaceTexture) {}
                }
            }
        },
    )
}
