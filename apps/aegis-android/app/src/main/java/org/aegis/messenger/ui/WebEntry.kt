package org.aegis.messenger.ui

import android.annotation.SuppressLint
import android.content.res.Configuration
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.viewinterop.AndroidView
import org.aegis.messenger.R
import org.aegis.messenger.app.Boot
import org.aegis.messenger.app.Session
import org.aegis.messenger.net.Endpoint
import org.json.JSONObject
import java.util.Locale

private const val HOST = "appassets.androidplatform.net"
private val PIN_RE = Regex("^\\d{4}(\\d{2})?$")

/**
 * The sign-in screens of the desktop app, shown in a WebView. The page only sends the same
 * commands as the old form and shows what the session reports; passwords never come back to it.
 */
@SuppressLint("SetJavaScriptEnabled")
@Composable
fun WebEntry(session: Session, onDone: () -> Unit) {
    val ctx = LocalContext.current
    var tab by remember { mutableStateOf("create") }
    var flash by remember { mutableStateOf<Pair<Boolean, Int>?>(null) }
    var lang by remember { mutableStateOf(Boot.language(ctx).ifEmpty { if (Locale.getDefault().language == "ru") "ru" else "en" }) }
    var importPass by remember { mutableStateOf("") }
    var ready by remember { mutableStateOf(false) }
    val done by rememberUpdatedState(onDone)
    val web = remember { WebView(ctx) }
    val authed = session.data != null

    fun text(id: Int): String {
        val c = Configuration(ctx.resources.configuration).apply { setLocale(Locale(lang)) }
        return ctx.createConfigurationContext(c).getString(id)
    }
    fun err(e: Int?) { if (e != null) flash = false to e }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        val p = importPass
        importPass = ""
        if (uri == null) { flash = false to R.string.err_import; return@rememberLauncherForActivityResult }
        session.importVault("", p, uri) { e -> flash = if (e == null) true to R.string.info_imported else false to e }
    }

    fun handle(raw: String) {
        val m = runCatching { JSONObject(raw) }.getOrNull() ?: return
        val a = m.optJSONObject("args") ?: JSONObject()
        when (m.optString("cmd")) {
            "ready" -> ready = true
            "entry_done" -> done()
            "auth_tab" -> tab = a.optString("tab", tab)
            "dismiss_flash" -> flash = null
            "set_lang" -> { lang = if (a.optString("lang") == "en") "en" else "ru"; Boot.setLanguage(ctx, lang) }
            "unlock" -> {
                val u = a.optString("username"); val p = a.optString("password")
                if ((session.pinSet || session.pinGhost) && PIN_RE.matches(p)) session.pinUnlock(p) { o -> err(o.msg) }
                else session.unlock(u, p) { e -> err(e) }
            }
            "create" -> {
                val p = a.optString("password")
                if (p != a.optString("confirm")) err(R.string.err_password_mismatch)
                else session.create(a.optString("username"), p, a.optString("display"), Endpoint.DEFAULT) { e -> err(e) }
            }
            "import" -> { importPass = a.optString("password"); picker.launch(arrayOf("*/*")) }
        }
    }

    val ui = remember { Handler(Looper.getMainLooper()) }
    val onMsg by rememberUpdatedState<(String) -> Unit>({ handle(it) })
    LaunchedEffect(Unit) {
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.settings.allowFileAccess = false
        web.settings.allowContentAccess = false
        web.setBackgroundColor(0xFF08080A.toInt())
        web.addJavascriptInterface(object {
            @JavascriptInterface fun postMessage(s: String) { ui.post { onMsg(s) } }
        }, "aegisNative")
        web.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, req: WebResourceRequest) = req.url.host != HOST
            override fun shouldInterceptRequest(view: WebView, req: WebResourceRequest): WebResourceResponse? {
                if (req.url.host != HOST) return WebResourceResponse("text/plain", null, 403, "Forbidden", null, null)
                val path = req.url.path.orEmpty().trimStart('/').ifEmpty { "index.html" }
                if (path.contains("..")) return null
                return runCatching { WebResourceResponse(mime(path), "utf-8", ctx.assets.open("web/$path")) }
                    .getOrElse { WebResourceResponse("text/plain", null, 404, "Not Found", null, null) }
            }
            override fun onPageFinished(view: WebView, url: String) { ready = true }
        }
        web.loadUrl("https://$HOST/index.html")
    }

    LaunchedEffect(ready, authed, tab, flash, lang) {
        if (!ready) return@LaunchedEffect
        val f = flash?.let { JSONObject().put("ok", it.first).put("text", text(it.second)) }
        val s = JSONObject().put("authed", authed).put("tab", tab).put("lang", lang).put("flash", f ?: JSONObject.NULL)
        web.evaluateJavascript("window.aegisEntry&&aegisEntry.update($s)", null)
    }

    AndroidView({ web }, Modifier.fillMaxSize().background(Color(0xFF08080A)).systemBarsPadding().imePadding())
}

private fun mime(p: String) = when (p.substringAfterLast('.')) {
    "html" -> "text/html"
    "js" -> "text/javascript"
    "css" -> "text/css"
    "woff2" -> "font/woff2"
    else -> "application/octet-stream"
}
