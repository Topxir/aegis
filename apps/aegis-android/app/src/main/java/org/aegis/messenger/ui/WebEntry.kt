package org.aegis.messenger.ui

import android.annotation.SuppressLint
import android.content.res.Configuration
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.compose.BackHandler
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
import org.aegis.messenger.app.Tor
import org.aegis.messenger.app.Transports
import org.aegis.messenger.net.Bridges
import org.aegis.messenger.app.TorStatus
import org.aegis.messenger.app.Updater
import org.aegis.messenger.core.Crypto
import org.aegis.messenger.core.Hex
import org.aegis.messenger.core.MediaKind
import org.aegis.messenger.core.Particles
import org.aegis.messenger.core.Qr
import org.aegis.messenger.data.Look
import org.aegis.messenger.data.Media
import org.aegis.messenger.data.Message
import org.aegis.messenger.data.Status
import org.aegis.messenger.data.VaultData
import org.aegis.messenger.data.channelKey
import org.aegis.messenger.data.dmKey
import org.aegis.messenger.data.groupKey
import org.aegis.messenger.net.Endpoint
import org.json.JSONArray
import org.json.JSONObject
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

private const val HOST = "appassets.androidplatform.net"
private val PIN_RE = Regex("^\\d{4}(\\d{2})?$")

/** Web chat id ("group:x") to the session key ("g:x") and back. */
private fun keyOf(id: String) = when {
    id.startsWith("group:") -> groupKey(id.removePrefix("group:"))
    id.startsWith("channel:") -> channelKey(id.removePrefix("channel:"))
    else -> id
}
private fun idOf(key: String) = when {
    key.startsWith("g:") -> "group:" + key.removePrefix("g:")
    key.startsWith("c:") -> "channel:" + key.removePrefix("c:")
    else -> key
}

/**
 * The whole app is the desktop web bundle in a WebView: the page draws the model built here
 * and sends commands, which go to the session. Passwords never come back to the page.
 */
@SuppressLint("SetJavaScriptEnabled")
@Composable
fun WebEntry(session: Session) {
    val ctx = LocalContext.current
    var tab by remember { mutableStateOf("create") }
    var flash by remember { mutableStateOf<Pair<Boolean, Int>?>(null) }
    var lang by remember { mutableStateOf(Boot.language(ctx).ifEmpty { if (Locale.getDefault().language == "ru") "ru" else "en" }) }
    var importPass by remember { mutableStateOf("") }
    var ready by remember { mutableStateOf(false) }
    var route by remember { mutableStateOf("") }
    var dlg by remember { mutableStateOf("") }
    var infoKey by remember { mutableStateOf("") }
    val web = remember { WebView(ctx) }
    val media = remember { ConcurrentHashMap<String, Media>() }
    val d = session.data
    val authed = d != null

    fun text(id: Int): String {
        val c = Configuration(ctx.resources.configuration).apply { setLocale(Locale(lang)) }
        return ctx.createConfigurationContext(c).getString(id)
    }
    fun err(e: Int?) { if (e != null) flash = false to e }
    fun res(e: Int?, ok: Int = R.string.saved) { flash = if (e == null) true to ok else false to e }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        val p = importPass
        importPass = ""
        if (uri == null) { flash = false to R.string.err_import; return@rememberLauncherForActivityResult }
        session.importVault("", p, uri) { e -> res(e, R.string.info_imported) }
    }
    val mediaPick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri != null && route.isNotEmpty()) session.sendMedia(keyOf(route), uri, "")
    }
    val wallPick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri != null) session.setWallPhoto(uri)
    }
    val exportPick = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri: Uri? ->
        val u = session.data?.username
        if (uri == null || u == null) flash = false to R.string.err_export
        else session.exportVault(u, uri) { e -> res(e, R.string.info_exported) }
    }

    fun look(key: String, v: String) {
        val l = session.data?.look ?: return
        val n = v.toIntOrNull()
        val on = v == "true" || v == "on"
        session.saveLook(when (key) {
            "theme" -> l.copy(theme = v)
            "wallpaper" -> if (v == "photo" && l.photo.isEmpty()) { wallPick.launch(arrayOf("image/*")); l } else l.copy(wall = v)
            "wall_scope" -> l.copy(wallScope = v)
            "wall_dim" -> l.copy(dim = n ?: l.dim)
            "effect" -> l.copy(effect = v)
            "effect_scope" -> l.copy(effectScope = v)
            "animated" -> l.copy(animated = on)
            "depth" -> l.copy(depth = on)
            "motion" -> l.copy(motion = v)
            "list" -> l.copy(list = v)
            "density" -> l.copy(density = v)
            "bubble" -> l.copy(bubble = v)
            "avatar" -> l.copy(avatar = v)
            "radius" -> l.copy(radius = n ?: l.radius)
            "font" -> l.copy(font = n ?: l.font)
            else -> l
        })
    }

    fun handle(raw: String) {
        val m = runCatching { JSONObject(raw) }.getOrNull() ?: return
        val a = m.optJSONObject("args") ?: JSONObject()
        val dd = session.data
        val k = keyOf(route)
        fun list(n: String) = a.optJSONArray(n)?.let { j -> (0 until j.length()).map { j.optString(it) } } ?: emptyList()
        when (m.optString("cmd")) {
            "ready" -> ready = true
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
        if (dd == null) return
        when (m.optString("cmd")) {
            "nav" -> {
                val to = a.optString("to"); val id = a.optString("id")
                if (to == "dm" || to == "group" || to == "channel") { route = "$to:$id"; session.markRead(keyOf(route)) }
                else if (to == "group_info") infoKey = groupKey(id)
                else if (to == "channel_info") infoKey = channelKey(id)
                else if (to == "list" || to.isEmpty()) route = ""
            }
            "ping" -> session.touch()
            "lock" -> session.lock()
            "send" -> if (route.isNotEmpty()) session.sendText(k, a.optString("text"))
            "retry" -> session.retry(k, a.optString("id"))
            "set_ttl" -> session.setChatTtl(k, a.optLong("ttl"))
            "mute" -> session.setMuted(listOf(k), !dd.pref(k).muted)
            "pin" -> session.setPinned(listOf(k), !dd.pref(k).pinned)
            "clear_chat" -> session.deleteChatHistory(k)
            "verify" -> if (k.startsWith("dm:")) session.setVerified(k.removePrefix("dm:"), a.optBoolean("on", true))
            "open_dialog" -> dlg = a.optString("id")
            "delete_chat" -> session.deleteChats(listOf(dmKey(dlg)))
            "leave_group" -> session.leaveGroup(dlg)
            "leave_channel" -> session.deleteChannel(dlg)
            "add_contact" -> session.addContact(a.optString("username")) { _, e -> err(e) }
            "create_group" -> session.createGroup(a.optString("title"), list("members")) { _, e -> err(e) }
            "create_channel" -> session.createChannel(a.optString("title"), list("members")) { _, e -> err(e) }
            "invite_channel" -> { session.inviteToChannel((if (infoKey.startsWith("c:")) infoKey else k).removePrefix("c:"), list("members")); res(null) }
            "resend_invite" -> session.resendInvites((if (infoKey.startsWith("g:")) infoKey else k).removePrefix("g:"))
            "create_invite" -> session.createInvite { e -> err(e) }
            "redeem_invite" -> session.redeemInvite(a.optString("link")) { _, e -> res(e) }
            "pick_media" -> mediaPick.launch(arrayOf("image/*", "video/*"))
            "pick_wall" -> wallPick.launch(arrayOf("image/*"))
            "set_look" -> look(a.optString("key"), a.optString("value"))
            "reset_look" -> session.saveLook(Look())
            "save_profile" -> session.saveProfile(a.optString("display"), a.optString("about"), Particles.parse(a.optString("particles"))) { e -> res(e) }
            "pin_set" -> if (a.optString("pin") != a.optString("confirm")) err(R.string.err_password_mismatch) else session.pinSetup(a.optString("pin")) { e -> err(e) }
            "pin_remove" -> session.pinRemove(a.optString("pin")) { e -> err(e) }
            "duress_set" -> session.duressSetup(a.optString("pin"), a.optString("duress")) { e -> err(e) }
            "duress_clear" -> session.duressRemove()
            "save_privacy" -> {
                val s = dd.settings
                session.saveSettings(s.copy(idleLockMin = a.optString("idle_min").toIntOrNull()?.coerceIn(1, 999) ?: s.idleLockMin, appLock = a.optBoolean("app_lock", s.appLock))) { e -> res(e) }
                val sec = a.optBoolean("protect", Boot.secureScreen(ctx))
                if (sec != Boot.secureScreen(ctx)) { Boot.setSecureScreen(ctx, sec); ctx.activity()?.applySecure() }
            }
            "save_hidden" -> session.setHidden(a.optBoolean("hidden")) { e -> res(e) }
            "save_notify" -> session.saveSettings(dd.settings.copy(notifications = a.optBoolean("on", true), showContent = a.optBoolean("name"))) { e -> res(e) }
            "save_connection" -> {
                val bm = Bridges.Mode.parse(a.optString("bridges")) ?: Transports.mode(ctx)
                val stored = try { Bridges.check(bm, a.optString("bridge_lines", Transports.custom(ctx))) } catch (e: Bridges.Invalid) {
                    err(if (e.empty) R.string.err_bridges_empty else if (e.tooMany) R.string.err_bridges_many else R.string.err_bridge_line); return
                }
                val nc = if (bm == Bridges.Mode.Custom) stored else Transports.custom(ctx)
                if (bm != Transports.mode(ctx) || nc != Transports.custom(ctx)) { Transports.save(ctx, bm, nc); Tor.restart() }
                val cv = listOf("off", "std", "high").indexOf(a.optString("cover")).takeIf { it >= 0 } ?: Boot.coverMode(ctx)
                if (cv != Boot.coverMode(ctx)) { Boot.setCoverMode(ctx, cv); session.coverChanged() }
                session.setTor(a.optBoolean("tor", Tor.enabled))
                session.saveSettings(dd.settings.copy(endpoint = a.optString("endpoint", dd.settings.endpoint), proxy = a.optString("socks5"))) { e -> res(e) }
            }
            "confirm_tor_off" -> session.setTor(false)
            "test_conn" -> session.testConnection { ok -> flash = ok to (if (ok) R.string.test_ok else R.string.test_fail) }
            "export" -> exportPick.launch("aegis-${dd.username}.vault")
            "delete_account" -> if (a.optString("confirm") == dd.username) session.deleteAccount()
            "update_now" -> Updater.checkNow()
            "install_update" -> Updater.install(ctx)
            "save_updates" -> Updater.setAuto(ctx, a.optBoolean("auto_update", true))
        }
    }

    val ui = remember { Handler(Looper.getMainLooper()) }
    val onMsg by rememberUpdatedState<(String) -> Unit>({ handle(it) })
    LaunchedEffect(Unit) {
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.settings.allowFileAccess = false
        web.settings.allowContentAccess = false
        web.settings.mediaPlaybackRequiresUserGesture = true
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
                val nf = WebResourceResponse("text/plain", null, 404, "Not Found", null, null)
                if (path.startsWith("media/")) {
                    val md = media[path.removePrefix("media/")] ?: return nf
                    val b = session.loadMedia(md) ?: return nf
                    return WebResourceResponse(if (md.kind == MediaKind.Video) "video/mp4" else "image/jpeg", null, b.inputStream())
                }
                if (path.startsWith("wall/")) {
                    val p = session.data?.look?.photo?.takeIf { it.isNotEmpty() } ?: return nf
                    return WebResourceResponse("image/jpeg", null, Base64.decode(p, Base64.NO_WRAP).inputStream())
                }
                return runCatching { WebResourceResponse(mime(path), "utf-8", ctx.assets.open("web/$path")) }.getOrElse { nf }
            }
            override fun onPageFinished(view: WebView, url: String) { ready = true }
        }
        web.loadUrl("https://$HOST/index.html")
    }

    LaunchedEffect(session.notice) { session.notice?.let { n -> flash = false to n; session.notice = null } }
    LaunchedEffect(authed) { if (!authed) route = "" }

    val tor = Tor.status
    val upd = Updater.state
    LaunchedEffect(ready, d, tab, flash, lang, route, session.busy, session.pinSet, session.duressSet, session.inviteLink, tor, upd, session.requestTick) {
        if (!ready) return@LaunchedEffect
        val f = flash?.let { JSONObject().put("ok", it.first).put("text", text(it.second)) }
        val s = JSONObject().put("authed", authed).put("tab", tab).put("lang", lang).put("flash", f ?: JSONObject.NULL)
        if (d != null) {
            if (route.isNotEmpty() && d.chat(keyOf(route)).unread > 0) session.markRead(keyOf(route))
            s.put("m", model(ctx, session, d, route, lang, media, Updater.auto(ctx)))
            s.put("look", lookJson(d.look))
        }
        web.evaluateJavascript("window.aegisEntry&&aegisEntry.update($s)", null)
    }

    BackHandler(authed) {
        web.evaluateJavascript("(function(){var o=!!(window.aegisEntry&&aegisEntry.layered&&aegisEntry.layered());if(o)document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}));return o})()") { v ->
            if (v != "true") ctx.activity()?.moveTaskToBack(true)
        }
    }

    AndroidView({ web }, Modifier.fillMaxSize().background(Color(0xFF08080A)).systemBarsPadding().imePadding())
}

private fun arr(l: Iterable<Any?>) = JSONArray().also { j -> l.forEach { j.put(it) } }

private fun ttlText(s: Long, ru: Boolean): String {
    if (s <= 0) return if (ru) "Исчезающие сообщения выключены" else "Disappearing messages off"
    val v = when { s < 60 -> "$s ${if (ru) "с" else "s"}"; s < 3600 -> "${s / 60} ${if (ru) "мин" else "min"}"; s < 86400 -> "${s / 3600} ${if (ru) "ч" else "h"}"; else -> "${s / 86400} ${if (ru) "д" else "d"}" }
    return (if (ru) "Исчезающие сообщения: " else "Disappearing messages: ") + v
}

private fun msgJson(m: Message, ru: Boolean, media: MutableMap<String, Media>): JSONObject {
    val base = if (m.baseMs != 0L) m.baseMs else m.tsMs
    val o = JSONObject().put("id", m.id).put("out", m.outgoing).put("from", m.sender).put("ts", m.tsMs)
        .put("ttl", m.ttlS).put("exp", if (m.ttlS > 0) base + m.ttlS * 1000 else 0)
        .put("text", if (m.timer != null) "" else m.body)
        .put("sys", m.timer?.let { ttlText(it, ru) } ?: JSONObject.NULL)
        .put("state", when (m.status) { Status.SENDING -> "sending"; Status.FAILED -> "failed"; else -> "sent" })
    val md = m.media
    if (md == null) o.put("media", JSONObject.NULL)
    else {
        media[md.file] = md
        o.put("media", JSONObject().put("url", "/media/${md.file}").put("video", md.kind == MediaKind.Video).put("w", md.width).put("h", md.height).put("dur", md.durationMs))
    }
    return o
}

private fun model(ctx: android.content.Context, s: Session, d: VaultData, route: String, lang: String, media: MutableMap<String, Media>, auto: Boolean): JSONObject {
    val ru = lang == "ru"
    val open = keyOf(route)
    val chats = JSONArray()
    fun chat(key: String, ttl: Long, extra: JSONObject) {
        val c = d.chat(key)
        val full = key == open
        val ms = if (full) c.messages else c.messages.takeLast(1)
        val p = d.pref(key)
        extra.put("id", idOf(key)).put("pinned", p.pinned).put("muted", p.muted).put("ttl", ttl).put("unread", if (full) 0 else c.unread)
            .put("last", c.messages.lastOrNull()?.tsMs ?: 0).put("full", full).put("msgs", arr(ms.map { msgJson(it, ru, media) }))
        chats.put(extra)
    }
    val dms = d.chats.keys.filter { it.startsWith("dm:") }.toMutableSet()
    if (open.startsWith("dm:") && d.contact(open.removePrefix("dm:")) != null) dms += open
    for (k in dms) {
        val u = k.removePrefix("dm:")
        chat(k, d.contact(u)?.ttlS ?: 0, JSONObject().put("kind", "dm").put("peer", u))
    }
    for (g in d.groups) chat(groupKey(g.id), g.ttlS, JSONObject().put("kind", "group").put("title", g.name).put("owner", g.creator).put("members", arr(g.members)))
    for (c in d.channels) chat(channelKey(c.id), 0, JSONObject().put("kind", if (c.official) "official" else "channel").put("title", c.name)
        .put("about", "").put("owner", c.owner).put("mine", c.mine(d.username)).put("subs", JSONArray()).put("warn", false))
    val contacts = arr(d.contacts.map { c ->
        JSONObject().put("u", c.username).put("name", c.title.ifEmpty { c.username }).put("ed", Hex.encode(c.ed)).put("x", Hex.encode(c.x))
            .put("verified", c.verified).put("sn", s.safetyNumber(c) ?: "").put("fp", s.keyFingerprint(c.x)).put("about", c.about).put("changed", c.keyChanged)
    })
    val x = Crypto.x25519Public(d.xSk)
    val st = d.settings
    val (tor, p) = when {
        !Tor.enabled -> "off" to 0
        Tor.status == TorStatus.Connected -> "ready" to 100
        Tor.status == TorStatus.Failed -> "fail" to 0
        Tor.status == TorStatus.Starting -> "start" to 50
        else -> "off" to 0
    }
    val inv = s.inviteLink?.let { JSONObject().put("link", it).put("qr", qrSvg(it)) } ?: JSONObject.NULL
    return JSONObject()
        .put("me", JSONObject().put("u", d.username).put("display", d.profile.name.ifEmpty { st.displayName }).put("about", d.profile.about)
            .put("particles", d.profile.particles.wire).put("ed", Hex.encode(Crypto.ed25519Public(d.edSk))).put("x", Hex.encode(x)).put("fp", s.keyFingerprint(x)))
        .put("version", org.aegis.messenger.BuildConfig.VERSION_NAME)
        .put("route", route).put("busy", s.busy).put("pin", s.pinSet).put("duress", s.duressSet).put("invite", inv)
        .put("update", Updater.state.name)
        .put("requests", arr(s.requests().map { JSONObject().put("x", it.first).put("first", 0) }))
        .put("tor", JSONObject().put("state", tor).put("p", p))
        .put("set", JSONObject().put("idle", st.idleLockMin).put("lock", st.appLock).put("lockMin", false).put("protect", Boot.secureScreen(ctx))
            .put("hidden", st.hidden).put("taskbar", st.notifications).put("notifyName", st.showContent).put("tor", Tor.enabled)
            .put("bridges", Transports.mode(ctx).code).put("bridgeLines", Transports.custom(ctx)).put("cover", Boot.coverMode(ctx)).put("autoUpd", auto)
            .put("server", st.endpoint).put("socks", st.proxy))
        .put("contacts", contacts)
        .put("chats", chats)
}

private fun lookJson(l: Look): JSONObject {
    val b = l.bubbleStops(); val a = l.stops()
    fun ink(s: List<Int>) = if (Look.darkInk(s)) "#0a0a0b" else "#ffffff"
    val tag = l.photo.fold(0xcbf29ce484222325uL) { h, c -> (h xor c.code.toULong()) * 0x100000001b3uL }.toString(16)
    return JSONObject().put("theme", l.theme).put("bubble", arr(b.map(Look::hex))).put("accent", arr(a.map(Look::hex)))
        .put("ink", ink(b)).put("on_accent", ink(a)).put("animated", l.animated).put("motion", l.motion).put("depth", l.depth)
        .put("list", l.list).put("width", 340).put("density", l.density).put("shape", l.bubble).put("radius", l.radius).put("font", l.font)
        .put("wall", l.wall).put("avatar", l.avatar).put("wall_scope", l.wallScope).put("dim", l.dim)
        .put("photo", if (l.wall == "photo" && l.photo.isNotEmpty()) "/wall/$tag" else "")
        .put("fx", l.effect).put("fx_scope", l.effectScope).put("cols", "").put("rows", "").put("areas", "")
}

private fun qrSvg(text: String): String {
    val c = runCatching { Qr.encode(text.toByteArray()) }.getOrNull() ?: return ""
    val sb = StringBuilder()
    for (y in 0 until c.size) for (x in 0 until c.size) if (c[x, y]) sb.append("M${x + 4} ${y + 4}h1v1h-1z")
    val side = c.size + 8
    return """<svg class="qr" viewBox="0 0 $side $side" shape-rendering="crispEdges" aria-hidden="true"><rect width="$side" height="$side" fill="#fff"/><path d="$sb" fill="#000"/></svg>"""
}

private fun mime(p: String) = when (p.substringAfterLast('.')) {
    "html" -> "text/html"
    "js" -> "text/javascript"
    "css" -> "text/css"
    "woff2" -> "font/woff2"
    else -> "application/octet-stream"
}
