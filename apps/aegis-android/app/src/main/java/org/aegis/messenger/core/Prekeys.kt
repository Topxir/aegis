package org.aegis.messenger.core

/** Prekey messages and forms (spec section 27.1). */
object Prekeys {
    const val MAX_OPKS = 100

    fun spkMessage(spkHex: String, ts: Long): ByteArray = Text.utf8("aegis-v2 spk\n$spkHex\n$ts")

    fun putMessage(u: String, spkHex: String, spkTs: Long, spkSigHex: String, opksCsv: String, ts: Long): ByteArray =
        Text.utf8("aegis-v2 prekeys\n$u\n$spkHex\n$spkTs\n$spkSigHex\n$opksCsv\n$ts")

    fun takeScope(u: String) = "pk:$u"
    fun takeBodyHash(u: String, ts: Long) = Pow.bodyHashHex(Text.utf8("$u\n$ts"))

    /** Form body of `prekeys/put`, signed with the identity. */
    fun putForm(id: Identity, u: String, spk: X3dh.SignedPrekey, opks: List<ByteArray>, ts: Long): String {
        if (opks.size > MAX_OPKS) throw AegisException.Length()
        val spkHex = Hex.encode(spk.pk)
        val sigHex = Hex.encode(spk.sig)
        val csv = opks.joinToString(",") { Hex.encode(it) }
        val sig = id.sign(putMessage(u, spkHex, spk.ts, sigHex, csv, ts))
        return "u=${Text.pctEncode(u)}&spk=$spkHex&spk_ts=${spk.ts}&spk_sig=$sigHex&opks=$csv&ts=$ts&sig=${Hex.encode(sig)}"
    }

    /** Form body of `prekeys/take`; [ed] is the key pinned for [u], required for a hidden user (section 29). */
    fun takeForm(u: String, ts: Long, pow: ULong, ed: ByteArray? = null) =
        "u=${Text.pctEncode(u)}&ts=$ts&pow=$pow" + (ed?.let { "&ed=${Hex.encode(it)}" } ?: "")
}
