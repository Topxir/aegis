package org.aegis.messenger.core

/** Typed failures of the protocol layer. Messages never contain key material or message text. */
sealed class AegisException(message: String) : Exception(message) {
    class InvalidUsername : AegisException("invalid username")
    class InvalidText : AegisException("invalid text")
    class InvalidHex : AegisException("invalid hex")
    class InvalidEnvelope(what: String) : AegisException("invalid envelope: $what")
    class Length : AegisException("bad length")
    class BadFrameType : AegisException("bad frame type")
    class Decrypt : AegisException("decryption failed")
    class BadSignature : AegisException("bad signature")
    class ZeroSharedSecret : AegisException("degenerate shared secret")
    class SenderMismatch : AegisException("sender key mismatch")
    class GroupMismatch : AegisException("group mismatch")
    class BadPadding : AegisException("bad padding")
    class FrameTooLarge : AegisException("frame too large")
    class VaultFormat : AegisException("not a vault file")
    class VaultParams : AegisException("vault parameters out of range")
    class VaultDecrypt : AegisException("wrong password or damaged vault")
    class InvalidEndpoint : AegisException("invalid endpoint")
    class BadResponse : AegisException("bad server response")
    class Http(val code: Int) : AegisException("http status $code")
    class Media(what: String) : AegisException("media: $what")
    class Session(what: String) : AegisException("session: $what")
    class NeedsUpdate : AegisException("contact has no prekeys")
    class ServerKeyChanged : AegisException("server key changed")
    class Network(what: String) : AegisException("network: $what")
}
