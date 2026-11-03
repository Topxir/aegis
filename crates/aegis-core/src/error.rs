use core::fmt;

pub type Result<T> = core::result::Result<T, Error>;

/// Protocol error. Never carries key material or plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Rng,
    Kdf,
    Length,
    InvalidHex,
    InvalidUsername,
    InvalidText,
    InvalidEnvelope(&'static str),
    ZeroSharedSecret,
    Decrypt,
    BadFrameType,
    BadSignature,
    GroupMismatch,
    SenderMismatch,
    FrameTooLarge,
    BadPadding,
    VaultFormat,
    VaultParams,
    VaultDecrypt,
    InvalidEndpoint,
    Net(String),
    Http(u16),
    BadResponse,
    Io(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Error::InvalidEnvelope(why) => return write!(f, "invalid envelope: {why}"),
            Error::Net(why) => return write!(f, "network error: {why}"),
            Error::Http(code) => return write!(f, "server answered {code}"),
            Error::Io(why) => return write!(f, "i/o error: {why}"),
            Error::Rng => "random number generator failure",
            Error::Kdf => "key derivation failure",
            Error::Length => "unexpected length",
            Error::InvalidHex => "invalid hex",
            Error::InvalidUsername => "invalid username",
            Error::InvalidText => "invalid text field",
            Error::ZeroSharedSecret => "all-zero shared secret",
            Error::Decrypt => "decryption failed",
            Error::BadFrameType => "frame type does not match envelope type",
            Error::BadSignature => "bad signature",
            Error::GroupMismatch => "group id does not match the queue's group",
            Error::SenderMismatch => "sender key does not match the pinned contact",
            Error::FrameTooLarge => "frame too large",
            Error::BadPadding => "bad padding",
            Error::VaultFormat => "not a vault file",
            Error::VaultParams => "unacceptable vault parameters",
            Error::VaultDecrypt => "wrong password or damaged vault",
            Error::InvalidEndpoint => "invalid or insecure endpoint",
            Error::BadResponse => "malformed server response",
        };
        f.write_str(s)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(format!("{:?}", e.kind()))
    }
}
