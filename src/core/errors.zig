//! Every error cocuyo returns. An error is an operational failure: a malformed response, a server
//! that did not answer, a name the caller spelled in a way DNS cannot carry. Programmer errors
//! assert instead (CLAUDE.md non-negotiable 3), so nothing here reports a bug in the caller's use
//! of the API.

/// The failures a lookup can end in, and the failures the codec can report.
pub const Error = error{
    /// The name does not exist: NXDOMAIN, after every search candidate was tried (RFC 1035 §4.1.1).
    NameNotFound,
    /// The name exists but carries no record of the type asked for.
    NoData,
    /// A server answered SERVFAIL.
    ServerFailure,
    /// A server answered REFUSED.
    Refused,
    /// A server answered NOTIMP.
    NotImplemented,
    /// A server answered FORMERR, and the retry without EDNS0 did not help.
    FormatError,
    /// Every pass over every server ran out of time.
    Timeout,
    /// Every server was tried and each one failed rather than timed out.
    AllServersFailed,
    /// The CNAME chain was longer than `constants.cname_hops_max`.
    ChainTooLong,
    /// The message is shorter than the part being read, or its counts disagree with its sections.
    MalformedMessage,
    /// A name in the message is not a legal encoding.
    MalformedName,
    /// A compression pointer does not point strictly backwards, or the hop bound was reached.
    BadCompressionPointer,
    /// A name would exceed `constants.name_bytes_max` in wire form.
    NameTooLong,
    /// A label would exceed `constants.label_bytes_max`.
    LabelTooLong,
    /// The record's rdata runs past the end of the message.
    TruncatedMessage,
    /// A record carries a class cocuyo does not query, which is anything but IN.
    UnsupportedClass,
    /// An OPT record carries a version cocuyo does not implement, which is anything but 0.
    UnsupportedEdnsVersion,
    /// The caller cancelled the lookup. The only failure here that cocuyo did not observe but was
    /// told about.
    Canceled,
};
