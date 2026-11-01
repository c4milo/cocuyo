//! What a validator says of a message, which `dnssec` writes and `resolver` reads
//! (docs/design.md §25, Stage B). The types live in `core` because neither of those modules may
//! import the other.
const Name = @import("name.zig").Name;
const Question = @import("question.zig").Question;

/// What a secure message ends a lookup's question with: its answer, a chain of CNAME links whose
/// end the message does not say, or the negative its proof gives (RFC 9824 §8: the response code
/// is not signed, so the proof decides).
pub const Ending = enum { answer, alias, no_data, name_error };

pub const Secure = struct {
    ending: Ending,
    /// The smallest TTL of §25 item 7 over every RRset the lookup used.
    ttl_seconds: u32,
};

pub const Reason = enum {
    /// A signature over an RRset the lookup uses failed, or the work ran past a limit.
    signature,
    /// The NSEC or NSEC3 records of a negative, or of a wildcard answer, prove nothing.
    proof,
    /// The message is malformed, holds more than `records_max` records, or a chain longer than
    /// `cname_hops_max`, which the lookup fails anyway.
    message,
};

pub const Validation = union(enum) {
    secure: Secure,
    insecure,
    /// The question cannot be secure: an RRSIG is never signed (RFC 4035 §2.2, §25 item 15).
    unchecked,
    bogus: Reason,
    /// The validator waits for the keys of this zone, or, for data with no signature, for a walk
    /// to this name (§25, walk rule 1).
    keys_wanted: Name,
};

/// How a walk for a message's keys ended without them (§25, walk rules 7 and 11).
pub const Walked = enum {
    /// It proved the message wrong.
    bogus,
    /// One of its questions went unanswered.
    timeout,
    /// Every server of one of its questions failed.
    failed,
};

/// How a walk for keys ended: with what its target needs held, or with a failure (§25, walk rules
/// 7, 8 and 11).
pub const End = union(enum) { ready, failed: Walked };

/// A walk's next question, which the table asks as a lookup of its own (§25 step 12).
pub const Asked = struct {
    walk: u8,
    question: Question,
};
