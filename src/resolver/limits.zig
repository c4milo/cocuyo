//! The limits the table and the lookup hold (docs/design.md §16 decision 56). The limits more than
//! one module shares are in `core/limits.zig`; these are the table's own.
const std = @import("std");
const core_limits = @import("core").limits;

/// The earlier tries one lookup keeps open for one name: each query it sent and has not heard back
/// from, after its deadline passed (docs/design.md §5, Tries kept open; §16 decision 66). A lookup
/// sends one name at most `queries_per_transport_max` queries for each server and each of the two
/// transports (RFC 9520 §3.1), so it never has more open than that.
pub const tries_open_max: usize = core_limits.servers_max * 2 * queries_per_transport_max;

/// The key table holds at least this many entries per slot. A slot keys its lookup's current
/// transaction and each try it keeps open, at most `tries_open_max` and one more, so the table is
/// never full. A lookup keys one or two ids in the usual case, which keeps the load factor far
/// below one half, where linear probing still finds an entry in a step or two. A table of
/// `lookup_slots_max` slots whose every lookup kept every try open is 77 percent full. Twice the
/// worst case does not fit: a key's index is its sixteen-bit id, so more than 2^16 entries are
/// not reached well (`constants.zig`). The table is sized by the caller, so the floor is checked
/// rather than assumed (docs/design.md §11).
pub const keys_per_slot_min: usize = 64;

comptime {
    // A slot never keys more ids than it has entries for.
    std.debug.assert(keys_per_slot_min > tries_open_max + 1);
}

/// The transactions a lookup draws for one name on one server in one pass: the query, the
/// retry without EDNS0 after FORMERR (RFC 6891 §6.2.2) and the retry with the server cookie
/// after BADCOOKIE (RFC 7873 §5.3), which is the server's once, over UDP or over a stream. It
/// bounds a transaction's `number` (docs/design.md §22).
pub const transactions_per_server_max: usize = 3;

/// The most queries one lookup sends one server over one transport for one name: a query and two
/// retries. "A resolver MUST NOT retry a given query to a server address over a given DNS
/// transport more than twice (i.e., three queries in total)" (RFC 9520 §3.1). The transports are
/// the datagram or the request over DoH or DoQ, and the stream, TCP or TLS. Each of these counts:
///
/// - the first query of each pass;
/// - the retry without EDNS0 after FORMERR;
/// - the retry after BADCOOKIE;
/// - the query again after a reply that the checks of §7 ignored.
///
/// A new name, a search candidate or a CNAME's target, is another query. `Config.attempts` can ask
/// for more passes, and a server with no query left is passed over (docs/design.md §5, §16
/// decision 58).
pub const queries_per_transport_max: usize = 3;

/// The samples a server needs since its table was built before its wait comes from them, and the
/// samples a window needs before the wait reads it: 3, c-ares's, read from its features page, not
/// measured. Until then the server waits `Config.timeout_ns` (docs/design.md §5).
pub const latency_samples_min: usize = 3;

// A constant with no type is a `comptime_int`, which takes the type of a narrow runtime value it
// meets in a sum. The lint rule reads the shape of each value, and this reads the type, so an
// alias or a call that gives a `comptime_int` is caught here (docs/design.md §16 decision 40).
test "each integer constant here has a type" {
    inline for (@typeInfo(@This()).@"struct".decls) |declaration| {
        const untyped = @TypeOf(@field(@This(), declaration.name)) == comptime_int;
        try std.testing.expectEqualStrings("", if (untyped) declaration.name else "");
    }
}

/// The times a lookup waits for keys for one name before a message whose keys are wanted reads as
/// bogus, so no validator makes a lookup wait forever (docs/design.md §25). Chosen, not measured:
/// one wait for the walk, and one more after a key rolled.
pub const key_asks_max: u8 = 2;

/// The slots of a validating table that only a walk's question may take, so a table full of
/// lookups that wait for keys still has a slot to fetch them in (docs/design.md §25, step 12).
/// One is enough, since a walk asks one question at a time and each question ends.
pub const trust_slots_min: u16 = 1;

/// The smallest payload a validating lookup advertises: a security-aware resolver "MUST support"
/// 1220 octets (RFC 4035 §4.1).
pub const dnssec_payload_bytes_min: u16 = 1220;
