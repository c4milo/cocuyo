//! Ending a lookup from memory: the two ways a cache under the table answers a question before
//! any query is built (docs/design.md §20). `table_memory.zig` is the one caller, at a lookup's
//! first poll, and both leave the lookup in the end state a lookup that went out would reach.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const Name = core.Name;
const Lookup = @import("lookup.zig").Lookup;

/// Ends `lookup` with answers the memory remembered. `ttl_seconds` is what is left of them, not
/// what they were given, so the answer reports the life it has now.
///
/// `canonical` is the end of the CNAME chain that reached them, or null when none did. The
/// answer reports it as a lookup that went out reports its own, so the same question answers the
/// same whether the memory held it or not (§17 question 13).
pub fn answer(
    lookup: *Lookup,
    answers: *const wire.Answers,
    ttl_seconds: u32,
    canonical: ?*const Name,
) void {
    assert(lookup.state == .query_ready);
    assert(!lookup.flags.aliased);
    lookup.answers = answers.*;
    lookup.answers.ttl_seconds = ttl_seconds;
    if (canonical) |name| {
        lookup.current = name.*;
        lookup.flags.aliased = true;
    }
    lookup.state = .done;
    assert(lookup.is_settled());
}

/// Ends `lookup` with a negative the memory remembered: one of the two of RFC 2308 §5, with what
/// is left of its life.
pub fn failure(lookup: *Lookup, err: core.Error, ttl_seconds: u32) void {
    assert(lookup.state == .query_ready);
    assert(err == core.Error.NameNotFound or err == core.Error.NoData);
    lookup.negative_ttl_seconds = ttl_seconds;
    lookup.fail(err);
}
