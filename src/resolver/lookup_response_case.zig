//! DNS-0x20 on a response: check 5's compare of the echoed question with the one the query
//! carried, and the mark a lowercase echo of a mixed query makes on its server (docs/design.md §7,
//! A server that changes the case). Split from `lookup_response.zig` by the file-length rule; its
//! tests are `lookup_case_test.zig` and `lookup_case_echo_test.zig`.
//!
//! Check 5 reads the echo in place. The name is held as `current`, without the case, and each
//! branch of `echoes_question` is a branch of `Lookup.cased_name`, the name the query was built
//! with, read against the echo without building it (§16 decision 5, the ruling of 2026-10-09). So
//! `cased_name`'s check that the cased name is `current` in another case runs where the query is
//! built: while the lookup waits, `current`, the case seed and `query_mixed` are what the build
//! had, and the case is a function of them alone.
const std = @import("std");
const assert = std.debug.assert;
const wire = @import("wire");
const lookup_module = @import("lookup.zig");
const Lookup = lookup_module.Lookup;
const response = @import("lookup_response.zig");
const cookies = @import("lookup_cookie.zig");

/// Check 5's compare: whether the message's question is byte for byte the one the query last
/// built carried, case included, as `Lookup.cased_name` gives it, without that name built.
pub fn echoes_question(self: *const Lookup, message: []const u8) bool {
    assert(self.state == .awaiting_udp or self.state == .awaiting_tcp);
    const kind = self.question.kind;
    // The query mixed the case from this transaction's seed.
    if (self.flags.query_mixed) {
        return wire.question.matches_mixed(message, &self.current, kind, self.transaction.case_seed);
    }
    // A server that answered a mixed name in lowercase was asked in lowercase (§7).
    if (self.flags.mix_case) return wire.question.matches_lowercase(message, &self.current, kind);
    return wire.question.matches(message, &self.current, kind);
}

/// A response that echoed in lowercase the question a mixed query asked, and that passes check 6
/// as an answer must, marks its server as one that lowercases the name: it is asked in lowercase
/// from now on. It stays ignored, and the wait stands (§16 decision 10). A mixed name always
/// carries a capital, so no echo of a mixed query of cocuyo's own is in lowercase. No RFC states
/// DNS-0x20, so none states this: the rule is the owner's of 2026-10-09, narrowed by its review
/// (docs/design.md §7, A server that changes the case; §16 decision 5).
pub fn case_change(self: *const Lookup, message: []const u8) void {
    assert(self.state == .awaiting_udp or self.state == .awaiting_tcp);
    if (!self.flags.query_mixed) return;
    // No query over DoH or DoQ mixes the case (docs/design.md §22, §23).
    assert(self.flags.mix_case and !self.config.sends_requests());
    // The same question with every letter small, which names the same name (RFC 1035 §2.3.3, as
    // clarified by RFC 4343 §3); any other case may be another query's echo. A mix changes the
    // case alone, so the name as held reads as the name the query sent.
    if (!wire.question.matches_lowercase(message, &self.current, self.question.kind)) return;
    mark(self, message);
}

/// The rest of `case_change`, for an echo in lowercase alone. Out of line, so the name it builds
/// is no cost to the path every response that fails check 5 takes.
noinline fn mark(self: *const Lookup, message: []const u8) void {
    @branchHint(.cold);
    // Check 5 refused it, so the name asked was not already lowercase: it held a capital. The name
    // the query sent, built as `cased_name` builds it, says so without the compare in place.
    var asked = self.current;
    wire.name.mix_case(&asked, self.transaction.case_seed);
    assert(!wire.question.matches(message, &asked, self.question.kind));
    const opt = response.opt_of(message, &self.current) orelse return;
    // "MUST discard the response if it contains ... an incorrect Client Cookie value" (RFC 7873
    // §5.3): a response check 6 refuses is no server's word on anything.
    if (!cookies.accepted(self, opt.cookie)) return;
    self.servers.record_case_change(self.server_slot());
}
