//! The pure decisions a lookup makes: which candidate name to try, how long to wait, and what a
//! response code means (docs/design.md §5).
//!
//! Nothing here touches a lookup's state. Each function takes what it needs and returns what it
//! decided, which is what makes the policy table testable on its own.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Config = core.Config;
const Name = core.Name;
const Question = core.Question;
const wire = @import("wire");

/// One candidate of the search walk.
pub const Candidate = union(enum) {
    /// The name to ask about.
    name: Name,
    /// This candidate cannot be encoded — the name and the suffix are together too long — so the
    /// walk moves past it. Skipping rather than failing is what a stub has to do: one long suffix
    /// in the search list must not make every name unresolvable.
    skip,
    /// The walk is over.
    exhausted,
};

/// The candidate at `index` for `question`, under `config`.
///
/// `ndots` decides the order and not whether the list is used (docs/design.md §5): a name with at
/// least `ndots` dots is tried as it was written first, and a name with fewer is tried against the
/// search list first. An absolute name has one candidate, itself.
pub fn candidate(config: *const Config, question: *const Question, index: u8) Candidate {
    assert(index <= core.constants.candidates_max);
    if (question.absolute) return if (index == 0) .{ .name = question.name } else .exhausted;
    const search_count: u8 = @intCast(config.search.len);
    const name_first = question.name.dot_count() >= config.ndots;
    const name_at: u8 = if (name_first) 0 else search_count;
    if (index == name_at) return .{ .name = question.name };
    const search_index = if (name_first) index - 1 else index;
    if (search_index >= search_count) return .exhausted;
    const joined = question.name.concat(&config.search[search_index]) catch return .skip;
    return .{ .name = joined };
}

/// How many candidates the walk has, the name included. Bounded by `candidates_max`.
pub fn candidate_count(config: *const Config, question: *const Question) u8 {
    if (question.absolute) return 1;
    const count: u8 = @intCast(config.search.len + 1);
    assert(count <= core.constants.candidates_max);
    return count;
}

/// When the wait for the current server runs out. The timeout doubles per pass over the server
/// list and is capped, so a configuration with a long timeout and several attempts cannot make one
/// lookup wait for minutes on its last pass.
pub fn deadline_ns(config: *const Config, round: u8, now_ns: u64) u64 {
    assert(round < core.constants.attempts_max);
    const doubled = config.timeout_ns << @intCast(round);
    const waited = @min(doubled, core.constants.timeout_ns_max);
    assert(waited >= config.timeout_ns);
    return now_ns + waited;
}

/// What a response code means for a lookup (docs/design.md §5).
pub const RcodeAction = enum {
    /// Read the answer section.
    collect,
    /// This name does not exist: try the next candidate.
    next_candidate,
    /// This server cannot answer: try the next server.
    next_server,
    /// This server does not understand EDNS0: ask it again without the OPT record
    /// (RFC 6891 §6.2.2).
    retry_without_edns,
};

pub fn rcode_action(rcode: wire.Rcode, edns_enabled: bool) RcodeAction {
    return switch (rcode) {
        .no_error => .collect,
        .name_error => .next_candidate,
        .format_error => if (edns_enabled) .retry_without_edns else .next_server,
        .server_failure, .refused, .not_implemented => .next_server,
    };
}

// Tests.

const testing = std.testing;

const Endpoint = core.Endpoint;
const Address = core.Address;

const one_server = @import("fixtures.zig").servers_one;

fn config_with(search: []const Name, ndots: u8) Config {
    return .{ .servers = &one_server, .search = search, .ndots = ndots };
}

test "an absolute name has one candidate and no search list is tried" {
    const search = [_]Name{try Name.from_text("example.net")};
    const config = config_with(&search, 1);
    const question = try Question.from_text("host.example.com.", .a);
    try testing.expect(candidate(&config, &question, 0).name.equal(&question.name));
    try testing.expectEqual(Candidate.exhausted, candidate(&config, &question, 1));
    try testing.expectEqual(@as(u8, 1), candidate_count(&config, &question));
}

test "a name with enough dots is tried first, then the search list" {
    const search = [_]Name{ try Name.from_text("one.net"), try Name.from_text("two.net") };
    const config = config_with(&search, 1);
    const question = try Question.from_text("host.example.com", .a);
    try testing.expect(candidate(&config, &question, 0).name.equal(&question.name));
    try testing.expect(candidate(&config, &question, 1).name.equal(
        &try Name.from_text("host.example.com.one.net"),
    ));
    try testing.expect(candidate(&config, &question, 2).name.equal(
        &try Name.from_text("host.example.com.two.net"),
    ));
    try testing.expectEqual(Candidate.exhausted, candidate(&config, &question, 3));
    try testing.expectEqual(@as(u8, 3), candidate_count(&config, &question));
}

test "a name with too few dots is tried against the search list first" {
    const search = [_]Name{ try Name.from_text("one.net"), try Name.from_text("two.net") };
    const config = config_with(&search, 2);
    const question = try Question.from_text("host", .a);
    try testing.expect(candidate(&config, &question, 0).name.equal(&try Name.from_text("host.one.net")));
    try testing.expect(candidate(&config, &question, 1).name.equal(&try Name.from_text("host.two.net")));
    try testing.expect(candidate(&config, &question, 2).name.equal(&question.name));
    try testing.expectEqual(Candidate.exhausted, candidate(&config, &question, 3));
}

test "a candidate too long to encode is skipped, not fatal" {
    const long = try Name.from_text("a" ** 63 ++ "." ++ "b" ** 63 ++ "." ++ "c" ** 63);
    const search = [_]Name{ long, try Name.from_text("short.net") };
    const config = config_with(&search, 2);
    const question = try Question.from_text("host" ++ "." ++ "d" ** 63, .a);
    try testing.expectEqual(Candidate.skip, candidate(&config, &question, 0));
    try testing.expect(candidate(&config, &question, 1).name.equal(
        &try Name.from_text("host." ++ "d" ** 63 ++ ".short.net"),
    ));
}

test "an empty search list leaves the name as the only candidate" {
    const config = config_with(&.{}, 1);
    const question = try Question.from_text("host", .a);
    try testing.expect(candidate(&config, &question, 0).name.equal(&question.name));
    try testing.expectEqual(Candidate.exhausted, candidate(&config, &question, 1));
    try testing.expectEqual(@as(u8, 1), candidate_count(&config, &question));
}

test "the deadline doubles per pass and stops at the cap" {
    const config = config_with(&.{}, 1);
    try testing.expectEqual(config.timeout_ns, deadline_ns(&config, 0, 0));
    try testing.expectEqual(config.timeout_ns * 2, deadline_ns(&config, 1, 0));
    try testing.expectEqual(config.timeout_ns * 4, deadline_ns(&config, 2, 0));
    // 5 seconds doubled four times is 80, over the 30-second cap.
    try testing.expectEqual(core.constants.timeout_ns_max, deadline_ns(&config, 4, 0));
    try testing.expectEqual(core.constants.timeout_ns_max + 7, deadline_ns(&config, 4, 7));
}

test "every response code maps to one decision" {
    try testing.expectEqual(RcodeAction.collect, rcode_action(.no_error, true));
    try testing.expectEqual(RcodeAction.next_candidate, rcode_action(.name_error, true));
    try testing.expectEqual(RcodeAction.next_server, rcode_action(.server_failure, true));
    try testing.expectEqual(RcodeAction.next_server, rcode_action(.refused, true));
    try testing.expectEqual(RcodeAction.next_server, rcode_action(.not_implemented, true));
    try testing.expectEqual(RcodeAction.retry_without_edns, rcode_action(.format_error, true));
    try testing.expectEqual(RcodeAction.next_server, rcode_action(.format_error, false));
}
