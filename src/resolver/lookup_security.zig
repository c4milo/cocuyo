//! What a lookup knows of where its end came from (docs/design.md §25, Stage A). A lookup relies
//! on the AD bit of a response only as `Config.authenticated_data` allows for its transport (RFC
//! 4035 §4.6). It ends `authenticated` when every message it acted on had AD set (rule 3): each
//! link of a CNAME chain that spans messages, each negative that moved it to the next search
//! candidate, and the message that ended it. Split from `lookup.zig` by the file-length rule.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const lookup_module = @import("lookup.zig");
const Lookup = lookup_module.Lookup;

/// Rule 3's conjunction. Whether the configuration relies on the AD bit of a response from the
/// lookup's servers is decided once, at init, so a message costs one comparison.
pub const Conjunction = enum(u2) {
    /// The configuration does not rely on the bit, so every end is `unchecked`.
    not_relied,
    /// Every message the lookup acted on so far had AD set.
    holds,
    /// A message the lookup acted on had AD clear. Once clear it stays clear.
    cleared,

    /// The model's `authentic`: false once a message without AD cleared the conjunction.
    pub fn authentic(self: Conjunction) bool {
        return self != .cleared;
    }
};

/// Where a lookup under `config` starts (RFC 4035 §4.6; docs/design.md §25, Stage A rule 1).
pub fn start(config: *const core.Config) Conjunction {
    return if (config.authenticated_data.relied_on(config.transport())) .holds else .not_relied;
}

/// The lookup acts on a message with `header`: a message without AD clears rule 3's conjunction,
/// while the configuration relies on the bit.
pub fn acted_on(lookup: *Lookup, header: wire.Header) void {
    assert(lookup.state == .awaiting_udp or lookup.state == .awaiting_tcp);
    if (lookup.authentic == .holds and !header.authentic_data()) lookup.authentic = .cleared;
    assert(lookup.authentic != .holds or header.authentic_data());
}

/// What `Answer.security` and `Failure.security` report.
pub fn of(lookup: *const Lookup) core.Security {
    assert(lookup.is_settled());
    return if (lookup.authentic == .holds) .authenticated else .unchecked;
}

/// The table's memory ended the lookup with what it kept, and `status` is what the lookup that
/// found it knew. The end reports it, and `authenticated` only while this lookup relies on the
/// bit too (docs/design.md §25, Stage A rule 5).
pub fn recalled(lookup: *Lookup, status: core.Security) void {
    assert(lookup.is_settled());
    if (lookup.authentic == .holds and status != .authenticated) lookup.authentic = .cleared;
    assert(of(lookup) != .authenticated or status == .authenticated);
}

// Tests, through the fake server of `fixtures.zig`. Its servers are in the clear.

const testing = std.testing;
const fixtures = @import("fixtures.zig");
const Name = core.Name;
const AuthenticatedData = core.AuthenticatedData;

const servers = fixtures.servers_two;
const seed = fixtures.seed;

/// `reply` with AD set: the server says it validated the answer (RFC 4035 §3.2.3).
fn with_ad(reply: fixtures.Reply) fixtures.Reply {
    var signed = reply;
    signed.authentic_data = true;
    return signed;
}

/// The security of the answer that `replies` lead to, under `mode`, all from the first server.
fn answered(mode: AuthenticatedData, replies: []const fixtures.Reply) !core.Security {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .authenticated_data = mode } };
    try harness.start("example.com.", .a, seed);
    for (replies) |reply| {
        _ = harness.send();
        _ = harness.respond(reply, servers[0].endpoint);
    }
    return harness.poll().done.security;
}

/// The failure that `replies` lead to, under `always`, with the search list `search`.
fn failed(search: []const Name, replies: []const fixtures.Reply) !lookup_module.Failure {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .search = search, .ndots = 1, .authenticated_data = .always } };
    try harness.start("example.com", .a, seed);
    for (replies) |reply| {
        _ = harness.send();
        _ = harness.respond(reply, servers[0].endpoint);
    }
    return harness.poll().failed;
}

test "an answer with AD set is authenticated where the configuration relies on the bit, and unchecked elsewhere" {
    // RFC 4035 §4.6: the bit counts over a secure channel, or where the configuration says so.
    try testing.expectEqual(core.Security.authenticated, try answered(.always, &.{with_ad(fixtures.answer_a)}));
    try testing.expectEqual(core.Security.unchecked, try answered(.encrypted, &.{with_ad(fixtures.answer_a)}));
    try testing.expectEqual(core.Security.unchecked, try answered(.ignored, &.{with_ad(fixtures.answer_a)}));
    try testing.expectEqual(core.Security.unchecked, try answered(.always, &.{fixtures.answer_a}));
}

test "a chain across two messages is authenticated only when both had AD set" {
    // Rule 3: each link of a chain that spans messages is a message the lookup acted on.
    try testing.expectEqual(core.Security.authenticated, try answered(.always, &.{ with_ad(fixtures.cname_only), with_ad(fixtures.answer_a) }));
    try testing.expectEqual(core.Security.unchecked, try answered(.always, &.{ fixtures.cname_only, with_ad(fixtures.answer_a) }));
    try testing.expectEqual(core.Security.unchecked, try answered(.always, &.{ with_ad(fixtures.cname_only), fixtures.answer_a }));
}

test "a negative with AD set is authenticated, and a server failure is unchecked" {
    try testing.expectEqual(core.Security.authenticated, (try failed(&.{}, &.{with_ad(fixtures.name_error)})).security);
    try testing.expectEqual(core.Security.authenticated, (try failed(&.{}, &.{with_ad(fixtures.no_data)})).security);
    try testing.expectEqual(core.Security.unchecked, (try failed(&.{}, &.{fixtures.name_error})).security);
    const search = [_]Name{try Name.from_text("one.net")};
    // The negative that moved the walk to the next candidate is a message the lookup acted on.
    try testing.expectEqual(core.Security.unchecked, (try failed(&search, &.{ fixtures.name_error, with_ad(fixtures.name_error) })).security);
    try testing.expectEqual(core.Security.authenticated, (try failed(&search, &.{ with_ad(fixtures.name_error), with_ad(fixtures.name_error) })).security);
}

test "a server failure without AD leaves the next server's answer authenticated" {
    // The lookup takes nothing from a SERVFAIL, so it is no message the lookup acted on.
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .authenticated_data = .always } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.server_failure, servers[0].endpoint);
    _ = harness.send();
    _ = harness.respond(with_ad(fixtures.answer_a), servers[1].endpoint);
    try testing.expectEqual(core.Security.authenticated, harness.poll().done.security);
}

test "a query sets AD when the configuration relies on the bit, and leaves it clear when ignored" {
    // RFC 6840 §5.7, docs/design.md §25 rule 2.
    for ([_]AuthenticatedData{ .ignored, .encrypted, .always }) |mode| {
        var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .authenticated_data = mode } };
        try harness.start("example.com.", .a, seed);
        const header = try wire.header.parse(harness.send().send_udp.message_bytes);
        try testing.expectEqual(mode != .ignored, header.authentic_data());
        try testing.expect(!header.checking_disabled());
    }
}
