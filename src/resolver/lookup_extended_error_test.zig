//! The extended error a failure carries, driven through the fake server (docs/design.md §16
//! decision 64, RFC 8914): the code of the last response that was not NOERROR and carried one.
//! Split from `lookup_failure.zig` by the file-length rule.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const wire = @import("wire");
const lookup_module = @import("lookup.zig");
const fixtures = @import("fixtures.zig");

const servers = fixtures.servers_two;
const seed = fixtures.seed;
const code = wire.fixtures.extended_error_code;

/// `reply` with the options `options` in its OPT record.
fn with_options(reply: fixtures.Reply, options: []const u8) fixtures.Reply {
    var carried = reply;
    carried.options = options;
    return carried;
}

/// The failure that `replies` lead to, one pass over both servers, each reply from the server
/// the lookup is on.
fn failed(replies: []const fixtures.Reply) !lookup_module.Failure {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .attempts = 1 } };
    try harness.start("example.com.", .a, seed);
    for (replies) |reply| {
        _ = harness.send();
        _ = harness.respond(reply, harness.lookup.server());
    }
    return harness.poll().failed;
}

test "a SERVFAIL's extended error reaches the failure, and a later SERVFAIL without one keeps it" {
    // RFC 8914 §2: a validating server says why it failed, as Stage A of §25 needs.
    const first = with_options(fixtures.server_failure, &wire.fixtures.opt_extended_error);
    const failure = try failed(&.{ first, fixtures.server_failure });
    try testing.expectEqual(core.Error.AllServersFailed, failure.err);
    try testing.expectEqual(@as(?u16, code), failure.extended_error);
    try testing.expectEqual(@as(?u16, null), (try failed(&.{ fixtures.server_failure, fixtures.server_failure })).extended_error);
}

test "an NXDOMAIN's extended error reaches the failure, and a NOERROR's is never read" {
    const blocked = with_options(fixtures.name_error, &wire.fixtures.opt_extended_error_bare);
    try testing.expectEqual(@as(?u16, code), (try failed(&.{blocked})).extended_error);
    // NODATA is NOERROR: its message is not read for why (§16 decision 64).
    const empty = with_options(fixtures.no_data, &wire.fixtures.opt_extended_error_bare);
    const failure = try failed(&.{empty});
    try testing.expectEqual(core.Error.NoData, failure.err);
    try testing.expectEqual(@as(?u16, null), failure.extended_error);
}

test "an extended error too short for its code is passed over, and the response stands" {
    // RFC 8914 §3: a receiver "MUST be able to accept EDE codes and EXTRA-TEXT in all messages".
    const short = with_options(fixtures.server_failure, &wire.fixtures.opt_extended_error_short);
    const failure = try failed(&.{ short, short });
    try testing.expectEqual(core.Error.AllServersFailed, failure.err);
    try testing.expectEqual(@as(?u16, null), failure.extended_error);
}
