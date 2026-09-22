//! The `options` line of a `resolv.conf`: `ndots:`, `timeout:`, `attempts:` and `rotate`
//! (`resolv.conf(5)`).
//!
//! An option cocuyo does not know is skipped, and so is one whose value will not parse or is out
//! of range. That is what every stub does, and the alternative — refusing the file — would stop a
//! program from resolving over a line it did not need.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");

/// What one option token asked for, or null when it asked for nothing cocuyo knows.
pub const Option = union(enum) {
    ndots: u8,
    timeout_ns: u64,
    attempts: u8,
    rotate,
    /// `use-vc`: every query over TCP (`resolv.conf(5)`).
    use_tcp,
};

/// The keywords, each with the limit its value is clamped to. The manual pages cap `ndots` at 15
/// and `attempts` at 5, and cocuyo's own `attempts_max` is the same 5.
const ndots_keyword = "ndots:";
const timeout_keyword = "timeout:";
const attempts_keyword = "attempts:";
const rotate_keyword = "rotate";

/// `resolv.conf(5)` caps ndots at 15.
const ndots_limit = 15;

/// `resolv.conf(5)` caps timeout at 30 seconds, which is also cocuyo's `timeout_ns_max`.
const timeout_seconds_limit = 30;

/// One second in nanoseconds, spelled out because nothing under `src/` may name `std.time`
/// (CLAUDE.md non-negotiable 4).
const ns_per_s = 1_000_000_000;

/// The base an option's value is written in.
const decimal_base = 10;

pub fn parse(token: []const u8) ?Option {
    if (std.mem.eql(u8, token, rotate_keyword)) return .rotate;
    if (std.mem.eql(u8, token, constants.option_use_vc)) return .use_tcp;
    if (value_of(token, ndots_keyword)) |text| {
        const ndots = number(text, ndots_limit) orelse return null;
        return .{ .ndots = @intCast(ndots) };
    }
    if (value_of(token, timeout_keyword)) |text| {
        const seconds = number(text, timeout_seconds_limit) orelse return null;
        // A timeout of zero would make every query time out before it was sent, so it reads as
        // the smallest wait there is rather than as no wait.
        const clamped = @max(seconds, 1);
        return .{ .timeout_ns = clamped * ns_per_s };
    }
    if (value_of(token, attempts_keyword)) |text| {
        const attempts = number(text, core.constants.attempts_max) orelse return null;
        return .{ .attempts = @intCast(@max(attempts, 1)) };
    }
    return null;
}

fn value_of(token: []const u8, keyword: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, token, keyword)) return null;
    return token[keyword.len..];
}

/// A decimal number at or below `limit`, or null. A value over the limit is clamped to it, which
/// is what the manual pages say happens; a value that is not a number at all is skipped.
fn number(text: []const u8, limit: u64) ?u64 {
    if (text.len == 0) return null;
    var value: u64 = 0;
    for (text) |byte| {
        if (byte < '0' or byte > '9') return null;
        if (value > limit) return limit;
        value = value * decimal_base + (byte - '0');
    }
    assert(text.len >= 1);
    return @min(value, limit);
}

// Tests.

const testing = std.testing;

test "every option cocuyo knows parses" {
    try testing.expectEqual(Option{ .ndots = 3 }, parse("ndots:3").?);
    try testing.expectEqual(Option{ .attempts = 4 }, parse("attempts:4").?);
    try testing.expectEqual(Option{ .timeout_ns = 2 * ns_per_s }, parse("timeout:2").?);
    try testing.expectEqual(Option.rotate, parse("rotate").?);
}

test "an option cocuyo does not know is skipped" {
    try testing.expectEqual(@as(?Option, null), parse("edns0"));
    try testing.expectEqual(@as(?Option, null), parse("single-request"));
    try testing.expectEqual(@as(?Option, null), parse("inet6"));
    try testing.expectEqual(@as(?Option, null), parse(""));
    try testing.expectEqual(@as(?Option, null), parse("ndots"));
}

test "a value that is not a number is skipped" {
    try testing.expectEqual(@as(?Option, null), parse("ndots:"));
    try testing.expectEqual(@as(?Option, null), parse("ndots:x"));
    try testing.expectEqual(@as(?Option, null), parse("timeout:1x"));
    try testing.expectEqual(@as(?Option, null), parse("attempts:-1"));
}

test "a value over the limit is clamped, not refused" {
    try testing.expectEqual(Option{ .ndots = ndots_limit }, parse("ndots:99").?);
    try testing.expectEqual(Option{ .ndots = ndots_limit }, parse("ndots:999999999999999999999").?);
    try testing.expectEqual(Option{ .attempts = core.constants.attempts_max }, parse("attempts:9").?);
    try testing.expectEqual(
        Option{ .timeout_ns = timeout_seconds_limit * ns_per_s },
        parse("timeout:600").?,
    );
}

test "a zero timeout or zero attempts reads as the smallest there is" {
    // Zero would make a lookup give up before it sent anything, which no configuration can mean.
    try testing.expectEqual(Option{ .timeout_ns = ns_per_s }, parse("timeout:0").?);
    try testing.expectEqual(Option{ .attempts = 1 }, parse("attempts:0").?);
}

test "ndots zero is a real setting and is kept" {
    // ndots:0 means try the name as written first, always. It is not the same as no setting.
    try testing.expectEqual(Option{ .ndots = 0 }, parse("ndots:0").?);
}

test "use-vc asks for TCP" {
    try testing.expectEqual(Option.use_tcp, parse("use-vc").?);
    try testing.expectEqual(@as(?Option, null), parse("use-vc:1"));
}
