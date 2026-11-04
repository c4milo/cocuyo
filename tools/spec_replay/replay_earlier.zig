//! The replay's events of an earlier try (spec/lean/Spec/Lookup.lean, `Event.earlier` and
//! `Event.earlierFailed`; docs/design.md §5, Tries kept open). The transcript spells one as
//! `earlier_<position>_<datagram|stream>_` and then a reply as `reply_` spells it, or `failed_`
//! and a reason. The replay hands the lookup the reply of the newest try open at that position
//! over that transport, built from that try's id, server, case and cookie, or the failure of that
//! try's connection or request. Split from `replay.zig` by the file-length rule.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const resolver = @import("resolver");
const Lookup = resolver.Lookup;
const fixtures = @import("fixtures.zig");
const event_module = @import("replay_event.zig");
const Event = event_module.Event;

/// One earlier try's event, as the transcript names it.
pub const Earlier = struct {
    position: u8,
    stream: bool,
    /// The reply event, or null for a failure.
    reply: ?Event,
    reason: resolver.Reason = .closed,
};

/// Reads `earlier_<position>_<datagram|stream>_<rest>`, or null when the token is no such event.
pub fn parse(token: []const u8) ?Earlier {
    const prefix = "earlier_";
    if (!std.mem.startsWith(u8, token, prefix)) return null;
    var words = std.mem.splitScalar(u8, token[prefix.len..], '_');
    const position = std.fmt.parseInt(u8, words.next() orelse return null, 10) catch return null;
    const transport = words.next() orelse return null;
    const stream = if (std.mem.eql(u8, transport, "stream")) true else if (std.mem.eql(u8, transport, "datagram")) false else return null;
    const rest = words.rest();
    const failed = "failed_";
    if (std.mem.startsWith(u8, rest, failed)) {
        const reason = std.meta.stringToEnum(resolver.Reason, rest[failed.len..]) orelse return null;
        return .{ .position = position, .stream = stream, .reply = null, .reason = reason };
    }
    const reply = std.meta.stringToEnum(Event, rest) orelse return null;
    if (!std.mem.startsWith(u8, rest, "reply_")) return null;
    return .{ .position = position, .stream = stream, .reply = reply };
}

/// The newest earlier try open at `position` over `stream`, or null.
pub fn newest(lookup: *const Lookup, position: u8, stream: bool) ?usize {
    const tries = lookup.tries.slice();
    var index: usize = tries.len;
    while (index > 0) {
        index -= 1;
        if (tries[index].position == position and tries[index].marks.stream == stream) return index;
    }
    return null;
}

/// An id no try of the lookup holds and the current transaction does not hold: what the model's
/// unmatched reply carries, now that a lookup listens for its earlier tries too.
pub fn unmatched_id(lookup: *const Lookup) u16 {
    var id = lookup.transaction.id +% 1;
    for (0..lookup.tries.count + 1) |_| {
        if (id != lookup.transaction.id and !held(lookup, id)) return id;
        id +%= 1;
    }
    unreachable;
}

fn held(lookup: *const Lookup, id: u16) bool {
    for (lookup.tries.slice()) |kept| if (kept.id == id) return true;
    return false;
}

/// The reply of the try at `index`, as its server would write it.
pub fn build(lookup: *const Lookup, index: usize, reply: fixtures.Reply, authentic: bool, out: []u8) []const u8 {
    const view = lookup.viewed_as(index);
    return fixtures.build_with(&view, reply, authentic, out);
}

/// Where the try at `index` waits for its reply: its server, on the port of its transport.
pub fn source(lookup: *const Lookup, index: usize) core.Endpoint {
    const view = lookup.viewed_as(index);
    return if (view.state == .awaiting_tcp) view.server_tcp() else view.server();
}

// Tests.

const testing = std.testing;

test "an earlier try's event names its position, its transport and its reply or its failure" {
    const reply = parse("earlier_1_stream_reply_ad_answer").?;
    try testing.expectEqual(@as(u8, 1), reply.position);
    try testing.expect(reply.stream);
    try testing.expectEqual(Event.reply_ad_answer, reply.reply.?);
    const failed = parse("earlier_0_datagram_failed_reset").?;
    try testing.expect(!failed.stream and failed.reply == null);
    try testing.expectEqual(resolver.Reason.reset, failed.reason);
    try testing.expectEqual(@as(?Earlier, null), parse("earlier_0_wire_reply_answer"));
    try testing.expectEqual(@as(?Earlier, null), parse("earlier_0_stream_poll"));
    try testing.expectEqual(@as(?Earlier, null), parse("reply_answer"));
}
