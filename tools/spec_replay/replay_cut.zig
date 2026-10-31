//! The replay's cut datagram: what `Lookup.on_datagram_cut` makes of a datagram that the buffer
//! cut, checked against what the model says (spec/lean/Spec/Lookup.lean, `Reply.truncated`;
//! docs/design.md §7, A datagram that the buffer cut). Split from `replay.zig` by the file-length
//! rule.
//!
//! The model has no reply of its own for a cut datagram. Its TC=1 stands for one where the lookup
//! waits over UDP and not over DoH or DoQ, and its unmatched reply stands for one everywhere else.
//! So a cut datagram goes to the lookup that the line's parent left, at each `reply_truncated` line
//! in the first case and at each `reply_unmatched` line in the others. It must answer and move as
//! the line's reply does. The datagram is the answer to what the lookup asks, less its last octet.
//! Then the parent's frame is restored, and the line's own event runs as before.
const std = @import("std");
const assert = std.debug.assert;
const replay_module = @import("replay.zig");
const Replay = replay_module.Replay;
const Out = replay_module.Out;
const Event = replay_module.Event;
const fixtures = @import("fixtures.zig");
const text_module = @import("replay_text.zig");

/// Whether the line's reply is the one that a cut datagram stands for, to the lookup that the line's
/// parent left, whose frame the replay has restored.
pub fn applies(replay: *const Replay, event: Event) bool {
    const stands_for_tc = replay.lookup.state == .awaiting_udp and !replay.config.sends_requests();
    return event == if (stands_for_tc) Event.reply_truncated else Event.reply_unmatched;
}

/// The cut datagram at line `depth`, whose parent the replay has restored. Returns false and
/// records the mismatch when the lookup does not answer and move as the line's reply does.
pub fn agrees(replay: *Replay, depth: usize, expected_out: Out, expected_state: []const u8) bool {
    assert(depth > 0);
    const whole = fixtures.build(&replay.lookup, .answer, &replay.reply);
    assert(whole.len > 1);
    const verdict = replay.lookup.on_datagram_cut(whole[0 .. whole.len - 1], replay.source(), replay.now_ns);
    const got_out: Out = if (verdict == .accepted) .accepted else .ignored;
    var got_buffer: [replay_module.state_bytes_max]u8 = undefined;
    const got_state = text_module.line_text(&replay.lookup, &got_buffer);
    replay.cuts += 1;
    replay.restore(depth - 1);
    if (got_out == expected_out and std.mem.eql(u8, got_state, expected_state)) return true;
    var mismatch: replay_module.Mismatch = .{
        .line = replay.lines,
        .depth = depth,
        .expected_out = expected_out,
        .got_out = got_out,
        .expected_state = undefined,
        .expected_state_len = expected_state.len,
        .got_state = got_buffer,
        .got_state_len = got_state.len,
        .cut = true,
    };
    @memcpy(mismatch.expected_state[0..expected_state.len], expected_state);
    replay.mismatch = mismatch;
    return false;
}

// Tests.

const testing = std.testing;

test "a cut datagram moves a lookup that waits over UDP as TC=1 does, and leaves one on a stream" {
    const replay = try testing.allocator.create(Replay);
    defer testing.allocator.destroy(replay);
    replay.* = .{};
    // Over UDP the cut datagram stands for TC=1; over TCP, where the lookup waits on the stream, it
    // stands for the unmatched reply.
    const text = "hops 8\nconfig 1 1 1 udp ignored\n0 init none query_ready 0/0/0/0 E--- - A -\n" ++
        "1 poll send_udp query_ready 0/0/0/0 E--- - A -\n2 sent none awaiting_udp 0/0/0/0 E--- - A -\n" ++
        "3 reply_truncated accepted tcp_needed 0/0/0/0 E--- - A -\n" ++
        "config 1 1 1 tcp ignored\n0 init none tcp_needed 0/0/0/0 E--- - A -\n" ++
        "1 poll connect_tcp connecting_tcp 0/0/0/0 E--- - A -\n2 tcp_connected none tcp_ready 0/0/0/0 E--- - A -\n" ++
        "3 poll send_tcp tcp_ready 0/0/0/0 E--- - A -\n4 sent none awaiting_tcp 0/0/0/0 E--- - A -\n" ++
        "5 reply_unmatched ignored awaiting_tcp 0/0/0/0 E--- - A -\n";
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |one| try replay.line(one);
    try testing.expectEqual(@as(usize, 2), replay.cuts);
}

test "a cut datagram the lookup reads otherwise than the model's reply is a mismatch" {
    const replay = try testing.allocator.create(Replay);
    defer testing.allocator.destroy(replay);
    replay.* = .{};
    // A model whose TC=1 left the lookup waiting: the cut datagram moved it, and the replay says so.
    const text = "hops 8\nconfig 1 1 1 udp ignored\n0 init none query_ready 0/0/0/0 E--- - A -\n" ++
        "1 poll send_udp query_ready 0/0/0/0 E--- - A -\n2 sent none awaiting_udp 0/0/0/0 E--- - A -\n" ++
        "3 reply_truncated ignored awaiting_udp 0/0/0/0 E--- - A -\n";
    var lines = std.mem.splitScalar(u8, text, '\n');
    var failed: ?replay_module.Error = null;
    while (lines.next()) |one| replay.line(one) catch |err| {
        failed = err;
        break;
    };
    try testing.expectEqual(@as(?replay_module.Error, error.Mismatch), failed);
    const mismatch = replay.mismatch.?;
    try testing.expect(mismatch.cut);
    try testing.expectEqual(Out.accepted, mismatch.got_out);
}
