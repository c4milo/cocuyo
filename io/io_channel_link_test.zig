//! A channel's links on the twin (docs/design.md §24, request rules 17, 19 and 23, and 14): a TCP
//! link that connects first, one whose connect fails, a close that waits for the octets a link
//! kept, a ticket kept for each transport, a receive the loop refused armed again, a link opened
//! again while an earlier connect is in flight, and the channel read at a send's end.
const std = @import("std");
const testing = std.testing;
const rotor = @import("rotor");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const channel_test = @import("io_channel_test.zig");
const question = sim_test.question;
const Rig = channel_test.Rig;
const start = channel_test.start;
const tell = channel_test.tell;
const channel_of = channel_test.channel_of;

/// A connect slower than a step, so a test sees the link connect before it runs.
const slow: rotor.server.Script = .{ .connect_delay_ns = fixtures.slow_connect_ns };

test "a TCP link connects first, and its connection starts at the connect's end" {
    // Request rule 14: a stream socket connects before the connection on it starts.
    var rig: Rig = .{};
    try start(&rig, 101, .{ slow, .{} });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    const link = &rig.engine.doh.slots[0].links[1];
    try tell(&rig, 0, .{ .open = .tcp });
    try testing.expect(link.state == .connecting);
    try testing.expect(!channel_of(&rig, 0).running[1]);
    _ = try rig.step(fixtures.slow_connect_ns);
    try testing.expect(link.state == .running);
    try testing.expect(link.receive != null);
    try testing.expect(channel_of(&rig, 0).running[1]);
    rig.engine.cancel(handle, rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a link's connect that fails is told to the channel, and fails no request itself" {
    // Rule 19: the channel decides what a link's end fails, and says so at a read.
    var rig: Rig = .{};
    try start(&rig, 102, .{ .{ .tcp = false }, .{} });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    try tell(&rig, 0, .{ .open = .tcp });
    _ = try rig.step(fixtures.channel_read_ns);
    try testing.expect(rig.engine.doh.slots[0].links[1].state == .down);
    try testing.expectEqual(@as(u32, 1), channel_of(&rig, 0).ended_links[1]);
    try testing.expect(rig.engine.requests[handle.index].live);
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    rig.engine.cancel(handle, rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a link the channel closes shuts its socket once the octets it kept have gone" {
    // Rule 19: once closed, a link sends only what it kept, then its socket closes. The loop
    // refuses the send, so the link keeps its octets when the channel closes it.
    var rig: Rig = .{};
    try start(&rig, 103, .{ .{}, .{} });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    const link = &rig.engine.doh.slots[0].links[0];
    try tell(&rig, 0, .{ .open = .quic });
    rig.loop.refuse_submissions = true;
    try tell(&rig, 0, .{ .octets = .quic });
    try testing.expect(link.made > 0);
    try tell(&rig, 0, .{ .close = .quic });
    try testing.expect(link.state == .closing);
    try testing.expectEqual(@as(?rotor.Handle, null), link.receive);
    rig.loop.refuse_submissions = false;
    rig.engine.drive(rig.loop.now());
    _ = try rig.step(fixtures.channel_read_ns);
    try testing.expect(link.state == .down);
    rig.engine.cancel(handle, rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "each transport's ticket is kept, and the next link of that transport spends it at its age" {
    // Rule 23: a server keeps the newest ticket of each transport, spent once, and offered with
    // its age, the time since it came (RFC 9846 §4.3.11.1).
    var rig: Rig = .{};
    try start(&rig, 104, .{ .{}, .{} });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    try tell(&rig, 0, .{ .open = .quic });
    try testing.expect(!channel_of(&rig, 0).resumed[0]);
    try tell(&rig, 0, .{ .ticket = .quic });
    const came_ns = rig.engine.doh.tickets[0][0].?.since_ns;
    try testing.expect(rig.engine.doh.tickets[0][1] == null);
    try tell(&rig, 0, .{ .close = .quic });
    // Time passes before the next link of the transport opens, so the ticket has an age. What the
    // close left due at its instant is delivered first, and the clock moves after it.
    for (0..fixtures.until_rounds_max) |_| {
        if (rig.loop.now() > came_ns) break;
        _ = try rig.step(fixtures.channel_read_ns);
    }
    const opened_ns = rig.loop.now();
    try tell(&rig, 0, .{ .open = .quic });
    try testing.expect(channel_of(&rig, 0).resumed[0]);
    try testing.expect(rig.engine.doh.tickets[0][0] == null);
    try testing.expect(opened_ns > came_ns);
    try testing.expectEqual(opened_ns - came_ns, channel_of(&rig, 0).ticket_ages_ns[0]);
    rig.engine.cancel(handle, rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a running link whose receive the loop refused has it armed at the next drive" {
    // The datagram's rule 1, which rule 19 keeps for a link: a receive the loop refuses is asked
    // for again at the next drive.
    var rig: Rig = .{};
    try start(&rig, 105, .{ .{}, .{} });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    const link = &rig.engine.doh.slots[0].links[0];
    rig.loop.refuse_submissions = true;
    try tell(&rig, 0, .{ .open = .quic });
    try testing.expect(link.state == .running);
    try testing.expectEqual(@as(?rotor.Handle, null), link.receive);
    rig.loop.refuse_submissions = false;
    rig.engine.drive(rig.loop.now());
    try testing.expect(link.receive != null);
    rig.engine.cancel(handle, rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a TCP link opened again while its earlier connect is in flight connects at that connect's end" {
    // Request rule 14: the loop borrows a link's address until its connect's final event, and the
    // link connects nothing until then.
    var rig: Rig = .{};
    try start(&rig, 106, .{ slow, .{} });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    const link = &rig.engine.doh.slots[0].links[1];
    try tell(&rig, 0, .{ .open = .tcp });
    try testing.expect(link.state == .connecting);
    const first = link.incarnation;
    channel_of(&rig, 0).say(.{ .close = .tcp }, rig.loop.now());
    try tell(&rig, 0, .{ .open = .tcp });
    try testing.expect(link.state == .reopening);
    try testing.expectEqual(first, link.incarnation);
    _ = try rig.step(fixtures.channel_read_ns);
    try testing.expect(link.state == .connecting);
    try testing.expect(link.incarnation != first);
    rig.engine.cancel(handle, rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "the channel is read at a link's send end, and tells then what it held" {
    // Rule 17: what the channel held while a link's octets waited to go is told at that send's end.
    // Once its steps are said the channel is not due, so no timer brings a read: the link's sends'
    // ends are the reads that come.
    var rig: Rig = .{};
    try start(&rig, 107, .{ .{}, .{} });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    const channel = channel_of(&rig, 0);
    channel.say(.{ .open = .quic }, rig.loop.now());
    channel.say(.{ .hold = .{ .index = handle.index, .answer = true } }, rig.loop.now());
    try tell(&rig, 0, .{ .octets = .quic });
    const result = try rig.until_result();
    try testing.expect(result.outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "the channel is read when a link's socket ends, and tells then what it held" {
    // Rules 17 and 19: a link's end is told to the channel, and the channel is read then. The
    // server takes no TCP connection, so the link's connect fails, and that end is the read that
    // comes.
    var rig: Rig = .{};
    try start(&rig, 108, .{ .{ .tcp = false }, .{} });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    const channel = channel_of(&rig, 0);
    channel.say(.{ .open = .tcp }, rig.loop.now());
    try tell(&rig, 0, .{ .hold = .{ .index = handle.index, .answer = true } });
    const result = try rig.until_result();
    try testing.expect(result.outcome == .answer);
    try testing.expectEqual(@as(u32, 1), channel.ended_links[1]);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}
