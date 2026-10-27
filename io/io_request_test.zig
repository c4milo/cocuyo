//! The engine over DoQ on the twin (docs/design.md §24, the request rules): a handshake before
//! the first stream, the requests that wait for it, a stream answered, a refused handshake and a
//! protocol the engine refuses failed over, a ticket kept and spent, and the idle close. The
//! connection is the twin's (`rotor.quic`), whose datagrams carry items in the clear; what only
//! colibri can show is colibri's, over the twin as well.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const question = sim_test.question;

/// An engine that speaks the twin's QUIC, and keeps no TCP connection: DoQ needs none.
pub const Resolver = io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = 0,
    .quic = rotor.quic.Connection,
});
pub const Rig = sim_test.RigOf(Resolver);

/// A rig whose servers speak DoQ as `scripts` say, under a timeout long enough for any of them.
pub fn start(rig: *Rig, seed: u64, scripts: [fixtures.servers]rotor.server.Script) !void {
    const quic: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text("dns.example.") };
    for (&rig.servers) |*server| server.quic = quic;
    try rig.init(seed, scripts, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
    rig.use_test_contexts();
}

/// The server side of the twin's connection to server `server`, if one was opened.
pub fn peer_of(rig: *Rig, server: u8) ?*rotor.quic.Peer {
    for (&rig.loop.network().quic_peers) |*entry| {
        if (entry.open and entry.server == server) return &entry.peer;
    }
    return null;
}

test "a lookup over DoQ handshakes, then is answered on its stream, and no plain socket is opened" {
    var rig: Rig = .{};
    try start(&rig, 61, .{ .{}, .{} });
    try testing.expectEqual(@as(u8, 0), rig.engine.sockets.count);
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expect(rig.engine.quic.connections[0].state == .up);
    try testing.expect(!rig.engine.requests[result.handle.index].live);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a lookup of a name of 255 octets is answered over DoQ" {
    // The answer of a request passes check 5 too, over the longest question (docs/design.md §23).
    var rig: Rig = .{};
    try start(&rig, fixtures.longest_name_seed, .{ .{}, .{} });
    _ = try rig.engine.start(question(fixtures.longest_name_text), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "requests taken while the handshake runs wait for its end, then each opens a stream" {
    var rig: Rig = .{};
    try start(&rig, 62, .{ .{ .quic = .{ .flights = 2 } }, .{} });
    _ = try rig.engine.start(question("one.example."), rig.loop.now());
    _ = try rig.engine.start(question("two.example."), rig.loop.now());
    try testing.expectEqual(@as(u16, 2), rig.engine.quic.connections[0].queue_len);
    var answered: usize = 0;
    while (answered < 2) : (answered += 1) {
        const result = try rig.until_result();
        try testing.expect(result.outcome == .answer);
    }
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    try testing.expectEqual(@as(u64, 2 * rotor.constants.quic_stream_step), rig.engine.quic.connections[0].transport.next_stream);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a lookup cancelled while its stream is open has the stream cancelled, and hears nothing" {
    // The server never answers, so the stream is open when the caller cancels the lookup, which
    // takes no new request: the drive cancels the stream it left (request rule 6).
    var rig: Rig = .{};
    try start(&rig, 68, .{ .{ .drop_per_256 = fixtures.always }, .{} });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    const connection = &rig.engine.quic.connections[0];
    var rounds: usize = 0;
    while (connection.streams == 0 and rounds < fixtures.until_rounds_max) : (rounds += 1) {
        _ = try rig.step(fixtures.wait_ns);
    }
    try testing.expectEqual(@as(u16, 1), connection.streams);
    rig.engine.cancel(handle, rig.loop.now());
    try testing.expectEqual(@as(u16, 0), connection.users());
    const result = try rig.until_result();
    try testing.expectEqual(cocuyo.Error.Canceled, result.outcome.failure.err);
    // The STOP_SENDING goes once the buffer is back from the datagram before it (rule 8).
    _ = try rig.step(fixtures.wait_ns);
    try testing.expectEqual(@as(u16, 1), peer_of(&rig, 0).?.cancels);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

/// Lets the idle close run: the clock moves past the set's `idle_ns` with nothing due, twice, so the
/// timer the last lookup left is gone as well.
pub fn idle(rig: *Rig) !void {
    _ = try rig.step(fixtures.tcp_idle_jump_ns);
    _ = try rig.step(fixtures.tcp_idle_jump_ns);
    rig.engine.drive(rig.loop.now());
}

/// One lookup of `name`, answered, and its result taken.
pub fn answer(rig: *Rig, name: []const u8) !void {
    _ = try rig.engine.start(question(name), rig.loop.now());
    const result = try rig.until_result();
    try testing.expect(result.outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
}

test "an idle connection says CONNECTION_CLOSE, and closes once it has gone" {
    var rig: Rig = .{};
    try start(&rig, 63, .{ .{}, .{} });
    try answer(&rig, "example.com.");
    try idle(&rig);
    try testing.expect(rig.engine.quic.connections[0].state == .closing);
    try testing.expect(peer_of(&rig, 0).?.closed);
    _ = try rig.step(fixtures.wait_ns);
    try testing.expect(rig.engine.quic.connections[0].state == .closed);
    try rig.deinit();
}

test "a ticket the server gave is kept, and the next connection resumes with it" {
    var rig: Rig = .{};
    try start(&rig, 64, .{ .{ .quic = .{ .tickets = true } }, .{} });
    try answer(&rig, "one.example.");
    try testing.expect(rig.engine.quic.tickets[0] != null);
    try testing.expectEqual(@as(u16, 0), peer_of(&rig, 0).?.resumed);
    try idle(&rig);
    _ = try rig.step(fixtures.wait_ns);
    try testing.expect(rig.engine.quic.connections[0].state == .closed);
    try answer(&rig, "two.example.");
    // The new connection spent the ticket, and its handshake gave another (request rule 10).
    try testing.expectEqual(@as(u16, 1), peer_of(&rig, 0).?.resumed);
    try testing.expect(rig.engine.quic.tickets[0] != null);
    try rig.deinit();
}

test "a request its lookup left is cancelled with STOP_SENDING, and the next server answers" {
    // The first server's handshake ends, and it never answers the stream: the lookup's deadline
    // moves it on, and the drive cancels the stream it left (request rule 6, RFC 9250 §4.3.1).
    var rig: Rig = .{};
    try start(&rig, 65, .{ .{ .drop_per_256 = fixtures.always }, .{} });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expect(result.outcome == .answer);
    try testing.expectEqual(@as(u16, 1), peer_of(&rig, 0).?.cancels);
    try testing.expectEqual(@as(u16, 0), rig.engine.quic.connections[0].users());
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a closing connection reads nothing more, and a close the loop refused goes at the next drive" {
    var rig: Rig = .{};
    try start(&rig, 66, .{ .{}, .{} });
    try answer(&rig, "example.com.");
    _ = try rig.step(fixtures.tcp_idle_jump_ns);
    _ = try rig.step(fixtures.tcp_idle_jump_ns);
    // The loop refuses the CONNECTION_CLOSE's send, so the connection stays closing (rule 8).
    rig.loop.refuse_submissions = true;
    rig.engine.drive(rig.loop.now());
    rig.loop.refuse_submissions = false;
    const connection = &rig.engine.quic.connections[0];
    try testing.expect(connection.state == .closing);
    try testing.expect(connection.made > 0);
    // A ticket the server sent before it heard the close arrives after it, and is not read
    // (request rule 9).
    const pending = rig.loop.network().queue_datagram().?;
    pending.socket = connection.descriptor.?;
    pending.from = rotor.Network.server_address(0);
    pending.due_ns = rig.loop.now();
    pending.len = @intCast(rotor.quic.write_item(.{ .kind = .ticket }, &pending.bytes));
    _ = try rig.step(fixtures.wait_ns);
    try testing.expect(rig.engine.quic.tickets[0] == null);
    _ = try rig.step(fixtures.wait_ns);
    try testing.expect(connection.state == .closed);
    try rig.deinit();
}

/// An engine whose datagram group runs dry under its own answers.
const Starved = io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .group_buffers = fixtures.small_group_buffers,
    .quic = rotor.quic.Connection,
});

test "a receive that runs out of buffers is armed again, and fails nothing" {
    var rig: sim_test.RigOf(Starved) = .{};
    const quic: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text("dns.example.") };
    for (&rig.servers) |*server| server.quic = quic;
    // Every answer comes at the same instant: more datagrams than the group has buffers.
    const script: rotor.server.Script = .{ .delay_ns_min = fixtures.slow_answer_ns, .delay_ns_max = fixtures.slow_answer_ns };
    try rig.init(67, .{ script, .{} }, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
    rig.use_test_contexts();
    const names = [_][]const u8{ "a.example.", "b.example.", "c.example.", "d.example.", "e.example.", "f.example." };
    for (names) |name| _ = try rig.engine.start(question(name), rig.loop.now());
    for (names) |_| {
        const result = try rig.until_result();
        try testing.expect(result.outcome == .answer);
    }
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a receive that ends on a datagram has the datagram read, and is armed at the next drive" {
    // rotor's io_uring backend can end a multishot with the event that carries a datagram. Here
    // each receive ends on its first, so the handshake and every answer come on final events.
    var rig: Rig = .{};
    try start(&rig, 68, .{ .{}, .{} });
    rig.loop.network().multishot_deliveries_max = 1;
    const names = [_][]const u8{ "a.example.", "b.example.", "c.example." };
    for (names) |name| _ = try rig.engine.start(question(name), rig.loop.now());
    for (names) |_| {
        const result = try rig.until_result();
        try testing.expect(result.outcome == .answer);
    }
    try testing.expect(rig.engine.quic.connections[0].state == .up);
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a QUIC connection's incarnation wraps at the last of its thirty-two bits, and each opening answers" {
    // The incarnation tells the events of the current opening from those of the openings before
    // it, as the stream's rule 2 has it for a TCP connection (docs/design.md §19 step 13). An
    // opening adds one, so the first one here runs at the largest incarnation, and the second
    // wraps it to zero.
    var rig: Rig = .{};
    try start(&rig, 69, .{ .{}, .{} });
    rig.engine.quic.connections[0].incarnation = std.math.maxInt(u32) - 1;
    try answer(&rig, "one.example.");
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), rig.engine.quic.connections[0].incarnation);
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    try idle(&rig);
    _ = try rig.step(fixtures.wait_ns);
    try testing.expect(rig.engine.quic.connections[0].state == .closed);
    try answer(&rig, "two.example.");
    try testing.expectEqual(@as(u32, 0), rig.engine.quic.connections[0].incarnation);
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    try rig.deinit();
}

/// The twin's connection, which says `flood` tickets of its own before anything the twin says, as
/// a connection whose server sends a flood of them would. Its timer is due while it has any left.
const Flooding = struct {
    const Twin = rotor.quic.Connection;
    pub const enabled = true;
    pub const output_bytes_max = Twin.output_bytes_max;
    pub const request_bytes_max = Twin.request_bytes_max;
    pub const Error = Twin.Error;
    pub const Context = Twin.Context;
    pub const Ticket = Twin.Ticket;
    pub const Answered = Twin.Answered;
    pub const Next = Twin.Next;

    twin: Twin = .{},
    flood: usize = 0,
    said: usize = 0,

    pub fn start(self: *Flooding, context: anytype) Error!void {
        return self.twin.start(context);
    }
    pub fn lifetime_ns(ticket: *const Ticket) u64 {
        return Twin.lifetime_ns(ticket);
    }
    pub fn receive(self: *Flooding, bytes: []const u8, now_ns: u64) Error!void {
        return self.twin.receive(bytes, now_ns);
    }
    pub fn next(self: *Flooding, out: []u8) ?Next {
        if (self.flood == 0) return self.twin.next(out);
        self.flood -= 1;
        self.said += 1;
        return .{ .ticket = .{} };
    }
    pub fn request(self: *Flooding, bytes: []u8, len: usize) Error!?u64 {
        return self.twin.request(bytes, len);
    }
    pub fn cancel(self: *Flooding, stream: u64) void {
        self.twin.cancel(stream);
    }
    pub fn output(self: *Flooding, out: []u8, now_ns: u64) usize {
        return self.twin.output(out, now_ns);
    }
    pub fn deadline(self: *const Flooding) ?u64 {
        return if (self.flood > 0) 0 else self.twin.deadline();
    }
    pub fn expire(self: *Flooding, now_ns: u64) void {
        if (self.flood == 0) self.twin.expire(now_ns);
    }
    pub fn idle_left_ns(self: *const Flooding, now_ns: u64) u64 {
        return self.twin.idle_left_ns(now_ns);
    }
    pub fn close(self: *Flooding) void {
        self.twin.close();
    }
    pub fn wipe(self: *Flooding) void {
        self.twin.wipe();
    }
};

const FloodingRig = sim_test.RigOf(io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = 0,
    .quic = Flooding,
}));

test "one read of a connection takes an end for each request and 16 of its own, and the rest at the next" {
    // `quic_connection_events_max`: what a flood leaves is read with the next datagram or expiry
    // (docs/design.md §24, New limits). Here the connection says one ticket more than one read
    // takes.
    const request_events = @import("io_request_events.zig");
    var rig: FloodingRig = .{};
    const quic: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text("dns.example.") };
    for (&rig.servers) |*server| server.quic = quic;
    try rig.init(70, .{ .{}, .{} }, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
    rig.use_test_contexts();
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    try testing.expect((try rig.until_result()).outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    const transport = &rig.engine.quic.connections[0].transport;
    const per_read = rig.engine.requests.len + io.limits.quic_connection_events_max;
    transport.flood = per_read + 1;
    request_events.expire_due(&rig.engine, rig.loop.now());
    try testing.expectEqual(per_read, transport.said);
    request_events.expire_due(&rig.engine, rig.loop.now());
    try testing.expectEqual(per_read + 1, transport.said);
    try rig.deinit();
}
