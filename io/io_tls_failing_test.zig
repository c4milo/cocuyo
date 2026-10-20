//! The engine over TLS on the twin, with a session that fails where a test says, or that asks for
//! more room than the twin's: a session that cannot start, seal or open, or whose peer closes,
//! fails over to the next server; the records buffer holds a session that asks for all of it, and
//! refuses one that asks for more (docs/design.md §21, TLS rule 3); a queue holds two entries of
//! the records a session makes of its own accord beside each lookup's query (TLS rule 2), and
//! such records move none of what a send reads (TLS rule 3); a reset empties the state. A second
//! pass waits for a slot whose records buffer the loop holds, a query's send among the sends that
//! hold it (TLS rule 3). Or it opens another slot.
//! Split from `io_tls_test.zig` by the file-length rule.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io.zig");
const tcp = @import("io_tcp.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const tls_test = @import("io_tls_test.zig");
const tcp_test = @import("io_tcp_test.zig");
const question = sim_test.question;

/// Where the failing session fails. A TLS stack can fail to start or to seal. It can refuse a
/// handshake, as it refuses a certificate that does not verify, or a record, as it refuses a forged
/// one. It can hear its peer close. The twin's session does none of these.
const Failure = enum { start, handshake, seal, open, closed };
const Plan = struct { at: Failure = .start, left: u8 = 0 };
threadlocal var failing: Plan = .{};
/// How many empty records the failing session makes of its own accord, one at each collection,
/// as a session that answers a KeyUpdate makes records the engine did not ask for.
threadlocal var unasked: usize = 0;

fn fails_now(at: Failure) bool {
    if (failing.at != at or failing.left == 0) return false;
    failing.left -= 1;
    return true;
}

/// The twin's session, failing where `failing` says and as often, which asks for `room` octets
/// of the records buffer before it stages anything.
fn FailingOf(comptime room: usize) type {
    return struct {
        const Self = @This();
        const Twin = rotor.tls.Session;
        pub const enabled = true;
        pub const out_bytes_max = room;
        pub const Error = Twin.Error;
        pub const Context = Twin.Context;
        pub const Ticket = Twin.Ticket;
        pub const Handshake = Twin.Handshake;
        pub const Opened = Twin.Opened;

        twin: Twin = .{},

        pub fn start(self: *Self, context: anytype) Error!void {
            if (fails_now(.start)) return error.Failed;
            return self.twin.start(context);
        }
        pub fn lifetime_ns(ticket: *const Ticket) u64 {
            return Twin.lifetime_ns(ticket);
        }
        pub fn take_out(self: *Self, out: []u8) usize {
            const made = self.twin.take_out(out);
            if (unasked == 0) return made;
            unasked -= 1;
            return made + rotor.tls.write_record(rotor.constants.tls_content_application, &.{}, out[made..]);
        }
        pub fn handshake(self: *Self, record: []const u8) Error!Handshake {
            // The twin's session refuses the `refused` step, and stages its fatal alert for the
            // engine to say (§21, TLS rule 4).
            if (fails_now(.handshake)) {
                var refused: [rotor.constants.tls_record_header_bytes + 1]u8 = undefined;
                return self.twin.handshake(refused[0..rotor.tls.write_step(.refused, &refused)]);
            }
            return self.twin.handshake(record);
        }
        pub fn seal(self: *Self, plaintext: []const u8) Error!void {
            if (fails_now(.seal)) return error.Failed;
            return self.twin.seal(plaintext);
        }
        pub fn open(self: *Self, record: []const u8, plaintext: []u8) Error!Opened {
            if (fails_now(.open)) return error.Failed;
            if (fails_now(.closed)) return .closed;
            return self.twin.open(record, plaintext);
        }
        pub fn take_ticket(self: *Self) ?Ticket {
            return self.twin.take_ticket();
        }
        pub fn close(self: *Self) void {
            self.twin.close();
        }
        pub fn wipe(self: *Self) void {
            self.twin.wipe();
        }
    };
}

/// The failing session with the twin's own room.
const Failing = FailingOf(rotor.tls.Session.out_bytes_max);

/// An engine over a session of type `Session`.
fn RigOver(comptime Session: type) type {
    return sim_test.RigOf(io.Resolver(.{
        .lookups = fixtures.small_lookups,
        .group_buffers = fixtures.group_buffers,
        .tcp_connections = fixtures.servers,
        .tls = Session,
    }));
}

const FailingRig = RigOver(Failing);

/// The first server's session fails once, at `at`: its connection fails, the server is charged
/// with it, and the next server answers over TLS.
fn expect_fails_over(seed: u64, at: Failure) !void {
    failing = .{ .at = at, .left = 1 };
    defer failing = .{};
    var rig: FailingRig = .{};
    try tls_test.encrypt(&rig);
    try rig.init(seed, .{ .{}, .{} }, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
    rig.use_test_contexts();
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 0), failing.left);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    // At once, and not once the first server's wait ran out.
    try testing.expect(rig.loop.now() < rig.config.timeout_ns);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a session that cannot start, seal or open, or whose peer closes, fails over to the next server" {
    try expect_fails_over(48, .start);
    try expect_fails_over(49, .seal);
    try expect_fails_over(50, .open);
    try expect_fails_over(51, .closed);
}

test "a session that fails at each server ends in AllServersFailed, its cause where it failed" {
    // A session that cannot start fails its connection before the lookup hears that it is up, so
    // the cause is the connect's. One that cannot seal, or opens a record it refuses or a
    // `close_notify`, fails it once up, and the cause is the stream's (docs/design.md §5, The
    // cause of a failure).
    const cases = [_]struct { at: Failure, cause: cocuyo.Cause }{
        .{ .at = .start, .cause = .connect },
        .{ .at = .seal, .cause = .stream },
        .{ .at = .open, .cause = .stream },
        .{ .at = .closed, .cause = .stream },
    };
    for (cases) |case| {
        failing = .{ .at = case.at, .left = std.math.maxInt(u8) };
        defer failing = .{};
        var rig: FailingRig = .{};
        try tls_test.encrypt(&rig);
        try rig.init(117, .{ .{}, .{} }, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
        rig.use_test_contexts();
        _ = try rig.engine.start(question("example.com."), rig.loop.now());
        const result = try rig.until_result();
        try testing.expectEqual(cocuyo.Error.AllServersFailed, result.outcome.failure.err);
        try testing.expectEqual(@as(?cocuyo.Cause, case.cause), result.outcome.failure.cause);
        _ = rig.engine.take(rig.loop.now());
        try rig.deinit();
    }
}

/// One server and one connection slot, the least that TLS rule 6 allows, over the failing session.
const OneSlotRig = sim_test.RigOfServers(io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = 1,
    .tls = Failing,
}), 1);

test "a second pass waits for the slot that a refused connection holds while its alert goes" {
    // The session refuses the first handshake. The connection says its alert, and holds its one
    // slot until the alert has gone (TLS rules 4 and 5). The lookup's second pass to the same server
    // comes at once. It waits for the slot, and the server answers it on a new connection
    // (docs/design.md §19 step 13, the stream's rule 12).
    failing = .{ .at = .handshake, .left = 1 };
    defer failing = .{};
    var rig: OneSlotRig = .{};
    try tls_test.encrypt(&rig);
    try rig.init(62, .{.{}}, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
    rig.use_test_contexts();
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    for (0..fixtures.until_rounds_max) |_| {
        if (rig.engine.tcp_waiters > 0) break;
        _ = try rig.step(fixtures.wait_ns);
    }
    // The refusal counted one failure, and the pass that waits counts none.
    try testing.expectEqual(@as(u16, 1), rig.engine.tcp_waiters);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    const result = try rig.until_result();
    const cause: ?cocuyo.Cause = if (result.outcome == .failure) result.outcome.failure.cause else null;
    try testing.expectEqual(@as(?cocuyo.Cause, null), cause);
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 0), failing.left);
    // The server heard the alert of the first connection, and answered on the second.
    try testing.expectEqual(@as(u32, 1), rig.loop.network().alerts_heard[0]);
    try testing.expect(rig.engine.connections[0].state == .up);
    // At once, and not once the first pass's wait ran out.
    try testing.expect(rig.loop.now() < rig.config.timeout_ns);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a second pass waits for a closed slot whose records the loop still holds" {
    // One server and one slot. The connect ends, the session's hello goes out, and the peer resets
    // the connection before that send has ended. The connection closes at once, and the loop holds
    // its records buffer until the send's event (TLS rule 3). The lookup's second pass waits for
    // the slot, and the server answers it on a new connection (the stream's rule 12).
    var rig: OneSlotRig = .{};
    try tls_test.encrypt(&rig);
    try rig.init(63, .{.{}}, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
    rig.use_test_contexts();
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const connection = &rig.engine.connections[0];
    try until_hello_in_flight(&rig);
    reset_first(&rig);
    // The second pass asked in that event's drive, and found the slot closed and borrowed.
    try testing.expect(connection.state == .closed and connection.borrowed());
    try testing.expectEqual(@as(u16, 1), rig.engine.tcp_waiters);
    const result = try rig.until_result();
    const cause: ?cocuyo.Cause = if (result.outcome == .failure) result.outcome.failure.cause else null;
    try testing.expectEqual(@as(?cocuyo.Cause, null), cause);
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expect(rig.loop.now() < rig.config.timeout_ns);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a second pass waits for a closed slot whose query's records the loop still holds" {
    // One server and one slot. The connection is up, and a query's send is in flight. That send
    // reads the query's sealed records from the connection's records buffer. The peer resets the
    // connection before the send has ended, and the connection closes at once. The loop holds the
    // records buffer until the send's event (TLS rule 3). So the lookup's second pass waits for the
    // slot, and no new opening writes its hello there. After the event, the server answers the
    // second pass on a new connection (the stream's rule 12).
    var rig: OneSlotRig = .{};
    try tls_test.encrypt(&rig);
    try rig.init(65, .{.{}}, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
    rig.use_test_contexts();
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    const connection = &rig.engine.connections[0];
    try until_query_in_flight(&rig);
    const lent = io.tls.pending(&rig.engine, 0, connection.queue.first().?.end);
    var sealed: [io.constants.tls_records_out_bytes]u8 = undefined;
    @memcpy(sealed[0..lent.len], lent);
    reset_first(&rig);
    // The loop holds the send's event back, as a slow send's end comes late.
    const send = @TypeOf(rig.engine).user_data(.tcp_send, handle.index);
    var held: ?rotor.Event = null;
    for (0..fixtures.until_rounds_max) |_| {
        if (connection.state == .handshaking) break;
        try tcp_test.step_holding(&rig, send, &held);
    }
    try testing.expect(held != null);
    // The octets the loop may still read are the ones it was lent.
    try testing.expectEqualSlices(u8, sealed[0..lent.len], lent);
    try testing.expect(connection.state == .closed and connection.borrowed());
    try testing.expectEqual(@as(u16, 1), rig.engine.tcp_waiters);
    // The reset counted one failure, and the pass that waits counts none.
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    // The send's event gives the buffer back, and the drive's end admits the lookup. The new
    // opening's connect is in flight.
    _ = rig.engine.apply(held.?, rig.loop.now());
    try testing.expect(connection.state == .connecting and connection.records_send == null);
    try testing.expectEqual(@as(u16, 0), rig.engine.tcp_waiters);
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expect(rig.loop.now() < rig.config.timeout_ns);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

/// Steps the rig until the first slot's connection is up with a query's send in flight.
pub fn until_query_in_flight(rig: anytype) !void {
    const connection = &rig.engine.connections[0];
    for (0..fixtures.until_rounds_max) |_| {
        const head = connection.queue.first();
        if (connection.state == .up and connection.sending and head != null and head.?.is_query()) return;
        _ = try rig.step(fixtures.channel_read_ns);
    }
    return error.NotSent;
}

/// Steps the rig until the first slot's connection handshakes with its hello's send in flight.
fn until_hello_in_flight(rig: anytype) !void {
    const connection = &rig.engine.connections[0];
    for (0..fixtures.until_rounds_max) |_| {
        if (connection.state == .handshaking) break;
        _ = try rig.step(fixtures.wait_ns);
    }
    try testing.expect(connection.state == .handshaking and connection.records_send != null);
}

/// The peer resets the first slot's connection.
fn reset_first(rig: anytype) void {
    const receive = tcp.user_data_of(&rig.engine, .tcp_receive, 0);
    _ = rig.engine.apply(rotor.Event.failure(receive, .connection_reset), rig.loop.now());
}

/// One server and two connection slots over the failing session.
const TwoSlotRig = sim_test.RigOfServers(io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = fixtures.tcp_slots_pair,
    .tls = Failing,
}), 1);

test "a second pass whose connect the loop refuses is told at once, though a slot is pending" {
    // One server and two slots. The peer resets the first connection while its hello's send is in
    // flight, so the loop holds that slot (TLS rule 3). The loop refuses each submission from then.
    // The second pass finds the other slot free, and the loop refuses its connect. That is no want
    // of a slot, so the lookup is told at once and does not wait (the stream's rule 12).
    var rig: TwoSlotRig = .{};
    try tls_test.encrypt(&rig);
    try rig.init(64, .{.{}}, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
    rig.use_test_contexts();
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    try until_hello_in_flight(&rig);
    rig.loop.refuse_submissions = true;
    reset_first(&rig);
    rig.loop.refuse_submissions = false;
    try testing.expect(rig.engine.connections[0].state == .closed and rig.engine.connections[0].borrowed());
    try testing.expectEqual(@as(u16, 0), rig.engine.tcp_waiters);
    const result = rig.engine.take(rig.loop.now()) orelse return error.NoResult;
    const failure: ?cocuyo.Error = if (result.outcome == .failure) result.outcome.failure.err else null;
    try testing.expectEqual(@as(?cocuyo.Error, cocuyo.Error.AllServersFailed), failure);
    try testing.expectEqual(@as(?cocuyo.Cause, .connect), result.outcome.failure.cause);
    try rig.deinit();
}

test "a second pass opens the other slot while a query's send reads the first one's records" {
    // One server and two slots. The peer resets the first connection while a query's send is in
    // flight. The loop holds that slot's records buffer until the send's event (TLS rule 3). The
    // second pass opens the other slot at once. Its query waits, held, until the same event gives
    // the lookup's buffer back (the stream's rule 6). Then it goes out on the new connection.
    var rig: TwoSlotRig = .{};
    try tls_test.encrypt(&rig);
    try rig.init(66, .{.{}}, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
    rig.use_test_contexts();
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    const first = &rig.engine.connections[0];
    const second = &rig.engine.connections[1];
    try until_query_in_flight(&rig);
    const lent = io.tls.pending(&rig.engine, 0, first.queue.first().?.end);
    var sealed: [io.constants.tls_records_out_bytes]u8 = undefined;
    @memcpy(sealed[0..lent.len], lent);
    reset_first(&rig);
    const send = @TypeOf(rig.engine).user_data(.tcp_send, handle.index);
    var held: ?rotor.Event = null;
    for (0..fixtures.until_rounds_max) |_| {
        if (rig.engine.held[handle.index] != null) break;
        try tcp_test.step_holding(&rig, send, &held);
    }
    try testing.expect(held != null and rig.engine.held[handle.index] != null);
    try testing.expect(second.state == .up and !second.queue.contains(handle.index));
    try testing.expect(first.state == .closed);
    try testing.expectEqual(@as(?u16, handle.index), first.records_send);
    try testing.expectEqualSlices(u8, sealed[0..lent.len], lent);
    // The send's event frees the first slot, and the held query joins the second connection.
    _ = rig.engine.apply(held.?, rig.loop.now());
    try testing.expect(first.records_send == null and second.queue.contains(handle.index));
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expect(rig.loop.now() < rig.config.timeout_ns);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

/// What one lookup came to: its error, null for an answer, the first server's failures, and
/// whether it ended before its wait ran out.
const Seen = struct { failure: ?cocuyo.Error, failures: u8, at_once: bool };

/// One lookup on an engine over a session that asks for `room` octets of the records buffer.
/// Both servers answer.
fn lookup_with_room(comptime room: usize, seed: u64) !Seen {
    var rig: RigOver(FailingOf(room)) = .{};
    try tls_test.start(&rig, seed, .{ .{}, .{} });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    const failure: ?cocuyo.Error = if (result.outcome == .failure) result.outcome.failure.err else null;
    const seen: Seen = .{ .failure = failure, .failures = rig.engine.resolver.servers.failures(0), .at_once = rig.loop.now() < rig.config.timeout_ns };
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
    return seen;
}

test "the records buffer takes a session that asks for all of it, and a session that asks for more fails" {
    // A session stages its records in the room after the sealed records. The engine gives it that
    // room only when the room holds the most the session asks for (§21, TLS rule 3). Each opening
    // asks for room for its hello first. So a session that asks for more than the buffer fails
    // each connection before it sends an octet.
    const whole = try lookup_with_room(io.constants.tls_records_out_bytes, 59);
    try testing.expectEqual(@as(?cocuyo.Error, null), whole.failure);
    try testing.expectEqual(@as(u8, 0), whole.failures);
    const over = try lookup_with_room(io.constants.tls_records_out_bytes + 1, 60);
    // Each pass over the servers fails both at once, and the first server is charged each time.
    try testing.expectEqual(@as(?cocuyo.Error, cocuyo.Error.AllServersFailed), over.failure);
    try testing.expectEqual(@as(u8, cocuyo.constants.attempts_default), over.failures);
    try testing.expect(over.at_once);
}

/// Names a lookup each, none of which the cache holds.
const queued_names = [_][]const u8{ "a.example.", "b.example.", "c.example.", "d.example.", "e.example.", "f.example." };

test "a queue holds a query for each lookup and two entries of the records the session made itself" {
    // Records the session makes go after what is sealed, and records made behind an entry that has
    // not started join it (TLS rule 2). So beside one entry in flight there is one more at most.
    // Here every lookup's query waits behind the entry in flight, and the session makes records
    // twice more.
    var rig: FailingRig = .{};
    try tls_test.start(&rig, 61, .{ .{}, .{} });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    _ = rig.engine.take(rig.loop.now());
    const connection = &rig.engine.connections[0];
    defer unasked = 0;
    unasked = 1;
    try testing.expect(io.tls.make_records(&rig.engine, 0, rig.loop.now()));
    try testing.expect(connection.sending);
    comptime std.debug.assert(queued_names.len == fixtures.small_lookups);
    for (queued_names) |name| _ = try rig.engine.start(question(name), rig.loop.now());
    for (0..io.constants.tls_records_entries_max) |_| {
        unasked = 1;
        try testing.expect(io.tls.make_records(&rig.engine, 0, rig.loop.now()));
    }
    try testing.expectEqual(fixtures.small_lookups + io.constants.tls_records_entries_max, connection.queue.count);
    for (queued_names) |_| try testing.expect((try rig.until_result()).outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "records the session makes while a send is in flight go behind it, and move none of it" {
    // Sealed octets that the loop holds never move (TLS rule 3). The session makes records while a
    // query's send is in flight, and they wait behind it. Once the query has gone, they are in
    // flight from inside the buffer. The session makes records again, and these go behind them.
    var rig: FailingRig = .{};
    try tls_test.start(&rig, 67, .{ .{}, .{} });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const connection = &rig.engine.connections[0];
    defer unasked = 0;
    try until_query_in_flight(&rig);
    unasked = 1;
    try testing.expect(io.tls.make_records(&rig.engine, 0, rig.loop.now()));
    for (0..fixtures.until_rounds_max) |_| {
        const head = connection.queue.first() orelse break;
        if (connection.tls.out_head > 0 and !head.is_query()) break;
        _ = try rig.step(fixtures.channel_read_ns);
    }
    try testing.expect(connection.sending and connection.tls.out_head > 0);
    const lent = io.tls.pending(&rig.engine, 0, connection.queue.first().?.end);
    unasked = 1;
    try testing.expect(io.tls.make_records(&rig.engine, 0, rig.loop.now()));
    try testing.expectEqual(lent.ptr, io.tls.pending(&rig.engine, 0, connection.queue.first().?.end).ptr);
    try testing.expect((try rig.until_result()).outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

/// The octet a test's buffer holds before a reset, which no reset writes.
const untouched: u8 = 0x5a;

test "a TLS reset empties the state and leaves the records' bytes, which the loop may hold" {
    var holder: struct { tls: io.tls.State(Failing) = .{} } = .{};
    holder.tls.ticket_since_ns = 9;
    holder.tls.record_in_used = 3;
    holder.tls.out_head = 1;
    holder.tls.out_tail = 2;
    @memset(&holder.tls.record_in, untouched);
    @memset(&holder.tls.out, untouched);
    io.tls.reset(&holder);
    try testing.expectEqual(@as(u64, 0), holder.tls.ticket_since_ns);
    try testing.expectEqual(@as(usize, 0), holder.tls.record_in_used);
    try testing.expectEqual(@as(u16, 0), holder.tls.out_head);
    try testing.expectEqual(@as(u16, 0), holder.tls.out_tail);
    for (holder.tls.record_in) |octet| try testing.expectEqual(untouched, octet);
    for (holder.tls.out) |octet| try testing.expectEqual(untouched, octet);
}
