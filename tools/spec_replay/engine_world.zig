//! One engine of `io/` over the twin in manual mode, driven by the events of the engine model's
//! transcript (spec/lean/Spec/EngineWalk.lean), and its state written the way the model writes its
//! own (`stateLine`), so the two can be compared line by line.
//!
//! The twin performs nothing in manual mode: every operation the engine submits waits until the
//! transcript ends it, with the outcome it names, which is how the replay reaches the orders
//! rotor decision 5, rule 2 allows and the network's own timing never produces.
//!
//! This is developer tooling. It is never linked into the library.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io");
const lookup_text = @import("replay.zig");
const fixtures = @import("fixtures.zig");
const text_module = @import("engine_text.zig");

/// The seed every engine of the replay starts from; the model abstracts the entropy away.
const seed = 0x5eed_e791;

/// The model's tick: how long a connection nobody uses is kept, and what `idle` moves the clock
/// by. A lookup waits two of them, the model's `timeoutTicks`, so an `idle` can end a wait as
/// well as close a connection.
const idle_ns = 1_000_000;
const timeout_ns = 2 * idle_ns;

/// The longest state line: two slots, two connections, a handful of operations.
pub const text_bytes_max = 1024;

pub const Error = error{ Malformed, NoSuchOperation, NoBuffer, Full, BufferKept };

/// Whether every query goes over TCP, over TLS, or over UDP; and the queries a port carries before
/// it is replaced. A walk's `config` line names both.
pub const Transport = struct { tcp: bool, per_port: u32, tls: bool = false };

/// What ends an operation, as the transcript names it.
const Outcome = enum { ok, failed, canceled, exhausted, short };

pub fn World(comptime slots: u16, comptime conns: u16) type {
    return struct {
        const Self = @This();
        pub const Engine = io.Engine(.{
            .lookups = slots,
            .cache_slots = 2,
            .group_buffers = 2,
            .tcp_connections = conns,
            .tcp_group_buffers = 2,
            .tcp_message_bytes = 512,
            // The twin's session: every configuration may speak TLS (docs/design.md §21).
            .tls = rotor.tls.Session,
        });

        loop: rotor.Loop,
        memory: [0]u8 align(rotor.memory_alignment),
        servers: [2]cocuyo.Server,
        config: cocuyo.Config,
        engine: Engine,
        now_ns: u64,
        /// Names asked so far in this walk: each start asks a new one, so the cache never
        /// answers, as the model has it.
        names: u32,
    };
}

pub fn begin(self: anytype, transport: Transport) !void {
    try self.loop.init(&self.memory, .{ .operations = @TypeOf(self.engine).loop_operations });
    self.loop.manual = true;
    for (&self.servers, 0..) |*server, index| {
        const address = rotor.Network.server_address(@intCast(index));
        server.* = .{ .endpoint = .{
            .address = cocuyo.Address.from_v4(address.bytes[0..cocuyo.constants.address_v4_bytes].*),
            .port = address.port,
        } };
        if (transport.tls) server.tls = .{ .name = cocuyo.Name.from_text("dns.example.") catch unreachable };
    }
    self.config = .{
        .servers = &self.servers,
        .use_tcp = transport.tcp,
        .attempts = 1,
        .timeout_ns = timeout_ns,
        .failover_retry_chance = 0,
        .udp_queries_per_port = transport.per_port,
    };
    // The clock starts past zero, which is what a connection's idle instant reads before
    // it has one.
    self.now_ns = 1;
    self.names = 0;
    try self.engine.init(&self.loop, &self.config, seed, self.now_ns);
    self.engine.tcp_idle_ns = idle_ns;
}

/// One event of the transcript, then the timers the engine let go of, ended. Every
/// buffer an event hands the engine is back in its group when the event is over: a chunk
/// once its messages are out, and a stale event's buffer at once (the stream's rule 2).
pub fn apply(self: anytype, token: []const u8) Error!void {
    // A refusal lasts the one event after it, as the model has it.
    if (std.mem.eql(u8, token, "jam")) {
        self.loop.refuse_submissions = true;
        return;
    }
    if (std.mem.eql(u8, token, "starve")) {
        self.loop.network().refuse_open = true;
        return;
    }
    const result = dispatch(self, token);
    self.loop.refuse_submissions = false;
    self.loop.network().refuse_open = false;
    try result;
    for ([_]u16{ io.constants.group_id, io.constants.tcp_group_id }) |group_id| {
        const group = &self.loop.groups[group_id];
        if (group.free_count != group.count) return error.BufferKept;
    }
}

fn dispatch(self: anytype, token: []const u8) Error!void {
    var parts = std.mem.splitScalar(u8, token, ':');
    const name = parts.first();
    if (std.mem.eql(u8, name, "expire")) {
        self.now_ns = next_deadline(self) orelse return error.Malformed;
        self.engine.drive(self.now_ns);
    } else if (std.mem.eql(u8, name, "idle")) {
        self.now_ns += idle_ns;
        self.engine.drive(self.now_ns);
    } else {
        // Every other event comes at the instant of the one before it, as the model has
        // it: waits that begin between two moves of the clock share their deadline.
        try instant(self, name, &parts);
    }
    end_cancelled_timers(self);
}

fn instant(self: anytype, name: []const u8, parts: *std.mem.SplitIterator(u8, .scalar)) Error!void {
    if (std.mem.eql(u8, name, "start")) return start(self);
    if (std.mem.eql(u8, name, "lapse")) {
        // A kept ticket reaches its lifetime, or seven days: the model's lapse, which no drive
        // follows (docs/design.md §21, TLS rule 8).
        self.engine.tls_tickets[try number(parts.next())] = null;
        return;
    }
    if (std.mem.eql(u8, name, "take")) {
        _ = self.engine.take(self.now_ns);
        return;
    }
    if (std.mem.eql(u8, name, "cancel")) {
        const slot = try number(parts.next());
        return self.engine.cancel(self.engine.handles[slot], self.now_ns);
    }
    const op = parts.next() orelse return error.Malformed;
    if (std.mem.eql(u8, name, "straggle")) return straggle(self, op);
    if (std.mem.eql(u8, name, "finish")) {
        const outcome = std.meta.stringToEnum(Outcome, parts.next() orelse "") orelse return error.Malformed;
        return finish(self, op, outcome);
    }
    if (std.mem.eql(u8, name, "message")) {
        const slot = try number(parts.next());
        const reply = std.meta.stringToEnum(fixtures.Reply, parts.next() orelse "") orelse return error.Malformed;
        return message(self, op, slot, reply);
    }
    if (std.mem.eql(u8, name, "tls")) return tls_step(self, op, parts.next() orelse "");
    return error.Malformed;
}

fn start(self: anytype) Error!void {
    var text: [32]u8 = undefined;
    const name = std.fmt.bufPrint(&text, "n{d}.test.", .{self.names}) catch unreachable;
    self.names += 1;
    const question = cocuyo.Question.from_text(name, .a) catch unreachable;
    _ = self.engine.start(question, self.now_ns) catch return error.Full;
}

/// The soonest deadline a lookup waits for.
fn next_deadline(self: anytype) ?u64 {
    var soonest: ?u64 = null;
    for (self.engine.slots[0..]) |*slot| {
        if (!slot.occupied or !slot.lookup.is_waiting()) continue;
        if (soonest == null or slot.lookup.deadline_ns < soonest.?) soonest = slot.lookup.deadline_ns;
    }
    return soonest;
}

/// The oldest operation the loop holds whose token is `name`. The model's operations are a bag, so
/// an event names one by its token; two with one token are one to the model, and the replay shows
/// whether the engine treats them alike.
fn operation(self: anytype, name: []const u8) Error!u32 {
    var ordered: [rotor.constants.operations_max]u32 = undefined;
    const count = known_operations(self, &ordered);
    for (ordered[0..count]) |loop_slot| {
        var text: [16]u8 = undefined;
        if (std.mem.eql(u8, text_module.token_of(self, loop_slot).write(&text), name)) return loop_slot;
    }
    return error.NoSuchOperation;
}

/// The loop's operations the model knows, every one but the timer, oldest first, by the slot
/// generation the loop gave them.
pub fn known_operations(self: anytype, out: []u32) usize {
    var count: usize = 0;
    for (self.loop.slots[0..], 0..) |*slot, index| {
        if (!slot.live or kind_of(slot.user_data) == null) continue;
        out[count] = @intCast(index);
        count += 1;
    }
    const Context = struct {
        loop: *const rotor.Loop,
        fn older(context: @This(), left: u32, right: u32) bool {
            return context.loop.slots[left].generation < context.loop.slots[right].generation;
        }
    };
    std.mem.sort(u32, out[0..count], Context{ .loop = &self.loop }, Context.older);
    return count;
}

fn finish(self: anytype, op: []const u8, outcome: Outcome) Error!void {
    const slot = try operation(self, op);
    const user_data = self.loop.slots[slot].user_data;
    const kind = kind_of(user_data).?;
    var event = switch (outcome) {
        .ok => rotor.Event.success(user_data, moved(self, user_data, kind, false)),
        .short => rotor.Event.success(user_data, moved(self, user_data, kind, true)),
        .failed => rotor.Event.failure(user_data, failure_of(kind)),
        .canceled => rotor.Event.failure(user_data, .canceled),
        .exhausted => rotor.Event.failure(user_data, .buffers_exhausted),
    };
    // A receive that ends in success after a cancel carries the bytes it read (rule 2).
    if (outcome == .ok and (kind == .tcp_receive or kind == .udp_receive)) {
        event = try carrying(self, user_data, kind, false);
    }
    self.loop.end(slot);
    _ = self.engine.apply(event, self.now_ns);
}

/// The octets a stream's send reports: what is left of its head, or half of it when short, which
/// is at least one and fewer than all, since a query or a record is longer than two octets. A
/// send whose connection is gone, and every other operation, reports none.
fn moved(self: anytype, user_data: u64, kind: io.Kind, short: bool) u32 {
    const index: usize = @intCast(user_data & io.constants.index_mask);
    const left = switch (kind) {
        .tcp_send => query_left(self, index),
        .tls_send => records_left(self, index),
        else => null,
    } orelse return 0;
    return if (short) left / 2 else left;
}

/// What is left of the query in slot `slot` on the connection sending it, if one is.
fn query_left(self: anytype, slot: usize) ?u32 {
    for (self.engine.connections[0..]) |*connection| {
        if (!connection.sending) continue;
        const head = connection.queue.first() orelse continue;
        if (head.slot != slot) continue;
        return head_left(self, connection, head);
    }
    return null;
}

/// What is left of the records a send of the connection's opening `index` names, if the opening
/// is still the connection's.
fn records_left(self: anytype, index: usize) ?u32 {
    const connection = &self.engine.connections[index & io.constants.tcp_slot_mask];
    const incarnation: u32 = @truncate(index >> io.constants.tcp_incarnation_shift);
    const live = connection.state != .closed and connection.state != .reopening;
    if (!live or connection.incarnation != incarnation or !connection.sending) return null;
    return head_left(self, connection, connection.queue.first() orelse return null);
}

fn head_left(self: anytype, connection: anytype, head: anytype) u32 {
    if (self.config.uses_tls()) return head.end - connection.tls.out_head - connection.sent_bytes;
    return self.engine.send_lengths[head.slot] - connection.sent_bytes;
}

/// The session's step on a TLS connection's receive, as the model names it: one handshake step
/// in a record of its own, in one buffer of the stream's group.
fn tls_step(self: anytype, op: []const u8, name: []const u8) Error!void {
    const loop_slot = try operation(self, op);
    const user_data = self.loop.slots[loop_slot].user_data;
    if (kind_of(user_data) != .tcp_receive) return error.Malformed;
    const steps = [_]struct { name: []const u8, step: rotor.tls.Step }{
        .{ .name = "flight", .step = .flight },
        .{ .name = "done", .step = .done },
        .{ .name = "failed", .step = .refused },
        .{ .name = "rekey", .step = .rekey },
        .{ .name = "ticket", .step = .ticket },
    };
    const step = for (steps) |entry| {
        if (std.mem.eql(u8, entry.name, name)) break entry.step;
    } else return error.Malformed;
    const buffer_id = self.loop.groups[io.constants.tcp_group_id].take() orelse return error.NoBuffer;
    const buffer = self.loop.provided_buffer(io.constants.tcp_group_id, buffer_id);
    var event = rotor.Event.success(user_data, @intCast(rotor.tls.write_step(step, buffer)));
    event.flags = .{ .buffer = true, .more = true, .buffer_id = buffer_id };
    _ = self.engine.apply(event, self.now_ns);
}

/// A datagram or a chunk on a receive that is gone, before its end: the receive stays.
fn straggle(self: anytype, op: []const u8) Error!void {
    const slot = try operation(self, op);
    const user_data = self.loop.slots[slot].user_data;
    const kind = kind_of(user_data).?;
    if (kind != .tcp_receive and kind != .udp_receive) return error.Malformed;
    const event = try carrying(self, user_data, kind, true);
    _ = self.engine.apply(event, self.now_ns);
}

/// An event that carries one octet in a buffer of its receive's group.
fn carrying(self: anytype, user_data: u64, kind: io.Kind, more: bool) Error!rotor.Event {
    const group_id: u16 = if (kind == .tcp_receive) io.constants.tcp_group_id else io.constants.group_id;
    const buffer_id = self.loop.groups[group_id].take() orelse return error.NoBuffer;
    const buffer = self.loop.provided_buffer(group_id, buffer_id);
    var length: u32 = 1;
    if (kind == .udp_receive) {
        const peer = rotor.Network.server_address(0);
        length = rotor.buffers.write_delivery(buffer, .{}, &peer, &.{0});
    }
    var event = rotor.Event.success(user_data, length);
    event.flags = .{ .buffer = true, .more = more, .buffer_id = buffer_id };
    return event;
}

/// A message on the receive at `position`, for the lookup in `slot`: on a stream, one whole
/// frame, length and all, in one buffer of the stream's group (RFC 7766 §8); on a socket, one
/// datagram from its server, laid out in the datagram group as rotor lays one out.
fn message(self: anytype, op: []const u8, slot: usize, reply: fixtures.Reply) Error!void {
    const loop_slot = try operation(self, op);
    const user_data = self.loop.slots[loop_slot].user_data;
    const lookup = self.engine.resolver.lookup_of(self.engine.handles[slot]);
    var body_buffer: [512]u8 = undefined;
    const body = fixtures.build(lookup, reply, &body_buffer);
    const kind = kind_of(user_data) orelse return error.Malformed;
    const group_id: u16 = switch (kind) {
        .tcp_receive => io.constants.tcp_group_id,
        .udp_receive => io.constants.group_id,
        else => return error.Malformed,
    };
    const buffer_id = self.loop.groups[group_id].take() orelse return error.NoBuffer;
    const buffer = self.loop.provided_buffer(group_id, buffer_id);
    var length: u32 = undefined;
    if (kind == .tcp_receive) {
        length = stream_frame(self, body, buffer);
    } else {
        const server: u8 = @intCast((user_data & io.constants.index_mask) & io.constants.receive_index_mask);
        const peer = rotor.Network.server_address(server);
        length = rotor.buffers.write_delivery(buffer, .{}, &peer, body);
    }
    var event = rotor.Event.success(user_data, length);
    event.flags = .{ .buffer = true, .more = true, .buffer_id = buffer_id };
    _ = self.engine.apply(event, self.now_ns);
}

/// One whole frame, length and all (RFC 7766 §8), and over TLS in a data record of its own
/// (RFC 7858 §3.3).
fn stream_frame(self: anytype, body: []const u8, buffer: []u8) u32 {
    const prefix = cocuyo.constants.tcp_prefix_bytes;
    var frame: [512 + prefix]u8 = undefined;
    std.mem.writeInt(u16, frame[0..prefix], @intCast(body.len), .big);
    @memcpy(frame[prefix..][0..body.len], body);
    const framed = frame[0 .. prefix + body.len];
    if (!self.config.uses_tls()) {
        @memcpy(buffer[0..framed.len], framed);
        return @intCast(framed.len);
    }
    return @intCast(rotor.tls.write_record(rotor.constants.tls_content_application, framed, buffer));
}

/// A timer the engine moved away from ends as rotor ends it, `Canceled`, and says
/// nothing: the model has no timer.
fn end_cancelled_timers(self: anytype) void {
    for (self.loop.slots[0..], 0..) |*slot, index| {
        if (!slot.live or !slot.cancelling) continue;
        if (kind_of_any(slot.user_data) != .timer) continue;
        const event = rotor.Event.failure(slot.user_data, .canceled);
        self.loop.end(@intCast(index));
        _ = self.engine.apply(event, self.now_ns);
    }
}

fn number(token: ?[]const u8) Error!usize {
    return std.fmt.parseInt(usize, token orelse return error.Malformed, 10) catch error.Malformed;
}

fn kind_of_any(user_data: u64) io.Kind {
    return @enumFromInt(@as(u8, @truncate(user_data >> io.constants.kind_shift)));
}

/// The kind of an operation the model knows, or null for the timer, which it does not.
pub fn kind_of(user_data: u64) ?io.Kind {
    const kind = kind_of_any(user_data);
    return switch (kind) {
        .tcp_connect, .tcp_send, .tcp_receive, .udp_send, .udp_receive, .tls_send => kind,
        .timer => null,
    };
}

fn failure_of(kind: io.Kind) rotor.Code {
    return switch (kind) {
        .tcp_connect => .connection_refused,
        .tcp_send, .tls_send => .broken_pipe,
        .udp_send => .network_unreachable,
        else => .connection_reset,
    };
}

test {
    _ = lookup_text;
}
