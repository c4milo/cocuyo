//! One engine of `io/` over the twin in manual mode, driven by the events of the engine model's
//! transcript (spec/Spec/EngineWalk.lean), and its state written the way the model writes its
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

/// What ends an operation, as the transcript names it.
const Outcome = enum { ok, failed, canceled };

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

pub fn begin(self: anytype) !void {
    try self.loop.init(&self.memory, .{ .operations = @TypeOf(self.engine).loop_operations });
    self.loop.manual = true;
    for (&self.servers, 0..) |*server, index| {
        const address = rotor.Network.server_address(@intCast(index));
        server.* = .{ .endpoint = .{
            .address = cocuyo.Address.from_v4(address.bytes[0..cocuyo.constants.address_v4_bytes].*),
            .port = address.port,
        } };
    }
    self.config = .{
        .servers = &self.servers,
        .use_tcp = true,
        .attempts = 1,
        .timeout_ns = timeout_ns,
        .failover_retry_chance = 0,
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
    try dispatch(self, token);
    const group = &self.loop.groups[io.constants.tcp_group_id];
    if (group.free_count != group.count) return error.BufferKept;
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
    if (std.mem.eql(u8, name, "take")) {
        _ = self.engine.take(self.now_ns);
        return;
    }
    if (std.mem.eql(u8, name, "cancel")) {
        const slot = try number(parts.next());
        return self.engine.cancel(self.engine.handles[slot], self.now_ns);
    }
    const op = try number(parts.next());
    if (std.mem.eql(u8, name, "finish")) {
        const outcome = std.meta.stringToEnum(Outcome, parts.next() orelse "") orelse return error.Malformed;
        return finish(self, op, outcome);
    }
    if (std.mem.eql(u8, name, "message")) {
        const slot = try number(parts.next());
        const reply = std.meta.stringToEnum(fixtures.Reply, parts.next() orelse "") orelse return error.Malformed;
        return message(self, op, slot, reply);
    }
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

/// The operation at position `position` among the stream operations the loop holds,
/// oldest first: the model's `ops`.
fn operation(self: anytype, position: usize) Error!u32 {
    var ordered: [rotor.constants.operations_max]u32 = undefined;
    const count = stream_operations(self, &ordered);
    if (position >= count) return error.NoSuchOperation;
    return ordered[position];
}

/// The loop's stream operations, oldest first, by the slot generation the loop gave them.
pub fn stream_operations(self: anytype, out: []u32) usize {
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

fn finish(self: anytype, position: usize, outcome: Outcome) Error!void {
    const slot = try operation(self, position);
    const user_data = self.loop.slots[slot].user_data;
    var event = switch (outcome) {
        .ok => rotor.Event.success(user_data, 0),
        .failed => rotor.Event.failure(user_data, failure_of(kind_of(user_data).?)),
        .canceled => rotor.Event.failure(user_data, .canceled),
    };
    // A receive that ends in success after a cancel carries the bytes it read (rule 2).
    if (outcome == .ok and kind_of(user_data).? == .tcp_receive) {
        const buffer_id = self.loop.groups[io.constants.tcp_group_id].take() orelse return error.NoBuffer;
        event.result = 1;
        event.flags = .{ .buffer = true, .buffer_id = buffer_id };
    }
    self.loop.end(slot);
    _ = self.engine.apply(event, self.now_ns);
}

/// A message on the receive at `position`, for the lookup in `slot`: one whole frame,
/// length and all, in one buffer of the stream's group (RFC 7766 §8).
fn message(self: anytype, position: usize, slot: usize, reply: fixtures.Reply) Error!void {
    const loop_slot = try operation(self, position);
    const user_data = self.loop.slots[loop_slot].user_data;
    if (kind_of(user_data) != .tcp_receive) return error.Malformed;
    const buffer_id = self.loop.groups[io.constants.tcp_group_id].take() orelse return error.NoBuffer;
    const buffer = self.loop.provided_buffer(io.constants.tcp_group_id, buffer_id);
    const prefix = cocuyo.constants.tcp_prefix_bytes;
    const lookup = self.engine.resolver.lookup_of(self.engine.handles[slot]);
    const body = fixtures.build(lookup, reply, buffer[prefix..]);
    std.mem.writeInt(u16, buffer[0..prefix], @intCast(body.len), .big);
    var event = rotor.Event.success(user_data, @intCast(prefix + body.len));
    event.flags = .{ .buffer = true, .more = true, .buffer_id = buffer_id };
    _ = self.engine.apply(event, self.now_ns);
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

/// The kind of a stream operation, or null for any other.
pub fn kind_of(user_data: u64) ?io.Kind {
    const kind = kind_of_any(user_data);
    return switch (kind) {
        .tcp_connect, .tcp_send, .tcp_receive => kind,
        .udp_send, .udp_receive, .timer => null,
    };
}

fn failure_of(kind: io.Kind) rotor.Code {
    return switch (kind) {
        .tcp_connect => .connection_refused,
        .tcp_send => .broken_pipe,
        else => .connection_reset,
    };
}

test {
    _ = lookup_text;
}
