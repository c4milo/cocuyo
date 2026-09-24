//! The engine's state, written the way the engine model writes its own (`Line` in
//! spec/tla/engine/EngineTrace.tla): the slots, the connections, the sockets, the loop's operations,
//! then the ready list, the results, the slot taken last, the waits, the failures, the free list
//! and what the twin refuses.
//!
//! Each part is read off the engine and the table as they are, not as the engine says it is:
//! an operation is current when its incarnation is its connection's, or when the attempt it was
//! sent for is still its lookup's, whatever the engine is about to do with it.
//!
//! This is developer tooling. It is never linked into the library.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const io = @import("io");
const rotor = @import("rotor");
const lookup_text = @import("replay.zig");
const world_module = @import("engine_world.zig");

const slot_none = cocuyo.resolver.table_slots.slot_none;

/// A line being written into a fixed buffer.
const Line = struct {
    buffer: []u8,
    len: usize = 0,

    fn print(line: *Line, comptime format: []const u8, arguments: anytype) void {
        const written = std.fmt.bufPrint(line.buffer[line.len..], format, arguments) catch unreachable;
        line.len += written.len;
    }

    fn flag(line: *Line, set: bool, letter: u8) void {
        line.print("{c}", .{if (set) letter else '-'});
    }

    fn list(line: *Line, items: []const usize) void {
        line.print("[", .{});
        for (items, 0..) |item, index| {
            if (index > 0) line.print(",", .{});
            line.print("{d}", .{item});
        }
        line.print("]", .{});
    }
};

/// The whole state line of `world`.
pub fn write(world: anytype, out: *[world_module.text_bytes_max]u8) []const u8 {
    var line: Line = .{ .buffer = out };
    const engine = &world.engine;
    for (0..engine.slots.len) |index| {
        if (index > 0) line.print(" ; ", .{});
        slot(&line, world, index);
    }
    line.print(" | ", .{});
    for (engine.connections[0..], 0..) |*connection, index| {
        if (index > 0) line.print(" ; ", .{});
        connection_text(&line, world, connection);
    }
    line.print(" | ", .{});
    sockets_text(&line, world);
    line.print(" | ", .{});
    operations(&line, world);
    line.print(" | ", .{});
    table(&line, world);
    return line.buffer[0..line.len];
}

/// A connection: its stage, server and users, whether it went idle now and a head went short,
/// its queue, and over TLS how many entries are sealed and whether this opening resumes (§21).
fn connection_text(line: *Line, world: anytype, connection: anytype) void {
    line.print("{s} s{d} u{d}", .{ @tagName(connection.state), connection.server, connection.users });
    line.flag(connection.state != .closed and connection.idle_since_ns == world.now_ns, 'I');
    line.flag(connection.sent_bytes > 0, 'P');
    line.print(" q[", .{});
    for (0..connection.queue.count) |position| {
        if (position > 0) line.print(",", .{});
        const entry = connection.queue.at(@intCast(position));
        if (entry.is_query()) line.print("{d}", .{entry.slot}) else line.print("r", .{});
    }
    line.print("]", .{});
    if (!world.config.uses_tls()) return;
    line.print(" k{d}", .{connection.queue.sealed});
    line.flag(connection.tls.ticket != null, 'M');
}

/// Each server's sockets: none over TLS (§21, TLS rule 9).
fn sockets_text(line: *Line, world: anytype) void {
    const engine = &world.engine;
    for (0..engine.sockets.count) |server| {
        if (server > 0) line.print(" ; ", .{});
        const socket = &engine.sockets.items[server];
        line.print("open s{d}", .{socket.sent});
        line.flag(socket.retiring, 'R');
        line.flag(engine.sockets.draining[server].open, 'D');
    }
}

fn slot(line: *Line, world: anytype, index: usize) void {
    const engine = &world.engine;
    const table_slot = &engine.slots[index];
    if (!table_slot.occupied) {
        line.print("free ", .{});
        line.flag(engine.send_in_flight[index], 'B');
        line.print(" u", .{});
        sent_from(line, world, index);
        return;
    }
    const lookup = &table_slot.lookup;
    var text: [lookup_text.state_bytes_max]u8 = undefined;
    line.print("{s} o", .{lookup_text.state_text(lookup, &text)});
    var order: [cocuyo.constants.servers_max]usize = undefined;
    const ordered: usize = if (lookup.flags.ordered) world.config.servers.len else 0;
    for (order[0..ordered], 0..) |*position, at| position.* = lookup.order[at];
    line.list(order[0..ordered]);
    if (engine.tcp_connection[index]) |at| line.print(" c{d} u", .{at}) else line.print(" c- u", .{});
    sent_from(line, world, index);
    line.print(" ", .{});
    line.flag(engine.send_in_flight[index], 'B');
    line.flag(engine.held[index] != null, 'H');
    line.flag(engine.reported[index], 'R');
}

/// The socket a slot's last datagram left from, as it stands now: its server, then `c` for the
/// current socket, `d` for the draining one, `g` for one that is gone.
fn sent_from(line: *Line, world: anytype, index: usize) void {
    const from = world.engine.sent_from[index] orelse return line.print("-", .{});
    const sockets = &world.engine.sockets;
    const draining = &sockets.draining[from.server];
    const age: u8 = if (sockets.items[from.server].epoch == from.epoch)
        'c'
    else if (draining.open and draining.epoch == from.epoch) 'd' else 'g';
    line.print("{d}{c}", .{ from.server, age });
}

/// One of the loop's operations as the model names it: its kind's letter, its target, and whether
/// it is current. The model's operations are a bag, so an event names one by this token and a state
/// writes them in `key` order (spec/tla/engine/EngineTrace.tla, `OpKey`).
pub const Token = struct {
    letter: u8,
    target: usize,
    current: bool,

    /// The letters in the order the model writes them.
    const letters = "CRSDLMT";

    pub fn key(token: Token) usize {
        const rank = std.mem.indexOfScalar(u8, letters, token.letter).?;
        return (rank * 256 + token.target) * 2 + @intFromBool(token.current);
    }

    pub fn write(token: Token, out: []u8) []const u8 {
        return std.fmt.bufPrint(out, "{c}{d}{c}", .{ token.letter, token.target, mark(token.current) }) catch unreachable;
    }
};

/// The token of the operation the loop holds in `loop_slot`, read off the engine as it stands.
pub fn token_of(world: anytype, loop_slot: u32) Token {
    const user_data = world.loop.slots[loop_slot].user_data;
    const index: usize = @intCast(user_data & io.constants.index_mask);
    return switch (world_module.kind_of(user_data).?) {
        .tcp_connect, .tcp_receive, .tls_send => |kind| blk: {
            const at = index & io.constants.tcp_slot_mask;
            const incarnation: u32 = @truncate(index >> io.constants.tcp_incarnation_shift);
            const connection = &world.engine.connections[at];
            const live = connection.state != .closed and connection.state != .reopening;
            const letter: u8 = switch (kind) {
                .tcp_connect => 'C',
                .tcp_receive => 'R',
                else => 'T',
            };
            break :blk .{ .letter = letter, .target = at, .current = live and connection.incarnation == incarnation };
        },
        .tcp_send => .{ .letter = 'S', .target = index, .current = send_is_current(world, index) },
        .udp_send => .{ .letter = 'D', .target = index, .current = send_is_current(world, index) },
        .udp_receive => blk: {
            const found = world.engine.sockets.find(index);
            const draining = found != null and found.?.which == .draining;
            const letter: u8 = if (draining) 'M' else 'L';
            break :blk .{ .letter = letter, .target = index & io.constants.receive_index_mask, .current = found != null };
        },
        else => unreachable,
    };
}

/// The loop's operations the model knows, in the model's order.
fn operations(line: *Line, world: anytype) void {
    var ordered: [rotor.constants.operations_max]u32 = undefined;
    const count = world_module.known_operations(world, &ordered);
    var tokens: [rotor.constants.operations_max]Token = undefined;
    for (ordered[0..count], tokens[0..count]) |loop_slot, *token| token.* = token_of(world, loop_slot);
    const Context = struct {
        fn before(_: void, left: Token, right: Token) bool {
            return left.key() < right.key();
        }
    };
    std.mem.sort(Token, tokens[0..count], {}, Context.before);
    for (tokens[0..count], 0..) |token, position| {
        if (position > 0) line.print(" ", .{});
        var text: [16]u8 = undefined;
        line.print("{s}", .{token.write(&text)});
    }
}

fn mark(current: bool) u8 {
    return if (current) '*' else 'x';
}

/// Whether the send in flight from slot `index` speaks for the attempt the lookup is on.
fn send_is_current(world: anytype, index: usize) bool {
    const engine = &world.engine;
    const owner = engine.send_owner[index] orelse return false;
    if (!engine.slots[index].occupied or engine.handles[index] != owner.handle) return false;
    const lookup = &engine.slots[index].lookup;
    return !lookup.is_settled() and std.meta.eql(lookup.transaction, owner.transaction);
}

fn table(line: *Line, world: anytype) void {
    const engine = &world.engine;
    const resolver = &engine.resolver;
    var items: [64]usize = undefined;
    var count: usize = 0;
    var at = resolver.ready_head;
    while (at != slot_none and count < items.len) : (at = resolver.slots.items[at].next_ready) {
        items[count] = at;
        count += 1;
    }
    line.print("r", .{});
    line.list(items[0..count]);
    count = 0;
    while (count < engine.results.count) : (count += 1) {
        items[count] = engine.results.items[(engine.results.head + count) % engine.results.items.len].handle.index;
    }
    line.print(" q", .{});
    line.list(items[0..count]);
    if (engine.last_taken) |handle| line.print(" t{d}", .{handle.index}) else line.print(" t-", .{});
    waits(line, world);
    line.print(" f[", .{});
    for (0..world.config.servers.len) |server| {
        if (server > 0) line.print(",", .{});
        line.print("{d}", .{resolver.servers.failures(server)});
    }
    line.print("] e", .{});
    count = 0;
    at = resolver.slots.free_head;
    while (at != slot_none and count < items.len) : (at = resolver.slots.items[at].next_free) {
        items[count] = at;
        count += 1;
    }
    line.list(items[0..count]);
    line.print(" ", .{});
    line.flag(world.loop.refuse_submissions, 'J');
    line.flag(world.loop.network().refuse_open, 'Z');
    if (!world.config.uses_tls()) return;
    line.print(" tk[", .{});
    for (0..world.config.servers.len) |server| {
        if (server > 0) line.print(",", .{});
        line.print("{d}", .{@intFromBool(engine.tls_tickets[server] != null)});
    }
    line.print("]", .{});
}

/// The waiting lookups, grouped by the deadline they wait for, soonest first.
fn waits(line: *Line, world: anytype) void {
    const engine = &world.engine;
    var waiting: [64]usize = undefined;
    var count: usize = 0;
    for (engine.slots[0..], 0..) |*table_slot, index| {
        if (!table_slot.occupied or !table_slot.lookup.is_waiting()) continue;
        waiting[count] = index;
        count += 1;
    }
    const Context = struct {
        slots: []const cocuyo.Slot,
        fn sooner(context: @This(), left: usize, right: usize) bool {
            const a = context.slots[left].lookup.deadline_ns;
            const b = context.slots[right].lookup.deadline_ns;
            return a < b or (a == b and left < right);
        }
    };
    std.mem.sort(usize, waiting[0..count], Context{ .slots = engine.slots[0..] }, Context.sooner);
    line.print(" w[", .{});
    var start: usize = 0;
    while (start < count) {
        var end = start + 1;
        const deadline = engine.slots[waiting[start]].lookup.deadline_ns;
        while (end < count and engine.slots[waiting[end]].lookup.deadline_ns == deadline) : (end += 1) {}
        if (start > 0) line.print(",", .{});
        line.list(waiting[start..end]);
        start = end;
    }
    line.print("]", .{});
}
