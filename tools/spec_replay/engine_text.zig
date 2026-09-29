//! The engine's state, written the way the engine model writes its own (`Line` in
//! spec/tla/engine/EngineTrace.tla): the slots, the connections, the sockets, over DoQ the QUIC
//! connections and the request slots, the loop's operations, then the ready list, the results, the
//! slot taken last, the waits, the failures, the free list and what the twin refuses.
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
    if (world.config.sends_requests()) requests_text(&line, world);
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

/// Each server's QUIC connection, then each slot's request: the server it went to, or "-"
/// (EngineTrace.tla, `RConnToken` and `ReqToken`). An engine that carries DoH over channels has no
/// request connection, and writes each server's channel after the requests (`ChanToken`).
fn requests_text(line: *Line, world: anytype) void {
    const engine = &world.engine;
    const channels = comptime @TypeOf(world.engine).Doh.enabled;
    if (!channels) request_connections_text(line, world);
    line.print(" | ", .{});
    for (engine.requests[0..], 0..) |*request, index| {
        if (index > 0) line.print(" ; ", .{});
        if (request.live) line.print("{d}", .{request.server}) else line.print("-", .{});
    }
    line.print(" | ", .{});
    if (channels) channels_text(line, world);
}

/// Each server's request connection, over QUIC, or over TCP when DoH goes over HTTP/2.
fn request_connections_text(line: *Line, world: anytype) void {
    for (0..world.config.servers.len) |server| {
        if (server > 0) line.print(" ; ", .{});
        if (world.config.uses_https()) {
            request_connection_text(line, world, &world.engine.h2, @intCast(server));
        } else {
            request_connection_text(line, world, &world.engine.quic, @intCast(server));
        }
    }
}

/// Each server's channel, and the section's end.
fn channels_text(line: *Line, world: anytype) void {
    for (0..world.config.servers.len) |server| {
        if (server > 0) line.print(" ; ", .{});
        channel_text(line, world, @intCast(server));
    }
    line.print(" | ", .{});
}

/// A server's channel: its stage, the requests it holds as exchanges and those waiting for the next
/// channel, the end it holds, whether it went idle now, and its links (EngineTrace.tla,
/// `ChanToken`).
fn channel_text(line: *Line, world: anytype, server: u8) void {
    const engine = &world.engine;
    const set_slot = &engine.doh.slots[server];
    var items: [64]usize = undefined;
    var count: usize = 0;
    for (engine.requests[0..], 0..) |*request, index| {
        if (!request.live or request.server != server or !request.exchange) continue;
        items[count] = index;
        count += 1;
    }
    line.print("{s} x", .{@tagName(set_slot.state)});
    line.list(items[0..count]);
    for (set_slot.queue[0..set_slot.queue_len], 0..) |index, position| items[position] = index;
    line.print(" q", .{});
    line.list(items[0..set_slot.queue_len]);
    line.print(" h", .{});
    if (set_slot.channel.held) |held| {
        line.print("{d}:{s}", .{ held.index, if (held.answer) "answer" else "failed" });
    } else {
        line.print("-", .{});
    }
    line.flag(set_slot.state != .closed and set_slot.idle_since_ns == world.now_ns, 'I');
    for (0..set_slot.links.len) |at| {
        line.print(" ", .{});
        link_text(line, world, server, at);
    }
}

/// A channel's link: its state, and whether its buffer is lent, a connect borrows its address, the
/// channel owes octets on it, it keeps octets not yet sent, its connection started with a ticket,
/// the channel asked for it, and a ticket of its transport is kept (EngineTrace.tla, `LinkToken`).
fn link_text(line: *Line, world: anytype, server: u8, at: usize) void {
    const engine = &world.engine;
    const set_slot = &engine.doh.slots[server];
    const link = &set_slot.links[at];
    const send = &engine.doh.sends[server][at];
    // A send in flight holds what the link made: the model keeps only what waits for a send.
    const in_flight = send.lent and send.incarnation == link.incarnation;
    line.print("{s} ", .{@tagName(link.state)});
    line.flag(send.lent, 'B');
    line.flag(send.connecting, 'N');
    line.flag(set_slot.channel.owes[at] and link.state == .running, 'O');
    line.flag(link.made > 0 and !in_flight, 'K');
    line.flag(set_slot.channel.resumed[at] and link.talks(), 'M');
    line.flag(set_slot.channel.asked[at], 'A');
    line.flag(engine.doh.tickets[server][at] != null, 'T');
}

/// A request connection of `set`: its stage, the requests waiting in its queue and those with a
/// stream, and whether its transport owes a datagram, it keeps one the loop refused, it lent its
/// buffer, and it went idle now (docs/design.md §24, request rule 8); over TCP, whether a connect
/// still borrows its address (request rule 14).
fn request_connection_text(line: *Line, world: anytype, set: anytype, server: u8) void {
    const engine = &world.engine;
    const connection = &set.connections[server];
    var items: [64]usize = undefined;
    for (connection.queue[0..connection.queue_len], 0..) |index, position| items[position] = index;
    line.print("{s} q", .{@tagName(connection.state)});
    line.list(items[0..connection.queue_len]);
    var streams: usize = 0;
    for (engine.requests[0..], 0..) |*request, index| {
        if (!request.live or request.server != server or request.stream == null) continue;
        items[streams] = index;
        streams += 1;
    }
    line.print(" st", .{});
    line.list(items[0..streams]);
    line.print(" ", .{});
    line.flag(owes(connection), 'O');
    // Over TCP the octets of a send in flight stay counted until it ends, so a short one's rest is
    // known; the model keeps only what waits for a send (request rules 8 and 15).
    const in_flight = @TypeOf(set.*).stream and set.sends[server].lent;
    line.flag(connection.made > 0 and !in_flight, 'K');
    line.flag(set.sends[server].lent, 'B');
    line.flag(connection.state != .closed and connection.idle_since_ns == world.now_ns, 'I');
    if (comptime @TypeOf(set.*).stream) {
        line.flag(set.sends[server].connecting, 'N');
        held_text(line, engine, server, &connection.transport.inner);
    }
}

/// What the twin holds of a TCP connection, as the model's colibri does: the slot whose answer or
/// reset it keeps, the GOAWAY a refused request owes, and whether its stream identifiers ran out
/// (request rule 17). A held stream no live request has is written so no model's line matches.
fn held_text(line: *Line, engine: anytype, server: u8, twin: anytype) void {
    line.print(" h", .{});
    if (twin.held_stream()) |stream| {
        const found = for (engine.requests[0..], 0..) |*request, index| {
            if (request.live and request.server == server and request.stream == stream) break index;
        } else null;
        if (found) |index| line.print("{d}", .{index}) else line.print("?", .{});
    } else {
        line.print("-", .{});
    }
    line.flag(twin.goaway_owed, 'G');
    line.flag(twin.spent, 'X');
}

/// Whether a connection's transport owes the server something: the twin's QUIC, over UDP or
/// inside its frames over TCP.
fn owes(connection: anytype) bool {
    const transport = &connection.transport;
    if (@hasField(@TypeOf(transport.*), "inner")) return transport.inner.owes;
    return transport.owes;
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
    const letters = "CRSDLMTQVNAWY";

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
        .tcp_connect, .tcp_receive, .tls_send => |kind| connection_token(world, kind, index),
        .tcp_send => .{ .letter = 'S', .target = index, .current = send_is_current(world, index) },
        .udp_send => .{ .letter = 'D', .target = index, .current = send_is_current(world, index) },
        .udp_receive => blk: {
            const found = world.engine.sockets.find(index);
            const draining = found != null and found.?.which == .draining;
            const letter: u8 = if (draining) 'M' else 'L';
            break :blk .{ .letter = letter, .target = index & io.constants.receive_index_mask, .current = found != null };
        },
        .quic_send, .quic_receive => |kind| request_token(&world.engine.quic, kind, index),
        .h2_connect, .h2_send, .h2_receive => |kind| request_token(&world.engine.h2, kind, index),
        .doh_connect, .doh_send, .doh_receive => |kind| link_token(world, kind, index),
        else => unreachable,
    };
}

/// A TCP connection's connect, receive or records send: current while its opening is the slot's.
fn connection_token(world: anytype, kind: io.Kind, index: usize) Token {
    // A request configuration's engine keeps no TCP connection, and submits none of these.
    if (comptime !@TypeOf(world.engine).keeps_tcp) unreachable;
    const at = index & io.constants.tcp_slot_mask;
    const incarnation: u32 = @truncate(index >> io.constants.tcp_incarnation_shift);
    const connection = &world.engine.connections[at];
    const live = connection.state != .closed and connection.state != .reopening;
    const letter: u8 = switch (kind) {
        .tcp_connect => 'C',
        .tcp_receive => 'R',
        else => 'T',
    };
    return .{ .letter = letter, .target = at, .current = live and connection.incarnation == incarnation };
}

/// A request connection's send or receive, and over TCP its connect: current while its opening is
/// the slot's, and has its socket, or over TCP connects, as a connect's is (request rule 14).
fn request_token(set: anytype, kind: io.Kind, index: usize) Token {
    const server = index & io.constants.quic_server_mask;
    const incarnation: u32 = @truncate(index >> io.constants.quic_incarnation_shift);
    const connection = &set.connections[server];
    const opening = connection.incarnation == incarnation;
    return switch (kind) {
        .h2_connect => .{ .letter = 'N', .target = server, .current = opening and connection.state == .connecting },
        .quic_send, .h2_send => .{ .letter = 'Q', .target = server, .current = opening and connection.talks() },
        else => .{ .letter = 'V', .target = server, .current = opening and connection.talks() },
    };
}

/// A channel's link's connect, send or receive: current while its opening is the link's, and has
/// what the operation needs of it: a connect while it connects, a send while it talks, a receive
/// while it runs (docs/design.md §24, rule 19).
fn link_token(world: anytype, kind: io.Kind, index: usize) Token {
    // Only an engine that carries DoH over channels submits these.
    if (comptime !@TypeOf(world.engine).Doh.enabled) unreachable;
    const target = index & io.constants.quic_server_mask;
    const incarnation: u32 = @truncate(index >> io.constants.quic_incarnation_shift);
    const link = &world.engine.doh.slots[target / 2].links[target % 2];
    const opening = link.incarnation == incarnation;
    return switch (kind) {
        .doh_connect => .{ .letter = 'A', .target = target, .current = opening and link.state == .connecting },
        .doh_send => .{ .letter = 'W', .target = target, .current = opening and link.talks() },
        else => .{ .letter = 'Y', .target = target, .current = opening and link.state == .running },
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
    tickets(line, world);
}

/// Over TLS or DoQ, whether each server keeps a ticket for its next connection.
fn tickets(line: *Line, world: anytype) void {
    const engine = &world.engine;
    if (!world.config.uses_tls() and !world.config.sends_requests()) return;
    line.print(" tk[", .{});
    for (0..world.config.servers.len) |server| {
        if (server > 0) line.print(",", .{});
        const kept = if (world.config.uses_tls())
            engine.tls_tickets[server] != null
        else if (world.config.uses_https())
            engine.h2.tickets[server] != null
        else
            engine.quic.tickets[server] != null;
        line.print("{d}", .{@intFromBool(kept)});
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
