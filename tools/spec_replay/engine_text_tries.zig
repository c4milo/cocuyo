//! A slot's open tries as the engine's walks write them (spec/tla/engine/EngineTrace.tla,
//! `TriesToken`; docs/design.md §16 decision 66). Split from `engine_text.zig` by the file-length
//! rule.
const std = @import("std");
const cocuyo = @import("cocuyo");

/// Which transports each position holds an open try over: a datagram, a stream, a request.
const Opens = [cocuyo.limits.servers_max][3]bool;

/// What a slot keeps for its lookup's open tries (EngineTrace.tla, `TriesToken`): ` t` and the
/// tries, each as its position and its transport's letter, ` k` and the connections the lookup
/// stays on, ` f` and the sockets its datagram tries went out from. None is written for none.
pub fn write(line: anytype, world: anytype, index: usize) void {
    var opens: Opens = @splat(@splat(false));
    const any = opens_of(world, index, &opens);
    var conns: [cocuyo.limits.servers_max]usize = undefined;
    const kept = kept_conns(world, index, &conns);
    if (!any and kept.len == 0 and !keeps_sockets(world, index)) return;
    line.print(" t[", .{});
    write_opens(line, world, &opens);
    line.print("] k", .{});
    line.list(kept);
    line.print(" f[", .{});
    write_sockets(line, world, index);
    line.print("]", .{});
}

/// Fills `opens` from the lookup's open tries, none for one that ended. True when it holds one.
fn opens_of(world: anytype, index: usize, opens: *Opens) bool {
    const lookup = &world.engine.slots[index].lookup;
    if (lookup.is_settled()) return false;
    for (lookup.tries.slice()) |kept| {
        const kind: usize = if (kept.marks.stream) 1 else if (world.config.sends_requests()) 2 else 0;
        opens[kept.position][kind] = true;
    }
    return lookup.tries.count > 0;
}

/// The connections the slot's lookup stays on, least first.
fn kept_conns(world: anytype, index: usize, out: *[cocuyo.limits.servers_max]usize) []usize {
    var count: usize = 0;
    for (world.engine.kept.conns[index][0..world.config.servers.len]) |held| {
        const at = held orelse continue;
        out[count] = at;
        count += 1;
    }
    std.mem.sort(usize, out[0..count], {}, std.sort.asc(usize));
    return out[0..count];
}

fn keeps_sockets(world: anytype, index: usize) bool {
    for (0..world.config.servers.len) |server| {
        if (kept_from_age(world, index, @intCast(server)) != null) return true;
    }
    return false;
}

fn write_opens(line: anytype, world: anytype, opens: *const Opens) void {
    var first = true;
    for (opens[0..world.config.servers.len], 0..) |kinds, position| for (kinds, 0..) |held, kind| {
        if (!held) continue;
        if (!first) line.print(",", .{});
        first = false;
        line.print("{d}{c}", .{ position, "utr"[kind] });
    };
}

fn write_sockets(line: anytype, world: anytype, index: usize) void {
    var first = true;
    for (0..world.config.servers.len) |server| {
        const age = kept_from_age(world, index, @intCast(server)) orelse continue;
        if (!first) line.print(",", .{});
        first = false;
        line.print("{d}{c}", .{ server, age });
    }
}

/// The age of the socket the open datagram try of slot `index` at `server` went out from, as
/// `sent_from` writes one, or null when no such try is open.
fn kept_from_age(world: anytype, index: usize, server: u8) ?u8 {
    const engine = &world.engine;
    if (world.config.sends_requests() or world.config.streams_only()) return null;
    const epoch = engine.kept.epochs[index][server] orelse return null;
    if (engine.slots[index].lookup.earlier_try_at(server, .datagram) == null) return null;
    const sockets = &engine.sockets;
    const draining = &sockets.draining[server];
    if (sockets.items[server].epoch == epoch) return 'c';
    return if (draining.open and draining.epoch == epoch) 'd' else 'g';
}
