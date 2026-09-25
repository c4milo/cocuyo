//! The twin driven the way the engine will drive it: a datagram to a scripted server and its
//! answer back, a timer, a cancel, a query over a stream in chunks, and the same seed twice.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const wire = @import("wire");
const sim = @import("sim.zig");
const constants = @import("constants.zig");
const Loop = sim.Loop;
const Event = sim.Event;
const Operation = sim.Operation;

const fixtures = @import("fixtures.zig");
const options: Loop.Options = .{ .operations = fixtures.operations };
const group_id = fixtures.group_id;
const group_buffers = fixtures.group_buffers;
const buffer_bytes = fixtures.buffer_bytes;
const group: sim.datagram.GroupOptions = .{};
const receive_tag = fixtures.receive_tag;
const send_tag = fixtures.send_tag;
const timer_tag = fixtures.timer_tag;
const connect_tag = fixtures.connect_tag;
const filler_tag = fixtures.filler_tag;

/// One loop with one group provided and one scripted server, in a struct so a test holds it.
const Rig = struct {
    loop: Loop = undefined,
    memory: [0]u8 align(constants.memory_alignment) = undefined,
    group_memory: [sim.buffers.group_bytes(group_buffers, buffer_bytes)]u8 align(sim.buffers.group_alignment) = undefined,
    query: [core.constants.query_bytes_max]u8 = undefined,
    query_len: usize = 0,
    outbound: sim.datagram.Outbound = undefined,

    fn init(rig: *Rig, seed: u64, script: sim.server.Script) !void {
        try rig.loop.init(&rig.memory, options);
        rig.loop.seed(seed);
        rig.loop.network().scripts[0] = script;
        rig.loop.network().server_count = 1;
        try rig.loop.provide_datagram_buffers(group_id, &rig.group_memory, group_buffers, buffer_bytes, group);
        var query: wire.Query = .{ .id = fixtures.query_id, .name = try core.Name.from_text("example.com"), .kind = .a, .tcp = false };
        rig.query_len = wire.query.write(&query, &rig.query);
        rig.outbound = .{
            .peer = sim.Network.server_address(0),
            .local = undefined,
            .segment_bytes = 0,
            .ecn = .not_ect,
            .flags = .{ .peer = true },
        };
    }

    fn collect(rig: *Rig, events: []Event, wait_ns: u64) !u32 {
        return try rig.loop.tick(events, wait_ns);
    }
};

fn receive_from(socket: sim.Descriptor) Operation {
    return .{ .user_data = receive_tag, .kind = .{ .receive_from = .{ .socket = socket, .group = group_id } } };
}

fn send_to(rig: *const Rig, socket: sim.Descriptor) Operation {
    return .{ .user_data = send_tag, .kind = .{ .send_to = .{
        .socket = socket,
        .buffer = .{ .bytes = rig.query[0..rig.query_len] },
        .to = &rig.outbound,
    } } };
}

test "a datagram to a scripted server comes back on the socket's receive, after the delay" {
    var rig: Rig = .{};
    try rig.init(1, .{ .delay_ns_min = 1000, .delay_ns_max = 1000 });
    const socket = try sim.sync.open_datagram(.ipv4, null, .{});
    defer sim.sync.close_now(socket);
    var handles: [1]sim.Handle = undefined;
    try testing.expectEqual(@as(u32, 1), rig.loop.submit(&.{receive_from(socket)}, &handles));
    try testing.expectEqual(@as(u32, 1), rig.loop.submit(&.{send_to(&rig, socket)}, &.{}));
    var events: [4]Event = undefined;
    try testing.expectEqual(@as(u32, 1), try rig.collect(&events, 0));
    try testing.expectEqual(@as(u64, send_tag), events[0].user_data);
    try testing.expectEqual(@as(u32, @intCast(rig.query_len)), try events[0].outcome());
    try testing.expectEqual(@as(u64, 0), rig.loop.now());
    try testing.expectEqual(@as(u32, 1), try rig.collect(&events, 10_000));
    try testing.expectEqual(@as(u64, 1000), rig.loop.now());
    try testing.expectEqual(@as(u64, receive_tag), events[0].user_data);
    try testing.expect(events[0].flags.buffer and events[0].flags.more);
    const delivery = rig.loop.datagram(group_id, events[0]);
    try testing.expect(delivery.from.peer.equal(&rig.outbound.peer));
    try testing.expectEqual(@as(u16, fixtures.query_id), (try wire.header.parse(delivery.bytes)).id);
    rig.loop.give_back_buffer(group_id, events[0].flags.buffer_id);
    rig.loop.cancel(handles[0]);
    try rig.loop.drain(&events);
    try testing.expectEqual(@as(u32, 0), rig.loop.in_flight());
    rig.loop.deinit();
}

/// A responder that echoes each datagram after `echo_delay_ns`, and counts the datagrams it heard
/// and the times it was woken at its one deadline.
const Echo = struct {
    network: *sim.Network,
    due_ns: ?u64 = fixtures.echo_deadline_ns,
    heard: usize = 0,
    woken: usize = 0,

    fn responder(echo: *Echo) sim.Responder {
        return .{ .context = echo, .hear = hear, .deadline = deadline, .expire = expire };
    }

    fn hear(context: *anyopaque, socket: sim.Descriptor, bytes: []const u8, now_ns: u64) void {
        const echo: *Echo = @ptrCast(@alignCast(context));
        echo.heard += 1;
        _ = echo.network.reply(socket, 0, bytes, now_ns + fixtures.echo_delay_ns);
    }

    fn deadline(context: *anyopaque) ?u64 {
        const echo: *Echo = @ptrCast(@alignCast(context));
        return echo.due_ns;
    }

    fn expire(context: *anyopaque, now_ns: u64) void {
        const echo: *Echo = @ptrCast(@alignCast(context));
        std.debug.assert(now_ns >= echo.due_ns.?);
        echo.woken += 1;
        echo.due_ns = null;
    }
};

test "a responder on a QUIC port hears what is sent there, answers, and is woken at its deadline" {
    var rig: Rig = .{};
    try rig.init(7, .{});
    var echo: Echo = .{ .network = rig.loop.network() };
    rig.loop.network().responders[0] = echo.responder();
    rig.outbound.peer = sim.Network.server_quic_address(0);
    const socket = try sim.sync.open_datagram(.ipv4, null, .{});
    defer sim.sync.close_now(socket);
    var handles: [1]sim.Handle = undefined;
    _ = rig.loop.submit(&.{receive_from(socket)}, &handles);
    _ = rig.loop.submit(&.{send_to(&rig, socket)}, &.{});
    var events: [4]Event = undefined;
    try testing.expectEqual(@as(u32, 1), try rig.collect(&events, 0));
    try testing.expectEqual(@as(usize, 1), echo.heard);
    // The deadline comes first, and nothing is delivered at it.
    try testing.expectEqual(@as(u32, 0), try rig.collect(&events, 10_000));
    try testing.expectEqual(@as(u64, fixtures.echo_deadline_ns), rig.loop.now());
    try testing.expectEqual(@as(usize, 1), echo.woken);
    try testing.expectEqual(@as(u32, 1), try rig.collect(&events, 10_000));
    try testing.expectEqual(@as(u64, fixtures.echo_delay_ns), rig.loop.now());
    const delivery = rig.loop.datagram(group_id, events[0]);
    try testing.expect(delivery.from.peer.equal(&rig.outbound.peer));
    try testing.expectEqualSlices(u8, rig.query[0..rig.query_len], delivery.bytes);
    rig.loop.give_back_buffer(group_id, events[0].flags.buffer_id);
    rig.loop.cancel(handles[0]);
    try rig.loop.drain(&events);
    rig.loop.deinit();
}

test "a timer fires at its instant and not before, and a wait with nothing due moves the clock" {
    var rig: Rig = .{};
    try rig.init(1, .{});
    const timer: Operation = .{ .user_data = timer_tag, .kind = .{ .timer = .{ .after_ns = 5000 } } };
    try testing.expectEqual(@as(u32, 1), rig.loop.submit(&.{timer}, &.{}));
    var events: [2]Event = undefined;
    try testing.expectEqual(@as(u32, 0), try rig.collect(&events, 1000));
    try testing.expectEqual(@as(u64, 1000), rig.loop.now());
    try testing.expectEqual(@as(u32, 1), try rig.collect(&events, 100_000));
    try testing.expectEqual(@as(u64, 5000), rig.loop.now());
    try testing.expectEqual(@as(u64, timer_tag), events[0].user_data);
    try testing.expectEqual(@as(u32, 0), rig.loop.in_flight());
    try testing.expectEqual(@as(u32, 0), try rig.collect(&events, 1000));
    try testing.expectEqual(@as(u64, 6000), rig.loop.now());
    rig.loop.deinit();
}

test "a timer cancelled before it fires ends with Canceled now, and one that fired is left to deliver" {
    var rig: Rig = .{};
    try rig.init(1, .{});
    const timer: Operation = .{ .user_data = timer_tag, .kind = .{ .timer = .{ .after_ns = 5000 } } };
    var handles: [1]sim.Handle = undefined;
    var events: [2]Event = undefined;
    _ = rig.loop.submit(&.{timer}, &handles);
    _ = try rig.collect(&events, 1000);
    rig.loop.cancel(handles[0]);
    try testing.expectEqual(@as(u32, 1), try rig.collect(&events, 100_000));
    try testing.expectEqual(@as(u64, 1000), rig.loop.now());
    try testing.expectError(error.Canceled, events[0].outcome());
    try testing.expectEqual(@as(u32, 0), rig.loop.in_flight());
    // Fired and not yet delivered: a filler due at the same instant and queued first takes the one
    // event the tick has room for, so the timer's fire waits in the loop. (An empty `events` did
    // it in one call, and rotor halts on that since 0.4.0.) The cancel finds nothing, and the fire
    // is the final event.
    const filler: Operation = .{ .user_data = filler_tag, .kind = .{ .timer = .{ .after_ns = 5000 } } };
    var both: [2]sim.Handle = undefined;
    _ = rig.loop.submit(&.{ filler, timer }, &both);
    try testing.expectEqual(@as(u32, 1), try rig.collect(events[0..1], 100_000));
    try testing.expectEqual(@as(u64, filler_tag), events[0].user_data);
    try testing.expectEqual(@as(u64, 6000), rig.loop.now());
    rig.loop.cancel(both[1]);
    try testing.expectEqual(@as(u32, 1), try rig.collect(&events, 100_000));
    try testing.expectEqual(@as(u64, timer_tag), events[0].user_data);
    try testing.expectEqual(@as(u32, 0), try events[0].outcome());
    try testing.expectEqual(@as(u32, 0), rig.loop.in_flight());
    rig.loop.deinit();
}

test "cancel ends a receive with Canceled and delivers nothing after it" {
    var rig: Rig = .{};
    try rig.init(1, .{ .delay_ns_min = 100, .delay_ns_max = 100 });
    const socket = try sim.sync.open_datagram(.ipv4, null, .{});
    defer sim.sync.close_now(socket);
    var handles: [1]sim.Handle = undefined;
    _ = rig.loop.submit(&.{receive_from(socket)}, &handles);
    _ = rig.loop.submit(&.{send_to(&rig, socket)}, &.{});
    var events: [4]Event = undefined;
    _ = try rig.collect(&events, 0);
    rig.loop.cancel(handles[0]);
    const count = try rig.collect(&events, 1000);
    try testing.expectEqual(@as(u32, 1), count);
    try testing.expectError(error.Canceled, events[0].outcome());
    try testing.expectEqual(@as(u32, 0), rig.loop.in_flight());
    try testing.expectEqual(@as(u32, 0), try rig.collect(&events, 1000));
    rig.loop.deinit();
}

test "a query over a stream is answered in framed chunks the seed sizes" {
    var rig: Rig = .{};
    try rig.init(7, .{ .delay_ns_min = 10, .delay_ns_max = 10 });
    const socket = try sim.sync.open_socket(.ipv4);
    defer sim.sync.close_now(socket);
    const address = sim.Network.server_address(0);
    const connect: Operation = .{ .user_data = connect_tag, .kind = .{ .connect = .{ .socket = socket, .address = &address } } };
    _ = rig.loop.submit(&.{connect}, &.{});
    var events: [4]Event = undefined;
    try testing.expectEqual(@as(u32, 1), try rig.collect(&events, 1000));
    try testing.expectEqual(@as(u32, 0), try events[0].outcome());
    var framed: [core.constants.query_bytes_max]u8 = undefined;
    var query: wire.Query = .{ .id = fixtures.stream_query_id, .name = try core.Name.from_text("example.com"), .kind = .a, .tcp = true };
    const framed_len = wire.query.write(&query, &framed);
    var handles: [1]sim.Handle = undefined;
    const receive: Operation = .{ .user_data = receive_tag, .kind = .{ .receive = .{ .socket = socket, .target = .{ .group = group_id }, .multishot = true } } };
    _ = rig.loop.submit(&.{receive}, &handles);
    const send: Operation = .{ .user_data = send_tag, .kind = .{ .send = .{ .socket = socket, .buffer = .{ .bytes = framed[0..framed_len] } } } };
    _ = rig.loop.submit(&.{send}, &.{});
    const prefix = core.constants.tcp_prefix_bytes;
    var assembled: [512]u8 = undefined;
    var assembled_len: usize = 0;
    var chunks: usize = 0;
    var rounds: usize = 0;
    while (rounds < 32) : (rounds += 1) {
        const count = try rig.collect(&events, 1000);
        for (events[0..count]) |event| {
            if (event.user_data != receive_tag) continue;
            const chunk = try event.outcome();
            const buffer = rig.loop.provided_buffer(group_id, event.flags.buffer_id);
            @memcpy(assembled[assembled_len..][0..chunk], buffer[0..chunk]);
            assembled_len += chunk;
            chunks += 1;
            rig.loop.give_back_buffer(group_id, event.flags.buffer_id);
        }
        if (assembled_len >= prefix and assembled_len >= prefix + @as(usize, wire.message_len(assembled[0..prefix]))) break;
    }
    const reply_len = wire.message_len(assembled[0..prefix]);
    try testing.expectEqual(assembled_len, prefix + @as(usize, reply_len));
    try testing.expectEqual(@as(u16, fixtures.stream_query_id), (try wire.header.parse(assembled[prefix..][0..reply_len])).id);
    try testing.expect(chunks >= 1);
    rig.loop.cancel(handles[0]);
    try rig.loop.drain(&events);
    rig.loop.deinit();
}

test "a server that is down answers nothing, and a connection to it is refused" {
    var rig: Rig = .{};
    try rig.init(1, .{ .down = true });
    const socket = try sim.sync.open_datagram(.ipv4, null, .{});
    defer sim.sync.close_now(socket);
    var handles: [1]sim.Handle = undefined;
    _ = rig.loop.submit(&.{receive_from(socket)}, &handles);
    _ = rig.loop.submit(&.{send_to(&rig, socket)}, &.{});
    var events: [4]Event = undefined;
    _ = try rig.collect(&events, 0);
    try testing.expectEqual(@as(u32, 0), try rig.collect(&events, 1_000_000));
    try testing.expectEqual(@as(u64, 1_000_000), rig.loop.now());
    const stream = try sim.sync.open_socket(.ipv4);
    defer sim.sync.close_now(stream);
    const address = sim.Network.server_address(0);
    const connect: Operation = .{ .user_data = connect_tag, .kind = .{ .connect = .{ .socket = stream, .address = &address } } };
    _ = rig.loop.submit(&.{connect}, &.{});
    try testing.expectEqual(@as(u32, 1), try rig.collect(&events, 1_000_000_000));
    try testing.expectError(error.ConnectionRefused, events[0].outcome());
    rig.loop.cancel(handles[0]);
    try rig.loop.drain(&events);
    rig.loop.deinit();
}

fn trace_of(seed: u64) !u64 {
    var rig: Rig = .{};
    try rig.init(seed, .{
        .delay_ns_min = fixtures.trace_delay_ns_min,
        .delay_ns_max = fixtures.trace_delay_ns_max,
        .drop_per_256 = fixtures.trace_drop_per_256,
    });
    const socket = try sim.sync.open_datagram(.ipv4, null, .{});
    defer sim.sync.close_now(socket);
    var handles: [1]sim.Handle = undefined;
    _ = rig.loop.submit(&.{receive_from(socket)}, &handles);
    var trace: u64 = seed;
    var sends: usize = 0;
    while (sends < fixtures.trace_sends) : (sends += 1) {
        _ = rig.loop.submit(&.{send_to(&rig, socket)}, &.{});
        var events: [fixtures.group_buffers]Event = undefined;
        const count = try rig.collect(&events, fixtures.trace_wait_ns);
        for (events[0..count]) |event| {
            trace = core.mix.next(trace ^ event.user_data ^ @as(u64, @bitCast(@as(i64, event.result))) ^ rig.loop.now());
            if (event.flags.buffer) rig.loop.give_back_buffer(group_id, event.flags.buffer_id);
        }
    }
    rig.loop.cancel(handles[0]);
    var events: [fixtures.group_buffers]Event = undefined;
    try rig.loop.drain(&events);
    rig.loop.deinit();
    return trace;
}

test "one seed gives one trace, twice over, and another seed another" {
    try testing.expectEqual(try trace_of(11), try trace_of(11));
    try testing.expect(try trace_of(11) != try trace_of(12));
}

test "a buffer is taken when its datagram is due and not before, and a group run dry ends the receive" {
    var rig: Rig = .{};
    try rig.init(3, .{ .delay_ns_min = 1000, .delay_ns_max = 1000 });
    const socket = try sim.sync.open_datagram(.ipv4, null, .{});
    defer sim.sync.close_now(socket);
    var handles: [1]sim.Handle = undefined;
    _ = rig.loop.submit(&.{receive_from(socket)}, &handles);
    var sends: usize = 0;
    while (sends < group_buffers + 1) : (sends += 1) _ = rig.loop.submit(&.{send_to(&rig, socket)}, &.{});
    var events: [group_buffers + 2]Event = undefined;
    _ = try rig.collect(&events, 0);
    try testing.expectEqual(@as(u16, group_buffers), rig.loop.groups[group_id].free_count);
    // At the due instant every buffer is taken by a delivery, and the fifth datagram ends the
    // receive with the group dry.
    const count = try rig.collect(&events, 10_000);
    try testing.expectEqual(@as(u16, 0), rig.loop.groups[group_id].free_count);
    var deliveries: usize = 0;
    var dry = false;
    for (events[0..count]) |event| {
        if (event.flags.buffer) deliveries += 1;
        if (event.outcome()) |_| {} else |err| {
            if (err == error.BuffersExhausted) dry = true;
        }
    }
    try testing.expectEqual(@as(usize, group_buffers), deliveries);
    try testing.expect(dry);
    try testing.expectEqual(@as(u32, 0), rig.loop.in_flight());
    rig.loop.deinit();
}
