//! The engine's DoH over a channel on the twin (docs/design.md §24, DoH over colibri's client,
//! request rules 18 to 25): a channel opened for a server's first request, its exchanges' ends
//! heard, a template the engine cannot read, a request that waits for room, a cancelled one, the
//! channel read when a request is put on it, and the channel's shutdown. The links' tests are
//! `io_channel_link_test.zig`'s. The channel is the twin's (`rotor.channel`), which says exactly
//! the steps a test queues; what only colibri's channel can show is colibri's (`cocuyo_doh`).
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const question = sim_test.question;

/// An engine that carries DoH over the twin's channel, and keeps no TCP connection of its own: a
/// channel's TCP link is the channel's.
pub const Resolver = io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = 0,
    .doh = rotor.channel.Channel,
});
pub const Rig = sim_test.RigOf(Resolver);
pub const Step = rotor.channel.Step;

/// A DoH server's template, on HTTPS's port (RFC 9110 §4.2.2).
const template = "https://dns.example/dns-query{?dns}";

/// A rig whose servers speak DoH through the twin's channel, their scripts as `scripts` say.
pub fn start(rig: *Rig, seed: u64, scripts: [fixtures.servers]rotor.server.Script) !void {
    for (&rig.servers) |*server| server.https = .{ .template = template };
    try rig.init(seed, scripts, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
    rig.use_test_contexts();
}

pub fn channel_of(rig: *Rig, server: u8) *rotor.channel.Channel {
    return &rig.engine.doh.slots[server].channel;
}

/// Has server `server`'s channel say `step` at the engine's next read, and lets that read come: the
/// channel is due at once, so the engine's timer fires for it.
pub fn tell(rig: *Rig, server: u8, step: Step) !void {
    channel_of(rig, server).say(step, rig.loop.now());
    rig.engine.drive(rig.loop.now());
    _ = try rig.step(fixtures.channel_read_ns);
}

/// One lookup of `name`, answered on server `server`'s channel, and its result taken.
pub fn answer(rig: *Rig, server: u8, name: []const u8) !void {
    const handle = try rig.engine.start(question(name), rig.loop.now());
    try tell(rig, server, .{ .finished = .{ .index = handle.index, .answer = true } });
    const result = try rig.until_result();
    try testing.expect(result.outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
}

test "a DoH lookup opens its server's channel with its request, and no link until the channel says" {
    var rig: Rig = .{};
    try start(&rig, 91, .{ .{}, .{} });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    const slot = &rig.engine.doh.slots[0];
    try testing.expect(slot.state == .open);
    try testing.expectEqual(@as(u16, 1), slot.exchanges);
    try testing.expect(channel_of(&rig, 0).holds(handle.index));
    try testing.expect(slot.links[0].state == .down and slot.links[1].state == .down);
    try tell(&rig, 0, .{ .open = .quic });
    try testing.expect(slot.links[0].state == .running);
    try testing.expect(slot.links[0].receive != null);
    try testing.expect(channel_of(&rig, 0).running[0]);
    try testing.expect(slot.links[1].state == .down);
    rig.engine.cancel(handle, rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "an exchange's answer goes to its lookup" {
    var rig: Rig = .{};
    try start(&rig, 92, .{ .{}, .{} });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    try tell(&rig, 0, .{ .open = .quic });
    try tell(&rig, 0, .{ .finished = .{ .index = handle.index, .answer = true } });
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u16, 0), rig.engine.doh.slots[0].exchanges);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "an exchange that fails fails its request once, as the server's failure, and the next server answers" {
    // Any end but a response carrying a DNS message fails the request (rule 22), and decision 25
    // counts it as the server's failure.
    var rig: Rig = .{};
    try start(&rig, 93, .{ .{}, .{} });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    try tell(&rig, 0, .{ .finished = .{ .index = handle.index, .answer = false } });
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    try testing.expect(channel_of(&rig, 1).holds(handle.index));
    try tell(&rig, 1, .{ .finished = .{ .index = handle.index, .answer = true } });
    const result = try rig.until_result();
    try testing.expect(result.outcome == .answer);
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(1));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a lookup whose every exchange failed ends in AllServersFailed, its cause the channel's reason" {
    // The channel says why each exchange failed, and the lookup keeps the last reason with its
    // server (docs/design.md §5, The cause of a failure).
    for ([_]cocuyo.Reason{ .status, .reset, .closed }, 0..) |reason, at| {
        var rig: Rig = .{};
        try start(&rig, 115 + at, .{ .{}, .{} });
        const handle = try rig.engine.start(question("example.com."), rig.loop.now());
        for (0..rig.config.attempts) |_| {
            for (0..fixtures.servers) |server| {
                try tell(&rig, @intCast(server), .{ .finished = .{ .index = handle.index, .answer = false, .reason = reason } });
            }
        }
        const result = try rig.until_result();
        try testing.expectEqual(cocuyo.Error.AllServersFailed, result.outcome.failure.err);
        try testing.expectEqual(@as(?cocuyo.Cause, .{ .server_index = 1, .what = .{ .reason = reason } }), result.outcome.failure.cause);
        _ = rig.engine.take(rig.loop.now());
        try rig.deinit();
    }
}

test "a template the engine cannot read fails its server before its channel opens" {
    // DoH "MUST be used with the https URI scheme" (RFC 8484 §5): the channel cannot start, the
    // request fails as the server's failure (request rule 7), and the next server answers.
    var rig: Rig = .{};
    rig.servers[0].https = .{ .template = "http://dns.example/dns-query{?dns}" };
    rig.servers[1].https = .{ .template = template };
    try rig.init(88, .{ .{}, .{} }, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
    rig.use_test_contexts();
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    try testing.expect(rig.engine.doh.slots[0].state == .closed);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    // No server took part (docs/design.md §5, The cause of a failure).
    const cause = rig.engine.resolver.lookup_of(handle).cause.get();
    try testing.expectEqual(@as(?cocuyo.Cause, .{ .server_index = 0, .what = .{ .reason = .local } }), cause);
    try testing.expect(channel_of(&rig, 1).holds(handle.index));
    try tell(&rig, 1, .{ .finished = .{ .index = handle.index, .answer = true } });
    const result = try rig.until_result();
    try testing.expect(result.outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a request its lookup left is cancelled on its channel, whose memory is the engine's again" {
    // Request rule 6: the drive cancels a request its lookup left, and the exchange's end tells
    // nobody.
    var rig: Rig = .{};
    try start(&rig, 94, .{ .{}, .{} });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    try testing.expect(channel_of(&rig, 0).holds(handle.index));
    rig.engine.cancel(handle, rig.loop.now());
    try testing.expect(!channel_of(&rig, 0).holds(handle.index));
    try testing.expectEqual(@as(u16, 0), rig.engine.doh.slots[0].users());
    const result = try rig.until_result();
    try testing.expectEqual(cocuyo.Error.Canceled, result.outcome.failure.err);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a request waits for room on its channel, and becomes an exchange once one ends" {
    // Rule 21: the channel holds as many exchanges as it has room for, and the rest wait.
    var rig: Rig = .{};
    try start(&rig, 95, .{ .{}, .{} });
    channel_of(&rig, 0).limit = 1;
    const first = try rig.engine.start(question("one.example."), rig.loop.now());
    const second = try rig.engine.start(question("two.example."), rig.loop.now());
    const slot = &rig.engine.doh.slots[0];
    try testing.expectEqual(@as(u16, 1), slot.exchanges);
    try testing.expectEqual(@as(u16, 1), slot.queue_len);
    try testing.expect(!channel_of(&rig, 0).holds(second.index));
    try tell(&rig, 0, .{ .finished = .{ .index = first.index, .answer = true } });
    try testing.expect(channel_of(&rig, 0).holds(second.index));
    try testing.expectEqual(@as(u16, 0), slot.queue_len);
    try tell(&rig, 0, .{ .finished = .{ .index = second.index, .answer = true } });
    for (0..2) |_| {
        const result = try rig.until_result();
        try testing.expect(result.outcome == .answer);
    }
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a request put on its channel has the channel read, which tells then what it held" {
    // Request rule 17: the engine reads a channel after each call that moves it, and putting a
    // request on it is one. The channel holds an end, and no step, send or instant brings a read.
    var rig: Rig = .{};
    try start(&rig, 97, .{ .{}, .{} });
    const first = try rig.engine.start(question("one.example."), rig.loop.now());
    try tell(&rig, 0, .{ .hold = .{ .index = first.index, .answer = true } });
    const channel = channel_of(&rig, 0);
    try testing.expect(channel.held != null);
    const second = try rig.engine.start(question("two.example."), rig.loop.now());
    try testing.expect(channel.held == null);
    const result = try rig.until_result();
    try testing.expectEqual(first, result.handle);
    try testing.expect(result.outcome == .answer);
    rig.engine.cancel(second, rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

/// Lets the idle close run: the clock moves past the set's `idle_ns` with nothing due, twice, so the
/// timer the last lookup left is gone as well.
fn idle(rig: *Rig) !void {
    _ = try rig.step(fixtures.tcp_idle_jump_ns);
    _ = try rig.step(fixtures.tcp_idle_jump_ns);
    rig.engine.drive(rig.loop.now());
}

test "an idle channel shuts down, a request taken meanwhile waits, and the next channel takes it" {
    // Rule 24: a channel with no request on it for the set's idle time shuts down, and says closed
    // once every link is closed; what waited opens the next.
    var rig: Rig = .{};
    try start(&rig, 96, .{ .{}, .{} });
    try answer(&rig, 0, "one.example.");
    try idle(&rig);
    const slot = &rig.engine.doh.slots[0];
    try testing.expect(slot.state == .shutting);
    try testing.expect(channel_of(&rig, 0).shut);
    const handle = try rig.engine.start(question("two.example."), rig.loop.now());
    try testing.expectEqual(@as(u16, 1), slot.queue_len);
    try testing.expectEqual(@as(u16, 0), slot.exchanges);
    try tell(&rig, 0, .closed);
    try testing.expect(slot.state == .open);
    try testing.expect(channel_of(&rig, 0).holds(handle.index));
    try tell(&rig, 0, .{ .finished = .{ .index = handle.index, .answer = true } });
    const result = try rig.until_result();
    try testing.expect(result.outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a channel that cannot open again for the request that waited gives local as the cause" {
    // The channel said closed with a request waiting, and the next cannot start: the template
    // changed to one the engine cannot read (RFC 8484 §5). No server took part (docs/design.md §5,
    // The cause of a failure).
    var rig: Rig = .{};
    try start(&rig, 97, .{ .{}, .{} });
    try answer(&rig, 0, "one.example.");
    try idle(&rig);
    const handle = try rig.engine.start(question("two.example."), rig.loop.now());
    rig.servers[0].https = .{ .template = "http://dns.example/dns-query{?dns}" };
    try tell(&rig, 0, .closed);
    try testing.expect(rig.engine.doh.slots[0].state == .closed);
    const cause = rig.engine.resolver.lookup_of(handle).cause.get();
    try testing.expectEqual(@as(?cocuyo.Cause, .{ .server_index = 0, .what = .{ .reason = .local } }), cause);
    try testing.expect(channel_of(&rig, 1).holds(handle.index));
    try tell(&rig, 1, .{ .finished = .{ .index = handle.index, .answer = true } });
    try testing.expect((try rig.until_result()).outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

/// The twin's channel, which says `flood` tickets of its own before anything the twin says, as a
/// channel whose server sends a flood of them would.
const Flooding = struct {
    const Twin = rotor.channel.Channel;
    pub const enabled = true;
    pub const output_bytes_max = Twin.output_bytes_max;
    pub const Error = Twin.Error;
    pub const Context = Twin.Context;
    pub const Ticket = Twin.Ticket;
    pub const Alternative = Twin.Alternative;
    pub const Link = Twin.Link;
    pub const Answer = Twin.Answer;
    pub const Finished = Twin.Finished;
    pub const Open = Twin.Open;
    pub const Event = Twin.Event;
    pub const Input = Twin.Input;

    twin: Twin = .{},
    flood: usize = 0,
    said: usize = 0,

    pub fn start(self: *Flooding, context: anytype) Error!void {
        return self.twin.start(context);
    }
    pub fn lifetime_ns(ticket: *const Ticket) u64 {
        return Twin.lifetime_ns(ticket);
    }
    pub fn request(self: *Flooding, index: u16, message: []const u8, now_ns: u64) bool {
        return self.twin.request(index, message, now_ns);
    }
    pub fn cancel(self: *Flooding, index: u16) void {
        self.twin.cancel(index);
    }
    pub fn shutdown(self: *Flooding) void {
        self.twin.shutdown();
    }
    pub fn receive(self: *Flooding, input: Input, now_ns: u64) void {
        self.twin.receive(input, now_ns);
    }
    pub fn next(self: *Flooding, now_ns: u64) ?Event {
        if (self.flood == 0) return self.twin.next(now_ns);
        self.flood -= 1;
        self.said += 1;
        return .{ .ticket = .quic };
    }
    pub fn datagram(self: *Flooding, out: []u8, now_ns: u64) usize {
        return self.twin.datagram(out, now_ns);
    }
    pub fn output(self: *Flooding, out: []u8, now_ns: u64) usize {
        return self.twin.output(out, now_ns);
    }
    pub fn deadline(self: *const Flooding) ?u64 {
        return self.twin.deadline();
    }
    pub fn expire(self: *Flooding, now_ns: u64) void {
        self.twin.expire(now_ns);
    }
    pub fn start_link(self: *Flooding, link: Link, ticket: ?*const Ticket, ticket_age_ns: u64, now_ns: u64) Error!void {
        return self.twin.start_link(link, ticket, ticket_age_ns, now_ns);
    }
    pub fn link_ended(self: *Flooding, link: Link) void {
        self.twin.link_ended(link);
    }
    pub fn take_ticket(self: *Flooding, link: Link) ?Ticket {
        return self.twin.take_ticket(link);
    }
    pub fn alternative(self: *const Flooding) ?Alternative {
        return self.twin.alternative();
    }
    pub fn wipe(self: *Flooding) void {
        self.twin.wipe();
    }
};

const FloodingRig = sim_test.RigOf(io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = 0,
    .doh = Flooding,
}));

test "one read of a channel takes an end for each request and 16 of its own, and the rest at the next" {
    // `channel_events_max`: what a flood leaves is read at the next read (docs/design.md §24, New
    // limits). Here the channel says one ticket more than one read takes.
    var rig: FloodingRig = .{};
    for (&rig.servers) |*server| server.https = .{ .template = template };
    try rig.init(98, .{ .{}, .{} }, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
    rig.use_test_contexts();
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    const channel = &rig.engine.doh.slots[0].channel;
    const per_read = rig.engine.requests.len + io.constants.channel_events_max;
    channel.flood = per_read + 1;
    io.channel.hear(&rig.engine, 0, rig.loop.now());
    try testing.expectEqual(per_read, channel.said);
    io.channel.hear(&rig.engine, 0, rig.loop.now());
    try testing.expectEqual(per_read + 1, channel.said);
    rig.engine.cancel(handle, rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}
