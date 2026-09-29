//! The twin's channel (docs/design.md §24, DoH over colibri's client): the calls the engine makes of
//! colibri's `client.Channel`, which says exactly the steps a test or the replay queues for it. A
//! step is said at the engine's next read of the channel, one a read, and a channel with a step
//! queued is due at once, so the engine's timer brings that read when nothing else does. The
//! replay spells the model's channel steps with them (spec/tla/engine/EngineChannel.tla,
//! `ChanStep`).
//!
//! Its links carry one item of the twin's QUIC that says nothing, an acknowledgement, so the
//! engine's sockets send and receive on the twin's network. What the twin cannot show is colibri's
//! and chapulin's to show: the choice between QUIC and TCP, HTTP/3, HTTP/2 and HTTP/1.1, and TLS.
//! The engine runs over colibri's channel for those.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");
const network_module = @import("sim_network.zig");
const server = @import("sim_server.zig");
const quic = @import("sim_quic.zig");
const stream = @import("sim_quic_stream.zig");

/// An exchange's end, as a step says it: an answer to the exchange's query, from the server's
/// script, or a failure.
pub const End = struct { index: u16, answer: bool };

/// What the channel says at a read, as a test or the replay queues it: open or close a link, owe
/// octets on one or give a ticket of its transport, end an exchange, hold an end until the next
/// read, or say it closed.
pub const Step = union(enum) {
    open: Channel.Link,
    close: Channel.Link,
    octets: Channel.Link,
    ticket: Channel.Link,
    finished: End,
    hold: End,
    closed,
};

pub const Channel = struct {
    pub const enabled = true;
    /// A channel's two links: QUIC over a datagram socket, TCP over a stream socket.
    pub const Link = enum(u1) { quic, tcp };
    const links = @typeInfo(Link).@"enum".fields.len;
    /// The most one call of `datagram` or `output` writes.
    pub const output_bytes_max = constants.channel_output_bytes_max;
    pub const Error = error{Failed};
    /// What the engine hands every channel it starts: nothing, for the twin.
    pub const Context = struct {};
    /// A ticket the server gave. The twin's carries nothing: it only has to be kept and spent.
    pub const Ticket = struct {};
    /// What the channel learned of the origin's HTTP/3: the twin learns nothing.
    pub const Alternative = struct {};
    pub const Answer = struct { message: []const u8, age_seconds: u32 };
    pub const Finished = struct { index: u16, answer: ?Answer };
    pub const Open = struct { link: Link, endpoint: core.Endpoint };
    pub const Event = union(enum) { open: Open, close: Link, ticket: Link, finished: Finished, closed };
    pub const Input = union(enum) { none, datagram: []const u8, stream: []const u8 };

    const Exchange = struct { live: bool = false, index: u16 = 0, len: u16 = 0, query: [core.constants.query_bytes_max]u8 = undefined };

    /// The server's index, and where its links go: its address, on the template's port.
    server: u8 = 0,
    endpoint: core.Endpoint = undefined,
    exchanges: [constants.channel_exchanges_max]Exchange = @splat(.{}),
    /// The steps queued, oldest first, and the instant the first was queued, when it is due.
    script: [constants.channel_steps_max]Step = undefined,
    script_len: usize = 0,
    due_ns: u64 = 0,
    /// An end a `hold` kept, told at the read after the one that brought it, and whether that read
    /// has ended (docs/design.md §24, request rule 17).
    held: ?End = null,
    held_told: bool = false,
    /// Each link: whether the channel asked for it and has not closed it or heard it ended, whether
    /// its connection runs, whether it owes octets, and whether a ticket of its transport waits for
    /// the engine to take it.
    asked: [links]bool = @splat(false),
    running: [links]bool = @splat(false),
    owes: [links]bool = @splat(false),
    tickets: [links]bool = @splat(false),
    /// For a test to read: whether a link started with a ticket the engine kept, the age the
    /// engine gave that ticket, and how many times the engine told the channel a link's socket
    /// ended.
    resumed: [links]bool = @splat(false),
    ticket_ages_ns: [links]u64 = @splat(0),
    ended_links: [links]u32 = @splat(0),
    shut: bool = false,
    answer: [constants.datagram_bytes_max]u8 = undefined,
    /// For a test: the exchanges the channel takes at once.
    limit: usize = constants.channel_exchanges_max,

    /// Makes a server's channel, with nothing opened (rule 18). What a test queued before it opened,
    /// the room it gave it, and what it reads of the links stay: a link the last channel closed
    /// stays the engine's until its socket shuts.
    pub fn start(self: *Channel, context: anytype) Error!void {
        self.* = .{
            .server = context.server,
            .endpoint = context.endpoint,
            .script = self.script,
            .script_len = self.script_len,
            .due_ns = self.due_ns,
            .resumed = self.resumed,
            .ticket_ages_ns = self.ticket_ages_ns,
            .ended_links = self.ended_links,
            .limit = self.limit,
        };
    }

    /// The twin's tickets never lapse on their own, so the engine's seven-day cap is what ends one.
    pub fn lifetime_ns(ticket: *const Ticket) u64 {
        _ = ticket;
        return std.math.maxInt(u64);
    }

    /// Takes slot `index`'s request as an exchange carrying `message`, or says it has no room, and
    /// the request waits (rule 21).
    pub fn request(self: *Channel, index: u16, message: []const u8, now_ns: u64) bool {
        _ = now_ns;
        assert(message.len <= core.constants.query_bytes_max);
        assert(self.exchange_of(index) == null);
        var held: usize = 0;
        for (&self.exchanges) |*exchange| held += @intFromBool(exchange.live);
        if (held >= self.limit) return false;
        const free = for (&self.exchanges) |*exchange| {
            if (!exchange.live) break exchange;
        } else return false;
        free.* = .{ .live = true, .index = index, .len = @intCast(message.len) };
        @memcpy(free.query[0..message.len], message);
        return true;
    }

    /// Ends slot `index`'s exchange, whose memory is the engine's again at once. What the channel
    /// held of it tells nobody, and goes with it.
    pub fn cancel(self: *Channel, index: u16) void {
        const exchange = self.exchange_of(index) orelse return;
        exchange.live = false;
        if (self.held) |held| {
            if (held.index == index) self.held = null;
        }
    }

    pub fn shutdown(self: *Channel) void {
        self.shut = true;
    }

    /// What a link read: the twin's channel says nothing of it, and its steps are what it says.
    pub fn receive(self: *Channel, input: Input, now_ns: u64) void {
        _ = self;
        _ = input;
        _ = now_ns;
    }

    /// What the channel says at this read, one thing at a time: what it held from the read before,
    /// then the steps queued. A step that says nothing to the engine, octets owed or an end held,
    /// is taken with the next.
    pub fn next(self: *Channel, now_ns: u64) ?Event {
        _ = now_ns;
        if (self.held) |held| {
            if (self.held_told) {
                self.held = null;
                self.held_told = false;
                if (self.ended(held)) |event| return event;
            }
        }
        for (0..constants.channel_steps_max) |_| {
            const step = self.pop() orelse break;
            if (self.said(step)) |event| return event;
        }
        // The read ends here: an end held at it is told at the next.
        if (self.held != null) self.held_told = true;
        return null;
    }

    /// What one step says, if anything.
    fn said(self: *Channel, step: Step) ?Event {
        switch (step) {
            .open => |link| {
                self.asked[@intFromEnum(link)] = true;
                return .{ .open = .{ .link = link, .endpoint = self.endpoint } };
            },
            .close => |link| {
                self.asked[@intFromEnum(link)] = false;
                self.running[@intFromEnum(link)] = false;
                self.owes[@intFromEnum(link)] = false;
                return .{ .close = link };
            },
            .octets => |link| self.owes[@intFromEnum(link)] = true,
            .ticket => |link| {
                self.tickets[@intFromEnum(link)] = true;
                return .{ .ticket = link };
            },
            .finished => |end| return self.ended(end),
            .hold => |end| {
                assert(self.held == null);
                self.held = end;
                self.held_told = false;
            },
            .closed => return .closed,
        }
        return null;
    }

    /// Slot `end.index`'s exchange ended, with an answer to its query from the server's script, or
    /// a failure. One the engine cancelled tells nothing.
    fn ended(self: *Channel, end: End) ?Event {
        const exchange = self.exchange_of(end.index) orelse return null;
        exchange.live = false;
        if (!end.answer) return .{ .finished = .{ .index = end.index, .answer = null } };
        const script = &network_module.network.scripts[self.server];
        const address = network_module.Network.server_address(self.server);
        const query = exchange.query[0..exchange.len];
        const answered = server.respond(script, &address, query, true, 0, &self.answer) orelse
            return .{ .finished = .{ .index = end.index, .answer = null } };
        const message = self.answer[0..answered.len];
        return .{ .finished = .{ .index = end.index, .answer = .{ .message = message, .age_seconds = 0 } } };
    }

    /// The QUIC link's next datagram: an acknowledgement when it owes one.
    pub fn datagram(self: *Channel, out: []u8, now_ns: u64) usize {
        _ = now_ns;
        if (!self.take_owed(.quic)) return 0;
        return quic.write_item(.{ .kind = .ack }, out);
    }

    /// The TCP link's next octets: an acknowledgement in a frame when it owes one.
    pub fn output(self: *Channel, out: []u8, now_ns: u64) usize {
        _ = now_ns;
        if (!self.take_owed(.tcp)) return 0;
        var item: [constants.quic_item_header_bytes]u8 = undefined;
        const len = quic.write_item(.{ .kind = .ack }, &item);
        return stream.frame(item[0..len], out);
    }

    fn take_owed(self: *Channel, link: Link) bool {
        const at = @intFromEnum(link);
        if (!self.running[at] or !self.owes[at]) return false;
        self.owes[at] = false;
        return true;
    }

    /// Due at once while a step is queued, so the engine's timer brings the read that says it.
    pub fn deadline(self: *const Channel) ?u64 {
        if (self.script_len == 0) return null;
        return self.due_ns;
    }

    /// The instant came: the read after it says what is queued.
    pub fn expire(self: *Channel, now_ns: u64) void {
        _ = self;
        _ = now_ns;
    }

    /// Starts a link's connection once its socket carries octets, offering the ticket the engine
    /// kept for its transport and the ticket's age: its first flight is owed.
    pub fn start_link(self: *Channel, link: Link, ticket: ?*const Ticket, ticket_age_ns: u64, now_ns: u64) Error!void {
        _ = now_ns;
        const at = @intFromEnum(link);
        self.running[at] = true;
        self.owes[at] = true;
        self.resumed[at] = ticket != null;
        self.ticket_ages_ns[at] = ticket_age_ns;
    }

    /// A link's socket ended: its connection is gone.
    pub fn link_ended(self: *Channel, link: Link) void {
        const at = @intFromEnum(link);
        self.ended_links[at] += 1;
        self.asked[at] = false;
        self.running[at] = false;
        self.owes[at] = false;
    }

    pub fn take_ticket(self: *Channel, link: Link) ?Ticket {
        const at = @intFromEnum(link);
        if (!self.tickets[at]) return null;
        self.tickets[at] = false;
        return .{};
    }

    pub fn alternative(self: *const Channel) ?Alternative {
        _ = self;
        return null;
    }

    pub fn wipe(self: *Channel) void {
        self.tickets = @splat(false);
    }

    /// Queues `step`, said at the engine's next read, and due now.
    pub fn say(self: *Channel, step: Step, now_ns: u64) void {
        assert(self.script_len < self.script.len);
        if (self.script_len == 0) self.due_ns = now_ns;
        self.script[self.script_len] = step;
        self.script_len += 1;
    }

    /// Whether slot `index` holds an exchange here, for a test to read.
    pub fn holds(self: *const Channel, index: u16) bool {
        for (&self.exchanges) |*exchange| {
            if (exchange.live and exchange.index == index) return true;
        }
        return false;
    }

    fn exchange_of(self: *Channel, index: u16) ?*Exchange {
        for (&self.exchanges) |*exchange| {
            if (exchange.live and exchange.index == index) return exchange;
        }
        return null;
    }

    fn pop(self: *Channel) ?Step {
        if (self.script_len == 0) return null;
        const step = self.script[0];
        std.mem.copyForwards(Step, self.script[0 .. self.script_len - 1], self.script[1..self.script_len]);
        self.script_len -= 1;
        return step;
    }
};

const testing = std.testing;

fn started() Channel {
    var channel: Channel = .{};
    const endpoint: core.Endpoint = .{ .address = .from_v4(constants.client_address), .port = constants.server_https_port };
    channel.start(.{ .server = 0, .endpoint = endpoint }) catch unreachable;
    return channel;
}

test "a queued step is said at the next read, and the channel is due until it is" {
    var channel = started();
    try testing.expectEqual(@as(?u64, null), channel.deadline());
    channel.say(.{ .open = .quic }, 7);
    try testing.expectEqual(@as(?u64, 7), channel.deadline());
    const event = channel.next(8).?;
    try testing.expectEqual(Channel.Link.quic, event.open.link);
    try testing.expectEqual(@as(?Channel.Event, null), channel.next(8));
    try testing.expectEqual(@as(?u64, null), channel.deadline());
}

test "a held end is told at the read after the one that held it" {
    var channel = started();
    try testing.expect(channel.request(3, "q", 0));
    channel.say(.{ .hold = .{ .index = 3, .answer = false } }, 0);
    try testing.expectEqual(@as(?Channel.Event, null), channel.next(0));
    const told = channel.next(0).?;
    try testing.expectEqual(@as(u16, 3), told.finished.index);
    try testing.expectEqual(@as(?Channel.Answer, null), told.finished.answer);
    try testing.expect(!channel.holds(3));
}

test "a link owes octets only while it runs, and a cancelled exchange ends in nothing" {
    var channel = started();
    var out: [Channel.output_bytes_max]u8 = undefined;
    channel.say(.{ .octets = .quic }, 0);
    try testing.expectEqual(@as(?Channel.Event, null), channel.next(0));
    try testing.expectEqual(@as(usize, 0), channel.datagram(&out, 0));
    try channel.start_link(.tcp, null, 0, 0);
    try testing.expect(channel.output(&out, 0) > 0);
    try testing.expectEqual(@as(usize, 0), channel.output(&out, 0));
    try testing.expect(channel.request(1, "q", 0));
    channel.cancel(1);
    channel.say(.{ .finished = .{ .index = 1, .answer = true } }, 0);
    try testing.expectEqual(@as(?Channel.Event, null), channel.next(0));
}
