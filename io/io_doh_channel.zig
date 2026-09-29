//! `cocuyo_doh`: colibri's `client.Channel` under the engine's DoH interface (docs/design.md §24,
//! DoH over colibri's client). A consumer that speaks DoH names `Channel(...)` in the engine's
//! `Options.doh`, and binds colibri's `client` and `tls` modules into this one. `cocuyo_rotor`
//! never imports colibri, so a consumer that speaks no DoH binds nothing more.
//!
//! The channel carries a server's requests over HTTP/3, or over HTTP/2 or HTTP/1.1 on TCP, and asks
//! the engine to open and close the sockets it runs over (rules 18 to 25). The type turns a request
//! into colibri's exchange and an exchange's end into an answer (`io_doh_channel_exchange.zig`),
//! keeps what a link read until the channel takes it, and keeps the ticket each link resumes with.
//! Its TLS is colibri's `tls` over chapulin, so an image that links it links chapulin.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const client = @import("client");
const tls = @import("tls");
const doh = @import("doh");
const hooks = @import("chapulin_hooks");
pub const constants = @import("io_doh_channel_constants.zig");
const exchange_module = @import("io_doh_channel_exchange.zig");
const start_module = @import("io_doh_channel_start.zig");
const read_module = @import("io_doh_channel_read.zig");

// colibri's objects call `ch_assert_fail` whatever of chapulin a program uses, so the image links
// it whenever it links this module.
comptime {
    _ = hooks;
}

pub const Options = struct {
    /// The exchanges a channel holds at once, each with its answer buffer: the responses it has in
    /// flight. A request past them waits (rule 21).
    answers: u16 = doh.constants.answers_default,
};

pub fn Channel(comptime options: Options) type {
    // A request becomes one of colibri's exchanges only while an answer buffer is free, so colibri
    // never has more than it can hold.
    comptime assert(options.answers > 0 and options.answers <= client.constants.exchanges_max);
    return struct {
        const Self = @This();

        pub const enabled = true;
        pub const Link = read_module.Link;
        pub const output_bytes_max = constants.output_bytes_max;
        pub const Error = error{Failed};
        pub const Context = start_module.Context;
        pub const Ticket = tls.Ticket;
        pub const Alternative = client.channel.Alternative;
        pub const Answer = exchange_module.Answer;
        pub const Finished = struct { index: u16, answer: ?Answer };
        pub const Open = struct { link: Link, endpoint: cocuyo.Endpoint };
        pub const Event = union(enum) { open: Open, close: Link, ticket: Link, finished: Finished, closed };
        pub const Input = union(enum) { none, datagram: []const u8, stream: []const u8 };

        channel: client.Channel = undefined,
        pool: client.ReceivePool(constants.receive_bytes) = undefined,
        /// What the channel starts from, which colibri and chapulin read through pointers into it.
        channel_config: client.ChannelConfig = undefined,
        tcp_config: client.Config = undefined,
        quic_config: client.QuicConfig = undefined,
        record_tls: tls.record.ClientConfig = undefined,
        quic_tls: tls.quic.ClientConfig = undefined,
        hostname: [cocuyo.constants.name_text_bytes_max]u8 = undefined,
        addresses: [1]client.channel.Address = undefined,
        context: *Context = undefined,
        /// The template's path, which each request's GET expands; the engine's configuration holds it.
        path: []const u8 = "",
        exchanges: [options.answers]exchange_module.Exchange = @splat(.{}),
        /// What a link read and the channel has not taken: one datagram, from where the QUIC link
        /// went, and the stream's octets. A stream that ran past its buffer owes the TCP link's close.
        inbound: [constants.datagram_bytes]u8 = undefined,
        inbound_len: usize = 0,
        quic_to: client.channel.Address = .{},
        stream: [constants.stream_bytes]u8 = undefined,
        stream_len: usize = 0,
        stream_overrun: bool = false,
        /// The ticket each link's connection resumes with: a copy, which `wipe` and the link's end zero.
        resuming: [@typeInfo(Link).@"enum".fields.len]Ticket = undefined,
        started: bool = false,

        pub fn start(self: *Self, context: anytype) Error!void {
            return start_module.start(self, context);
        }
        pub fn lifetime_ns(ticket: *const Ticket) u64 {
            return @as(u64, ticket.lifetime_s) * constants.ns_per_second;
        }
        pub fn request(self: *Self, index: u16, message: []const u8, now_ns: u64) bool {
            _ = now_ns;
            return read_module.request(self, index, message);
        }
        pub fn cancel(self: *Self, index: u16) void {
            read_module.cancel(self, index);
        }
        pub fn shutdown(self: *Self) void {
            self.channel.shutdown();
        }
        pub fn receive(self: *Self, input: Input, now_ns: u64) void {
            _ = now_ns;
            read_module.receive(self, input);
        }
        pub fn next(self: *Self, now_ns: u64) ?Event {
            return read_module.next(self, now_ns);
        }
        pub fn datagram(self: *Self, out: []u8, now_ns: u64) usize {
            return read_module.datagram(self, out, now_ns);
        }
        pub fn output(self: *Self, out: []u8, now_ns: u64) usize {
            return self.channel.send_stream(out, now_ns);
        }
        pub fn deadline(self: *Self) ?u64 {
            return self.channel.deadline_ns();
        }
        pub fn expire(self: *Self, now_ns: u64) void {
            self.channel.on_instant(now_ns);
        }
        pub fn start_link(self: *Self, link: Link, ticket: ?*const Ticket, ticket_age_ns: u64, now_ns: u64) Error!void {
            return start_module.start_link(self, link, ticket, ticket_age_ns, now_ns);
        }
        pub fn link_ended(self: *Self, link: Link) void {
            start_module.link_ended(self, link);
        }
        pub fn take_ticket(self: *Self, link: Link) ?Ticket {
            return self.channel.take_ticket(read_module.transport_of(link));
        }
        pub fn alternative(self: *const Self) ?Alternative {
            return self.channel.alternative();
        }
        pub fn wipe(self: *Self) void {
            start_module.wipe(self);
        }
    };
}

test {
    _ = constants;
    _ = exchange_module;
    _ = start_module;
    _ = read_module;
    _ = @import("io_doh_channel_test.zig");
    _ = @import("io_doh_channel_engine_test.zig");
}
