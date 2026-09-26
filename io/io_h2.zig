//! colibri's HTTP/2 under the engine's request interface (docs/design.md §24, DoH over HTTP/2):
//! `cocuyo_h2`, a module of its own, whose `h2` import a consumer that speaks DoH over HTTP/2 binds
//! to colibri's, so `cocuyo_rotor` never imports colibri. A connection is colibri's `h2` client over
//! a record-mode `tls.Provider`, on a TCP connection the engine opens: chapulin's record transport
//! for a consumer, and for the gate a provider of cocuyo's that encrypts nothing
//! (`io_h2_plain.zig`). The frames are colibri's; the GET, the answer buffers and the reading of a
//! response are `io_h2_connection.zig`'s.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const h2 = @import("h2");
const doh = @import("doh");
const connection_module = @import("io_h2_connection.zig");

/// A record-mode TLS provider that encrypts nothing, for tests (`io_h2_plain.zig`).
pub const plain = @import("io_h2_plain.zig");
/// A DoH server over colibri's `h2` and `plain`, for tests (`io_h2_server.zig`).
pub const server = @import("io_h2_server.zig");
pub const constants = @import("io_h2_constants.zig");

pub const Options = struct {
    /// The TLS: a record-mode provider with `start`, `provider`, `take_ticket`, `lifetime_ns` and
    /// `wipe`, and its `Context` and `Ticket`.
    Session: type = Plain,
    /// A connection's answer buffers: the responses it has in flight at once.
    answers: u16 = doh.constants.answers_default,
};

/// `plain.Session` behind the interface a connection's session has.
pub const Plain = struct {
    pub const Context = struct {};
    pub const Ticket = struct {};

    session: plain.Session = .{ .role = .client },

    pub fn start(self: *Plain, context: anytype) error{Failed}!void {
        self.session = plain.Session.client(context.alpn, context.ticket != null);
    }
    pub fn provider(self: *Plain) h2.tls.Provider {
        return self.session.provider();
    }
    pub fn take_ticket(self: *Plain) ?Ticket {
        return if (self.session.take_ticket()) .{} else null;
    }
    pub fn lifetime_ns(ticket: *const Ticket) u64 {
        _ = ticket;
        return std.math.maxInt(u64);
    }
    pub fn wipe(self: *Plain) void {
        self.session.wipe();
    }
};

pub fn Connection(comptime options: Options) type {
    return struct {
        const Self = @This();
        const Session = options.Session;

        pub const enabled = true;
        pub const http3 = false;
        /// A stream of octets, over TCP (docs/design.md §24, request rules 14 to 16).
        pub const socket = .stream;
        pub const output_bytes_max = constants.output_bytes_max;
        /// A request's slot holds the DNS message, which the GET carries in `dns`.
        pub const request_bytes_max = cocuyo.constants.query_bytes_max;
        pub const Error = error{Failed};
        pub const Context = Session.Context;
        pub const Ticket = Session.Ticket;
        /// What a DoH response says of its content (`io_doh_response.zig`).
        pub const Http = doh.response.Http;
        pub const Answered = struct { stream: u64, len: usize, http: ?Http = null };
        pub const Next = union(enum) { up: []const u8, refused, answered: Answered, reset: u64, closed, goaway, ticket: Ticket };

        session: Session = .{},
        state: connection_module.State(options.answers) = .{},

        pub fn start(self: *Self, context: anytype) Error!void {
            const https = context.https orelse return error.Failed;
            try self.session.start(context);
            try connection_module.start(self, https);
        }
        pub fn lifetime_ns(ticket: *const Ticket) u64 {
            return Session.lifetime_ns(ticket);
        }
        pub fn receive(self: *Self, bytes: []const u8, now_ns: u64) Error!void {
            _ = now_ns;
            try connection_module.receive(self, bytes);
        }
        pub fn next(self: *Self, out: []u8) ?Next {
            return connection_module.next(self, self.session.provider(), out);
        }
        pub fn request(self: *Self, bytes: []u8, len: usize) Error!?u64 {
            return connection_module.request(self, bytes[0..len]);
        }
        pub fn cancel(self: *Self, stream: u64) void {
            connection_module.cancel(self, stream);
        }
        pub fn output(self: *Self, out: []u8, now_ns: u64) usize {
            _ = now_ns;
            return connection_module.output(self, self.session.provider(), out);
        }
        /// TCP resends what is lost, and the engine fails no connection past colibri's SETTINGS
        /// deadline (docs/design.md §24, DoH over HTTP/2): there is none.
        pub fn deadline(self: *const Self) ?u64 {
            _ = self;
            return null;
        }
        pub fn expire(self: *Self, now_ns: u64) void {
            _ = self;
            _ = now_ns;
        }
        /// HTTP/2 negotiates no idle timeout (RFC 9113 §9.1).
        pub fn idle_left_ns(self: *const Self, now_ns: u64) u64 {
            _ = self;
            _ = now_ns;
            return std.math.maxInt(u64);
        }
        pub fn close(self: *Self) void {
            connection_module.close(self);
        }
        pub fn wipe(self: *Self) void {
            self.session.wipe();
            self.state.stage = .idle;
        }
    };
}

test {
    _ = plain;
    _ = constants;
    _ = connection_module;
    _ = server;
    _ = @import("io_h2_test.zig");
}
