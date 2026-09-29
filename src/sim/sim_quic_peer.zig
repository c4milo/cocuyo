//! The server's side of the twin's QUIC (`sim_quic.zig`): how a scripted server behaves, and what
//! it makes of each item a connection's client sends. Split from `sim_quic.zig`.
const constants = @import("constants.zig");
const quic = @import("sim_quic.zig");

const Kind = quic.Kind;
const Item = quic.Item;

/// How a scripted server's QUIC behaves (sim_server.zig's `Script`).
pub const Behaviour = struct {
    /// Flights it asks the client to answer before the handshake ends.
    flights: u8 = 0,
    /// Refuses every handshake, as a server whose certificate does not verify is refused.
    refuse: bool = false,
    /// Negotiates a protocol other than the one offered.
    other_protocol: bool = false,
    /// Gives a ticket when a handshake ends.
    tickets: bool = false,
    /// What it does with a request instead of answering it: reset its stream, or close the
    /// connection.
    instead: enum { answer, reset, close } = .answer,
    /// Sends GOAWAY once it has taken its first request on a connection, as an HTTP/3 server that
    /// stops taking streams does, and answers the streams it took (RFC 9114 §5.2). No DoQ server
    /// sends one (RFC 9250), but the engine drains a connection whose transport says one came.
    goaway: bool = false,
    /// Answers with a message whose prefix is one octet long, or whose ID is not 0: the protocol
    /// errors of RFC 9250 §4.3.3.
    malformed: enum { none, prefix, id } = .none,
};

/// One connection's server side.
pub const Peer = struct {
    flights_left: u8 = 0,
    up: bool = false,
    offered: [constants.quic_alpn_bytes_max]u8 = undefined,
    offered_len: u8 = 0,
    /// What it heard, which a test reads: the hellos that resumed, the cancels, and the close.
    resumed: u16 = 0,
    cancels: u16 = 0,
    closed: bool = false,
    /// It sent its GOAWAY.
    goaway_sent: bool = false,

    /// What the server does with one item: steps to write back, or a request to answer.
    pub const Heard = union(enum) {
        steps: struct { first: Kind, second: ?Kind = null },
        request: struct { stream: u32, bytes: []const u8 },
        nothing,
    };

    pub fn hear(self: *Peer, behaviour: *const Behaviour, item: Item) Heard {
        switch (item.kind) {
            .hello, .hello_resumed => {
                if (item.kind == .hello_resumed) self.resumed += 1;
                return self.begin(behaviour, item.bytes);
            },
            .flight_answer => return self.next_flight(behaviour),
            .request => if (self.up) return .{ .request = .{ .stream = item.stream, .bytes = item.bytes } },
            .stop_sending => self.cancels += 1,
            .close => self.closed = true,
            else => {},
        }
        return .nothing;
    }

    /// The protocol the handshake ends on: the one the client offered, unless the script says
    /// otherwise.
    pub fn negotiated(self: *const Peer, behaviour: *const Behaviour) []const u8 {
        if (behaviour.other_protocol) return constants.quic_alpn_other;
        return self.offered[0..self.offered_len];
    }

    fn begin(self: *Peer, behaviour: *const Behaviour, alpn: []const u8) Heard {
        if (behaviour.refuse) return .{ .steps = .{ .first = .refused } };
        const kept = @min(alpn.len, self.offered.len);
        @memcpy(self.offered[0..kept], alpn[0..kept]);
        self.offered_len = @intCast(kept);
        self.flights_left = behaviour.flights;
        return self.next_flight(behaviour);
    }

    fn next_flight(self: *Peer, behaviour: *const Behaviour) Heard {
        if (self.flights_left > 0) {
            self.flights_left -= 1;
            return .{ .steps = .{ .first = .flight } };
        }
        self.up = true;
        return .{ .steps = .{ .first = .done, .second = if (behaviour.tickets) .ticket else null } };
    }
};
