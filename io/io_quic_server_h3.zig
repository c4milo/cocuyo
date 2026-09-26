//! A DoH server over colibri's `h3` and `plain`, for tests (docs/design.md §24, DoH over HTTP/3).
//! A test puts one behind the twin's responder, so the engine runs colibri's HTTP/3 client against
//! colibri's HTTP/3 server on the twin's clock. It reads each GET's query out of its `dns`
//! parameter (RFC 8484 §4.1), and answers it with what an `Answerer` makes of it, under the status,
//! media type and `Age` its fields say. The QUIC side is the DoQ server's (`io_quic_server.zig`).
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const quic = @import("quic");
const h3 = @import("h3");
const constants = @import("io_quic_constants.zig");
const plain = @import("io_quic_plain.zig");
const doq = @import("io_quic_server.zig");

pub const Answerer = doq.Answerer;
const Writer = h3.core.Writer;
const connection_id_bytes_max = quic.crypto.constants.connection_id_len_max;
const query_of = @import("doh").query.query_of;

/// One of the client's request streams: its path, and the response the server keeps while
/// colibri may read it: the HEADERS frame and a DATA frame's header, then the content.
const Request = struct {
    live: bool = false,
    id: u64 = 0,
    path: [constants.doh_request_bytes_max]u8 = undefined,
    path_len: usize = 0,
    prefix: [constants.server_prefix_bytes_max]u8 = undefined,
    prefix_len: usize = 0,
    content: [constants.server_answer_bytes_max]u8 = undefined,
    content_len: usize = 0,
    answered: bool = false,
};

/// What a test has the server do: what its responses say, the status, the media type, a content
/// coding and an `Age`, each as the field's value, and whether an interim response goes first.
pub const Script = struct {
    status: []const u8 = "200",
    content_type: []const u8 = "application/dns-message",
    content_encoding: ?[]const u8 = null,
    age: ?[]const u8 = null,
    interim: bool = false,
    /// Selects a protocol other than the one offered, and sends GOAWAY once it has answered.
    other_protocol: bool = false,
    goaway: bool = false,
};

pub fn Server(comptime streams: u16) type {
    return struct {
        const Self = @This();

        connection: quic.Connection = undefined,
        session: plain.Session = undefined,
        h3: h3.Connection = undefined,
        section: h3.http.FieldSection = undefined,
        body: [constants.h3_chunk_bytes]u8 = undefined,
        pool: quic.stream.stream_incoming.Pool(constants.server_receive_bytes) = undefined,
        send_scratch: quic.connection_send.DefaultScratch = undefined,
        scratch: quic.connection_datagram.Scratch = undefined,
        inbound: [constants.datagram_receive_bytes]u8 = undefined,
        source: [constants.connection_id_bytes]u8 = @splat(constants.server_id_octet),
        original: [connection_id_bytes_max]u8 = undefined,
        original_len: usize = 0,
        client: [connection_id_bytes_max]u8 = undefined,
        client_len: usize = 0,
        started: bool = false,
        /// `h3` is set up with the connection, and started once the handshake ends.
        h3_ready: bool = false,
        h3_started: bool = false,
        requests: [streams]Request = @splat(.{}),
        answered: usize = 0,
        script: Script = .{},
        /// The code of the client's CONNECTION_CLOSE, once one came.
        close_code: ?u64 = null,

        pub fn receive(self: *Self, bytes: []const u8, now_ns: u64, answerer: Answerer) void {
            const taken = doq.take(self, bytes, now_ns, parameters(streams));
            if (self.started and !self.h3_ready) {
                self.h3.init(.{ .role = .server });
                self.h3_ready = true;
            }
            if (taken) step(self, answerer);
        }

        pub fn send(self: *Self, out: []u8, now_ns: u64) usize {
            if (!self.h3_ready) return 0;
            return doq.send(self, out, now_ns, self.h3.provider(.{ .context = self, .vtable = &stream_vtable }));
        }

        pub fn deadline(self: *Self) ?u64 {
            return doq.next_deadline(self);
        }

        pub fn expire(self: *Self, now_ns: u64) void {
            doq.expire_due(self, now_ns);
        }

        /// A new connection on a socket an old one used: the script stays.
        pub fn renew(self: *Self) void {
            self.* = .{ .script = self.script };
        }

        const stream_vtable: quic.stream.stream_provider.VTable = .{ .read = read_response };

        fn read_response(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
            const self: *Self = @ptrCast(@alignCast(context));
            return provide(&self.requests, stream_id, offset, output);
        }
    };
}

/// A request stream for each of the client's queries at once, each GET whole, and the client's
/// control and QPACK streams with the credit RFC 9114 §6.2 asks for.
fn parameters(streams: u16) quic.transport_parameters.Parameters {
    var local = doq.parameters(streams);
    local.initial_max_stream_data_bidi_remote = constants.doh_request_bytes_max;
    local.initial_max_streams_uni = constants.h3_peer_uni_streams;
    local.initial_max_stream_data_uni = constants.h3_peer_uni_stream_bytes;
    return local;
}

/// What a datagram may have changed: `h3` started once the handshake ended, every event read, and
/// the streams that ended freed.
fn step(self: anytype, answerer: Answerer) void {
    if (!self.h3_started) {
        if (!self.connection.handshake_complete) return;
        self.h3.start(&self.connection) catch return;
        self.h3_started = true;
    }
    // Bounded by the pool: each event takes an octet of it at least.
    for (0..constants.server_receive_bytes) |_| {
        const event = self.h3.receive(&self.connection, &self.body) catch return;
        switch (event orelse break) {
            .request => |held| take_request(self, held.stream_id, held.request),
            .end => |stream_id| answer(self, stream_id, answerer),
            .reset, .refused => |held| if (request_of(&self.requests, held.stream_id)) |request| {
                request.* = .{};
            },
            .data, .trailers, .settings, .goaway, .response => {},
        }
    }
    release_ended(self);
}

fn take_request(self: anytype, stream_id: u64, held: h3.message.Request) void {
    const slot = for (&self.requests) |*request| {
        if (!request.live) break request;
    } else return;
    const path = held.path orelse return;
    if (path.len > slot.path.len) return;
    slot.* = .{ .live = true, .id = stream_id, .path_len = path.len };
    @memcpy(slot.path[0..path.len], path);
}

fn request_of(requests: anytype, stream_id: u64) ?*Request {
    for (requests) |*request| if (request.live and request.id == stream_id) return request;
    return null;
}

/// Answers a GET whose stream ended: its query from `dns` (RFC 8484 §4.1), answered as the
/// answerer says, or the stream reset when there is none to answer.
fn answer(self: anytype, stream_id: u64, answerer: Answerer) void {
    const request = request_of(&self.requests, stream_id) orelse return;
    var query: [cocuyo.constants.query_bytes_max]u8 = undefined;
    const asked = query_of(request.path[0..request.path_len], &query) orelse return refuse(self, request);
    const len = answerer.answer(answerer.context, asked, &request.content) orelse return refuse(self, request);
    request.content_len = len;
    request.answered = true;
    write_response(self, request) catch return refuse(self, request);
    self.answered += 1;
    if (self.script.goaway) self.h3.shutdown(&self.connection) catch {};
}

/// The response's HEADERS frame, an interim one first if the test asks, and its DATA frame's header.
fn write_response(self: anytype, request: *Request) !void {
    var writer = Writer.init(&request.prefix);
    if (self.script.interim) {
        self.section.init();
        try self.section.append(":status", "103");
        try self.h3.write_response(&self.connection, request.id, &self.section, &.{}, &writer);
    }
    var length_digits: [constants.server_length_digits_max]u8 = undefined;
    self.section.init();
    try self.section.append(":status", self.script.status);
    try self.section.append("content-type", self.script.content_type);
    try self.section.append("content-length", std.fmt.bufPrint(&length_digits, "{d}", .{request.content_len}) catch unreachable);
    if (self.script.content_encoding) |coding| try self.section.append("content-encoding", coding);
    if (self.script.age) |age| try self.section.append("age", age);
    try self.h3.write_response(&self.connection, request.id, &self.section, &.{}, &writer);
    try h3.connection.write_data_header(request.content_len, &writer);
    request.prefix_len = writer.written().len;
    try quic.connection_stream_send.supply(&self.connection, .{ .value = request.id }, request.prefix_len + request.content_len, true);
}

fn refuse(self: anytype, request: *Request) void {
    request.answered = true;
    self.h3.cancel(&self.connection, request.id, constants.h3_request_cancelled);
}

/// The octets of stream `stream_id`'s response from `offset`, as many as fit.
fn provide(requests: anytype, stream_id: u64, offset: u64, output: []u8) usize {
    const request = request_of(requests, stream_id) orelse return 0;
    const whole = request.prefix_len + request.content_len;
    if (offset >= whole) return 0;
    var written: usize = 0;
    if (offset < request.prefix_len) {
        const left = request.prefix[@intCast(offset)..request.prefix_len];
        written = @min(left.len, output.len);
        @memcpy(output[0..written], left[0..written]);
    }
    const content_at: usize = @intCast(@max(offset, request.prefix_len) - request.prefix_len);
    const content = request.content[content_at..request.content_len];
    const more = @min(content.len, output.len - written);
    @memcpy(output[written..][0..more], content[0..more]);
    return written + more;
}

/// Frees each answered request whose response the client has whole, or which was reset.
fn release_ended(self: anytype) void {
    for (&self.requests) |*request| {
        if (!request.live or !request.answered) continue;
        switch (self.connection.streams.lookup(.{ .value = request.id })) {
            .live => |stream| switch (stream.sending.state) {
                .data_recvd, .reset_sent, .reset_recvd => request.* = .{},
                else => {},
            },
            .closed, .unopened => request.* = .{},
        }
    }
}
