//! A DoH server over colibri's `h2` and the plain record provider, for tests (docs/design.md §24,
//! DoH over HTTP/2). A test runs one against `cocuyo_h2`'s client, in memory or on the twin's TCP,
//! so the engine runs colibri's HTTP/2 client against colibri's HTTP/2 server. It reads each GET's
//! query out of its `dns` parameter (RFC 8484 §4.1), and answers it with what an `Answerer` makes
//! of it, under the status, media type and `Age` its script says.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const h2 = @import("h2");
const doh = @import("doh");
const plain = @import("io_h2_plain.zig");
const constants = @import("io_h2_constants.zig");

/// What makes an answer of a query, into `out`, or null to refuse it.
pub const Answerer = struct {
    context: *anyopaque,
    answer: *const fn (context: *anyopaque, query: []const u8, out: []u8) ?usize,
};

/// What a test has the server do: what its responses say, the status, the media type, a content
/// coding and an `Age`, and whether an interim response goes first; and whether it negotiates
/// another protocol, sends GOAWAY once it has answered, resets each request instead of answering
/// it, holds each unanswered, or gives a ticket once the handshake has ended.
pub const Script = struct {
    status: u16 = 200,
    content_type: []const u8 = "application/dns-message",
    content_encoding: ?[]const u8 = null,
    age: ?[]const u8 = null,
    interim: bool = false,
    other_protocol: bool = false,
    goaway: bool = false,
    reset: bool = false,
    hold: bool = false,
    tickets: bool = false,
};

/// The requests a server holds at once, as many as a test's client opens.
const requests_max = 8;
/// A response's status after its field lines' names: 100 and past, as RFC 9110 §15 numbers them.
const interim_status = 103;
const length_digits_max = 20;
/// A response's field lines: its media type and length, and a content coding and an `Age` when the
/// script names them.
const response_fields_max = 4;

/// One of the client's requests: its stream and its path.
const Request = struct {
    live: bool = false,
    id: u32 = 0,
    path: [doh.constants.doh_request_bytes_max]u8 = undefined,
    path_len: usize = 0,
};

pub const Server = struct {
    script: Script = .{},
    session: plain.Session = undefined,
    connection: h2.Connection = undefined,
    attached: bool = false,
    records: [constants.records_bytes]u8 = undefined,
    records_len: usize = 0,
    plaintext: [constants.h2_plaintext_bytes]u8 = undefined,
    plaintext_len: usize = 0,
    outgoing: [constants.outgoing_bytes]u8 = undefined,
    outgoing_len: usize = 0,
    requests: [requests_max]Request = @splat(.{}),
    content: [cocuyo.constants.message_bytes_max]u8 = undefined,
    /// What it heard, which a test reads: the answers it gave, the streams the client reset, and
    /// whether the client said its GOAWAY and its `close_notify`.
    answered: usize = 0,
    cancels: usize = 0,
    client_goaway: bool = false,
    client_closed: bool = false,

    pub fn init(self: *Server, script: Script) void {
        self.* = .{ .script = script };
        self.session = plain.Session.server(h2.tls.constants.alpn_h2[0..], script.tickets, script.other_protocol);
        self.connection.init(.server);
    }

    /// The client's octets: the handshake's, then its frames, each request answered as it ends.
    pub fn receive(self: *Server, bytes: []const u8, answerer: Answerer) void {
        assert(self.records_len + bytes.len <= self.records.len);
        @memcpy(self.records[self.records_len..][0..bytes.len], bytes);
        self.records_len += bytes.len;
        if (!self.attached) handshake(self);
        if (self.attached) read(self, answerer);
    }

    /// What it owes the client, sealed into `out`: its handshake flight or ticket, then its frames.
    pub fn send(self: *Server, out: []u8) usize {
        const provider = self.session.provider();
        const flight = provider.vtable.handshake_write(provider.context, out, 0) catch 0;
        if (flight > 0 or !self.attached) return flight;
        self.outgoing_len += self.connection.write_pending(self.outgoing[self.outgoing_len..], 0);
        const sealed = h2.connection_tls.encrypt(&self.connection, self.outgoing[0..self.outgoing_len], out, 0) catch return 0;
        std.mem.copyForwards(u8, self.outgoing[0 .. self.outgoing_len - sealed.consumed], self.outgoing[sealed.consumed..self.outgoing_len]);
        self.outgoing_len -= sealed.consumed;
        return sealed.written;
    }
};

fn consume(buffer: []u8, len: *usize, count: usize) void {
    std.mem.copyForwards(u8, buffer[0 .. len.* - count], buffer[count..len.*]);
    len.* -= count;
}

/// Whole records to the provider until the handshake is complete, then colibri takes it. A
/// handshake on another protocol leaves the server silent: the client refuses it.
fn handshake(self: *Server) void {
    const provider = self.session.provider();
    for (0..self.records.len) |_| {
        if (provider.is_complete()) break;
        const read_len = provider.vtable.handshake_read(provider.context, self.records[0..self.records_len], 0) catch return;
        if (read_len == 0) break;
        consume(&self.records, &self.records_len, read_len);
    }
    if (!provider.is_complete()) return;
    self.connection.attach_tls(provider) catch return;
    self.attached = true;
}

/// Every whole record opened and every whole frame read, what colibri owes written aside when it
/// must be before a frame is read.
fn read(self: *Server, answerer: Answerer) void {
    for (0..self.plaintext.len) |_| {
        const got = self.connection.receive(self.plaintext[0..self.plaintext_len], 0) catch return;
        if (got.consumed > 0) {
            // The event's octets are the plaintext's: it is heard before the frame is dropped.
            if (got.event) |event| hear(self, event, answerer);
            consume(&self.plaintext, &self.plaintext_len, got.consumed);
            continue;
        }
        if (self.connection.has_pending()) {
            self.outgoing_len += self.connection.write_pending(self.outgoing[self.outgoing_len..], 0);
            continue;
        }
        if (!open_record(self)) return;
    }
}

/// Opens the next whole record into the plaintext. False when none is whole, or it did not open.
fn open_record(self: *Server) bool {
    const room = self.plaintext[self.plaintext_len..];
    const opened = h2.connection_tls.decrypt(&self.connection, self.records[0..self.records_len], room, 0) catch return false;
    if (opened.consumed == 0) return false;
    consume(&self.records, &self.records_len, opened.consumed);
    self.plaintext_len += opened.plaintext_len;
    if (opened.end_of_data) self.client_closed = true;
    return true;
}

fn hear(self: *Server, event: h2.Event, answerer: Answerer) void {
    switch (event) {
        .request => |held| {
            const request = take_request(self, held.stream_id, held.request) orelse return;
            if (held.end_stream and !self.script.hold) answer(self, request, answerer);
        },
        .stream_reset => |held| {
            self.cancels += 1;
            if (request_of(&self.requests, held.stream_id)) |request| request.* = .{};
        },
        .goaway => self.client_goaway = true,
        else => {},
    }
}

fn take_request(self: *Server, stream_id: u32, held: h2.message.Request) ?*Request {
    const slot = for (&self.requests) |*request| {
        if (!request.live) break request;
    } else return null;
    const path = held.path orelse return null;
    if (path.len > slot.path.len) return null;
    slot.* = .{ .live = true, .id = stream_id, .path_len = path.len };
    @memcpy(slot.path[0..path.len], path);
    return slot;
}

fn request_of(requests: anytype, stream_id: u32) ?*Request {
    for (requests) |*request| if (request.live and request.id == stream_id) return request;
    return null;
}

/// Answers a GET: its query from `dns` (RFC 8484 §4.1), answered as the answerer says, or its
/// stream reset when there is none to answer, or when the script says so.
fn answer(self: *Server, request: *Request, answerer: Answerer) void {
    defer request.* = .{};
    if (self.script.reset) return refuse(self, request.id);
    var query: [cocuyo.constants.query_bytes_max]u8 = undefined;
    const asked = doh.query.query_of(request.path[0..request.path_len], &query) orelse return refuse(self, request.id);
    const len = answerer.answer(answerer.context, asked, &self.content) orelse return refuse(self, request.id);
    write_response(self, request.id, self.content[0..len]) catch return refuse(self, request.id);
    self.answered += 1;
    if (self.script.goaway) self.connection.shutdown(h2.constants.error_no_error);
}

/// "The stream is being closed prior to any processing having occurred" (RFC 9113 §8.7).
fn refuse(self: *Server, stream_id: u32) void {
    self.connection.reset_stream(stream_id, h2.constants.error_refused_stream) catch {};
}

/// The response's HEADERS, an interim one first if the script asks, then its content in DATA.
fn write_response(self: *Server, stream_id: u32, content: []const u8) !void {
    if (self.script.interim) {
        self.outgoing_len += try self.connection.write_response(self.outgoing[self.outgoing_len..], stream_id, interim_status, &.{}, false);
    }
    var digits: [length_digits_max]u8 = undefined;
    var fields: [response_fields_max]h2.hpack.Field = undefined;
    var count: usize = 0;
    fields[count] = .{ .name = "content-type", .value = self.script.content_type };
    count += 1;
    fields[count] = .{ .name = "content-length", .value = std.fmt.bufPrint(&digits, "{d}", .{content.len}) catch unreachable };
    count += 1;
    if (self.script.content_encoding) |coding| {
        fields[count] = .{ .name = "content-encoding", .value = coding };
        count += 1;
    }
    if (self.script.age) |age| {
        fields[count] = .{ .name = "age", .value = age };
        count += 1;
    }
    self.outgoing_len += try self.connection.write_response(self.outgoing[self.outgoing_len..], stream_id, self.script.status, fields[0..count], false);
    const data = try self.connection.write_data(self.outgoing[self.outgoing_len..], stream_id, content, true);
    if (data.consumed != content.len) return error.OutputTooSmall;
    self.outgoing_len += data.written;
}
