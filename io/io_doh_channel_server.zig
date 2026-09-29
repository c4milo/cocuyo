//! A DoH server over colibri's `server`, for `cocuyo_doh`'s tests (docs/design.md §24, DoH over
//! colibri's client): colibri's server over TLS under the test identity (`io_doh_channel_identity`),
//! selecting from the protocols its script names, which reads each GET's query out of its `dns`
//! parameter (RFC 8484 §4.1). It answers the query with what an `Answerer` makes of it, under the
//! status, media type, content coding and `Age` its script says, or holds it unanswered.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const server = @import("server");
const tls = @import("tls");
const doh = @import("doh");
const identity = @import("io_doh_channel_identity.zig");
const constants = @import("io_doh_channel_constants.zig");

/// What makes an answer of a query, into `out`, or null to refuse it.
pub const Answerer = struct {
    context: *anyopaque,
    answer: *const fn (context: *anyopaque, query: []const u8, out: []u8) ?usize,
};

/// What a test has the server do: the protocols it selects from, in its order (RFC 7301 §3.2),
/// what its responses say, whether it issues tickets, whether it holds each request unanswered,
/// and whether it resets a stream once its head has gone.
pub const Script = struct {
    alpn: []const []const u8 = &.{ "h2", "http/1.1" },
    status: u16 = 200,
    content_type: []const u8 = "application/dns-message",
    content_encoding: ?[]const u8 = null,
    age: ?[]const u8 = null,
    tickets: bool = false,
    hold: bool = false,
    reset_after_head: bool = false,
};

/// Keys a server needs: RFC 9846 §4.3.2's cookie key, and the one its tickets are sealed under,
/// each of one octet repeated, and the octet its stream is seeded with. Test-only values.
const cookie_octet = 0x5c;
const ticket_octet = 0x7e;
const stream_octet = 0x33;
const cookie_key: [tls.constants.server_key_len]u8 = @splat(cookie_octet);
const ticket_key: [tls.constants.server_key_len]u8 = @splat(ticket_octet);
/// A response's field lines at most: its media type, its length, a content coding and an `Age`.
const response_fields_max = 4;
const length_digits_max = 20;

/// A field's value a request carried, kept for a test to read.
pub const Heard = struct {
    value: [heard_bytes_max]u8 = undefined,
    len: usize = 0,

    fn keep(heard: *Heard, field: ?server.Field) void {
        const value = if (field) |line| line.value else "";
        heard.len = @min(value.len, heard.value.len);
        @memcpy(heard.value[0..heard.len], value[0..heard.len]);
    }

    pub fn text(heard: *const Heard) []const u8 {
        return heard.value[0..heard.len];
    }
};
const heard_bytes_max = 64;

pub const Server = struct {
    script: Script = .{},
    tls_config: tls.record.ServerConfig = undefined,
    config: server.Config = undefined,
    connection: server.Connection = undefined,
    stream: std.Random.ChaCha = std.Random.ChaCha.init(@splat(stream_octet)),
    /// The records the client sent and the server has not read.
    input: [constants.stream_bytes]u8 = undefined,
    input_len: usize = 0,
    content: [cocuyo.constants.message_bytes_max]u8 = undefined,
    /// What it heard, which a test reads: the queries it answered, the requests it holds, the last
    /// query it read, and what that request's `accept` and `accept-encoding` asked for.
    answered: usize = 0,
    held: usize = 0,
    query: [cocuyo.constants.message_bytes_max]u8 = undefined,
    query_len: usize = 0,
    accept: Heard = .{},
    accept_encoding: Heard = .{},

    pub fn init(self: *Server, script: Script, unix_seconds: u64) !void {
        self.* = .{ .script = script };
        try self.tls_config.init(.{
            .ecdsa_p256 = .{ .chain = &identity.chain, .public_key = identity.public_key, .private_key = identity.private_key },
            .cookie_key = &cookie_key,
            .ticket_key = if (script.tickets) &ticket_key else null,
            .alpn = script.alpn,
        });
        self.config = .{ .tls = &self.tls_config };
        try self.connection.init(&self.config, self.stream.random(), unix_seconds);
    }

    /// Takes what the client sent, and answers each request it reads whole.
    pub fn receive(self: *Server, bytes: []const u8, answerer: Answerer, now_ns: u64) void {
        assert(self.input_len + bytes.len <= self.input.len);
        @memcpy(self.input[self.input_len..][0..bytes.len], bytes);
        self.input_len += bytes.len;
        // Bounded: each pass takes octets or reads an event, and the input holds finitely many.
        for (0..self.input.len + 1) |_| {
            const received = self.connection.receive(self.input[0..self.input_len], now_ns) catch return;
            std.mem.copyForwards(u8, self.input[0 .. self.input_len - received.consumed], self.input[received.consumed..self.input_len]);
            self.input_len -= received.consumed;
            const event = received.event orelse {
                if (received.consumed == 0) return;
                continue;
            };
            if (event == .request) self.answer(event.request, answerer, now_ns);
        }
    }

    pub fn send(self: *Server, out: []u8, now_ns: u64) usize {
        return self.connection.send(out, now_ns);
    }

    /// Reads the request's query, and answers it as the script says.
    fn answer(self: *Server, request: server.Request, answerer: Answerer, now_ns: u64) void {
        const path = request.path orelse return;
        const query = doh.query.query_of(path, &self.query) orelse return;
        self.query_len = query.len;
        self.accept.keep(request.fields.find("accept"));
        self.accept_encoding.keep(request.fields.find("accept-encoding"));
        if (self.script.hold) {
            self.held += 1;
            return;
        }
        const len = answerer.answer(answerer.context, query, &self.content) orelse return;
        var digits: [length_digits_max]u8 = undefined;
        var fields: [response_fields_max]server.Field = undefined;
        var count: usize = 0;
        fields[count] = .{ .name = "content-type", .value = self.script.content_type };
        count += 1;
        fields[count] = .{ .name = "content-length", .value = std.fmt.bufPrint(&digits, "{d}", .{len}) catch unreachable };
        count += 1;
        if (self.script.content_encoding) |coding| {
            fields[count] = .{ .name = "content-encoding", .value = coding };
            count += 1;
        }
        if (self.script.age) |age| {
            fields[count] = .{ .name = "age", .value = age };
            count += 1;
        }
        // colibri's server writes a response ahead of the SETTINGS its HTTP/2 session owes, which
        // RFC 9113 §3.4 has go first, when the request came with the handshake's end: reported to
        // colibri on 2026-09-28. What the session owes is written first until colibri fixes it.
        _ = self.connection.write_owed(now_ns);
        self.connection.respond(request.id, self.script.status, fields[0..count], false) catch return;
        if (self.script.reset_after_head) {
            // RFC 9113 §6.4: RST_STREAM ends the stream at once, before its content.
            self.connection.cancel(request.id);
            return;
        }
        var written: usize = 0;
        // Bounded: each pass writes an octet of the content, or stops.
        for (0..len + 1) |_| {
            written += self.connection.write_body(request.id, self.content[written..len], true) catch return;
            if (written == len) break;
        }
        self.answered += 1;
    }
};
