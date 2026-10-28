//! A DoH server over colibri's `server.Endpoint`, for `cocuyo_doh`'s tests (docs/design.md §24, DoH
//! over colibri's client): an endpoint of one TCP connection over TLS under the test identity
//! (`io_doh_channel_identity`), which serves the versions its script names. Its route table sends a
//! GET to the query in the path's `dns` parameter (RFC 8484 §4.1). It answers the query with what
//! an `Answerer` makes of it, under the status, media type, content coding and `Age` its script
//! says. A script may also hold the query unanswered.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const server = @import("server");
const tls = @import("tls");
const doh = @import("doh");
const identity = @import("io_doh_channel_identity.zig");
const constants = @import("io_doh_channel_constants.zig");
const limits = @import("io_doh_channel_limits.zig");

/// What makes an answer of a query, into `out`, or null to refuse it.
pub const Answerer = struct {
    context: *anyopaque,
    answer: *const fn (context: *anyopaque, query: []const u8, out: []u8) ?usize,
};

/// What a test has the server do: its versions and its protocol, its responses, its tickets, and
/// whether it holds each request or resets its stream once the head has gone.
pub const Script = struct {
    /// Over TLS the endpoint offers `h2`, then `http/1.1`, as `versions` allows each (RFC 7301
    /// §3.2; colibri's decision 119).
    versions: server.Versions = .{},
    /// The handshake selects no protocol: the server's TLS names none (RFC 7301 §3.2).
    selects_none: bool = false,
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
const cookie_octet: u8 = 0x5c;
const ticket_octet: u8 = 0x7e;
const stream_octet: u8 = 0x33;
const cookie_key: [tls.constants.server_key_len]u8 = @splat(cookie_octet);
const ticket_key: [tls.constants.server_key_len]u8 = @splat(ticket_octet);

/// The server's TLS identity, the test's, with no protocol named: the endpoint names those its
/// versions allow (colibri's decision 119).
pub fn identity_values(tickets: bool) tls.Server {
    return .{
        .ecdsa_p256 = .{ .chain = &identity.chain, .public_key = identity.public_key, .private_key = identity.private_key },
        .cookie_key = &cookie_key,
        .ticket_key = if (tickets) &ticket_key else null,
        // Nothing, so the server's sessions hold TLS_CHACHA20_POLY1305_SHA256 alone.
        .cpu = identity.cpu_not_stated,
    };
}

/// A field's value a request carried, kept for a test to read.
pub const Heard = struct {
    value: [limits.server_heard_bytes_max]u8 = undefined,
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

/// The versions a request comes in, as RFC 9110 §2.5 numbers them, which a test reads: 1.1 for
/// HTTP/1.1, and 2.0 for HTTP/2.
const http_2_major: u8 = 2;
pub const http_1_1: server.Version = .{ .major = 1, .minor = 1 };
pub const http_2: server.Version = .{ .major = http_2_major, .minor = 0 };

/// An endpoint of one TCP connection, the one a test's channel opens.
const Endpoint = server.EndpointOf(.{ .tcp_connections = 1, .quic_connections = 0 });

pub const Server = struct {
    script: Script = .{},
    config: server.Config = undefined,
    endpoint: Endpoint = undefined,
    /// The connection the endpoint accepted, which each call names.
    connection: server.ConnectionHandle = undefined,
    stream: std.Random.ChaCha = std.Random.ChaCha.init(@splat(stream_octet)),
    /// The records the client sent and the server has not read.
    input: [limits.stream_bytes_max]u8 = undefined,
    input_len: usize = 0,
    owed: [limits.server_owed_max]Owed = @splat(.{}),
    /// What it heard, which a test reads: the queries it answered, the requests it holds, the last
    /// query it read, the version of its request, and what its `accept` and `accept-encoding` asked
    /// for. A program reads a request's version from the request (colibri's decision 121).
    answered: usize = 0,
    held: usize = 0,
    query: [cocuyo.limits.message_bytes_max]u8 = undefined,
    query_len: usize = 0,
    version: ?server.Version = null,
    accept: Heard = .{},
    accept_encoding: Heard = .{},

    pub fn init(self: *Server, script: Script, unix_seconds: u64, now_ns: u64) !void {
        self.* = .{ .script = script };
        self.config = .{ .tls = identity_values(script.tickets), .versions = script.versions };
        try self.endpoint.init(&self.config, self.stream.random(), unix_seconds, now_ns);
        // The endpoint names in ALPN the versions it serves. A server that names none has its
        // TCP configuration made again with the identity's empty list, which a test alone does.
        if (script.selects_none) try self.endpoint.tcp_tls.init(self.config.tls.?);
        self.connection = self.endpoint.accept(.tls, now_ns) orelse return error.AcceptRefused;
    }

    /// Takes what the client sent, and answers each request it reads whole.
    pub fn receive(self: *Server, bytes: []const u8, answerer: Answerer, now_ns: u64) void {
        assert(self.input_len + bytes.len <= self.input.len);
        @memcpy(self.input[self.input_len..][0..bytes.len], bytes);
        self.input_len += bytes.len;
        self.read(answerer, now_ns);
    }

    /// Writes what the answers still owe of their content, reads what that changed, then writes
    /// what the connection owes.
    pub fn send(self: *Server, out: []u8, answerer: Answerer, now_ns: u64) usize {
        self.write_owed();
        self.read(answerer, now_ns);
        return self.endpoint.send_stream(self.connection, out, now_ns);
    }

    /// Hands the endpoint the octets it holds, or none, until it takes nothing and says nothing.
    /// An event's slices point into the octets, so they leave once the event is read.
    fn read(self: *Server, answerer: Answerer, now_ns: u64) void {
        for (0..limits.server_events_per_input_max) |_| {
            const input: server.Input = if (self.input_len == 0) .none else .{ .stream = .{ .connection = self.connection, .octets = self.input[0..self.input_len] } };
            const received = self.endpoint.receive(input, now_ns);
            if (received.event) |event| self.take(event, answerer);
            std.mem.copyForwards(u8, self.input[0 .. self.input_len - received.consumed], self.input[received.consumed..self.input_len]);
            self.input_len -= received.consumed;
            if (received.event == null and received.consumed == 0) return;
        }
    }

    fn take(self: *Server, event: server.Event, answerer: Answerer) void {
        switch (event) {
            .request => |request| self.answer(request, answerer),
            .writable => self.write_owed(),
            .body, .trailers, .cancelled, .done, .send, .close, .ended, .closed => {},
        }
    }

    /// Reads the request's query, and answers it as the script says. The content goes into the
    /// connection as its output and the stream's window take it (RFC 9113 §6.9).
    fn answer(self: *Server, request: server.Request, answerer: Answerer) void {
        self.version = request.version;
        const query = read_request(self, &self.endpoint, request) orelse return;
        if (self.script.hold) {
            self.held += 1;
            return;
        }
        const owed = for (&self.owed) |*slot| {
            if (!slot.live) break slot;
        } else return;
        const len = answerer.answer(answerer.context, query, &owed.content) orelse return;
        if (!respond_head(&self.endpoint, request.id, self.script, len)) return;
        owed.live = true;
        owed.id = request.id;
        owed.len = len;
        owed.written = 0;
        self.write_owed();
    }

    /// Writes as much of each answer's content as the connection takes. An answer whose content
    /// has all gone is answered.
    fn write_owed(self: *Server) void {
        for (&self.owed) |*owed| {
            if (!owed.live) continue;
            owed.written += write_content(&self.endpoint, owed.id, owed.content[owed.written..owed.len]) orelse {
                owed.live = false;
                continue;
            };
            if (owed.written < owed.len) continue;
            owed.live = false;
            self.answered += 1;
        }
    }
};

/// An answer whose head has gone, and the content that it still owes.
const Owed = struct {
    live: bool = false,
    id: server.Id = undefined,
    content: [cocuyo.limits.message_bytes_max]u8 = undefined,
    len: usize = 0,
    written: usize = 0,
};

/// Writes `content`, the rest of request `id`'s content, until the endpoint takes no more. The
/// octets written, or null when the endpoint refused the request.
fn write_content(endpoint: anytype, id: server.Id, content: []const u8) ?usize {
    var written: usize = 0;
    // Bounded: each pass writes an octet of the content, or stops.
    for (0..content.len + 1) |_| {
        written += endpoint.write_body(id, .{ .octets = content[written..], .end = true }) catch |failure| switch (failure) {
            // No room in the output, or no window (RFC 9113 §6.9): the request's `writable` says
            // when to write again.
            error.Blocked, error.NoSpaceLeft => return written,
            else => return null,
        };
        if (written == content.len) return written;
    }
    return written;
}

/// What a route of the server names: a query in a GET's `dns` parameter (RFC 8484 §4.1).
const Route = enum { query };

/// The paths a test's channel asks for, which colibri's router matches (its decision 122): the
/// root, which a template of a query alone gives, and a path of one segment, such as the template's
/// `/dns-query`. The router reads a path up to its first "?", so the query stays for `dns`.
const routes = server.router(Route, .{
    .{ .get, "/", .query },
    .{ .get, "/:resource", .query },
});

/// The status of a request that no route takes: 404 for a path, 405 for a method of another path
/// (RFC 9110 §15.5.5, §15.5.6), and 501 for a method no route names (§15.6.2).
const status_not_found: u16 = 404;
const status_method_not_allowed: u16 = 405;
const status_not_implemented: u16 = 501;

/// Reads a request's query out of its path's `dns` parameter (RFC 8484 §4.1) into `record`, a
/// server that keeps what it heard, and what the request's `accept` and `accept-encoding` asked for.
/// A request that no route takes gets the status the router names from `endpoint`, and null; so
/// does one whose path carries no query, with nothing.
pub fn read_request(record: anytype, endpoint: anytype, request: server.Request) ?[]const u8 {
    const path = request.path orelse return null;
    var parameters: server.PathParameters = .{};
    switch (routes.match(request.method, path, &parameters)) {
        .found => |route| assert(route == .query),
        .method_not_allowed => |allow| return refuse(endpoint, request.id, status_method_not_allowed, allow),
        .not_found => return refuse(endpoint, request.id, status_not_found, null),
        .not_implemented => return refuse(endpoint, request.id, status_not_implemented, null),
    }
    const query = doh.query.query_of(path, &record.query) orelse return null;
    record.query_len = query.len;
    record.accept.keep(request.fields.find("accept"));
    record.accept_encoding.keep(request.fields.find("accept-encoding"));
    return query;
}

/// Answers request `id` with `status` and no content, and with the Allow field a 405 carries (RFC
/// 9110 §15.5.6). Null, for the caller to return.
fn refuse(endpoint: anytype, id: server.Id, status: u16, allow: ?[]const u8) ?[]const u8 {
    const fields = [_]server.Field{.{ .name = "allow", .value = allow orelse "" }};
    const named: usize = if (allow != null) fields.len else 0;
    endpoint.respond(id, .{ .status = status, .fields = fields[0..named], .end = true }) catch {};
    return null;
}

/// Answers request `id` on `endpoint`, over TCP or QUIC: the head the script says, then `content`,
/// or a reset once the head has gone. Whether it answered.
pub fn respond(endpoint: anytype, id: server.Id, script: Script, content: []const u8) bool {
    if (!respond_head(endpoint, id, script, content.len)) return false;
    var written: usize = 0;
    // Bounded: each pass writes an octet of the content, or stops.
    for (0..content.len + 1) |_| {
        written += endpoint.write_body(id, .{ .octets = content[written..], .end = true }) catch return false;
        if (written == content.len) return true;
    }
    return false;
}

/// Writes the head the script says for content `content_len` octets long, or a reset once the
/// head has gone. Whether the content goes next.
fn respond_head(endpoint: anytype, id: server.Id, script: Script, content_len: usize) bool {
    var digits: [limits.server_length_digits_max]u8 = undefined;
    var fields: [limits.server_response_fields_max]server.Field = undefined;
    var count: usize = 0;
    fields[count] = .{ .name = "content-type", .value = script.content_type };
    count += 1;
    fields[count] = .{ .name = "content-length", .value = std.fmt.bufPrint(&digits, "{d}", .{content_len}) catch unreachable };
    count += 1;
    if (script.content_encoding) |coding| {
        fields[count] = .{ .name = "content-encoding", .value = coding };
        count += 1;
    }
    if (script.age) |age| {
        fields[count] = .{ .name = "age", .value = age };
        count += 1;
    }
    endpoint.respond(id, .{ .status = script.status, .fields = fields[0..count], .end = false }) catch return false;
    if (script.reset_after_head) {
        // RFC 9113 §6.4 and RFC 9114 §4.1.1: the stream ends at once, before its content.
        endpoint.cancel(id);
        return false;
    }
    return true;
}
