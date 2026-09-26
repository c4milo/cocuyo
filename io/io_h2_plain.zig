//! A record-mode TLS provider that encrypts nothing, for the gate (docs/design.md §24, DoH over
//! HTTP/2). colibri's h2 connection takes a `tls.Provider`, and this one lets the engine run
//! colibri's real HTTP/2 on the twin: frames, streams, flow control, resets and GOAWAY, with
//! nothing sealed. It is written from colibri's provider table and RFC 9846, and it is for tests:
//! a consumer's connection runs chapulin's record transport instead.
//!
//! A record is RFC 9846 §5.1's: a content type, the legacy version, and a two-octet length. The
//! handshake's records carry made-up messages, each framed as §4 frames one: a type octet, a 24-bit
//! length, the body. The client's hello names the protocols it offers, each after its length as
//! RFC 7301 §3.1 lists them, then one octet saying whether it resumes. The server's hello names the
//! protocol it selects, or none, and whether it took the ticket; its Finished follows. The client
//! is complete once it has read that Finished, and owes its own, which ends the server's
//! handshake. After it, every record is application data whose body is
//! the plaintext, its inner content type, and sixteen octets standing for the AEAD's tag, which
//! check nothing (§5.2). A server that keeps tickets sends one once the handshake has ended.
const std = @import("std");
const assert = std.debug.assert;
const tls = @import("h2").tls;

pub const Role = enum { client, server };

/// RFC 9846 §5.1's content types and §4's handshake message types, as the records carry them.
const ContentType = enum(u8) { alert = 21, handshake = 22, application_data = 23 };
const Message = enum(u8) { client_hello = 1, server_hello = 2, new_session_ticket = 4, certificate_request = 13, finished = 20, key_update = 24 };

const header_bytes = tls.constants.record_header_len;
const length_at = 3;
/// A message's type and its 24-bit length (RFC 9846 §4).
const message_length_bytes = 3;
const message_header_bytes = 1 + message_length_bytes;
/// What an AEAD of TLS 1.3's suites adds to a record, which the plain records stand in for.
const tag_bytes = 16;
/// The inner content type after a record's plaintext (RFC 9846 §5.2).
const inner_type_bytes = 1;
const alpn_bytes_max = 16;
/// A hello's protocol follows one octet of length, and one octet saying whether it resumes ends
/// it: the client's offers its protocol, and the server's names the one it selected.
const hello_overhead_bytes = 2;
const hello_bytes_max = alpn_bytes_max + hello_overhead_bytes;
/// The longest flight: the server's hello and its Finished.
const flight_bytes_max = message_header_bytes + hello_bytes_max + message_header_bytes;
/// An alert's level and description (RFC 9846 §6); a `close_notify` is a warning.
const alert_level_warning = 1;
const alert_bytes = 2;
/// The suite the plain records claim, one colibri admits.
const suite = tls.constants.cipher_suite_aes_128_gcm_sha256;

pub const Session = struct {
    role: Role,
    stage: enum { hello, awaiting, complete, failed } = .hello,
    /// A client's offer, or the protocol a server takes when a client offers it.
    protocol: [alpn_bytes_max]u8 = undefined,
    protocol_len: u8 = 0,
    /// The protocol the handshake selected, if any.
    selected: [alpn_bytes_max]u8 = undefined,
    selected_len: u8 = 0,
    has_selected: bool = false,
    /// A client offers resumption; a server that keeps tickets takes it, and gives one.
    resuming: bool = false,
    resumed: bool = false,
    tickets: bool = false,
    /// A server selects another protocol than the one offered, as a refusing script says.
    other_protocol: bool = false,
    owed: enum { none, hello, server_flight, finished, ticket } = .none,
    /// The client heard a ticket; the peer's alert, until taken.
    ticket_seen: bool = false,
    alert: ?tls.AlertReport = null,
    close_sent: bool = false,

    pub fn client(alpn: []const u8, resuming: bool) Session {
        var session: Session = .{ .role = .client, .resuming = resuming, .owed = .hello };
        session.set_protocol(alpn);
        return session;
    }

    pub fn server(alpn: []const u8, tickets: bool, other_protocol: bool) Session {
        var session: Session = .{ .role = .server, .tickets = tickets, .other_protocol = other_protocol };
        session.set_protocol(alpn);
        return session;
    }

    fn set_protocol(self: *Session, alpn: []const u8) void {
        assert(alpn.len > 0 and alpn.len <= alpn_bytes_max);
        @memcpy(self.protocol[0..alpn.len], alpn);
        self.protocol_len = @intCast(alpn.len);
    }

    pub fn provider(self: *Session) tls.Provider {
        return .{ .context = @ptrCast(self), .vtable = &vtable };
    }

    /// Whether a ticket came since the last call.
    pub fn take_ticket(self: *Session) bool {
        defer self.ticket_seen = false;
        return self.ticket_seen;
    }

    pub fn wipe(self: *Session) void {
        self.* = .{ .role = self.role, .stage = .failed };
    }
};

const vtable: tls.VTable = .{
    .handshake_read = handshake_read,
    .handshake_write = handshake_write,
    .encrypt_record = encrypt_record,
    .decrypt_record = decrypt_record,
    .negotiated_alpn = negotiated_alpn,
    .handshake_complete = handshake_complete,
    .negotiated_parameters = negotiated_parameters,
    .take_alert = take_alert,
    .send_close_notify = send_close_notify,
    .initiate_key_update = initiate_key_update,
    .export_keying_material = export_keying_material,
};

fn session_of(context: *anyopaque) *Session {
    return @ptrCast(@alignCast(context));
}

fn session_of_const(context: *const anyopaque) *const Session {
    return @ptrCast(@alignCast(context));
}

/// A whole record of `input`: its type and its body, and the octets it takes; null when no whole
/// record is there yet.
fn record_of(input: []const u8) ?struct { kind: u8, body: []const u8, len: usize } {
    if (input.len < header_bytes) return null;
    const body_len: usize = std.mem.readInt(u16, input[length_at..][0..@sizeOf(u16)], .big);
    if (input.len < header_bytes + body_len) return null;
    return .{ .kind = input[0], .body = input[header_bytes..][0..body_len], .len = header_bytes + body_len };
}

/// Writes a record of `kind` around `body`, and returns its length.
fn write_record(kind: ContentType, body: []const u8, output: []u8) usize {
    assert(output.len >= header_bytes + body.len);
    output[0] = @intFromEnum(kind);
    std.mem.writeInt(u16, output[1..][0..@sizeOf(u16)], tls.constants.version_tls_1_2, .big);
    std.mem.writeInt(u16, output[length_at..][0..@sizeOf(u16)], @intCast(body.len), .big);
    @memcpy(output[header_bytes..][0..body.len], body);
    return header_bytes + body.len;
}

/// Writes a message of `kind` around `body` (RFC 9846 §4), and returns its length.
fn write_message(kind: Message, body: []const u8, output: []u8) usize {
    output[0] = @intFromEnum(kind);
    std.mem.writeInt(u24, output[1..][0..message_length_bytes], @intCast(body.len), .big);
    @memcpy(output[message_header_bytes..][0..body.len], body);
    return message_header_bytes + body.len;
}

// The handshake.

fn handshake_read(context: *anyopaque, input: []const u8, now_ns: u64) tls.provider.HandshakeReadError!usize {
    _ = now_ns;
    const self = session_of(context);
    const record = record_of(input) orelse return 0;
    if (record.kind != @intFromEnum(ContentType.handshake)) return fail(self);
    var at: usize = 0;
    var messages: usize = 0;
    while (at < record.body.len and messages < record.body.len) : (messages += 1) {
        const rest = record.body[at..];
        if (rest.len < message_header_bytes) return fail(self);
        const len: usize = std.mem.readInt(u24, rest[1..][0..message_length_bytes], .big);
        if (rest.len < message_header_bytes + len) return fail(self);
        try hear(self, rest[0], rest[message_header_bytes..][0..len]);
        at += message_header_bytes + len;
    }
    return record.len;
}

fn fail(self: *Session) error{TlsFailed} {
    self.stage = .failed;
    return error.TlsFailed;
}

/// One handshake message, by the role that hears it.
fn hear(self: *Session, kind: u8, body: []const u8) error{TlsFailed}!void {
    switch (self.role) {
        .server => if (kind == @intFromEnum(Message.client_hello) and self.stage == .hello) {
            return hear_hello(self, body);
        } else if (kind == @intFromEnum(Message.finished) and self.stage == .awaiting) {
            self.stage = .complete;
            if (self.tickets) self.owed = .ticket;
            return;
        },
        .client => if (kind == @intFromEnum(Message.server_hello) and self.stage == .awaiting) {
            return hear_server_hello(self, body);
        } else if (kind == @intFromEnum(Message.finished) and self.stage == .awaiting and self.owed == .none) {
            // The server's Finished completes the client's handshake; its own Finished is owed,
            // and goes before anything else it sends (RFC 9846 §4.4.4).
            self.owed = .finished;
            self.stage = .complete;
            return;
        },
    }
    return fail(self);
}

/// A client's hello: the protocols it offers, each after its length, then whether it resumes. The
/// server selects its own when the client offers it (RFC 7301 §3.2), or another if its script says.
fn hear_hello(self: *Session, body: []const u8) error{TlsFailed}!void {
    if (body.len < 1) return fail(self);
    const offered = body[0 .. body.len - 1];
    self.resumed = body[body.len - 1] == 1 and self.tickets;
    var at: usize = 0;
    while (at < offered.len) {
        const len = offered[at];
        if (at + 1 + len > offered.len) return fail(self);
        const name = offered[at + 1 ..][0..len];
        if (std.mem.eql(u8, name, self.protocol[0..self.protocol_len])) select(self, name);
        at += 1 + len;
    }
    if (self.other_protocol) select(self, tls.constants.alpn_http_1_1);
    self.stage = .awaiting;
    self.owed = .server_flight;
}

fn select(self: *Session, name: []const u8) void {
    assert(name.len <= alpn_bytes_max);
    @memcpy(self.selected[0..name.len], name);
    self.selected_len = @intCast(name.len);
    self.has_selected = true;
}

/// The server's hello: the protocol it selected, after its length, or a length of 0 for none; then
/// whether it took the ticket.
fn hear_server_hello(self: *Session, body: []const u8) error{TlsFailed}!void {
    if (body.len < hello_overhead_bytes or body[0] > alpn_bytes_max) return fail(self);
    if (body.len != hello_overhead_bytes + @as(usize, body[0])) return fail(self);
    if (body[0] > 0) select(self, body[1..][0..body[0]]);
    self.resumed = body[body.len - 1] == 1;
}

fn handshake_write(context: *anyopaque, output: []u8, now_ns: u64) tls.provider.HandshakeWriteError!usize {
    _ = now_ns;
    const self = session_of(context);
    if (output.len < tls.constants.record_write_len_min) return error.NoSpaceLeft;
    var body: [flight_bytes_max]u8 = undefined;
    switch (self.owed) {
        .none => return 0,
        .hello => {
            self.owed = .none;
            self.stage = .awaiting;
            return write_record(.handshake, hello_of(self, &body), output);
        },
        .server_flight => {
            self.owed = .none;
            return write_record(.handshake, server_flight_of(self, &body), output);
        },
        .finished => {
            self.owed = .none;
            return write_record(.handshake, body[0..write_message(.finished, &.{}, &body)], output);
        },
        .ticket => {
            self.owed = .none;
            const len = write_message(.new_session_ticket, &.{}, &body);
            return seal_one(.handshake, body[0..len], output);
        },
    }
}

fn hello_of(self: *const Session, out: []u8) []const u8 {
    var offer: [hello_bytes_max]u8 = undefined;
    offer[0] = self.protocol_len;
    @memcpy(offer[1..][0..self.protocol_len], self.protocol[0..self.protocol_len]);
    offer[1 + self.protocol_len] = @intFromBool(self.resuming);
    return out[0..write_message(.client_hello, offer[0 .. self.protocol_len + hello_overhead_bytes], out)];
}

fn server_flight_of(self: *const Session, out: []u8) []const u8 {
    var hello: [hello_bytes_max]u8 = undefined;
    const len: u8 = if (self.has_selected) self.selected_len else 0;
    hello[0] = len;
    @memcpy(hello[1..][0..len], self.selected[0..len]);
    hello[1 + len] = @intFromBool(self.resumed);
    var at = write_message(.server_hello, hello[0 .. len + hello_overhead_bytes], out);
    at += write_message(.finished, &.{}, out[at..]);
    return out[0..at];
}

// Records after the handshake.

/// Seals `plaintext`, whose inner type is `kind`, as one record.
fn seal_one(kind: ContentType, plaintext: []const u8, output: []u8) usize {
    const len = header_bytes + plaintext.len + inner_type_bytes + tag_bytes;
    assert(output.len >= len);
    output[0] = @intFromEnum(ContentType.application_data);
    std.mem.writeInt(u16, output[1..][0..@sizeOf(u16)], tls.constants.version_tls_1_2, .big);
    std.mem.writeInt(u16, output[length_at..][0..@sizeOf(u16)], @intCast(len - header_bytes), .big);
    @memcpy(output[header_bytes..][0..plaintext.len], plaintext);
    output[header_bytes + plaintext.len] = @intFromEnum(kind);
    @memset(output[header_bytes + plaintext.len + inner_type_bytes ..][0..tag_bytes], 0);
    return len;
}

fn encrypt_record(context: *anyopaque, plaintext: []const u8, output: []u8) tls.provider.SealError!tls.provider.Sealed {
    const self = session_of(context);
    if (self.stage != .complete) return error.HandshakeIncomplete;
    const overhead = header_bytes + inner_type_bytes + tag_bytes;
    var sealed: tls.provider.Sealed = .{ .consumed = 0, .written = 0 };
    var records: usize = 0;
    while (sealed.consumed < plaintext.len and records <= plaintext.len) : (records += 1) {
        const room = output.len - sealed.written;
        if (room <= overhead) break;
        const chunk = @min(plaintext.len - sealed.consumed, room - overhead, tls.constants.record_plaintext_len_max);
        sealed.written += seal_one(.application_data, plaintext[sealed.consumed..][0..chunk], output[sealed.written..]);
        sealed.consumed += chunk;
    }
    if (sealed.consumed == 0 and plaintext.len > 0) return error.NoSpaceLeft;
    return sealed;
}

fn decrypt_record(context: *anyopaque, input: []const u8, plaintext: []u8) tls.provider.OpenError!tls.provider.Opened {
    const self = session_of(context);
    const record = record_of(input) orelse return .{ .consumed = 0, .plaintext_len = 0, .content = .incomplete };
    if (self.stage != .complete) return error.HandshakeIncomplete;
    if (record.kind != @intFromEnum(ContentType.application_data)) return error.TlsFailed;
    if (record.body.len < inner_type_bytes + tag_bytes) return error.TlsFailed;
    const inner = record.body[0 .. record.body.len - tag_bytes - inner_type_bytes];
    const kind = record.body[inner.len];
    if (kind == @intFromEnum(ContentType.application_data)) {
        if (inner.len > plaintext.len) return error.NoSpaceLeft;
        @memcpy(plaintext[0..inner.len], inner);
        return .{ .consumed = record.len, .plaintext_len = inner.len, .content = .application_data };
    }
    const content = try content_of(self, kind, inner);
    return .{ .consumed = record.len, .plaintext_len = 0, .content = content };
}

/// What a record that carries no application data holds: a post-handshake message, or an alert.
fn content_of(self: *Session, kind: u8, inner: []const u8) error{TlsFailed}!tls.Content {
    if (kind == @intFromEnum(ContentType.alert)) {
        if (inner.len != alert_bytes) return error.TlsFailed;
        self.alert = .{ .description = @enumFromInt(inner[1]), .origin = .peer };
        return .alert;
    }
    if (kind != @intFromEnum(ContentType.handshake) or inner.len < message_header_bytes) return error.TlsFailed;
    return switch (inner[0]) {
        @intFromEnum(Message.new_session_ticket) => blk: {
            self.ticket_seen = true;
            break :blk .new_session_ticket;
        },
        @intFromEnum(Message.key_update) => .key_update,
        @intFromEnum(Message.certificate_request) => .certificate_request,
        else => error.TlsFailed,
    };
}

fn negotiated_alpn(context: *const anyopaque) ?[]const u8 {
    const self = session_of_const(context);
    if (!self.has_selected) return null;
    return self.selected[0..self.selected_len];
}

fn handshake_complete(context: *const anyopaque) bool {
    return session_of_const(context).stage == .complete;
}

fn negotiated_parameters(context: *const anyopaque) ?tls.provider.Negotiated {
    if (session_of_const(context).stage != .complete) return null;
    return .{ .version = tls.constants.version_tls_1_3, .cipher_suite = suite };
}

fn take_alert(context: *anyopaque) ?tls.AlertReport {
    const self = session_of(context);
    defer self.alert = null;
    return self.alert;
}

fn send_close_notify(context: *anyopaque, output: []u8) tls.provider.CloseError!usize {
    const self = session_of(context);
    if (self.close_sent) return 0;
    const alert = [alert_bytes]u8{ alert_level_warning, @intFromEnum(tls.Alert.close_notify) };
    if (output.len < header_bytes + alert.len + inner_type_bytes + tag_bytes) return error.NoSpaceLeft;
    self.close_sent = true;
    return seal_one(.alert, &alert, output);
}

fn initiate_key_update(context: *anyopaque, request: tls.provider.KeyUpdateRequest, output: []u8) tls.provider.KeyUpdateError!usize {
    _ = context;
    _ = request;
    _ = output;
    return error.Unsupported;
}

fn export_keying_material(context: *anyopaque, label: []const u8, context_value: ?[]const u8, output: []u8) tls.provider.ExportError!void {
    _ = context;
    _ = label;
    _ = context_value;
    _ = output;
    return error.Unsupported;
}

// Tests.

const testing = std.testing;

/// Carries what `from` owes to `to` through its handshake, as a test's socket would.
fn exchange(from: *Session, to: *Session, buffer: []u8) !void {
    const len = try from.provider().vtable.handshake_write(from, buffer, 0);
    if (len == 0) return;
    try testing.expectEqual(len, try to.provider().vtable.handshake_read(to, buffer[0..len], 0));
}

threadlocal var test_buffer: [tls.constants.record_write_len_min]u8 = undefined;

test "a handshake ends on the protocol both name, and each side is complete" {
    var client = Session.client("h2", false);
    var server = Session.server("h2", false, false);
    try exchange(&client, &server, &test_buffer);
    try testing.expect(!client.provider().is_complete());
    try exchange(&server, &client, &test_buffer);
    try testing.expect(client.provider().is_complete() and !server.provider().is_complete());
    try exchange(&client, &server, &test_buffer);
    try testing.expect(client.provider().is_complete() and server.provider().is_complete());
    try testing.expect(client.provider().speaks_h2() and server.provider().speaks_h2());
    try testing.expectEqual(tls.constants.version_tls_1_3, client.provider().vtable.negotiated_parameters(&client).?.version);
}

test "a server that negotiates another protocol leaves the client not speaking h2" {
    var client = Session.client("h2", false);
    var server = Session.server("h2", false, true);
    try exchange(&client, &server, &test_buffer);
    try exchange(&server, &client, &test_buffer);
    try exchange(&client, &server, &test_buffer);
    try testing.expect(client.provider().is_complete() and !client.provider().speaks_h2());
}

test "records carry their plaintext whole, and a ticket and a close_notify are told apart" {
    var client = Session.client("h2", true);
    var server = Session.server("h2", true, false);
    try exchange(&client, &server, &test_buffer);
    try exchange(&server, &client, &test_buffer);
    try exchange(&client, &server, &test_buffer);
    try testing.expect(client.resumed and server.resumed);
    var plaintext: [64]u8 = undefined;
    const sealed = try encrypt_record(&server, "frames", &test_buffer);
    try testing.expectEqual(@as(usize, 6), sealed.consumed);
    const opened = try decrypt_record(&client, test_buffer[0..sealed.written], &plaintext);
    try testing.expectEqualStrings("frames", plaintext[0..opened.plaintext_len]);
    try testing.expect(opened.content == .application_data);
    // The ticket the server owes once the handshake has ended.
    const ticket = try handshake_write(&server, &test_buffer, 0);
    try testing.expect((try decrypt_record(&client, test_buffer[0..ticket], &plaintext)).content == .new_session_ticket);
    try testing.expect(client.take_ticket() and !client.take_ticket());
    const close = try send_close_notify(&server, &test_buffer);
    try testing.expectEqual(@as(usize, 0), try send_close_notify(&server, &test_buffer));
    try testing.expect((try decrypt_record(&client, test_buffer[0..close], &plaintext)).content == .alert);
    try testing.expectEqual(tls.Alert.close_notify, take_alert(&client).?.description);
    try testing.expect(take_alert(&client) == null);
    // A record not yet whole is no record.
    try testing.expect((try decrypt_record(&client, test_buffer[0 .. close - 1], &plaintext)).content == .incomplete);
}
