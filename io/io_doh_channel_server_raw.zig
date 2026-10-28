//! A DoH server over HTTP/1.1 that writes its own octets, for `cocuyo_doh`'s tests of the room
//! colibri keeps for a partial head or trailer section (docs/design.md §16 decision 41;
//! c4milo/cocuyo#44). It runs colibri's TLS record server under the test identity, and selects
//! `http/1.1`. Once the GETs it waits for have come, it answers with the octets a test gives. It
//! seals them in records of the plaintext lengths the test names (RFC 9846 §5.1).
//!
//! colibri's endpoint writes no whitespace around a value and no reason phrase of a program's. So
//! its head is no longer than the field section its client takes, 16,384 octets. A sound head may
//! be longer: whitespace around a value is part of the head, and no part of the value (RFC 9110
//! §5.5).
const std = @import("std");
const assert = std.debug.assert;
const server = @import("server");
const tls = @import("tls");
const constants = @import("io_doh_channel_constants.zig");
const limits = @import("io_doh_channel_limits.zig");
const identity = @import("io_doh_channel_identity.zig");

/// The protocol the server selects (RFC 7301 §3.2): HTTP/1.1 alone.
const alpn = [_][]const u8{"http/1.1"};
/// RFC 9846 §4.3.2's cookie key, of one octet repeated, and the octet the server's stream is
/// seeded with. Test-only values.
const cookie_octet: u8 = 0x5e;
const stream_octet: u8 = 0x35;
const cookie_key: [tls.constants.server_key_len]u8 = @splat(cookie_octet);
/// The end of a request's head over HTTP/1.1: an empty line after the field lines.
const head_end = "\r\n\r\n";

/// The calls on the records once the handshake has completed.
const Provider = @typeInfo(@TypeOf(tls.record.Server.provider)).@"fn".return_type.?;

pub const RawServer = struct {
    config: tls.record.ServerConfig = undefined,
    session: tls.record.Server = undefined,
    stream: std.Random.ChaCha = std.Random.ChaCha.init(@splat(stream_octet)),
    records: ?Provider = null,
    /// The records the client sent and the server has not read.
    input: [limits.stream_bytes_max]u8 = undefined,
    input_len: usize = 0,
    /// The request's plaintext up to the end of its head.
    request: [limits.server_request_bytes_max]u8 = undefined,
    request_len: usize = 0,
    /// The response's plaintext, its head then its content, before the server seals it.
    response: [limits.server_response_bytes_max]u8 = undefined,
    /// The octets the server owes the client: the handshake's flight, then the response's records.
    owed: [limits.server_response_bytes_max]u8 = undefined,
    owed_len: usize = 0,
    /// The heads of requests the server waits for before it answers, which `init` takes. Then
    /// that many heads arrived whole, and the server answered them.
    heads_wanted: usize = 1,
    asked: bool = false,
    answered: bool = false,

    pub fn init(self: *RawServer, unix_seconds: u64, heads_wanted: usize) !void {
        assert(heads_wanted > 0);
        self.* = .{ .heads_wanted = heads_wanted };
        try self.config.init(.{
            .ecdsa_p256 = .{ .chain = &identity.chain, .public_key = identity.public_key, .private_key = identity.private_key },
            .cookie_key = &cookie_key,
            .alpn = &alpn,
            .cpu = identity.cpu_not_stated,
        });
        try self.session.start(&self.config, self.stream.random(), unix_seconds);
    }

    /// Takes what the client sent: the handshake, then the records of its request.
    pub fn receive(self: *RawServer, bytes: []const u8) !void {
        assert(self.input_len + bytes.len <= self.input.len);
        @memcpy(self.input[self.input_len..][0..bytes.len], bytes);
        self.input_len += bytes.len;
        if (self.records == null) try self.handshake();
        if (self.records != null) try self.open();
    }

    fn handshake(self: *RawServer) !void {
        const room = self.owed[self.owed_len..];
        assert(room.len >= server.constants.flight_len_max);
        const progress = try self.session.handshake(self.input[0..self.input_len], room);
        self.owed_len += progress.written;
        self.take(progress.consumed);
        if (progress.complete) self.records = self.session.provider();
    }

    /// Opens each whole record, and keeps its plaintext until the heads it waits for have ended.
    fn open(self: *RawServer) !void {
        const records = self.records.?;
        // Bounded: each pass takes a whole record, or stops.
        for (0..self.input.len + 1) |_| {
            const room = self.request[self.request_len..];
            const opened = try records.vtable.decrypt_record(records.context, self.input[0..self.input_len], room);
            if (opened.consumed == 0) return;
            self.take(opened.consumed);
            self.request_len += opened.plaintext_len;
            if (std.mem.count(u8, self.request[0..self.request_len], head_end) >= self.heads_wanted) self.asked = true;
        }
    }

    fn take(self: *RawServer, consumed: usize) void {
        assert(consumed <= self.input_len);
        std.mem.copyForwards(u8, self.input[0 .. self.input_len - consumed], self.input[consumed..self.input_len]);
        self.input_len -= consumed;
    }

    /// Seals `head`, then `content`, into records whose plaintext lengths follow `lengths`: one
    /// record for each length, and the last length again until nothing is left.
    pub fn respond(self: *RawServer, head: []const u8, content: []const u8, lengths: []const usize) !void {
        assert(self.asked and !self.answered);
        assert(lengths.len > 0);
        const plaintext = &self.response;
        @memcpy(plaintext[0..head.len], head);
        @memcpy(plaintext[head.len..][0..content.len], content);
        const total = head.len + content.len;
        const records = self.records.?;
        var at: usize = 0;
        // Bounded: each pass seals an octet at least, or fails.
        for (0..total) |index| {
            if (at == total) break;
            const length = @min(lengths[@min(index, lengths.len - 1)], total - at);
            const sealed = try records.vtable.encrypt_record(records.context, plaintext[at..][0..length], self.owed[self.owed_len..]);
            assert(sealed.consumed == length);
            at += length;
            self.owed_len += sealed.written;
        }
        assert(at == total);
        self.answered = true;
    }

    /// Writes what the server owes into `out`, as much as it holds.
    pub fn send(self: *RawServer, out: []u8) usize {
        const written = @min(out.len, self.owed_len);
        @memcpy(out[0..written], self.owed[0..written]);
        std.mem.copyForwards(u8, self.owed[0 .. self.owed_len - written], self.owed[written..self.owed_len]);
        self.owed_len -= written;
        return written;
    }
};
