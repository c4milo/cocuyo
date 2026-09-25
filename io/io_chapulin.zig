//! chapulin's TLS session, over its record transport, behind the seam of docs/design.md §21. The
//! engine hands it whole records and takes the records it makes; chapulin does the handshake,
//! the ciphers, and the certificate, pin and ticket checks. Built only when `-Dchapulin` names a
//! checkout whose `bin/chapulin-record.o` was made by
//!
//!     make RAND=extern TRUST=webpki TRANSPORT=record lib && cp bin/chapulin.o bin/chapulin-record.o
//!
//! and the headers are read from that checkout in place: nothing of chapulin is vendored.
//!
//! chapulin's calls take a callback for every byte it sends or reads once connected. Here they
//! are buffer copies that never block: `send` stages what chapulin writes, and `recv` serves the
//! one whole record the engine handed over, and then nothing, which chapulin answers with
//! `CH_RECORD_AGAIN` (its rec.h). The image supplies `ch_rand_bytes` and `ch_assert_fail` once,
//! through the `chapulin_hooks` module it binds (`io/io_chapulin_hooks.zig`), and the session
//! points `ch_rand_bytes` at the engine's seeded stream while a handshake runs.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
// The engine's constants, through the engine's module: a file belongs to one module.
const constants = @import("io").constants;
const hooks = @import("chapulin_hooks");

// chapulin's object calls the hooks whatever of the session a program uses, so the image links
// them whenever it links the session: a module is analysed, and its exports emitted, only when
// something references it.
comptime {
    _ = hooks;
}

pub const c = @cImport({
    @cDefine("CH_TRUST_WEBPKI", "1");
    @cDefine("CH_TRANSPORT_RECORD", "1");
    @cDefine("CH_RAND_EXTERN", "1");
    @cInclude("rec.h");
    @cInclude("tls.h");
    @cInclude("build.h");
});

comptime {
    if (constants.tls_records_out_bytes < c.REC_HDR + c.CH_TX_STAGE + cocuyo.constants.query_bytes_max + constants.tls_record_overhead_bytes) {
        @compileError("a connection's records cannot hold what chapulin stages beside a query sealed at its longest");
    }
}

pub const Session = struct {
    pub const enabled = true;
    /// What the session stages between two of the engine's calls: at most what chapulin's own
    /// buffer holds, a record's header and its staging bound (its session.h), which is a
    /// ClientHello at its longest or a query sealed.
    pub const out_bytes_max = c.REC_HDR + c.CH_TX_STAGE;
    pub const Error = error{Failed};
    pub const Handshake = enum { going, done };
    pub const Opened = union(enum) { data: usize, nothing, closed };

    /// What every session starts from (docs/design.md §21). The anchors are the caller's and
    /// outlive the engine.
    pub const Context = struct {
        anchors: []const c.ch_trust_anchor = &.{},
        stream: std.Random.ChaCha = undefined,
        unix_seconds: u64 = 0,
        at_ns: u64 = 0,

        /// `seed` must come from a CSPRNG; `unix_seconds` is the wall clock at the caller's
        /// `now_ns`.
        pub fn init(anchors: []const c.ch_trust_anchor, seed: [std.Random.ChaCha.secret_seed_length]u8, unix_seconds: u64, now_ns: u64) Context {
            assert(anchors.len <= c.CH_WEBPKI_ANCHOR_MAX);
            return .{ .anchors = anchors, .stream = std.Random.ChaCha.init(seed), .unix_seconds = unix_seconds, .at_ns = now_ns };
        }
    };

    /// Whether the build record chapulin's object exports matches what its headers give under the
    /// defines of the import above (chapulin's build.h). The record is named after the object's
    /// transport, `ch_build_record`, so one image can link a QUIC object beside it: translate-c
    /// cannot read the `ch_build` macro that maps the name, and the name is written here.
    fn built_as_read(record: *const c.ch_build_info) bool {
        return c.ch_build_matches(record) != 0;
    }

    /// A ticket as chapulin handed it to `on_ticket`, copied: the identity, the resumption
    /// secret, the lifetime, the age mask and the binding to the hostname, the anchors and the
    /// pins (chapulin's webpki_ticket.h).
    pub const Ticket = struct {
        identity: [c.CH_TICKET_ID_MAX]u8,
        identity_len: u16,
        psk: [c.SHA256_LEN]u8,
        lifetime_s: u32,
        age_add: u32,
        binding: [c.SHA256_LEN]u8,
    };

    record: c.ch_record = undefined,
    config: c.ch_cfg = undefined,
    /// chapulin's own buffer: the handshake's reassembly, then plaintext it has not handed over.
    buffer: [c.CH_MIN_RXBUF]u8 = undefined,
    hostname: [cocuyo.constants.name_text_bytes_max]u8 = undefined,
    /// The ticket this session resumes with: chapulin reads it through `config` until it starts.
    resuming: Ticket = undefined,
    /// The engine's stream, which chapulin draws from during every call of the handshake.
    stream: ?*std.Random.ChaCha = null,
    given: ?Ticket = null,
    staged: [out_bytes_max]u8 = undefined,
    staged_len: usize = 0,
    /// The record `recv` serves, and how much of it has gone.
    input: []const u8 = &.{},
    input_at: usize = 0,
    live: bool = false,
    broken: bool = false,

    pub fn lifetime_ns(ticket: *const Ticket) u64 {
        return @as(u64, ticket.lifetime_s) * constants.ns_per_second;
    }

    /// Stages the hello for `start.tls`'s server, resuming with `start.ticket` when there is
    /// one, and collects it at once.
    pub fn start(self: *Session, start_with: anytype) Error!void {
        const tls: *const cocuyo.Tls = start_with.tls;
        const context = start_with.context;
        // The object linked must be the one these headers describe: an object built with other
        // defines lays its sessions out otherwise, and nothing else would say so. Every session
        // starts here, whatever made its context.
        if (!built_as_read(&c.ch_build_record)) {
            std.debug.panic("chapulin's object was built with other defines than cocuyo reads its headers with: rebuild it as build/dot.zig says", .{});
        }
        self.* = .{};
        self.config = std.mem.zeroes(c.ch_cfg);
        self.config.buf = &self.buffer;
        self.config.buf_len = self.buffer.len;
        self.config.send = send;
        self.config.recv = recv;
        self.config.on_ticket = keep_ticket;
        self.config.io = self;
        self.trust(tls, context, start_with.now_ns);
        if (start_with.ticket) |ticket| self.resume_with(ticket, start_with.ticket_age_ns);
        self.stream = &context.stream;
        hooks.enter(self.stream.?);
        defer hooks.leave();
        if (c.ch_record_init(&self.record, &self.config) != c.CH_OK) return Error.Failed;
        self.live = true;
        try self.collect();
    }

    /// The anchors, the clock and the name of a chain check, and the pins, whichever the server
    /// is known by (RFC 8310 §6.3, docs/design.md §21).
    fn trust(self: *Session, tls: *const cocuyo.Tls, context: anytype, now_ns: u64) void {
        if (context.anchors.len > 0) {
            self.config.anchors = context.anchors.ptr;
            self.config.anchor_count = context.anchors.len;
            self.config.now_seconds = context.unix_seconds + (now_ns -| context.at_ns) / constants.ns_per_second;
        }
        if (tls.name) |name| {
            var length = name.write_text(&self.hostname);
            // chapulin takes a hostname, which has no root label's dot.
            if (length > 1 and self.hostname[length - 1] == '.') length -= 1;
            self.config.hostname = &self.hostname;
            self.config.hostname_len = length;
        }
        if (tls.pins.len > 0) {
            self.config.spki_pins = @ptrCast(tls.pins.ptr);
            self.config.spki_pin_count = tls.pins.len;
        }
    }

    /// The obfuscated age is the ticket's age in milliseconds plus its age mask, modulo 2^32
    /// (RFC 9846 §4.3.11.1).
    fn resume_with(self: *Session, ticket: Ticket, age_ns: u64) void {
        self.resuming = ticket;
        const age_ms: u32 = @truncate(age_ns / constants.ns_per_millisecond);
        self.config.psk = &self.resuming.psk;
        self.config.psk_len = self.resuming.psk.len;
        self.config.psk_id = &self.resuming.identity;
        self.config.psk_id_len = self.resuming.identity_len;
        self.config.resumption = 1;
        self.config.obfuscated_age = age_ms +% self.resuming.age_add;
        self.config.ticket_binding = &self.resuming.binding;
    }

    /// Moves what chapulin staged during the handshake to `staged`, as soon as it staged it.
    fn collect(self: *Session) Error!void {
        var pieces: usize = 0;
        while (pieces < constants.chapulin_out_pieces_max) : (pieces += 1) {
            var made: usize = 0;
            const room = self.staged[self.staged_len..];
            if (room.len == 0) return self.fail();
            if (c.ch_record_out(&self.record, room.ptr, room.len, &made) != c.CH_OK) return self.fail();
            if (made == 0) return;
            self.staged_len += made;
        }
        return self.fail();
    }

    pub fn take_out(self: *Session, out: []u8) usize {
        assert(out.len >= self.staged_len);
        const made = self.staged_len;
        @memcpy(out[0..made], self.staged[0..made]);
        self.staged_len = 0;
        return made;
    }

    /// One whole record while the handshake runs. chapulin reads records in place, so `record`
    /// is rewritten.
    pub fn handshake(self: *Session, record: []u8) Error!Handshake {
        assert(self.live);
        hooks.enter(self.stream.?);
        defer hooks.leave();
        var consumed: usize = 0;
        if (c.ch_record_in(&self.record, record.ptr, record.len, &consumed) != c.CH_OK) return self.fail();
        // The engine hands over one whole record, and chapulin takes whole records: less is a
        // programmer's error, the engine's or chapulin's, not the peer's.
        assert(consumed == record.len);
        try self.collect();
        return switch (c.ch_record_state(&self.record)) {
            c.CH_ST_CONNECTED => .done,
            c.CH_ST_START => .going,
            else => self.fail(),
        };
    }

    /// Whether the handshake resumed with the ticket it offered: chapulin completes a declined
    /// ticket as a full handshake in the same connection (its docs/decisions.md 55), so an
    /// offered ticket says nothing of whether it was taken.
    pub fn resumed(self: *const Session) bool {
        return self.record.t.psk_selected == 1;
    }

    pub fn seal(self: *Session, plaintext: []const u8) Error!void {
        assert(self.live);
        if (c.ch_write(&self.record.t, plaintext.ptr, plaintext.len) != c.CH_OK) return self.fail();
        if (self.broken) return self.fail();
    }

    /// One whole record once up: its plaintext, or nothing the engine sees (a ticket, a
    /// KeyUpdate, whose answer chapulin sends through `send`), or the peer's close.
    pub fn open(self: *Session, record: []u8, plaintext: []u8) Error!Opened {
        assert(self.live);
        self.input = record;
        self.input_at = 0;
        const total = self.read_all(plaintext) catch |err| switch (err) {
            error.Closed => return .closed,
            error.Failed => return self.fail(),
        };
        if (self.broken or self.input_at != self.input.len) return self.fail();
        return if (total > 0) .{ .data = total } else .nothing;
    }

    /// Reads the record's plaintext into `plaintext` until chapulin has no record left to read,
    /// which it says with `CH_RECORD_AGAIN`. The peer's close is `Closed`, and only before data.
    fn read_all(self: *Session, plaintext: []u8) error{ Closed, Failed }!usize {
        var total: usize = 0;
        var reads: usize = 0;
        while (reads < constants.chapulin_reads_per_record_max and total < plaintext.len) : (reads += 1) {
            const read = c.ch_read(&self.record.t, plaintext[total..].ptr, plaintext.len - total);
            if (read > 0) {
                total += @intCast(read);
            } else if (read == c.CH_RECORD_AGAIN) {
                return total;
            } else if (read == 0 and total == 0) {
                return error.Closed;
            } else {
                return error.Failed;
            }
        }
        return total;
    }

    pub fn take_ticket(self: *Session) ?Ticket {
        const ticket = self.given;
        self.given = null;
        return ticket;
    }

    /// The `close_notify` of an idle close (RFC 9846 §6.1), sent through `send`.
    pub fn close(self: *Session) void {
        assert(self.live);
        c.ch_close(&self.record.t);
        self.live = false;
    }

    pub fn wipe(self: *Session) void {
        if (self.live) c.ch_record_close(&self.record);
        self.live = false;
    }

    fn fail(self: *Session) Error {
        self.wipe();
        return Error.Failed;
    }
};

/// chapulin sends: the bytes are staged for the engine. A send that does not fit is a failure,
/// which chapulin takes as the session's end.
fn send(io: ?*anyopaque, bytes: [*c]const u8, count: usize) callconv(.c) c_int {
    const self: *Session = @ptrCast(@alignCast(io.?));
    if (self.staged_len + count > self.staged.len) {
        self.broken = true;
        return -1;
    }
    @memcpy(self.staged[self.staged_len..][0..count], bytes[0..count]);
    self.staged_len += count;
    return 0;
}

/// chapulin reads: the rest of the record the engine handed over, and then nothing, which at a
/// record's boundary is chapulin's `CH_RECORD_AGAIN`.
fn recv(io: ?*anyopaque, bytes: [*c]u8, count: usize) callconv(.c) c_int {
    const self: *Session = @ptrCast(@alignCast(io.?));
    const rest = self.input[self.input_at..];
    const served = @min(rest.len, count);
    @memcpy(bytes[0..served], rest[0..served]);
    self.input_at += served;
    return @intCast(served);
}

fn keep_ticket(io: ?*anyopaque, ticket: [*c]const c.ch_ticket) callconv(.c) void {
    const self: *Session = @ptrCast(@alignCast(io.?));
    const given = ticket.*;
    if (given.identity_len > c.CH_TICKET_ID_MAX) return;
    var kept: Session.Ticket = .{
        .identity = undefined,
        .identity_len = @intCast(given.identity_len),
        .psk = given.psk,
        .lifetime_s = given.lifetime_s,
        .age_add = given.age_add,
        .binding = given.binding,
    };
    @memcpy(kept.identity[0..given.identity_len], given.identity[0..given.identity_len]);
    self.given = kept;
}

// Tests. They need no network: a session starts, stages a hello, and refuses what chapulin
// refuses.

const testing = std.testing;

test "the linked object's build record matches these headers, and one that differs does not" {
    try testing.expect(Session.built_as_read(&c.ch_build_record));
    var other = c.ch_build_record;
    other.sizeof_ch_tls += 1;
    try testing.expect(!Session.built_as_read(&other));
}

test "a session starts and stages a hello, a TLS handshake record" {
    var context = Session.Context.init(&.{}, @splat(7), 1_700_000_000, 0);
    const pin: cocuyo.Pin = @splat(0xab);
    const pins = [_]cocuyo.Pin{pin};
    const tls: cocuyo.Tls = .{ .pins = &pins };
    const session = try testing.allocator.create(Session);
    defer testing.allocator.destroy(session);
    session.* = .{};
    try session.start(.{ .tls = &tls, .ticket = @as(?Session.Ticket, null), .ticket_age_ns = 0, .context = &context, .now_ns = 0 });
    var out: [Session.out_bytes_max]u8 = undefined;
    const made = session.take_out(&out);
    // A handshake record (RFC 9846 §5.1): content type 22, then the length of the body.
    try testing.expect(made > constants.tls_record_header_bytes);
    try testing.expectEqual(@as(u8, 22), out[0]);
    const body = std.mem.readInt(u16, out[constants.tls_record_length_at..][0..@sizeOf(u16)], .big);
    try testing.expectEqual(made, constants.tls_record_header_bytes + body);
    session.wipe();
}

test "a session with neither pins nor anchors for its name is refused before a byte" {
    var context = Session.Context.init(&.{}, @splat(7), 1_700_000_000, 0);
    const tls: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text("dns.example.") };
    const session = try testing.allocator.create(Session);
    defer testing.allocator.destroy(session);
    session.* = .{};
    try testing.expectError(Session.Error.Failed, session.start(.{ .tls = &tls, .ticket = @as(?Session.Ticket, null), .ticket_age_ns = 0, .context = &context, .now_ns = 0 }));
    var out: [Session.out_bytes_max]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), session.take_out(&out));
}
