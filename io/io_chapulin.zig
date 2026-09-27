//! chapulin's TLS session, over its record transport, behind the session interface of
//! docs/design.md §21. The engine hands it whole records and takes the records it makes; chapulin
//! does the handshake, the ciphers, and the certificate, pin and ticket checks. It runs through
//! chapulin's Zig API (chapulin's docs/zig.md), the module of the `chapulin` dependency that
//! `build/dot.zig` builds `RAND=extern TRUST=webpki TRANSPORT=tcp-nonblocking`, which carries the
//! object: nothing of chapulin is vendored, and no object is linked beside the module.
//!
//! Every call is a copy between the engine's buffers and chapulin's. `recordOut` and `write` seal
//! into the session's staged octets, which the engine takes out; `recordIn` and `read` take the one
//! whole record the engine handed over, and what `read` answers of its own accord, a KeyUpdate's
//! answer, is staged the same way. The image supplies `ch_rand_bytes` and `ch_assert_fail` once,
//! through the `chapulin_hooks` module it binds (`io/io_chapulin_hooks.zig`), and the session
//! points `ch_rand_bytes` at the engine's seeded stream while a handshake runs.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
// The engine's constants, through the engine's module: a file belongs to one module.
const constants = @import("io").constants;
const hooks = @import("chapulin_hooks");
const chapulin = @import("chapulin");

/// chapulin's public headers, translated under the defines its object was built with.
pub const c = chapulin.c;

// chapulin's object calls the hooks whatever of the session a program uses, so the image links
// them whenever it links the session: a module is analysed, and its exports emitted, only when
// something references it.
comptime {
    _ = hooks;
}

comptime {
    if (constants.tls_records_out_bytes < c.REC_HDR + c.CH_TX_STAGE + cocuyo.constants.query_bytes_max + constants.tls_record_overhead_bytes) {
        @compileError("a connection's records cannot hold what chapulin stages beside a query sealed at its longest");
    }
    if (Session.out_bytes_max < chapulin.record.alert_record_len) {
        @compileError("the session's staged octets cannot hold the close_notify of an idle close");
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
    /// A NewSessionTicket as chapulin hands it over, its identity included (RFC 9846 §4.6.1). A copy
    /// holds a resumption secret, and whoever holds one zeroes it (chapulin's docs/zig.md).
    pub const Ticket = chapulin.Ticket;

    /// chapulin's record-mode client, whose receive buffer is chapulin's own least: the handshake's
    /// reassembly, then plaintext it has not handed over.
    const Client = chapulin.record.Client(c.CH_MIN_RXBUF);

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

    /// Whether `record` is the build record the linked object's headers describe (chapulin's
    /// build.h). chapulin's own `buildMatches` compares the object's record; a test hands a changed
    /// one here.
    fn built_as_read(record: *const c.ch_build_info) bool {
        return c.ch_build_matches(record) != 0;
    }

    client: Client = undefined,
    hostname: [cocuyo.constants.name_text_bytes_max]u8 = undefined,
    /// The ticket this session resumes with, which chapulin reads through its configuration until
    /// it starts: a copy, which `wipe` zeroes.
    resuming: Ticket = undefined,
    /// The engine's stream, which chapulin draws from during every call of the handshake.
    stream: ?*std.Random.ChaCha = null,
    staged: [out_bytes_max]u8 = undefined,
    staged_len: usize = 0,
    /// Started: `recordClose` has secrets to wipe. Live: records may be sealed and read.
    started: bool = false,
    live: bool = false,

    pub fn lifetime_ns(ticket: *const Ticket) u64 {
        return @as(u64, ticket.ticket.lifetime_s) * constants.ns_per_second;
    }

    /// Stages the hello for `start.tls`'s server, resuming with `start.ticket` when there is
    /// one, and collects it at once.
    pub fn start(self: *Session, start_with: anytype) Error!void {
        // The object linked must be the one these headers describe: an object built with other
        // defines lays its sessions out otherwise, and nothing else would say so. Every session
        // starts here, whatever made its context.
        if (!chapulin.buildMatches()) {
            std.debug.panic("chapulin's object was built with other defines than its headers were read with", .{});
        }
        self.* = .{};
        const configured = self.values(start_with);
        self.stream = &start_with.context.stream;
        hooks.enter(self.stream.?);
        defer hooks.leave();
        self.client.init(configured) catch return self.fail();
        self.started = true;
        self.live = true;
        try self.collect();
    }

    /// The anchors, the clock and the name of a chain check, and the pins, whichever the server
    /// is known by (RFC 8310 §6.3, docs/design.md §21), and the ticket to resume with. A server
    /// known by pins alone, "SPKI + IP", is known by its key and nothing else: it gets no anchors
    /// and no clock, however many the context carries for the servers that have names. chapulin
    /// refuses anchors with no name to check a chain against (its webpki_cfg.c), which would fail
    /// such a server at every start. A named server with no anchors is judged by its pins alone,
    /// its name sent and judged against nothing.
    fn values(self: *Session, start_with: anytype) chapulin.Client {
        const tls: *const cocuyo.Tls = start_with.tls;
        const context = start_with.context;
        const pins: []const chapulin.SpkiPin = tls.pins;
        var client: chapulin.Client = .{ .trust = .{ .pins = .{ .pins = pins } } };
        if (tls.name) |name| {
            var length = name.write_text(&self.hostname);
            // chapulin takes a hostname, which has no root label's dot.
            if (length > 1 and self.hostname[length - 1] == '.') length -= 1;
            const server_name = self.hostname[0..length];
            client.trust = if (context.anchors.len > 0) .{ .web_pki = .{
                .anchors = context.anchors,
                .server_name = server_name,
                .now_seconds = context.unix_seconds + (start_with.now_ns -| context.at_ns) / constants.ns_per_second,
                .pins = pins,
            } } else .{ .pins = .{ .pins = pins, .server_name = server_name } };
        }
        if (start_with.ticket) |ticket| {
            self.resuming = ticket;
            client.ticket = &self.resuming;
            client.ticket_age_ms = start_with.ticket_age_ns / constants.ns_per_millisecond;
        }
        return client;
    }

    /// Moves what chapulin staged during the handshake to `staged`, as soon as it staged it.
    fn collect(self: *Session) Error!void {
        var pieces: usize = 0;
        while (pieces < constants.chapulin_out_pieces_max) : (pieces += 1) {
            const room = self.staged[self.staged_len..];
            if (room.len == 0) return self.fail();
            const made = self.client.recordOut(room) catch return self.fail();
            if (made == 0) return;
            self.staged_len += made;
        }
        return self.fail();
    }

    /// What chapulin staged after a failure: the fatal alert it chose, for the engine to send
    /// before it closes (RFC 9846 §6.2). chapulin hands it over through `recordOut`, refuses once
    /// all of it has gone, and drops it when the session is closed first, so it is taken before
    /// the session is wiped.
    fn collect_alert(self: *Session) void {
        var pieces: usize = 0;
        while (pieces < constants.chapulin_out_pieces_max) : (pieces += 1) {
            const made = self.client.recordOut(self.staged[self.staged_len..]) catch return;
            if (made == 0) return;
            self.staged_len += made;
        }
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
        const consumed = self.client.recordIn(record) catch {
            self.collect_alert();
            return self.fail();
        };
        // The engine hands over one whole record, and chapulin takes whole records: less is a
        // programmer's error, the engine's or chapulin's, not the peer's.
        assert(consumed == record.len);
        try self.collect();
        return switch (self.client.recordState()) {
            .connected => .done,
            .start => .going,
            else => self.fail(),
        };
    }

    /// Whether the handshake resumed with the ticket it offered: chapulin completes a declined
    /// ticket as a full handshake in the same connection (its docs/decisions.md 55), so an
    /// offered ticket says nothing of whether it was taken.
    pub fn resumed(self: *const Session) bool {
        return self.client.pskSelected();
    }

    /// Seals a query whole into the staged octets, or fails: chapulin seals all of it or none.
    pub fn seal(self: *Session, plaintext: []const u8) Error!void {
        assert(self.live);
        const written = self.client.write(plaintext, self.staged[self.staged_len..]) catch return self.fail();
        self.staged_len += written;
        assert(self.staged_len <= self.staged.len);
    }

    /// One whole record once up: its plaintext, or nothing the engine sees (a ticket, or a
    /// KeyUpdate, whose answer is staged), or the peer's close.
    pub fn open(self: *Session, record: []u8, plaintext: []u8) Error!Opened {
        assert(self.live);
        var input: []const u8 = record;
        var total: usize = 0;
        var closed = false;
        var reads: usize = 0;
        while (reads < constants.chapulin_reads_per_record_max) : (reads += 1) {
            const read = self.client.read(input, plaintext[total..], self.staged[self.staged_len..]) catch return self.fail();
            self.staged_len += read.reply_len;
            input = input[read.consumed..];
            total += read.pt_len;
            closed = closed or read.peer_closed;
            if (read.consumed == 0 and read.pt_len == 0) break;
            if (total == plaintext.len) break;
        }
        // The engine hands over one whole record; one taken in part is one chapulin refused.
        if (input.len != 0) return self.fail();
        if (total > 0) return .{ .data = total };
        return if (closed) .closed else .nothing;
    }

    pub fn take_ticket(self: *Session) ?Ticket {
        return self.client.takeTicket();
    }

    /// The `close_notify` of an idle close (RFC 9846 §6.1), staged, and the keys wiped.
    pub fn close(self: *Session) void {
        assert(self.live);
        // An output that cannot take the alert still closes the session: the close goes unsaid,
        // and the connection closes all the same.
        const written = self.client.close(self.staged[self.staged_len..]) catch 0;
        self.staged_len += written;
        self.live = false;
    }

    /// Every secret gone: chapulin wipes its session and zeroes its ticket slot, and the copy this
    /// session resumed with is zeroed.
    pub fn wipe(self: *Session) void {
        if (self.started) self.client.recordClose();
        std.crypto.secureZero(u8, std.mem.asBytes(&self.resuming));
        self.started = false;
        self.live = false;
    }

    fn fail(self: *Session) Error {
        self.wipe();
        return Error.Failed;
    }
};

// Tests. They need no network: a session starts, stages a hello, and refuses what chapulin
// refuses.

const testing = std.testing;

test "the linked object's build record matches these headers, and one that differs does not" {
    try testing.expect(chapulin.buildMatches());
    try testing.expect(Session.built_as_read(&c.ch_build_info_tcp_nonblocking));
    var other = c.ch_build_info_tcp_nonblocking;
    other.sizeof_ch_tls += 1;
    try testing.expect(!Session.built_as_read(&other));
}

/// A session, which is too large for a test's stack, started as the engine starts one.
fn started(tls: *const cocuyo.Tls, context: *Session.Context) !*Session {
    const session = try testing.allocator.create(Session);
    errdefer testing.allocator.destroy(session);
    session.* = .{};
    try session.start(.{ .tls = tls, .ticket = @as(?Session.Ticket, null), .ticket_age_ns = 0, .context = context, .now_ns = 0 });
    return session;
}

test "a session starts and stages a hello, a TLS handshake record" {
    var context = Session.Context.init(&.{}, @splat(7), 1_700_000_000, 0);
    const pin: cocuyo.Pin = @splat(0xab);
    const pins = [_]cocuyo.Pin{pin};
    const tls: cocuyo.Tls = .{ .pins = &pins };
    const session = try started(&tls, &context);
    defer testing.allocator.destroy(session);
    var out: [Session.out_bytes_max]u8 = undefined;
    const made = session.take_out(&out);
    // A handshake record (RFC 9846 §5.1): content type 22, then the length of the body.
    try testing.expect(made > constants.tls_record_header_bytes);
    try testing.expectEqual(@as(u8, 22), out[0]);
    const body = std.mem.readInt(u16, out[constants.tls_record_length_at..][0..@sizeOf(u16)], .big);
    try testing.expectEqual(made, constants.tls_record_header_bytes + body);
    session.wipe();
}

test "a handshake chapulin refuses hands over its fatal alert, though the session is wiped" {
    // A first record from the server that is no ServerHello: chapulin fails the handshake and
    // stages the alert it chose, which the engine sends before it closes (RFC 9846 §6.2).
    var context = Session.Context.init(&.{}, @splat(7), 1_700_000_000, 0);
    const pins = [_]cocuyo.Pin{@splat(0xab)};
    const tls: cocuyo.Tls = .{ .pins = &pins };
    const session = try started(&tls, &context);
    defer testing.allocator.destroy(session);
    var out: [Session.out_bytes_max]u8 = undefined;
    _ = session.take_out(&out);
    // A handshake record whose one message is of a type no server sends (RFC 9846 §4).
    var record = [_]u8{ 22, 3, 3, 0, 4, 0xfe, 0, 0, 0 };
    try testing.expectError(Session.Error.Failed, session.handshake(&record));
    try testing.expect(!session.started);
    // An alert record, in the clear before any key: content type 21, and a fatal level (§6).
    const made = session.take_out(&out);
    try testing.expect(made >= constants.tls_record_header_bytes + 2);
    try testing.expectEqual(@as(u8, 21), out[0]);
    try testing.expectEqual(@as(u8, 2), out[constants.tls_record_header_bytes]);
}

test "a server known by pins alone gets no anchors, though the context carries them for named servers" {
    // The anchors are for the servers that have names; one known by its key alone gets none,
    // which chapulin would refuse with no name to check a chain against.
    const octet = [_]u8{0x30};
    const anchors = [_]c.ch_trust_anchor{.{ .name = &octet, .name_len = octet.len, .spki = &octet, .spki_len = octet.len }};
    var context = Session.Context.init(&anchors, @splat(7), 1_700_000_000, 0);
    const pins = [_]cocuyo.Pin{@splat(0xab)};
    const tls: cocuyo.Tls = .{ .pins = &pins };
    var session: Session = .{};
    const config = session.values(.{ .tls = &tls, .ticket = @as(?Session.Ticket, null), .ticket_age_ns = 0, .context = &context, .now_ns = 0 }).toCfg();
    try testing.expectEqual(@as(usize, 0), config.anchor_count);
    try testing.expectEqual(@as(usize, 1), config.spki_pin_count);
    try testing.expectEqual(@as(usize, 0), config.hostname_len);
    const pinned = try started(&tls, &context);
    defer testing.allocator.destroy(pinned);
    pinned.wipe();
}

test "a named server is checked against the anchors and its name, on the context's clock" {
    const octet = [_]u8{0x30};
    const anchors = [_]c.ch_trust_anchor{.{ .name = &octet, .name_len = octet.len, .spki = &octet, .spki_len = octet.len }};
    var context = Session.Context.init(&anchors, @splat(7), 1_700_000_000, 0);
    const tls: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text("dns.example.") };
    var session: Session = .{};
    const config = session.values(.{ .tls = &tls, .ticket = @as(?Session.Ticket, null), .ticket_age_ns = 0, .context = &context, .now_ns = 5 * constants.ns_per_second }).toCfg();
    try testing.expectEqual(@as(usize, 1), config.anchor_count);
    // chapulin takes a hostname, with no root label's dot.
    try testing.expectEqualStrings("dns.example", config.hostname[0..config.hostname_len]);
    try testing.expectEqual(@as(u64, 1_700_000_005), config.now_seconds);
}

test "a named server with no anchors to check is judged by its pins, and its name still sent" {
    var context = Session.Context.init(&.{}, @splat(7), 1_700_000_000, 0);
    const pins = [_]cocuyo.Pin{@splat(0xab)};
    const tls: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text("dns.example."), .pins = &pins };
    var session: Session = .{};
    const config = session.values(.{ .tls = &tls, .ticket = @as(?Session.Ticket, null), .ticket_age_ns = 0, .context = &context, .now_ns = 0 }).toCfg();
    try testing.expectEqual(@as(usize, 0), config.anchor_count);
    try testing.expectEqual(@as(usize, 1), config.spki_pin_count);
    try testing.expectEqualStrings("dns.example", config.hostname[0..config.hostname_len]);
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

test "the ticket a session would resume with is zeroed when it is wiped, or when its start fails" {
    // The copy holds the resumption secret (RFC 9846 §4.6.1), which nothing may keep past the
    // session it was for. This ticket's binding to the server matches nothing, so chapulin refuses
    // it, and the failed start wipes the session.
    var context = Session.Context.init(&.{}, @splat(7), 1_700_000_000, 0);
    const pins = [_]cocuyo.Pin{@splat(0xab)};
    const tls: cocuyo.Tls = .{ .pins = &pins };
    const psk: [c.SHA256_LEN]u8 = @splat(0x5a);
    const binding: [c.SHA256_LEN]u8 = @splat(0x33);
    const ticket = try Session.Ticket.fromFields(.{ .identity = "identity", .psk = &psk, .age_add = 1, .lifetime_s = 3600, .binding = &binding });
    const start_with = .{ .tls = &tls, .ticket = @as(?Session.Ticket, ticket), .ticket_age_ns = @as(u64, 0), .context = &context, .now_ns = @as(u64, 0) };
    const session = try testing.allocator.create(Session);
    defer testing.allocator.destroy(session);
    session.* = .{};
    try testing.expectError(Session.Error.Failed, session.start(start_with));
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&session.resuming), 0));
    // The copy the configuration points chapulin at, gone once the session is wiped.
    _ = session.values(start_with);
    try testing.expectEqualSlices(u8, &psk, session.resuming.ticket.psk[0..psk.len]);
    session.wipe();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&session.resuming), 0));
}
