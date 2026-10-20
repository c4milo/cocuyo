//! chapulin's TLS session, through colibri's `tls.record.Client`, behind the session interface of
//! docs/design.md §21. The engine hands it whole records and takes the records it makes; chapulin
//! does the handshake, the ciphers, and the certificate, pin and ticket checks. colibri's `tls`
//! module carries chapulin's objects (§16 decision 32): nothing of chapulin is vendored, and no
//! object is linked beside the module.
//!
//! Every call is a copy between the engine's buffers and colibri's. The handshake writes its
//! records into the session's staged octets, which the engine takes out, and so does every call
//! once the connection is up: a query sealed, what colibri owes after a record it opened (a
//! KeyUpdate's answer, or the alert a refused record raised), and the `close_notify`. chapulin
//! draws every random octet from the engine's seeded stream, which `start` hands colibri
//! (colibri#71), and the image supplies chapulin's one remaining hook, `ch_assert_fail`, through
//! the `chapulin_hooks` module it binds (`io/io_chapulin_hooks.zig`).
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
// The engine's constants, through the engine's module: a file belongs to one module.
const constants = @import("io").constants;
const hooks = @import("chapulin_hooks");
const tls = @import("tls");
const tls_provider = @import("tls_provider");

// colibri's objects call `ch_assert_fail` whatever of the session a program uses, so the image
// links it whenever it links the session: a module is analysed, and its exports emitted, only when
// something references it.
comptime {
    _ = hooks;
}

comptime {
    if (constants.tls_records_out_bytes < Session.out_bytes_max + cocuyo.constants.query_bytes_max + constants.tls_record_overhead_bytes) {
        @compileError("a connection's records cannot hold what the session stages beside a query sealed at its longest");
    }
    if (Session.out_bytes_max < cocuyo.constants.query_bytes_max + constants.tls_record_overhead_bytes) {
        @compileError("the session's staged octets cannot hold a query sealed at its longest");
    }
    if (Session.out_bytes_max < tls.record.alert_record_len) {
        @compileError("the session's staged octets cannot hold an alert or the close_notify of an idle close");
    }
}

/// What the session states of the CPU and the thread that drive it: nothing (docs/design.md §21,
/// §17 question 56). colibri then runs no AES instruction and the portable multiply, so the hello
/// offers TLS_CHACHA20_POLY1305_SHA256 alone. Only the program can state the timing mode of its
/// thread, so the engine claims none.
const cpu_not_stated: tls.Cpu = .{ .probe = .{ .aes_clmul = .not_known, .dit = .not_known }, .timing = .not_stated };

pub const Session = struct {
    pub const enabled = true;
    /// What the session stages between two of the engine's calls: what one of colibri's handshake
    /// calls writes at its longest, a ClientHello, which a sealed query is shorter than. An output
    /// that long takes the whole flight in one call, and leaves nothing with chapulin that the
    /// engine would never take.
    pub const out_bytes_max = tls.record.Client.handshake_output_len_min;
    pub const Error = error{Failed};
    pub const Handshake = enum { going, done };
    pub const Opened = union(enum) { data: usize, nothing, closed };
    /// A NewSessionTicket as colibri hands it over, its identity included (RFC 9846 §4.7.1). A
    /// copy holds a resumption secret, and whoever holds one zeroes it.
    pub const Ticket = tls.Ticket;
    /// A root the chain may end at: its subject Name and its SubjectPublicKeyInfo, each a whole
    /// DER TLV (colibri's `values.zig`).
    pub const Anchor = tls.Anchor;
    /// The most roots a context holds: what colibri's configuration takes, chapulin's
    /// `CH_WEBPKI_ANCHOR_MAX`.
    pub const anchors_max = tls.record.ClientConfig.anchors_max;

    /// What every session starts from (docs/design.md §21, and §24, the context a session starts
    /// from): the roots a named server's chain may end at, the stream chapulin draws from, and
    /// the wall clock at an instant of the caller's. No field has a default, so a context is
    /// built by `init`, with each of them named (§16 decision 39). The anchors are the caller's
    /// and outlive the engine.
    pub const Context = struct {
        anchors: []const Anchor,
        stream: std.Random.ChaCha,
        unix_seconds: u64,
        at_ns: u64,

        /// `seed` must be 32 octets of a CSPRNG, drawn for this context alone: chapulin draws
        /// each handshake's random and its key shares from the stream they key. `unix_seconds` is
        /// the wall clock at the caller's `now_ns`. `anchors` may be none when every server is
        /// known by its pins.
        pub fn init(anchors: []const Anchor, seed: [std.Random.ChaCha.secret_seed_length]u8, unix_seconds: u64, now_ns: u64) Context {
            assert(anchors.len <= anchors_max);
            return .{ .anchors = anchors, .stream = std.Random.ChaCha.init(seed), .unix_seconds = unix_seconds, .at_ns = now_ns };
        }

        /// The wall clock at `now_ns`, carried forward from the instant the context was made.
        pub fn seconds_at(context: *const Context, now_ns: u64) u64 {
            return context.unix_seconds + (now_ns -| context.at_ns) / constants.ns_per_second;
        }
    };

    client: tls.record.Client = undefined,
    /// What the session starts from, which chapulin reads through pointers into it.
    config: tls.record.ClientConfig = undefined,
    /// colibri's calls on the records once the handshake has completed.
    records: tls_provider.Provider = undefined,
    hostname: [cocuyo.constants.name_text_bytes_max]u8 = undefined,
    /// The ticket this session resumes with: a copy, which `wipe` zeroes.
    resuming: Ticket = undefined,
    staged: [out_bytes_max]u8 = undefined,
    staged_len: usize = 0,
    /// Started: `client` has secrets to wipe. Live: records may be sealed and read.
    started: bool = false,
    live: bool = false,

    pub fn lifetime_ns(ticket: *const Ticket) u64 {
        return @as(u64, ticket.lifetime_s) * constants.ns_per_second;
    }

    /// Stages the hello for `start.tls`'s server, resuming with `start.ticket` when there is
    /// one, and collects it at once.
    pub fn start(self: *Session, start_with: anytype) Error!void {
        const server: *const cocuyo.Tls = start_with.tls;
        const context = start_with.context;
        self.* = .{};
        self.config.init(.{ .trust = trust(server, context, &self.hostname), .cpu = cpu_not_stated }) catch return self.fail();
        var resumption: ?tls.Resumption = null;
        if (start_with.ticket) |ticket| {
            self.resuming = ticket;
            resumption = .{ .ticket = &self.resuming, .age_ms = start_with.ticket_age_ns / constants.ns_per_millisecond };
        }
        // A refused start leaves colibri's copy of the ticket for `close` to zero, and chapulin's
        // close writes zeros and reads nothing, so a session is started before colibri is called.
        // chapulin draws from the context's stream, which outlives every session of the engine.
        self.started = true;
        self.client.start(&self.config, context.stream.random(), context.seconds_at(start_with.now_ns), resumption) catch return self.fail();
        self.live = true;
        var nothing: [0]u8 = .{};
        const progress = self.client.handshake(&nothing, &self.staged) catch return self.fail();
        self.took(progress.written, self.staged.len);
    }

    /// How chapulin checks the server (RFC 8310 §6.3, docs/design.md §21): a name against the
    /// context's anchors, and pins as they are. A server known by pins alone, "SPKI + IP", is
    /// known by its key and nothing else: it gets no anchors and no clock, however many the
    /// context carries for the servers that have names. chapulin refuses anchors with no name to
    /// check a chain against (its webpki_cfg.c), which would fail such a server at every start. A
    /// named server with no anchors is judged by its pins alone, its name sent and judged against
    /// nothing.
    pub fn trust(server: *const cocuyo.Tls, context: *const Context, hostname: *[cocuyo.constants.name_text_bytes_max]u8) tls.Trust {
        const pins: []const tls.Pin = server.pins;
        const name = server.name orelse return .{ .pins = .{ .pins = pins } };
        var length = name.write_text(hostname);
        // chapulin takes a hostname, which has no root label's dot.
        if (length > 1 and hostname[length - 1] == '.') length -= 1;
        const server_name = hostname[0..length];
        if (context.anchors.len == 0) return .{ .pins = .{ .pins = pins, .server_name = server_name } };
        return .{ .web_pki = .{ .anchors = context.anchors, .server_name = server_name, .pins = pins } };
    }

    /// Counts `written` octets staged, of `room`, which held colibri's longest flight: nothing of
    /// the step's flight stayed with chapulin.
    fn took(self: *Session, written: usize, room: usize) void {
        assert(room >= tls.record.Client.handshake_output_len_min);
        assert(written <= room);
        self.staged_len += written;
        assert(self.staged_len <= self.staged.len);
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
        // The engine takes what the session staged after every call, so each step has all of it.
        assert(self.staged_len == 0);
        const room = self.staged[self.staged_len..];
        const progress = self.client.handshake(record, room) catch {
            // colibri wrote the fatal alert chapulin chose behind what the call wrote before it
            // (RFC 9846 §6.2): kept, for the engine to send before it closes.
            self.staged_len += self.client.failure_written();
            return self.fail();
        };
        self.took(progress.written, room.len);
        // The engine hands over one whole record, and chapulin takes whole records: less is a
        // programmer's error, the engine's or colibri's, not the peer's.
        assert(progress.consumed == record.len);
        if (!progress.complete) return .going;
        self.records = self.client.provider();
        return .done;
    }

    /// Whether the handshake resumed with the ticket it offered: chapulin completes a declined
    /// ticket as a full handshake in the same connection (its docs/decisions.md 55), so an
    /// offered ticket says nothing of whether it was taken.
    pub fn resumed(self: *const Session) bool {
        return self.started and self.client.resumed();
    }

    /// Seals a query whole into the staged octets, or fails: a query sealed in part could not go.
    pub fn seal(self: *Session, plaintext: []const u8) Error!void {
        assert(self.live);
        assert(plaintext.len <= cocuyo.constants.query_bytes_max);
        const sealed = self.records.vtable.encrypt_record(self.records.context, plaintext, self.staged[self.staged_len..]) catch return self.fail();
        if (sealed.consumed != plaintext.len) return self.fail();
        self.staged_len += sealed.written;
        assert(self.staged_len <= self.staged.len);
    }

    /// One whole record once up: its plaintext, or nothing the engine sees (a ticket, or a
    /// KeyUpdate, whose answer is staged), or the peer's close. colibri opens a record whole, so
    /// plaintext too short for one fails the session rather than drop part of it.
    pub fn open(self: *Session, record: []u8, plaintext: []u8) Error!Opened {
        assert(self.live);
        const opened = self.records.vtable.decrypt_record(self.records.context, record, plaintext) catch {
            // colibri owes the fatal alert chapulin chose (RFC 9846 §6.2): kept, for the engine to
            // send before it closes.
            self.stage_owed() catch {};
            return self.fail();
        };
        // The engine hands over one whole record; one taken in part is one colibri refused.
        if (opened.consumed != record.len) return self.fail();
        // A KeyUpdate's answer that could not go would leave the server reading records under keys
        // it was never told of (RFC 9846 §4.7.3).
        self.stage_owed() catch return self.fail();
        return switch (opened.content) {
            .application_data => .{ .data = opened.plaintext_len },
            .new_session_ticket, .key_update => .nothing,
            // The peer's close_notify (RFC 9846 §6.1), the one alert a record read leaves unfailed.
            .alert => .closed,
            // RFC 8310 §9 asks no client certificate of DoT, and RFC 9846 §4.7.2 lets a client
            // answer a CertificateRequest it did not offer to take with a failure.
            .certificate_request, .incomplete => self.fail(),
        };
    }

    /// What colibri owes after a record: a KeyUpdate's answer, or the alert a failure raised,
    /// staged behind what the session holds. colibri's record provider reads no clock here.
    fn stage_owed(self: *Session) error{NoSpaceLeft}!void {
        const now_ns = 0;
        const written = self.records.vtable.handshake_write(self.records.context, self.staged[self.staged_len..], now_ns) catch return error.NoSpaceLeft;
        self.staged_len += written;
        assert(self.staged_len <= self.staged.len);
    }

    pub fn take_ticket(self: *Session) ?Ticket {
        if (!self.started) return null;
        return self.client.take_ticket();
    }

    /// The `close_notify` of an idle close (RFC 9846 §6.1), staged, and the keys wiped.
    pub fn close(self: *Session) void {
        assert(self.live);
        // An output that cannot take the alert still closes the session: the close goes unsaid,
        // and the connection closes all the same.
        const written = self.records.vtable.send_close_notify(self.records.context, self.staged[self.staged_len..]) catch 0;
        self.staged_len += written;
        self.live = false;
    }

    /// Every secret gone: colibri wipes chapulin's session and its copy of the ticket, and the
    /// copy this session resumed with is zeroed.
    pub fn wipe(self: *Session) void {
        if (self.started) self.client.close();
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

/// A handshake record's content type, and an alert's, and an alert's fatal level (RFC 9846 §5.1,
/// §6).
const content_handshake = 22;
const content_alert = 21;
const alert_fatal = 2;

/// The wall clock the tests' contexts are made at.
const test_seconds = 1_700_000_000;

/// The octet a test's stream is seeded with when the test does not read what the stream gives.
const test_seed_octet = 7;

/// A context for a test: the stream seeded with `seed_octet` repeated, so each run draws what the
/// last drew, and the wall clock at `test_seconds`. Never for a network, whose seed comes from a
/// CSPRNG.
fn test_context(anchors: []const tls.Anchor, seed_octet: u8) Session.Context {
    return .init(anchors, @splat(seed_octet), test_seconds, 0);
}

/// The octets of the pin the tests' servers are known by, which no key hashes to.
const pin_octet = 0xab;

/// A session, which is too large for a test's stack, started as the engine starts one.
fn started(server: *const cocuyo.Tls, context: *Session.Context) !*Session {
    const session = try testing.allocator.create(Session);
    errdefer testing.allocator.destroy(session);
    session.* = .{};
    try session.start(.{ .tls = server, .ticket = @as(?Session.Ticket, null), .ticket_age_ns = @as(u64, 0), .context = context, .now_ns = @as(u64, 0) });
    return session;
}

fn finish(session: *Session) void {
    session.wipe();
    testing.allocator.destroy(session);
}

/// One octet of DER, which colibri hands chapulin as an anchor's name and key without reading.
const anchor_octet = "\x30";
const anchors_test = [_]tls.Anchor{.{ .subject = anchor_octet, .spki = anchor_octet }};

test "the context carries no default, so each of its fields is named where one is built" {
    // Until 2026-10-11 the fields defaulted to no anchors, an undefined stream and a wall clock of
    // zero, and so did the engine's context when no consumer set one (docs/design.md §16
    // decision 39).
    inline for (comptime std.meta.fields(Session.Context)) |field| {
        try testing.expectEqual(@as(?*const anyopaque, null), field.default_value_ptr);
    }
}

test "a session starts and stages a hello, a TLS handshake record" {
    var context = test_context(&.{}, test_seed_octet);
    const pins = [_]cocuyo.Pin{@splat(pin_octet)};
    const session = try started(&.{ .pins = &pins }, &context);
    defer finish(session);
    var out: [Session.out_bytes_max]u8 = undefined;
    const made = session.take_out(&out);
    // A handshake record (RFC 9846 §5.1): content type 22, then the length of the body.
    try testing.expect(made > constants.tls_record_header_bytes);
    try testing.expectEqual(@as(u8, content_handshake), out[0]);
    const body = std.mem.readInt(u16, out[constants.tls_record_length_at..][0..@sizeOf(u16)], .big);
    try testing.expectEqual(made, constants.tls_record_header_bytes + body);
}

/// The hello a session over `seed` stages first.
const Hello = struct {
    bytes: [Session.out_bytes_max]u8 = undefined,
    len: usize = 0,

    fn of(seed: u8) !Hello {
        var context = test_context(&.{}, seed);
        const pins = [_]cocuyo.Pin{@splat(pin_octet)};
        const session = try started(&.{ .pins = &pins }, &context);
        defer finish(session);
        var hello: Hello = .{};
        hello.len = session.take_out(&hello.bytes);
        return hello;
    }

    fn slice(hello: *const Hello) []const u8 {
        return hello.bytes[0..hello.len];
    }
};

test "the hello is drawn from the context's stream: the same seed makes the same hello" {
    const first = try Hello.of(1);
    const again = try Hello.of(1);
    const other = try Hello.of(2);
    // The random and the key shares are the stream's (non-negotiable 4).
    try testing.expectEqualSlices(u8, first.slice(), again.slice());
    try testing.expect(!std.mem.eql(u8, first.slice(), other.slice()));
}

/// Where a ClientHello's cipher_suites start (RFC 9846 §4, §4.2.2): after the message's type and
/// length, the legacy_version, the random, and the legacy_session_id's length octet and its body.
const message_header_bytes = 4;
const legacy_version_bytes = 2;
const random_bytes = 32;
/// TLS_CHACHA20_POLY1305_SHA256, {0x13,0x03} (RFC 9846 Appendix B.4).
const chacha20_poly1305_sha256: u16 = 0x1303;

/// Requires that `suites` offer TLS_CHACHA20_POLY1305_SHA256 and nothing else.
fn expect_chacha20_alone(suites: []const u8) !void {
    try testing.expectEqual(@as(usize, @sizeOf(u16)), suites.len);
    try testing.expectEqual(chacha20_poly1305_sha256, std.mem.readInt(u16, suites[0..@sizeOf(u16)], .big));
}

/// The cipher_suites a ClientHello handshake message offers.
fn suites_of(message: []const u8) []const u8 {
    const session_id_at = message_header_bytes + legacy_version_bytes + random_bytes;
    const suites_at = session_id_at + 1 + message[session_id_at] + @sizeOf(u16);
    const suites_len = std.mem.readInt(u16, message[suites_at - @sizeOf(u16) ..][0..@sizeOf(u16)], .big);
    return message[suites_at..][0..suites_len];
}

test "a session states nothing of the CPU, so its hello offers TLS_CHACHA20_POLY1305_SHA256 alone" {
    // docs/design.md §21 and §17 question 56: colibri runs the AES instructions only for a program
    // that states its thread's timing mode, which the engine cannot state.
    const hello = try Hello.of(test_seed_octet);
    try expect_chacha20_alone(suites_of(hello.slice()[constants.tls_record_header_bytes..]));
}

test "a handshake chapulin refuses hands over its fatal alert, though the session is wiped" {
    // A first record from the server that is no ServerHello: chapulin fails the handshake and
    // colibri writes the alert it chose, which the engine sends before it closes (RFC 9846 §6.2).
    var context = test_context(&.{}, test_seed_octet);
    const pins = [_]cocuyo.Pin{@splat(pin_octet)};
    const session = try started(&.{ .pins = &pins }, &context);
    defer finish(session);
    var out: [Session.out_bytes_max]u8 = undefined;
    _ = session.take_out(&out);
    // A handshake record whose one message is of a type no server sends (RFC 9846 §4).
    var record = [_]u8{ content_handshake, 3, 3, 0, 4, 0xfe, 0, 0, 0 };
    try testing.expectError(Session.Error.Failed, session.handshake(&record));
    try testing.expect(!session.started);
    // An alert record, in the clear before any key: content type 21, and a fatal level (§6).
    const made = session.take_out(&out);
    try testing.expect(made >= constants.tls_record_header_bytes + 2);
    try testing.expectEqual(@as(u8, content_alert), out[0]);
    try testing.expectEqual(@as(u8, alert_fatal), out[constants.tls_record_header_bytes]);
}

test "a server known by pins alone gets no anchors, though the context carries them for named servers" {
    // The anchors are for the servers that have names; one known by its key alone gets none,
    // which chapulin would refuse with no name to check a chain against.
    const context = test_context(&anchors_test, test_seed_octet);
    const pins = [_]cocuyo.Pin{@splat(pin_octet)};
    var hostname: [cocuyo.constants.name_text_bytes_max]u8 = undefined;
    const trust = Session.trust(&.{ .pins = &pins }, &context, &hostname);
    try testing.expect(trust == .pins);
    try testing.expectEqual(pins.len, trust.pins.pins.len);
    try testing.expectEqual(@as(?[]const u8, null), trust.pins.server_name);
}

test "a named server is checked against the anchors and its name, on the context's clock" {
    const context = test_context(&anchors_test, test_seed_octet);
    var hostname: [cocuyo.constants.name_text_bytes_max]u8 = undefined;
    const trust = Session.trust(&.{ .name = try cocuyo.Name.from_text("dns.example.") }, &context, &hostname);
    try testing.expect(trust == .web_pki);
    try testing.expectEqual(anchors_test.len, trust.web_pki.anchors.len);
    // chapulin takes a hostname, with no root label's dot.
    try testing.expectEqualStrings("dns.example", trust.web_pki.server_name);
    try testing.expectEqual(@as(u64, test_seconds + 5), context.seconds_at(5 * constants.ns_per_second));
}

test "a named server with no anchors to check is judged by its pins, and its name still sent" {
    const context = test_context(&.{}, test_seed_octet);
    const pins = [_]cocuyo.Pin{@splat(pin_octet)};
    var hostname: [cocuyo.constants.name_text_bytes_max]u8 = undefined;
    const trust = Session.trust(&.{ .name = try cocuyo.Name.from_text("dns.example."), .pins = &pins }, &context, &hostname);
    try testing.expect(trust == .pins);
    try testing.expectEqual(pins.len, trust.pins.pins.len);
    try testing.expectEqualStrings("dns.example", trust.pins.server_name.?);
}

test "a session with neither pins nor anchors for its name is refused before a byte" {
    var context = test_context(&.{}, test_seed_octet);
    const server: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text("dns.example.") };
    const session = try testing.allocator.create(Session);
    defer testing.allocator.destroy(session);
    session.* = .{};
    try testing.expectError(Session.Error.Failed, session.start(.{ .tls = &server, .ticket = @as(?Session.Ticket, null), .ticket_age_ns = @as(u64, 0), .context = &context, .now_ns = @as(u64, 0) }));
    var out: [Session.out_bytes_max]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), session.take_out(&out));
}

test "the ticket a session would resume with is zeroed when its start fails" {
    // The copy holds the resumption secret (RFC 9846 §4.7.1), which nothing may keep past the
    // session it was for. This ticket's binding to the server matches nothing, so chapulin refuses
    // it, and the failed start wipes the session.
    var context = test_context(&.{}, test_seed_octet);
    const pins = [_]cocuyo.Pin{@splat(pin_octet)};
    var ticket = std.mem.zeroes(Session.Ticket);
    ticket.identity_len = 1;
    ticket.psk_len = tls.constants.sha256_len;
    @memset(&ticket.psk, 0x5a);
    @memset(&ticket.binding, 0x33);
    ticket.lifetime_s = 1;
    const session = try testing.allocator.create(Session);
    defer testing.allocator.destroy(session);
    session.* = .{};
    try testing.expectError(Session.Error.Failed, session.start(.{ .tls = &cocuyo.Tls{ .pins = &pins }, .ticket = @as(?Session.Ticket, ticket), .ticket_age_ns = @as(u64, 0), .context = &context, .now_ns = @as(u64, 0) }));
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&session.resuming), 0));
    try testing.expect(!session.started);
}

test "chapulin starts a session for a server of four pins, the most a configuration names, and refuses five" {
    // `spki_pins_max` is chapulin's own bound as well (docs/design.md §21). A server of four pins
    // starts. Five pins, which no valid configuration names, are refused at the start.
    var context = test_context(&.{}, test_seed_octet);
    const pins: [cocuyo.constants.spki_pins_max + 1]cocuyo.Pin = @splat(@splat(pin_octet));
    const most = try started(&.{ .pins = pins[0..cocuyo.constants.spki_pins_max] }, &context);
    finish(most);
    try testing.expectError(Session.Error.Failed, started(&.{ .pins = &pins }, &context));
}
