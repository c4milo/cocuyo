//! chapulin's QUIC object behind colibri's TLS provider and packet suite: `cocuyo_quic`'s session
//! for real DoQ (docs/design.md §24, chapulin under colibri). chapulin owns every key: it derives
//! the Initial keys from the Destination Connection ID (RFC 9001 §5.2), applies and removes header
//! protection, and moves handshake octets one level at a time. Built only when `-Dchapulin` names
//! a checkout whose `bin/chapulin-quic-nonblocking.o` was made by
//!
//!     make RAND=extern TRUST=webpki TRANSPORT=quic-nonblocking lib && cp bin/chapulin.o bin/chapulin-quic-nonblocking.o
//!
//! and the headers are read from that checkout in place. The image supplies `ch_rand_bytes` and
//! `ch_assert_fail` once, through `chapulin_hooks`, and the session enters the engine's stream
//! around the two calls that draw: the session's start, and handshake octets arriving.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const quic = @import("quic");
const constants = @import("cocuyo_quic").constants;
const hooks = @import("chapulin_hooks");

// chapulin's object calls the hooks whatever of the session a program uses, so the image links
// them whenever it links the session.
comptime {
    _ = hooks;
}

pub const c = @cImport({
    @cDefine("CH_TRUST_WEBPKI", "1");
    @cDefine("CH_TRANSPORT_QUIC_NONBLOCKING", "1");
    @cDefine("CH_RAND_EXTERN", "1");
    @cInclude("quic.h");
    @cInclude("build.h");
});

const tls = quic.tls;
const suite_module = quic.crypto.suite;
const Level = quic.core.Level;
const levels = quic.core.levels_count;

pub const Session = struct {
    /// What every session starts from: the anchors, the wall clock, and the stream chapulin draws
    /// from, seeded from a CSPRNG. The anchors are the caller's and outlive the engine.
    pub const Context = struct {
        anchors: []const c.ch_trust_anchor = &.{},
        stream: std.Random.ChaCha = std.Random.ChaCha.init(@splat(0)),
        unix_seconds: u64 = 0,
        at_ns: u64 = 0,

        /// `seed` must come from a CSPRNG; `unix_seconds` is the wall clock at the caller's
        /// `now_ns`.
        pub fn init(anchors: []const c.ch_trust_anchor, seed: [std.Random.ChaCha.secret_seed_length]u8, unix_seconds: u64, now_ns: u64) Context {
            assert(anchors.len <= c.CH_WEBPKI_ANCHOR_MAX);
            return .{ .anchors = anchors, .stream = std.Random.ChaCha.init(seed), .unix_seconds = unix_seconds, .at_ns = now_ns };
        }
    };

    /// A ticket as chapulin handed it to `on_ticket`, copied: the identity, the resumption
    /// secret, the lifetime, the age mask and the binding to the hostname and the anchors
    /// (chapulin's webpki_ticket.h).
    pub const Ticket = struct {
        identity: [c.CH_TICKET_ID_MAX]u8,
        identity_len: u16,
        psk: [c.HKDF_HASH_MAX]u8,
        psk_len: u8,
        lifetime_s: u32,
        age_add: u32,
        binding: [c.SHA256_LEN]u8,
    };

    quic: c.ch_quic = undefined,
    config: c.ch_cfg = undefined,
    /// chapulin's own buffer, which reassembles each handshake message.
    buffer: [c.CH_MIN_RXBUF]u8 = undefined,
    hostname: [cocuyo.constants.name_text_bytes_max]u8 = undefined,
    alpn: [1]c.ch_alpn_protocol = undefined,
    params: [c.CH_TRANSPORT_PARAMS_MAX]u8 = undefined,
    peer_params: [constants.peer_params_bytes_max]u8 = undefined,
    peer_params_len: ?usize = null,
    /// What each level owes the server, pulled from chapulin after every call that stages it.
    owed: [levels][c.CH_TX_STAGE]u8 = undefined,
    owed_len: [levels]usize = @splat(0),
    overflowed: bool = false,
    /// The ticket this session resumes with: chapulin reads it through `config`.
    resuming: Ticket = undefined,
    given: ?Ticket = null,
    stream: ?*std.Random.ChaCha = null,
    started: bool = false,
    alert_taken: bool = false,

    pub fn lifetime_ns(ticket: *const Ticket) u64 {
        return @as(u64, ticket.lifetime_s) * constants.ns_per_second;
    }

    /// Whether the object linked is the one these headers describe (chapulin's build.h): an
    /// object built with other defines lays its sessions out otherwise. translate-c cannot read
    /// the `ch_build` macro, so the record's name is written here.
    fn built_as_read() bool {
        return c.ch_build_matches(&c.ch_build_info_quic_nonblocking) != 0;
    }

    /// Prepares a client session for `start.tls`'s server, offering `start.alpn`, resuming with
    /// `start.ticket` when there is one. chapulin starts at `set_transport_params`, once colibri
    /// has the parameters it carries (RFC 9001 §4.1.3). A server known by SPKI pins, or with no
    /// name, is refused: chapulin's QUIC mode checks a chain against anchors and a hostname, and
    /// takes no pins (docs/design.md §24, chapulin under colibri).
    pub fn start(self: *Session, start_with: anytype) error{Failed}!void {
        if (!built_as_read()) {
            std.debug.panic("chapulin's QUIC object was built with other defines than cocuyo reads its headers with: rebuild it as io/io_chapulin_quic.zig says", .{});
        }
        const server: *const cocuyo.Tls = start_with.tls;
        const context = &start_with.context.session;
        if (server.pins.len > 0 or context.anchors.len == 0) return error.Failed;
        const name = server.name orelse return error.Failed;
        self.* = .{};
        self.config = std.mem.zeroes(c.ch_cfg);
        self.config.buf = &self.buffer;
        self.config.buf_len = self.buffer.len;
        self.config.io = self;
        self.config.on_level_ready = level_ready;
        self.config.on_transport_params = keep_params;
        self.config.on_ticket = keep_ticket;
        const alpn: []const u8 = start_with.alpn;
        self.alpn[0] = .{ .name = alpn.ptr, .name_len = alpn.len };
        self.config.alpn_protocols = &self.alpn;
        self.config.alpn_count = self.alpn.len;
        self.config.anchors = context.anchors.ptr;
        self.config.anchor_count = context.anchors.len;
        self.config.now_seconds = context.unix_seconds + (start_with.now_ns -| context.at_ns) / constants.ns_per_second;
        var length = name.write_text(&self.hostname);
        // chapulin takes a hostname, which has no root label's dot.
        if (length > 1 and self.hostname[length - 1] == '.') length -= 1;
        self.config.hostname = &self.hostname;
        self.config.hostname_len = length;
        if (start_with.ticket) |ticket| self.resume_with(ticket, start_with.ticket_age_ns);
        self.stream = &context.stream;
    }

    /// The obfuscated age is the ticket's age in milliseconds plus its age mask, modulo 2^32
    /// (RFC 9846 §4.3.11.1).
    fn resume_with(self: *Session, ticket: Ticket, age_ns: u64) void {
        self.resuming = ticket;
        const age_ms: u32 = @truncate(age_ns / constants.ns_per_millisecond);
        self.config.psk = &self.resuming.psk;
        self.config.psk_len = self.resuming.psk_len;
        self.config.psk_id = &self.resuming.identity;
        self.config.psk_id_len = self.resuming.identity_len;
        self.config.resumption = 1;
        self.config.obfuscated_age = age_ms +% self.resuming.age_add;
        self.config.ticket_binding = &self.resuming.binding;
    }

    pub fn provider(self: *Session) tls.QuicProvider {
        return .{ .context = self, .vtable = &provider_vtable };
    }

    pub fn suite(self: *Session) quic.crypto.Suite {
        return .{ .context = self, .vtable = &suite_vtable };
    }

    pub fn take_ticket(self: *Session) ?Ticket {
        const ticket = self.given;
        self.given = null;
        return ticket;
    }

    /// Whether the server took the ticket the session offered (RFC 9846 §4.2.11).
    pub fn resumed(self: *const Session) bool {
        return self.started and self.quic.t.psk_selected == 1;
    }

    /// Every secret gone: chapulin wipes its session, and the ticket copies are zeroed.
    pub fn wipe(self: *Session) void {
        if (self.started) c.ch_quic_close(&self.quic);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.resuming));
        if (self.given) |*ticket| std.crypto.secureZero(u8, std.mem.asBytes(ticket));
        self.started = false;
        self.given = null;
    }

    fn of(context: *anyopaque) *Session {
        return @ptrCast(@alignCast(context));
    }

    fn of_const(context: *const anyopaque) *const Session {
        return @ptrCast(@alignCast(context));
    }

    /// Moves what chapulin staged at each level into what that level owes. chapulin stages a whole
    /// message at a time, and refuses the next input while one waits (its quic.h).
    fn pull(self: *Session) void {
        for (0..levels) |level| {
            const room = self.owed[level][self.owed_len[level]..];
            var written: usize = 0;
            const result = c.ch_quic_crypto_out(&self.quic, @intCast(level), room.ptr, room.len, &written);
            if (result == c.CH_ECAP) self.overflowed = true;
            if (result == c.CH_OK) self.owed_len[level] += written;
        }
    }

    fn level_ready(io: ?*anyopaque, level: u8, direction: u8) callconv(.c) void {
        _ = io;
        _ = level;
        _ = direction;
    }

    /// The server's transport parameters, copied: chapulin's pointer lives for the call alone.
    fn keep_params(io: ?*anyopaque, body: [*c]const u8, len: usize) callconv(.c) void {
        const self = of(io.?);
        if (len > self.peer_params.len) return;
        @memcpy(self.peer_params[0..len], body[0..len]);
        self.peer_params_len = len;
    }

    /// A ticket the server gave, copied, replacing any before it (docs/design.md §24, request
    /// rule 10). One whose identity is longer than chapulin keeps is dropped.
    fn keep_ticket(io: ?*anyopaque, ticket: [*c]const c.ch_ticket) callconv(.c) void {
        const self = of(io.?);
        const given = ticket.*;
        if (given.identity_len > c.CH_TICKET_ID_MAX or given.psk_len > c.HKDF_HASH_MAX) return;
        var kept: Ticket = .{
            .identity = undefined,
            .identity_len = @intCast(given.identity_len),
            .psk = undefined,
            .psk_len = @intCast(given.psk_len),
            .lifetime_s = given.lifetime_s,
            .age_add = given.age_add,
            .binding = given.binding,
        };
        @memcpy(kept.identity[0..given.identity_len], given.identity[0..given.identity_len]);
        kept.psk = given.psk;
        self.given = kept;
    }
};

// The TLS provider (colibri's `tls.QuicVTable`).

const provider_vtable: tls.quic_provider.VTable = .{
    .set_transport_params = set_transport_params,
    .peer_transport_params = peer_transport_params,
    .provide_handshake = provide_handshake,
    .write_handshake = write_handshake,
    .negotiated_alpn = negotiated_alpn,
    .handshake_complete = handshake_complete,
    .take_alert = take_alert,
    .export_keying_material = export_keying_material,
};

/// The parameters colibri encoded, which the hello carries (RFC 9001 §8.2): chapulin starts here,
/// drawing its keys from the engine's stream, and stages the hello.
fn set_transport_params(context: *anyopaque, body: []const u8) tls.quic_provider.TransportParamsError!void {
    const self = Session.of(context);
    if (self.started) return error.HandshakeStarted;
    if (body.len > self.params.len) return error.TlsFailed;
    @memcpy(self.params[0..body.len], body);
    self.config.transport_params = &self.params;
    self.config.transport_params_len = body.len;
    hooks.enter(self.stream.?);
    defer hooks.leave();
    if (c.ch_quic_init(&self.quic, &self.config) != c.CH_OK) return error.TlsFailed;
    self.started = true;
    self.pull();
}

fn peer_transport_params(context: *const anyopaque) ?[]const u8 {
    const self = Session.of_const(context);
    const len = self.peer_params_len orelse return null;
    return self.peer_params[0..len];
}

/// Handshake octets at `level`, in order and once (RFC 9001 §4.1.3). chapulin may draw here: a
/// HelloRetryRequest for P-256 makes a new key share.
fn provide_handshake(context: *anyopaque, level: Level, data: []const u8) tls.quic_provider.ProvideError!void {
    const self = Session.of(context);
    if (!self.started) return error.WrongLevel;
    const result = in: {
        hooks.enter(self.stream.?);
        defer hooks.leave();
        break :in c.ch_quic_crypto_in(&self.quic, @intFromEnum(level), data.ptr, data.len);
    };
    self.pull();
    if (self.overflowed) return error.NoSpaceLeft;
    if (result == c.CH_OK) return;
    if (result == c.CH_EINVAL and c.ch_quic_state(&self.quic) != c.CH_ST_FAILED) return error.WrongLevel;
    if (result == c.CH_ECAP) return error.NoSpaceLeft;
    return error.TlsFailed;
}

fn write_handshake(context: *anyopaque, level: Level, output: []u8) tls.quic_provider.WriteError!usize {
    const self = Session.of(context);
    if (self.overflowed) return error.NoSpaceLeft;
    const at = @intFromEnum(level);
    const owed = self.owed[at][0..self.owed_len[at]];
    const written = @min(owed.len, output.len);
    @memcpy(output[0..written], owed[0..written]);
    std.mem.copyForwards(u8, self.owed[at][0 .. owed.len - written], owed[written..]);
    self.owed_len[at] -= written;
    return written;
}

fn negotiated_alpn(context: *const anyopaque) ?[]const u8 {
    const self = Session.of_const(context);
    if (!self.started or self.quic.t.alpn_selected == c.CH_ALPN_NONE) return null;
    const chosen = self.alpn[self.quic.t.alpn_selected];
    return chosen.name[0..chosen.name_len];
}

/// chapulin is connected once it has handed out the client's Finished (RFC 9001 §4.1.1).
fn handshake_complete(context: *const anyopaque) bool {
    const self = Session.of_const(context);
    return self.started and c.ch_quic_state(&self.quic) == c.CH_ST_CONNECTED;
}

/// The alert of a handshake that failed, once: a chain that ends at no anchor is `unknown_ca`,
/// a name the certificate does not carry `bad_certificate` (chapulin's webpki.c).
fn take_alert(context: *anyopaque) ?tls.Alert {
    const self = Session.of(context);
    if (!self.started or self.alert_taken or c.ch_quic_state(&self.quic) != c.CH_ST_FAILED) return null;
    self.alert_taken = true;
    const alert = c.ch_quic_alert(&self.quic);
    if (alert == 0) return null;
    return @enumFromInt(alert);
}

fn export_keying_material(context: *anyopaque, label: []const u8, context_value: ?[]const u8, output: []u8) tls.quic_provider.ExportError!void {
    _ = context;
    _ = label;
    _ = context_value;
    _ = output;
    return error.Unsupported;
}

// The packet-protection suite (colibri's `crypto.suite.VTable`).

const suite_vtable: suite_module.VTable = .{
    .install_initial_keys = install_initial_keys,
    .keys_available = keys_available,
    .seal = seal,
    .open = open,
    .retry_tag_valid = retry_tag_valid,
    .retry_tag_write = retry_tag_write,
    .retry_token_write = retry_token_write,
    .retry_token_check = retry_token_check,
    .update_keys = update_keys,
    .key_phase = key_phase,
    .discard_previous_keys = discard_previous_keys,
    .discard_keys = discard_keys,
};

/// The Initial keys derive from the client's Destination Connection ID (RFC 9001 §5.2), which
/// chapulin stores; the session must have started, which `set_transport_params` does.
fn install_initial_keys(context: *anyopaque, role: suite_module.Role, dcid: []const u8) suite_module.InstallError!void {
    const self = Session.of(context);
    if (role != .client or !self.started) return error.Unsupported;
    if (c.ch_quic_initial_keys(&self.quic, dcid.ptr, dcid.len) != c.CH_OK) return error.Unsupported;
}

fn keys_available(context: *const anyopaque, level: Level, direction: suite_module.Direction) bool {
    const self = Session.of_const(context);
    if (!self.started) return false;
    const shift = @as(u3, @intFromEnum(level)) * constants.chapulin_bits_per_level + @intFromEnum(direction);
    return self.quic.levels_ready & (@as(u8, 1) << shift) != 0;
}

/// Packet protection, then header protection (RFC 9001 §5.3, §5.4). A session that failed seals
/// the one CONNECTION_CLOSE a level may carry, and nothing else.
fn seal(context: *anyopaque, sealing: suite_module.Sealing, output: []u8) suite_module.SealError!usize {
    const self = Session.of(context);
    const failed = c.ch_quic_state(&self.quic) == c.CH_ST_FAILED;
    const sealer = if (failed) &c.ch_quic_seal_close else &c.ch_quic_seal;
    var written: usize = 0;
    const result = sealer(&self.quic, @intFromEnum(sealing.level), sealing.packet_number, sealing.packet_number_len, sealing.header.ptr, sealing.header.len, sealing.payload.ptr, sealing.payload.len, output.ptr, output.len, &written);
    if (result == c.CH_OK) return written;
    if (result == c.CH_ECAP) return error.NoSpaceLeft;
    if (failed or !keys_available(context, sealing.level, .write)) return error.KeysUnavailable;
    return error.ConfidentialityLimitReached;
}

/// Header protection removed, then the packet opened in place (RFC 9001 §5.4, §5.3). A packet
/// that does not open is discarded, and the session lives (RFC 9001 §5.5).
fn open(context: *anyopaque, opening: suite_module.Opening) suite_module.OpenError!suite_module.Opened {
    const self = Session.of(context);
    var key_set: u8 = 0;
    var number: u64 = 0;
    var payload_len: usize = 0;
    const packet = opening.packet;
    const result = c.ch_quic_open(&self.quic, @intFromEnum(opening.level), packet.ptr, packet.len, opening.packet_number_offset, opening.largest_packet_number orelse 0, opening.current_phase_lowest orelse std.math.maxInt(u64), &key_set, &number, &payload_len);
    if (result == c.CH_QUIC_DISCARD) return error.Discarded;
    if (result == c.CH_QUIC_AEAD_LIMIT) return error.IntegrityLimitReached;
    if (result != c.CH_OK) return error.KeysUnavailable;
    return .{
        .packet_number = number,
        // Header protection is off the first octet now, whose low bits give the length.
        .packet_number_len = (packet[0] & quic.crypto.constants.packet_number_len_mask) + 1,
        .payload_len = payload_len,
        .key_set = switch (key_set) {
            c.CH_QUIC_KEY_PREVIOUS => .previous,
            c.CH_QUIC_KEY_NEXT => .next,
            else => .current,
        },
    };
}

fn retry_tag_valid(context: *const anyopaque, pseudo_packet: []const u8, tag: *const [quic.crypto.constants.retry_integrity_tag_len]u8) bool {
    const self = Session.of_const(context);
    return c.ch_quic_retry_ok(&self.quic, pseudo_packet.ptr, pseudo_packet.len, tag) == 1;
}

/// A client writes no Retry.
fn retry_tag_write(context: *const anyopaque, pseudo_packet: []const u8, tag: *[quic.crypto.constants.retry_integrity_tag_len]u8) suite_module.RetryTagError!void {
    _ = context;
    _ = pseudo_packet;
    _ = tag;
    return error.Unsupported;
}

fn retry_token_write(context: *anyopaque, address: []const u8, ids: *const suite_module.RetryConnectionIds, now_ns: u64, output: []u8) suite_module.TokenError!usize {
    _ = context;
    _ = address;
    _ = ids;
    _ = now_ns;
    _ = output;
    return error.Unsupported;
}

fn retry_token_check(context: *const anyopaque, address: []const u8, token: []const u8, now_ns: u64) suite_module.TokenCheck {
    _ = context;
    _ = address;
    _ = token;
    _ = now_ns;
    return .not_retry;
}

fn update_keys(context: *anyopaque) suite_module.UpdateError!void {
    const self = Session.of(context);
    if (c.ch_quic_key_update(&self.quic) != c.CH_OK) return error.KeysUnavailable;
}

fn key_phase(context: *const anyopaque) bool {
    return c.ch_quic_key_phase(&Session.of_const(context).quic) != 0;
}

fn discard_previous_keys(context: *anyopaque) void {
    c.ch_quic_drop_previous_keys(&Session.of(context).quic);
}

fn discard_keys(context: *anyopaque, level: Level) void {
    _ = c.ch_quic_discard(&Session.of(context).quic, @intFromEnum(level));
}

// Tests.

const testing = std.testing;

test "the object linked is the one the headers describe" {
    try testing.expect(Session.built_as_read());
}

/// What the engine hands a session's start, for a server known as `server` is.
fn start_for(server: *const cocuyo.Tls, context: anytype) !void {
    var session: Session = .{};
    try session.start(.{
        .tls = server,
        .alpn = "doq",
        .ticket = @as(?Session.Ticket, null),
        .ticket_age_ns = 0,
        .context = context,
        .now_ns = 1,
    });
    session.wipe();
}

test "a server known by SPKI pins, or by no name, is refused before chapulin starts" {
    // chapulin's QUIC mode checks a chain against anchors and a hostname, and takes no pins
    // (docs/design.md §24, chapulin under colibri).
    const octet = [_]u8{0x30};
    const anchors = [_]c.ch_trust_anchor{.{ .name = &octet, .name_len = octet.len, .spki = &octet, .spki_len = octet.len }};
    var context: struct { session: Session.Context } = .{ .session = .init(&anchors, @splat(0), 1, 1) };
    const pin: cocuyo.Pin = @splat(0);
    const name = try cocuyo.Name.from_text("dns.example.");
    try testing.expectError(error.Failed, start_for(&.{ .name = name, .pins = &.{pin} }, &context));
    try testing.expectError(error.Failed, start_for(&.{ .pins = &.{pin} }, &context));
    try testing.expectError(error.Failed, start_for(&.{}, &context));
    // A name and anchors start it.
    try start_for(&.{ .name = name }, &context);
}
