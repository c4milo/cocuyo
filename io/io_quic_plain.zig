//! A TLS provider and a packet-protection suite that encrypt nothing, for the gate (docs/design.md
//! §24, colibri under the request interface). colibri's connection takes both, and this pair lets
//! the engine run colibri's real QUIC on the twin: packets, streams, flow control, loss and its
//! recovery, with nothing sealed. It is written from colibri's two vtables and RFC 9001, and it is
//! for tests: a consumer's connection runs chapulin's QUIC object instead.
//!
//! It encrypts nothing, authenticates nobody, and is never for a network. Whoever reads the path
//! reads every packet, whoever writes to it can change one, and any peer that sends the made-up
//! messages below completes the handshake. No option of `cocuyo_quic` defaults to it
//! (docs/design.md §16 decision 38): a test names it.
//!
//! The handshake's messages are made-up octets at the Initial, Handshake and 1-RTT levels of RFC
//! 9001 §4, in the order §4.1.5's Figure 5 puts them, each framed as RFC 9846 §4 frames a message:
//! a type octet, a 24-bit length, the body. The client's hello carries the ALPN it offers and its
//! transport parameters; the server's EncryptedExtensions carry the ALPN it selects and its own. A
//! level's keys are there from the message that brings them, and a packet is sealed by appending
//! sixteen octets, the tag every QUIC cipher suite adds (RFC 9001 §5.3), which check nothing.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const tls = quic.tls_provider;
const crypto = quic.crypto;
const suite_module = crypto.suite;

pub const Role = suite_module.Role;
const Level = quic.core.Level;
const levels = quic.core.levels_count;

/// The handshake's messages, by the type octet RFC 9846 §4 gives each.
const Message = enum(u8) { client_hello = 1, server_hello = 2, encrypted_extensions = 8, finished = 20 };

/// A message's framing: its type, then its length in three octets (RFC 9846 §4).
const length_bytes = 3;
const frame_bytes = 1 + length_bytes;
/// The longest transport parameters either side sends, and the longest ALPN token it keeps.
const params_bytes_max = 256;
const alpn_bytes_max = 16;
/// What one level holds of messages, both ways: a hello at its longest, with room over.
const level_bytes_max = 512;
/// The protocol a server scripted to select another names, which is not DoQ's.
pub const other_protocol = "h2";

/// One side of one connection's handshake, and its keys, which are flags and no secret: the
/// session encrypts nothing and authenticates nobody. For tests, and never for a network.
pub const Session = struct {
    role: Role,
    /// Whether a server selects another protocol than the one offered, for a test.
    other: bool = false,
    params: [params_bytes_max]u8 = undefined,
    params_len: usize = 0,
    peer_params: [params_bytes_max]u8 = undefined,
    peer_params_len: ?usize = null,
    offered: [alpn_bytes_max]u8 = undefined,
    offered_len: usize = 0,
    selected: [alpn_bytes_max]u8 = undefined,
    selected_len: ?usize = null,
    /// What each level owes the peer, and what it has read and not yet framed whole.
    owed: [levels][level_bytes_max]u8 = undefined,
    owed_len: [levels]usize = @splat(0),
    heard: [levels][level_bytes_max]u8 = undefined,
    heard_len: [levels]usize = @splat(0),
    started: bool = false,
    complete: bool = false,
    alert: ?tls.Alert = null,
    /// The keys each level has, for reading and for writing.
    keys: [levels][suite_module.directions_count]bool = @splat(@splat(false)),

    /// A client offers `alpn`; a server selects what it is offered, or `other_protocol`.
    pub fn init(role: Role, alpn: []const u8, other: bool) Session {
        assert(alpn.len <= alpn_bytes_max);
        var session: Session = .{ .role = role, .other = other };
        @memcpy(session.offered[0..alpn.len], alpn);
        session.offered_len = alpn.len;
        return session;
    }

    pub fn provider(session: *Session) tls.QuicProvider {
        return .{ .context = session, .vtable = &provider_vtable };
    }

    pub fn suite(session: *Session) crypto.Suite {
        return .{ .context = session, .vtable = &suite_vtable };
    }

    pub fn wipe(session: *Session) void {
        session.* = undefined;
    }

    fn of(context: *anyopaque) *Session {
        return @ptrCast(@alignCast(context));
    }

    fn of_const(context: *const anyopaque) *const Session {
        return @ptrCast(@alignCast(context));
    }

    fn owe(session: *Session, level: Level, message: Message, body: []const []const u8) void {
        const owed = &session.owed[@intFromEnum(level)];
        var at = session.owed_len[@intFromEnum(level)];
        var len: usize = 0;
        for (body) |part| len += part.len;
        // A side owes each of its messages once, whatever the peer sends: `hear_as_client` and
        // `hear_as_server` refuse the message that would owe one again.
        assert(at + frame_bytes + len <= owed.len);
        owed[at] = @intFromEnum(message);
        std.mem.writeInt(u24, owed[at + 1 ..][0..length_bytes], @intCast(len), .big);
        at += frame_bytes;
        for (body) |part| {
            @memcpy(owed[at..][0..part.len], part);
            at += part.len;
        }
        session.owed_len[@intFromEnum(level)] = at;
    }

    fn open_keys(session: *Session, level: Level) void {
        session.keys[@intFromEnum(level)] = @splat(true);
    }

    fn fail(session: *Session, alert: tls.Alert) tls.quic_provider.ProvideError {
        session.alert = alert;
        return error.TlsFailed;
    }

    /// One whole message at `level`, as this side's script reads it.
    fn hear(session: *Session, level: Level, message: Message, body: []const u8) tls.quic_provider.ProvideError!void {
        switch (session.role) {
            .client => try session.hear_as_client(level, message, body),
            .server => try session.hear_as_server(level, message, body),
        }
    }

    fn hear_as_client(session: *Session, level: Level, message: Message, body: []const u8) tls.quic_provider.ProvideError!void {
        switch (message) {
            .server_hello => {
                if (level != .initial) return error.WrongLevel;
                session.open_keys(.handshake);
            },
            .encrypted_extensions => {
                if (level != .handshake) return error.WrongLevel;
                try session.take_extensions(body);
            },
            .finished => {
                if (level != .handshake or session.selected_len == null) return session.fail(.unexpected_message);
                // RFC 9846 §4: a message out of its order ends the handshake with this alert. A
                // second Finished is one, and each owes a Finished: the peer chooses how many come.
                if (keys_available(session, .application, .read)) return session.fail(.unexpected_message);
                session.owe(.handshake, .finished, &.{});
                session.open_keys(.application);
            },
            .client_hello => return session.fail(.unexpected_message),
        }
    }

    fn hear_as_server(session: *Session, level: Level, message: Message, body: []const u8) tls.quic_provider.ProvideError!void {
        switch (message) {
            .client_hello => {
                if (level != .initial) return error.WrongLevel;
                // RFC 9846 §4, as for a client's second Finished: each hello owes a whole flight.
                if (session.selected_len != null) return session.fail(.unexpected_message);
                try session.take_extensions(body);
                if (session.other) {
                    @memcpy(session.selected[0..other_protocol.len], other_protocol);
                    session.selected_len = other_protocol.len;
                }
                const alpn = session.selected[0..session.selected_len.?];
                session.owe(.initial, .server_hello, &.{});
                session.open_keys(.handshake);
                const alpn_len = [_]u8{@intCast(alpn.len)};
                session.owe(.handshake, .encrypted_extensions, &.{ &alpn_len, alpn, session.params[0..session.params_len] });
                session.owe(.handshake, .finished, &.{});
            },
            .finished => {
                if (level != .handshake) return error.WrongLevel;
                session.open_keys(.application);
                session.complete = true;
            },
            else => return session.fail(.unexpected_message),
        }
    }

    /// A hello's or EncryptedExtensions' body: an ALPN token after its length, then transport
    /// parameters.
    fn take_extensions(session: *Session, body: []const u8) tls.quic_provider.ProvideError!void {
        if (body.len < 1) return session.fail(.decode_error);
        // `usize`, not the octet the length is read as: a length of 255 and its own octet are 256.
        const alpn_len: usize = body[0];
        if (body.len < 1 + alpn_len) return session.fail(.decode_error);
        const alpn = body[1..][0..alpn_len];
        const params = body[1 + alpn.len ..];
        if (alpn.len > alpn_bytes_max or params.len > params_bytes_max) return session.fail(.decode_error);
        @memcpy(session.selected[0..alpn.len], alpn);
        session.selected_len = alpn.len;
        @memcpy(session.peer_params[0..params.len], params);
        session.peer_params_len = params.len;
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

fn set_transport_params(context: *anyopaque, body: []const u8) tls.quic_provider.TransportParamsError!void {
    const session = Session.of(context);
    // RFC 9001 §4.1.3: QUIC provides them before starting the handshake.
    if (session.started) return error.HandshakeStarted;
    if (body.len > params_bytes_max) return error.TlsFailed;
    @memcpy(session.params[0..body.len], body);
    session.params_len = body.len;
    session.started = true;
    if (session.role == .server) return;
    const alpn_len = [_]u8{@intCast(session.offered_len)};
    session.owe(.initial, .client_hello, &.{ &alpn_len, session.offered[0..session.offered_len], body });
}

fn peer_transport_params(context: *const anyopaque) ?[]const u8 {
    const session = Session.of_const(context);
    const len = session.peer_params_len orelse return null;
    return session.peer_params[0..len];
}

fn provide_handshake(context: *anyopaque, level: Level, data: []const u8) tls.quic_provider.ProvideError!void {
    const session = Session.of(context);
    const heard = &session.heard[@intFromEnum(level)];
    const len = &session.heard_len[@intFromEnum(level)];
    if (len.* + data.len > heard.len) return error.NoSpaceLeft;
    @memcpy(heard[len.*..][0..data.len], data);
    len.* += data.len;
    var messages: usize = 0;
    while (messages < level_bytes_max / frame_bytes and len.* >= frame_bytes) : (messages += 1) {
        // `usize`, not the `u24` the length is read as: with the frame's four octets a length of
        // 2^24 - 4 or more passes twenty-four bits.
        const body_len: usize = std.mem.readInt(u24, heard[1..][0..length_bytes], .big);
        if (len.* < frame_bytes + body_len) return;
        const message = std.enums.fromInt(Message, heard[0]) orelse return session.fail(.unexpected_message);
        try session.hear(level, message, heard[frame_bytes..][0..body_len]);
        const whole = frame_bytes + body_len;
        std.mem.copyForwards(u8, heard[0 .. len.* - whole], heard[whole..len.*]);
        len.* -= whole;
    }
}

fn write_handshake(context: *anyopaque, level: Level, output: []u8) tls.quic_provider.WriteError!usize {
    const session = Session.of(context);
    const owed = &session.owed[@intFromEnum(level)];
    const len = &session.owed_len[@intFromEnum(level)];
    const written = @min(len.*, output.len);
    @memcpy(output[0..written], owed[0..written]);
    std.mem.copyForwards(u8, owed[0 .. len.* - written], owed[written..len.*]);
    len.* -= written;
    // A client's handshake completes when it has sent its Finished, having read the server's
    // (RFC 9001 §4.1.1).
    const application = session.keys[@intFromEnum(Level.application)][@intFromEnum(suite_module.Direction.write)];
    if (session.role == .client and level == .handshake and len.* == 0 and application) {
        session.complete = true;
    }
    return written;
}

fn negotiated_alpn(context: *const anyopaque) ?[]const u8 {
    const session = Session.of_const(context);
    const len = session.selected_len orelse return null;
    return session.selected[0..len];
}

fn handshake_complete(context: *const anyopaque) bool {
    return Session.of_const(context).complete;
}

fn take_alert(context: *anyopaque) ?tls.Alert {
    const session = Session.of(context);
    const alert = session.alert;
    session.alert = null;
    return alert;
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
    .switch_version = switch_version,
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

fn install_initial_keys(context: *anyopaque, role: Role, dcid: []const u8) suite_module.InstallError!void {
    _ = role;
    _ = dcid;
    Session.of(context).open_keys(.initial);
}

fn keys_available(context: *const anyopaque, level: Level, direction: suite_module.Direction) bool {
    return Session.of_const(context).keys[@intFromEnum(level)][@intFromEnum(direction)];
}

/// The header, the payload, and sixteen octets of tag (RFC 9001 §5.3), with no header protection.
fn seal(context: *anyopaque, sealing: suite_module.Sealing, output: []u8) suite_module.SealError!usize {
    if (!keys_available(context, sealing.level, .write)) return error.KeysUnavailable;
    const tag = crypto.constants.aead_tag_len;
    const len = sealing.header.len + sealing.payload.len + tag;
    if (output.len < len) return error.NoSpaceLeft;
    @memcpy(output[0..sealing.header.len], sealing.header);
    @memcpy(output[sealing.header.len..][0..sealing.payload.len], sealing.payload);
    @memset(output[len - tag .. len], 0);
    return len;
}

/// The packet number, read where the header puts it, and the payload in place. The first octet's
/// low bits give the packet number's length (RFC 9000 §17.2, §17.3.1), since nothing masked them.
fn open(context: *anyopaque, opening: suite_module.Opening) suite_module.OpenError!suite_module.Opened {
    if (!keys_available(context, opening.level, .read)) return error.KeysUnavailable;
    const packet = opening.packet;
    const number_len: u8 = (packet[0] & crypto.constants.packet_number_len_mask) + 1;
    const tag = crypto.constants.aead_tag_len;
    if (packet.len < opening.packet_number_offset + number_len + tag) return error.Discarded;
    var value: u32 = 0;
    for (packet[opening.packet_number_offset..][0..number_len]) |octet| value = (value << @bitSizeOf(u8)) | octet;
    const number = crypto.packet_number.decode(opening.largest_packet_number, .{ .value = value, .len = number_len });
    return .{
        .packet_number = number,
        .packet_number_len = number_len,
        .payload_len = packet.len - opening.packet_number_offset - number_len - tag,
        .key_set = .current,
    };
}

// What the gate's QUIC never does: a switch to QUIC version 2 (colibri's decision 108), a Retry, a
// key update. colibri drops a packet whose switch the suite refuses (its `connection_receive.zig`).
// No packet on the twin asks for a switch: the test server never asks colibri to choose a version,
// so it answers in version 1 (RFC 9000 §15).

fn switch_version(context: *anyopaque, version: suite_module.Version) suite_module.SwitchError!void {
    _ = context;
    _ = version;
    return error.Refused;
}

fn retry_tag_valid(context: *const anyopaque, version: suite_module.Version, pseudo_packet: []const u8, tag: *const [crypto.constants.retry_integrity_tag_len]u8) bool {
    _ = context;
    _ = version;
    _ = pseudo_packet;
    _ = tag;
    return false;
}

fn retry_tag_write(context: *const anyopaque, version: suite_module.Version, pseudo_packet: []const u8, tag: *[crypto.constants.retry_integrity_tag_len]u8) suite_module.RetryTagError!void {
    _ = context;
    _ = version;
    _ = pseudo_packet;
    _ = tag;
    return error.Unsupported;
}

fn retry_token_write(context: *anyopaque, version: suite_module.Version, address: []const u8, ids: *const suite_module.RetryConnectionIds, now_ns: u64, output: []u8) suite_module.TokenError!usize {
    _ = context;
    _ = version;
    _ = address;
    _ = ids;
    _ = now_ns;
    _ = output;
    return error.Unsupported;
}

fn retry_token_check(context: *const anyopaque, version: suite_module.Version, address: []const u8, token: []const u8, now_ns: u64) suite_module.TokenCheck {
    _ = context;
    _ = version;
    _ = address;
    _ = token;
    _ = now_ns;
    return .not_retry;
}

fn update_keys(context: *anyopaque) suite_module.UpdateError!void {
    _ = context;
    return error.Unsupported;
}

fn key_phase(context: *const anyopaque) bool {
    _ = context;
    return false;
}

fn discard_previous_keys(context: *anyopaque) void {
    _ = context;
}

fn discard_keys(context: *anyopaque, level: Level) void {
    Session.of(context).keys[@intFromEnum(level)] = @splat(false);
}

// Tests.

const testing = std.testing;

/// A client that has given its transport parameters, and so has begun its handshake.
fn started_client() !Session {
    var session = Session.init(.client, "doq", false);
    try session.provider().set_transport_params(&.{0});
    return session;
}

test "an ALPN length of 255 with no token after it is a decode error, as one of 254 is" {
    // The length and its own octet sum to 256, past the octet the length is read as.
    for ([_]u8{ std.math.maxInt(u8) - 1, std.math.maxInt(u8) }) |alpn_len| {
        var session = try started_client();
        const extensions = [_]u8{ @intFromEnum(Message.encrypted_extensions), 0, 0, 1, alpn_len };
        try testing.expectError(error.TlsFailed, session.provider().provide_handshake(.handshake, &extensions));
        try testing.expectEqual(@as(?tls.Alert, .decode_error), session.alert);
    }
}

test "a message as long as three octets can say is waited for, and nothing is read of it" {
    // The length and the frame's four octets sum past twenty-four bits from a length of 2^24 - 4.
    const longest = std.math.maxInt(u24);
    for ([_]u24{ longest - frame_bytes, longest - frame_bytes + 1, longest }) |body_len| {
        var session = try started_client();
        var frame: [frame_bytes]u8 = undefined;
        frame[0] = @intFromEnum(Message.server_hello);
        std.mem.writeInt(u24, frame[1..][0..length_bytes], body_len, .big);
        try session.provider().provide_handshake(.initial, &frame);
        try testing.expectEqual(@as(usize, frame_bytes), session.heard_len[@intFromEnum(Level.initial)]);
        try testing.expectEqual(@as(?tls.Alert, null), session.alert);
        try testing.expect(!keys_available(&session, .handshake, .read));
    }
}

/// A Finished, which has no body.
const finished = [_]u8{ @intFromEnum(Message.finished), 0, 0, 0 };

test "a client refuses a second Finished, and owes one of its own" {
    // Each Finished a client hears owes one, and the peer chooses how many come.
    var session = try started_client();
    const extensions = [_]u8{ @intFromEnum(Message.encrypted_extensions), 0, 0, 4, 3, 'd', 'o', 'q' };
    try session.provider().provide_handshake(.handshake, &(extensions ++ finished));
    const owed = session.owed_len[@intFromEnum(Level.handshake)];
    try testing.expectEqual(@as(usize, frame_bytes), owed);
    try testing.expectError(error.TlsFailed, session.provider().provide_handshake(.handshake, &finished));
    try testing.expectEqual(@as(?tls.Alert, .unexpected_message), session.alert);
    try testing.expectEqual(owed, session.owed_len[@intFromEnum(Level.handshake)]);
}

test "a server refuses a second ClientHello, and its flight at its longest fits a level" {
    var session = Session.init(.server, "doq", false);
    const params: [params_bytes_max]u8 = @splat(0);
    try session.provider().set_transport_params(&params);
    // A hello at its longest: an ALPN token and transport parameters, each the most a side keeps.
    var hello: [frame_bytes + 1 + alpn_bytes_max + params_bytes_max]u8 = @splat('a');
    hello[0] = @intFromEnum(Message.client_hello);
    std.mem.writeInt(u24, hello[1..][0..length_bytes], hello.len - frame_bytes, .big);
    hello[frame_bytes] = alpn_bytes_max;
    try session.provider().provide_handshake(.initial, &hello);
    // EncryptedExtensions as long as the hello, and a Finished.
    const owed = session.owed_len;
    try testing.expectEqual(@as(usize, hello.len + frame_bytes), owed[@intFromEnum(Level.handshake)]);
    try testing.expectError(error.TlsFailed, session.provider().provide_handshake(.initial, &hello));
    try testing.expectEqual(@as(?tls.Alert, .unexpected_message), session.alert);
    try testing.expectEqual(owed, session.owed_len);
}

test "the plain suite refuses a switch to QUIC version 2, so colibri drops a packet that asks for one" {
    // colibri's suite names the QUIC version of each packet (its decision 108). The gate's QUIC
    // speaks version 1 alone, which RFC 9000 §15 numbers 0x00000001: the test server never asks
    // colibri to choose a version, and `Plain` starts in version 1.
    var session = try started_client();
    try testing.expectError(error.Refused, session.suite().vtable.switch_version(&session, .v2));
}
