//! A TLS provider and a packet-protection suite that encrypt nothing, for the gate (docs/design.md
//! §24, colibri under the request interface). colibri's connection takes both, and this pair lets
//! the engine run colibri's real QUIC on the twin: packets, streams, flow control, loss and its
//! recovery, with nothing sealed. It is written from colibri's two vtables and RFC 9001, and it is
//! for tests: a consumer's connection runs chapulin's QUIC object instead.
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
const tls = quic.tls;
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

/// One side of one connection's handshake, and its keys.
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
        if (body.len < 1 or body.len < 1 + body[0]) return session.fail(.decode_error);
        const alpn = body[1..][0..body[0]];
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
        const body_len = std.mem.readInt(u24, heard[1..][0..length_bytes], .big);
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

// What the gate's QUIC never does: a Retry, a key update.

fn retry_tag_valid(context: *const anyopaque, pseudo_packet: []const u8, tag: *const [crypto.constants.retry_integrity_tag_len]u8) bool {
    _ = context;
    _ = pseudo_packet;
    _ = tag;
    return false;
}

fn retry_tag_write(context: *const anyopaque, pseudo_packet: []const u8, tag: *[crypto.constants.retry_integrity_tag_len]u8) suite_module.RetryTagError!void {
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
