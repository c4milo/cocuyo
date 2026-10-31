//! The servers the replay asks and the replies they answer with: one message per reply the model
//! names (spec/lean/Spec/Lookup.lean, `Reply`), built around the question the lookup is asking now.
//!
//! A reply must echo the name as it went out, case included, and carry the transaction's id, so a
//! message cannot be written until the lookup has drawn both (docs/design.md §7). Each builder
//! reads them from the lookup rather than from the query bytes, which the replay does not keep.
//!
//! This file is exempt from the magic-numbers rule: it is a corpus of wire octets, and naming each
//! one would say less than the octets do (tools/lint/magic_numbers.zig).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const Lookup = @import("resolver").Lookup;

/// The servers a configuration takes the first of: documentation addresses from RFC 5737.
pub const servers = [_]core.Server{
    .{ .endpoint = .{ .address = core.Address.from_v4(.{ 192, 0, 2, 53 }) } },
    .{ .endpoint = .{ .address = core.Address.from_v4(.{ 192, 0, 2, 54 }) } },
    .{ .endpoint = .{ .address = core.Address.from_v4(.{ 192, 0, 2, 55 }) } },
};

/// The same servers over DoH (docs/design.md §22).
const https: core.Https = .{ .template = "https://dns.example/dns-query{?dns}" };
pub const servers_https = [_]core.Server{
    .{ .endpoint = servers[0].endpoint, .https = https },
    .{ .endpoint = servers[1].endpoint, .https = https },
    .{ .endpoint = servers[2].endpoint, .https = https },
};

/// The same servers over DoQ (docs/design.md §23), known by a name as a DoT server is.
const quic: core.Tls = .{ .name = core.Name.from_text("dns.example.") catch unreachable };
pub const servers_quic = [_]core.Server{
    .{ .endpoint = servers[0].endpoint, .quic = quic },
    .{ .endpoint = servers[1].endpoint, .quic = quic },
    .{ .endpoint = servers[2].endpoint, .quic = quic },
};

/// What a reply is, once §7's checks and §5's rcode policy have read it: the model's `Reply`.
pub const Reply = enum {
    /// The right server and question with an id one off: it fails check 2 of §7. Over DoH or
    /// DoQ, where the id is not checked, the replay hands it over as another transaction's answer.
    unmatched,
    answer,
    cname,
    nxdomain,
    nodata,
    /// YXDOMAIN, which a DNAME substitution that made the name too long gives (RFC 6672 §2.2).
    yxdomain,
    servfail,
    formerr,
    truncated,
    badcookie,
    /// A datagram longer than a buffer's room, which the kernel cut to the room and marked: the
    /// engine model's reply alone (spec/tla/engine/EngineEvents.tla, `Replies`), which `build_cut`
    /// writes.
    cut,
};

/// An A record owned by the question's name, 192.0.2.1, TTL 300. The owner is the compression
/// pointer to the question every real server sends (RFC 1035 §4.1.4).
const record_a = [_]u8{
    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 192, 0, 2, 1,
};

/// An AAAA record owned by the question's name, 2001:db8::1, TTL 300 (RFC 3596 §2.2).
const record_aaaa = [_]u8{ 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x10 } ++
    [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 11 ++ [_]u8{1};

/// A PTR record owned by the question's name, pointing at `host.test`, TTL 300 (RFC 1035 §3.3.12).
const record_ptr = [_]u8{ 0xc0, 0x0c, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x0b } ++
    "\x04host\x04test\x00".*;

/// A CNAME from the question's name to `c.` plus that name: a target no record in the message
/// owns, and a new one at every hop, so each reply moves the chain by exactly one.
const record_cname = [_]u8{
    0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x01, 'c', 0xc0, 0x0c,
};

/// The OPT record's TTL octet that carries the extended rcode's high bits (RFC 6891 §6.1.3).
const opt_extended_rcode_at = 5;

const Shape = struct {
    rcode: wire.Rcode = .no_error,
    truncated: bool = false,
    records: []const u8 = &.{},
    ancount: u16 = 0,
    id_offset: u16 = 0,
};

/// The record that answers a question of `kind`: an A record for anything but AAAA and PTR.
fn answer_of(kind: core.Kind) []const u8 {
    return switch (kind) {
        .aaaa => &record_aaaa,
        .ptr => &record_ptr,
        else => &record_a,
    };
}

fn shape_of(reply: Reply, kind: core.Kind) Shape {
    return switch (reply) {
        .unmatched => .{ .records = &record_a, .ancount = 1, .id_offset = 1 },
        .answer => .{ .records = answer_of(kind), .ancount = 1 },
        .cname => .{ .records = &record_cname, .ancount = 1 },
        .nxdomain => .{ .rcode = .name_error },
        .nodata => .{},
        .yxdomain => .{ .rcode = .yxdomain },
        .servfail => .{ .rcode = .server_failure },
        .formerr => .{ .rcode = .format_error },
        .truncated => .{ .truncated = true },
        .badcookie => .{ .rcode = .bad_cookie },
        // The answer, before the cut took its end (`build_cut`).
        .cut => .{ .records = answer_of(kind), .ancount = 1 },
    };
}

/// Builds `reply` to what `lookup` is asking into `out`, with AD clear.
pub fn build(lookup: *const Lookup, reply: Reply, out: []u8) []const u8 {
    return build_with(lookup, reply, false, out);
}

/// As `build`, with AD set when `authentic` says so (docs/design.md §25, Stage A).
pub fn build_with(lookup: *const Lookup, reply: Reply, authentic: bool, out: []u8) []const u8 {
    const shape = shape_of(reply, lookup.question.kind);
    const rcode: u16 = @intFromEnum(shape.rcode);
    const extended_high: u8 = @intCast(rcode >> wire.constants.extended_rcode_low_bits);
    var flags: u16 = wire.constants.flag_response | wire.constants.flag_recursion_desired |
        wire.constants.flag_recursion_available | (rcode & wire.constants.rcode_mask);
    if (shape.truncated) flags |= wire.constants.flag_truncated;
    if (authentic) flags |= wire.constants.flag_authentic_data;
    const header: wire.Header = .{
        .id = lookup.transaction.id +% shape.id_offset,
        .flags = flags,
        .qdcount = 1,
        .ancount = shape.ancount,
        .nscount = 0,
        .arcount = if (extended_high != 0) 1 else 0,
    };
    wire.header.write(&header, out);
    var offset: usize = core.constants.header_bytes;
    const name = lookup.cased_name();
    offset += wire.question.write(&name, lookup.question.kind, out[offset..]);
    @memcpy(out[offset..][0..shape.records.len], shape.records);
    offset += shape.records.len;
    // BADCOOKIE is an extended rcode, so it needs an OPT record to hold its high bits. The
    // record has no COOKIE option: a server that has never given a server cookie may omit it,
    // and the lookup's check lets that through (RFC 7873 §5.3).
    if (extended_high != 0) {
        const written = wire.edns.write(core.constants.udp_payload_bytes_default, null, out[offset..]);
        out[offset + opt_extended_rcode_at] = extended_high;
        offset += written;
    }
    assert(offset <= out.len);
    return out[0..offset];
}

/// Where an OPT record's RDLENGTH sits: after the root owner, the type, the class and the TTL
/// (RFC 6891 §6.1.2).
const opt_rdlength_at = 9;

/// The answer to what `lookup` is asking, grown to one octet past `room` by a Padding option of
/// zeros in an OPT record (RFC 7830 §3), and the first `room` octets of it: what a buffer of that
/// room keeps of the datagram. The cut takes the last octet of the padding.
pub fn build_cut(lookup: *const Lookup, room: usize, out: []u8) []const u8 {
    assert(out.len > room);
    const answer = build(lookup, .answer, out);
    var header = wire.header.parse(answer) catch unreachable;
    header.arcount = 1;
    wire.header.write(&header, out);
    const opt_at = answer.len;
    const options_at = opt_at + wire.edns.write(core.constants.udp_payload_bytes_default, null, out[opt_at..]);
    const padding = room + 1 - options_at - core.constants.opt_option_header_bytes;
    wire.integer.write_u16(out, options_at, wire.constants.padding_option_code);
    wire.integer.write_u16(out, options_at + 2, @intCast(padding));
    @memset(out[options_at + core.constants.opt_option_header_bytes ..][0..padding], 0);
    wire.integer.write_u16(out, opt_at + opt_rdlength_at, @intCast(core.constants.opt_option_header_bytes + padding));
    return out[0..room];
}
