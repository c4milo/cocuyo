//! The scripted DNS server (docs/design.md §19 step 13): what a query gets back is decided by a
//! script and a seed, not by a network. It answers A and AAAA with an address derived from the
//! name, says NODATA for any other type, and, as the draw says, drops the query, delays it,
//! truncates it, answers SERVFAIL or NXDOMAIN, or echoes the cookie it was sent with a server
//! cookie of its own (RFC 7873 §5.2.3).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("constants.zig");
const types = @import("sim_types.zig");
const Address = types.Address;
const Name = core.Name;

/// What one server does, per query. Chances are in 256ths and drawn from the seed.
pub const Script = struct {
    drop_per_256: u8 = 0,
    truncate_per_256: u8 = 0,
    servfail_per_256: u8 = 0,
    nxdomain_per_256: u8 = 0,
    /// The reply's delay, drawn between the two.
    delay_ns_min: u64 = 1_000_000,
    delay_ns_max: u64 = 5_000_000,
    /// Never answers, over UDP or TCP.
    down: bool = false,
    /// A send to it fails at the socket, the way a route that is not there fails one.
    no_route: bool = false,
    /// Echoes the client cookie with a server cookie; off, the OPT record carries no cookie.
    cookies: bool = true,
    /// Accepts TCP connections.
    tcp: bool = true,
    ttl_seconds: u32 = constants.answer_ttl_seconds,
};

pub const Answer = struct { len: usize, delay_ns: u64 };

/// Answers `query` into `out` as `script` and `draw` decide, or null when the query is dropped
/// or the server is down. `over_tcp` turns truncation off: a stream has nothing to truncate
/// (RFC 7766 §5).
pub fn respond(
    script: *const Script,
    address: *const Address,
    query: []const u8,
    over_tcp: bool,
    draw: u64,
    out: []u8,
) ?Answer {
    if (script.down) return null;
    const header = wire.header.parse(query) catch return null;
    if (header.qdcount != 1) return null;
    var name: Name = Name.empty;
    const question = wire.question.parse(query, &name) catch return null;
    const dice = Dice.of(draw);
    if (dice.hit(script.drop_per_256)) return null;
    const decision = decide(script, &dice, over_tcp, question.kind_code);
    const opt = (wire.response_opt.find(query, &name) catch null);
    const reply_header: wire.Header = .{
        .id = header.id,
        .flags = decision.flags,
        .qdcount = 1,
        .ancount = if (decision.answered) 1 else 0,
        .nscount = 0,
        .arcount = if (opt != null) 1 else 0,
    };
    var len: usize = core.constants.header_bytes;
    wire.header.write(&reply_header, out);
    const question_bytes = query[core.constants.header_bytes..question.end];
    @memcpy(out[len..][0..question_bytes.len], question_bytes);
    len += question_bytes.len;
    if (decision.answered) len += write_answer(&name, core.Kind.from_code(question.kind_code).?, script.ttl_seconds, out[len..]);
    if (opt) |record| len += write_opt(script, address, &record, out[len..]);
    assert(len <= out.len);
    return .{ .len = len, .delay_ns = dice.delay(script) };
}

const Decision = struct { flags: u16, answered: bool };

/// The rcode, the TC bit and whether a record goes in, from the script and the dice.
fn decide(script: *const Script, dice: *const Dice, over_tcp: bool, kind_code: u16) Decision {
    var flags: u16 = wire.constants.flag_response | wire.constants.flag_recursion_desired |
        wire.constants.flag_recursion_available;
    var rcode: wire.Rcode = .no_error;
    if (dice.hit_second(script.servfail_per_256)) rcode = .server_failure;
    if (rcode == .no_error and dice.hit_third(script.nxdomain_per_256)) rcode = .name_error;
    const truncate = !over_tcp and rcode == .no_error and dice.hit_fourth(script.truncate_per_256);
    if (truncate) flags |= wire.constants.flag_truncated;
    flags |= @intFromEnum(rcode);
    const kind = core.Kind.from_code(kind_code);
    const answered = rcode == .no_error and !truncate and kind != null and address_kind(kind.?);
    return .{ .flags = flags, .answered = answered };
}

fn address_kind(kind: core.Kind) bool {
    return kind == .a or kind == .aaaa;
}

/// One record owned by the question, a pointer to it (RFC 1035 §4.1.4): an A or AAAA whose
/// address is a function of the name, so the same name answers the same on every seed.
fn write_answer(name: *const Name, kind: core.Kind, ttl_seconds: u32, out: []u8) usize {
    const octet: u8 = @truncate(core.mix.next(std.hash.Wyhash.hash(0, name.wire())));
    var len: usize = 0;
    wire.integer.write_u16(out, len, wire.constants.label_kind_pointer << wire.constants.octet_bits | core.constants.header_bytes);
    len += wire.constants.u16_bytes;
    wire.integer.write_u16(out, len, kind.code());
    len += wire.constants.u16_bytes;
    wire.integer.write_u16(out, len, core.constants.class_internet);
    len += wire.constants.u16_bytes;
    wire.integer.write_u32(out, len, ttl_seconds);
    len += wire.constants.u32_bytes;
    const rdata_len: u16 = if (kind == .a) core.constants.address_v4_bytes else core.constants.address_v6_bytes;
    wire.integer.write_u16(out, len, rdata_len);
    len += wire.constants.u16_bytes;
    @memset(out[len..][0..rdata_len], 0);
    if (kind == .a) {
        out[len..][0..constants.server_prefix.len].* = constants.server_prefix;
        out[len + constants.server_prefix.len] = octet | 1;
    } else {
        out[len..][0..constants.answer_v6_prefix.len].* = constants.answer_v6_prefix;
        out[len + rdata_len - 1] = octet | 1;
    }
    len += rdata_len;
    assert(len == core.constants.record_fixed_bytes + wire.constants.pointer_bytes + rdata_len);
    return len;
}

/// The OPT record in the reply: the client cookie echoed with this server's cookie when the
/// script says so (RFC 7873 §5.2.3), or an OPT with no options.
fn write_opt(script: *const Script, address: *const Address, opt: *const wire.Record, out: []u8) usize {
    const view = (wire.edns.find_cookie(opt.rdata) catch null);
    if (!script.cookies or view == null) {
        return wire.edns.write(core.constants.udp_payload_bytes_default, null, out);
    }
    const cookie: wire.Cookie = .{
        .client = view.?.client.*,
        .server = server_cookie(address),
        .server_len = constants.server_cookie_bytes,
    };
    return wire.edns.write(core.constants.udp_payload_bytes_default, &cookie, out);
}

/// A server's cookie: its address, repeated, which the tests can predict.
pub fn server_cookie(address: *const Address) [core.constants.cookie_server_bytes_max]u8 {
    var cookie: [core.constants.cookie_server_bytes_max]u8 = @splat(0);
    for (cookie[0..constants.server_cookie_bytes], 0..) |*byte, index| {
        byte.* = address.bytes[index % Address.ipv4_bytes] ^ @as(u8, @truncate(address.port));
    }
    return cookie;
}

/// The draws one query makes from one word: four chances and a delay, each from its own octets.
const Dice = struct {
    word: u64,

    fn of(draw: u64) Dice {
        return .{ .word = core.mix.next(draw) };
    }

    fn octet(self: Dice, shift: u6) u8 {
        return @truncate(self.word >> shift);
    }

    fn hit(self: Dice, per_256: u8) bool {
        return self.octet(constants.dice_drop_shift) < per_256;
    }

    fn hit_second(self: Dice, per_256: u8) bool {
        return self.octet(constants.dice_servfail_shift) < per_256;
    }

    fn hit_third(self: Dice, per_256: u8) bool {
        return self.octet(constants.dice_nxdomain_shift) < per_256;
    }

    fn hit_fourth(self: Dice, per_256: u8) bool {
        return self.octet(constants.dice_truncate_shift) < per_256;
    }

    fn delay(self: Dice, script: *const Script) u64 {
        assert(script.delay_ns_max >= script.delay_ns_min);
        const span = script.delay_ns_max - script.delay_ns_min + 1;
        return script.delay_ns_min + (self.word >> constants.dice_delay_shift) % span;
    }
};

// Tests.

const testing = std.testing;

const fixtures = @import("fixtures.zig");
const server_address = fixtures.server_address;

fn query_bytes(out: []u8, kind: core.Kind, with_cookie: bool) []const u8 {
    var query: wire.Query = .{
        .id = fixtures.server_query_id,
        .name = Name.from_text("example.com") catch unreachable,
        .kind = kind,
    };
    if (with_cookie) query.cookie = .{ .client = @splat(fixtures.client_cookie_fill), .server = @splat(0), .server_len = 0 };
    return out[0..wire.query.write(&query, out)];
}

test "an A question is answered with one address owned by the name, the same on every seed" {
    var query_out: [core.constants.query_bytes_max]u8 = undefined;
    const query = query_bytes(&query_out, .a, false);
    var reply: [constants.datagram_bytes_max]u8 = undefined;
    const script: Script = .{};
    const first = respond(&script, &server_address, query, false, 1, &reply).?;
    var chain = try Name.from_text("example.com");
    var answers: wire.Answers = undefined;
    try testing.expectEqual(wire.Outcome.answered, try wire.response.collect(reply[0..first.len], &chain, .a, 0, &answers));
    const address = answers.addresses()[0];
    const second = respond(&script, &server_address, query, false, 99, &reply).?;
    try testing.expectEqual(wire.Outcome.answered, try wire.response.collect(reply[0..second.len], &chain, .a, 0, &answers));
    try testing.expect(address.equal(&answers.addresses()[0]));
    try testing.expect(first.delay_ns >= script.delay_ns_min and first.delay_ns <= script.delay_ns_max);
}

test "a server that is down, or a drop, answers nothing" {
    var query_out: [core.constants.query_bytes_max]u8 = undefined;
    const query = query_bytes(&query_out, .a, false);
    var reply: [constants.datagram_bytes_max]u8 = undefined;
    const down: Script = .{ .down = true };
    try testing.expectEqual(@as(?Answer, null), respond(&down, &server_address, query, false, 1, &reply));
    const drops: Script = .{ .drop_per_256 = 255 };
    var dropped: usize = 0;
    var draw: u64 = 0;
    while (draw < 64) : (draw += 1) {
        if (respond(&drops, &server_address, query, false, draw, &reply) == null) dropped += 1;
    }
    try testing.expect(dropped >= 60);
}

test "truncation sets TC over UDP and never over TCP, and the rcodes come as scripted" {
    var query_out: [core.constants.query_bytes_max]u8 = undefined;
    const query = query_bytes(&query_out, .a, false);
    var reply: [constants.datagram_bytes_max]u8 = undefined;
    const truncating: Script = .{ .truncate_per_256 = 255 };
    const udp = respond(&truncating, &server_address, query, false, 1, &reply).?;
    try testing.expect((try wire.header.parse(reply[0..udp.len])).truncated());
    const tcp = respond(&truncating, &server_address, query, true, 1, &reply).?;
    try testing.expect(!(try wire.header.parse(reply[0..tcp.len])).truncated());
    const failing: Script = .{ .servfail_per_256 = 255 };
    const failed = respond(&failing, &server_address, query, false, 1, &reply).?;
    try testing.expectEqual(wire.Rcode.server_failure, try (try wire.header.parse(reply[0..failed.len])).rcode());
    const missing: Script = .{ .nxdomain_per_256 = 255 };
    const nx = respond(&missing, &server_address, query, false, 1, &reply).?;
    try testing.expectEqual(wire.Rcode.name_error, try (try wire.header.parse(reply[0..nx.len])).rcode());
}

test "a cookie is echoed with the server's own, and a server without cookies sends a bare OPT" {
    var query_out: [core.constants.query_bytes_max]u8 = undefined;
    const query = query_bytes(&query_out, .a, true);
    var reply: [constants.datagram_bytes_max]u8 = undefined;
    const script: Script = .{};
    const answer = respond(&script, &server_address, query, false, 1, &reply).?;
    const name = try Name.from_text("example.com");
    const opt = (try wire.response_opt.find(reply[0..answer.len], &name)).?;
    const cookie = (try wire.edns.find_cookie(opt.rdata)).?;
    try testing.expectEqualSlices(u8, &[_]u8{fixtures.client_cookie_fill} ** 8, cookie.client);
    try testing.expectEqualSlices(u8, server_cookie(&server_address)[0..constants.server_cookie_bytes], cookie.server);
    const bare: Script = .{ .cookies = false };
    const plain = respond(&bare, &server_address, query, false, 1, &reply).?;
    const bare_opt = (try wire.response_opt.find(reply[0..plain.len], &name)).?;
    try testing.expectEqual(@as(?wire.CookieView, null), try wire.edns.find_cookie(bare_opt.rdata));
}

test "a question of a type the server does not hold is NODATA" {
    var query_out: [core.constants.query_bytes_max]u8 = undefined;
    const query = query_bytes(&query_out, .mx, false);
    var reply: [constants.datagram_bytes_max]u8 = undefined;
    const script: Script = .{};
    const answer = respond(&script, &server_address, query, false, 1, &reply).?;
    try testing.expectEqual(@as(u16, 0), (try wire.header.parse(reply[0..answer.len])).ancount);
}
