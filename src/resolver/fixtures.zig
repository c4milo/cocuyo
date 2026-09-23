//! A fake server for the tests of this module: it echoes whatever the lookup asked and appends
//! the records a test wants.
//!
//! Canned messages will not do here. A lookup draws a new transaction id and a new case pattern
//! per query, and moves through search candidates, so the question a response must echo is not
//! known until the query is built. The harness reads the query the lookup produced, copies its
//! question section back, and builds a reply around it. That also means the tests run with
//! DNS-0x20 on, which is the default a caller gets.
//!
//! This file is exempt from the magic-numbers rule: it is a corpus of wire octets, and naming each
//! one would say less than the octets do (tools/lint/magic_numbers.zig).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const Config = core.Config;
const Endpoint = core.Endpoint;
const Kind = core.Kind;
const Name = core.Name;
const Question = core.Question;
const lookup_module = @import("lookup.zig");
const table_module = @import("table.zig");
const slots_module = @import("table_slots.zig");
const Resolver = table_module.Resolver;
const Event = table_module.Event;
const MatchKey = table_module.MatchKey;
const Handle = slots_module.Handle;
const Slot = slots_module.Slot;
const Lookup = lookup_module.Lookup;
const Action = lookup_module.Action;
const Verdict = lookup_module.Verdict;
const Server = core.Server;
const Servers = @import("servers.zig").Servers;

/// The servers the tests ask. Documentation addresses, from RFC 5737.
pub const servers_one = [_]Server{
    .{ .endpoint = .{ .address = core.Address.from_v4(.{ 192, 0, 2, 53 }) } },
};

pub const servers_two = [_]Server{
    .{ .endpoint = .{ .address = core.Address.from_v4(.{ 192, 0, 2, 53 }) } },
    .{ .endpoint = .{ .address = core.Address.from_v4(.{ 192, 0, 2, 54 }) } },
};

pub const servers_three = [_]Server{
    .{ .endpoint = .{ .address = core.Address.from_v4(.{ 192, 0, 2, 53 }) } },
    .{ .endpoint = .{ .address = core.Address.from_v4(.{ 192, 0, 2, 54 }) } },
    .{ .endpoint = .{ .address = core.Address.from_v4(.{ 192, 0, 2, 55 }) } },
};

/// A port that is not 53, for the check that a reply from the right host on the wrong port is not
/// a reply (RFC 5452 §4.5).
pub const port_other = 5353;

/// The seed the tests start their lookups with.
pub const seed = 0x5eed_5eed;

/// An A record owned by whatever the question named: 192.0.2.1, TTL 300. The owner is the
/// compression pointer every real server sends (RFC 1035 §4.1.4). This record and the six others
/// taken from `wire.fixtures` are the codec's corpus, octet for octet.
pub const record_a = wire.fixtures.record_a;

/// An AAAA record owned by whatever the question named: 2001:db8::1, TTL 60, so a join of the
/// two families has a smaller TTL to take.
pub const record_aaaa = [_]u8{
    0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x10,
    0x20, 0x01, 0x0d, 0xb8, 0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    1,
};

/// A second A record for the same owner: 192.0.2.2.
pub const record_a_second = wire.fixtures.record_a_second;

/// A PTR record owned by whatever the question named, pointing at `host.example.net`, TTL 300.
pub const record_ptr = [_]u8{
    0xc0, 0x0c, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x12,
} ++ "\x04host\x07example\x03net\x00".*;

/// A CNAME from the question's name to `host.example.net`, TTL 60.
pub const record_cname = wire.fixtures.record_cname;

/// A CNAME to `host.` plus a pointer to offset 20, which is the `com` label of `example.com` in
/// the question the harness echoes back. A server that compresses a target's suffix into the
/// question is doing something ordinary; what makes it interesting is that the question carries
/// the case DNS-0x20 randomised.
pub const record_cname_into_question = [_]u8{
    0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x07,
} ++ "\x04host".* ++ [_]u8{ 0xc0, 0x14 };

/// The A record for `host.example.net`, 192.0.2.3, TTL 300.
pub const record_cname_target_a = wire.fixtures.record_cname_target_a;

/// A CNAME from `host.example.net` back to whatever the question named, its rdata a pointer to
/// the question's own name at offset 12. With the record above, this is a chain that loops.
pub const record_cname_back = "\x04host\x07example\x03net\x00".* ++ [_]u8{
    0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x02, 0xc0, 0x0c,
};

/// An A record for a name nobody asked about.
pub const record_injected_a = wire.fixtures.record_injected_a;

/// An MX record owned by the question's name: preference 10, exchange `mail` then a pointer to
/// the question's name, TTL 300 (RFC 1035 §3.3.9, §4.1.4).
pub const record_mx = wire.fixtures.record_mx_compressed;

/// An A record whose rdlength reaches past the end of the message.
pub const record_long_rdlength = [_]u8{
    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x01, 0x90, 192, 0, 2, 1,
};

/// An SOA owned by the question's name, TTL 300, MINIMUM 60: what an authoritative server puts in
/// the authority section of a negative answer (RFC 2308 §2).
pub const record_soa = wire.fixtures.record_soa;

/// The same SOA with an rdlength one octet over its rdata, so its minimum cannot be read.
pub const record_soa_broken = record_soa[0..10].* ++ [_]u8{ 0x00, 0x22 } ++ record_soa[12..].* ++ [_]u8{0x00};

/// What the fake server sends back.
pub const Reply = struct {
    rcode: wire.Rcode = .no_error,
    truncated: bool = false,
    /// The answer section, one of the records above or several concatenated.
    records: []const u8 = &.{},
    ancount: u16 = 0,
    /// The authority section, where a negative answer's SOA goes.
    authority: []const u8 = &.{},
    nscount: u16 = 0,
    /// An id to echo instead of the one that was asked, which is how a spoof is written.
    id: ?u16 = null,
    /// Whether to fold the question's case rather than echoing it: the other half of a spoof.
    fold_case: bool = false,
    /// Whether to echo a question for another name entirely.
    other_name: bool = false,
    /// The COOKIE option to put in an OPT record in the additional section (RFC 7873 §5.2).
    cookie: CookieReply = .none,
    /// The server cookie to send beside the client's, when `cookie` sends one; empty for the
    /// short form.
    server_cookie: []const u8 = &.{},
};

/// What the fake server does about cookies.
pub const CookieReply = enum {
    /// No OPT record at all.
    none,
    /// An OPT record with no options: a server that has EDNS and no cookies.
    opt_only,
    /// The client cookie the lookup sent, echoed back (RFC 7873 §5.2.3, §5.2.5).
    echo,
    /// Another client cookie: an answer forged off-path, or a mix-up (RFC 7873 §5.3).
    wrong,
    /// A COOKIE option nine octets long, which neither form allows (RFC 7873 §5.2.2).
    malformed,
};

/// A sixteen-octet server cookie, the length RFC 9018 §3 fixes.
pub const server_cookie = [_]u8{0xc0} ++ [_]u8{0xcc} ** 15;
/// Another one, for the fresh cookie a BADCOOKIE response carries (RFC 7873 §5.2.4).
pub const server_cookie_fresh = [_]u8{0xf0} ++ [_]u8{0xff} ** 15;

/// The record rewritten at the harness's cookie: the client's own, or a wrong one.
const cookie_client_wrong = [_]u8{ 0xba, 0xdc, 0x00, 0xc1, 0xe0, 0x00, 0x00, 0x01 };

/// A reply carrying one A record.
/// Answers as a memory above the table hands them back: one A record, with a life to spare so
/// nothing expires while a test runs (docs/design.md §20).
pub const cached_ttl_seconds = 300;

pub fn cached_a(text: []const u8) wire.Answers {
    return wire.fixtures.answers_address(core.Address.from_text(text).?, cached_ttl_seconds);
}

pub const answer_a: Reply = .{ .records = &record_a, .ancount = 1 };
pub const answer_ptr: Reply = .{ .records = &record_ptr, .ancount = 1 };
pub const answer_aaaa: Reply = .{ .records = &record_aaaa, .ancount = 1 };

/// The most polls an address lookup's test drives before it gives up, and the jump that makes a
/// lookup time out on the fake server, which never answers on its own.
pub const address_polls_max = 64;
pub const address_timeout_jump_ns = 60 * 1_000_000_000;

/// The search list the address lookup's rig configures, and the slots a walk may hold at most:
/// one per family (docs/design.md §19 step 14).
pub const address_search_entries = 2;
pub const address_slots_per_walk = 2;

/// The A record with the client cookie echoed and a server cookie learned.
pub const answer_a_cookie: Reply = .{ .records = &record_a, .ancount = 1, .cookie = .echo, .server_cookie = &server_cookie };
/// The A record with an OPT record and no cookie: a server without them.
pub const answer_a_opt_only: Reply = .{ .records = &record_a, .ancount = 1, .cookie = .opt_only };
/// The A record with another client's cookie.
pub const answer_a_cookie_wrong: Reply = .{ .records = &record_a, .ancount = 1, .cookie = .wrong, .server_cookie = &server_cookie };
/// The A record with a COOKIE option of nine octets.
pub const answer_a_cookie_malformed: Reply = .{ .records = &record_a, .ancount = 1, .cookie = .malformed };
/// A CNAME with no target, with the cookie echoed and a server cookie: the lookup asks again.
pub const cname_only_cookie: Reply = .{ .records = &record_cname, .ancount = 1, .cookie = .echo, .server_cookie = &server_cookie };
/// BADCOOKIE with a fresh server cookie (RFC 7873 §5.2.4).
pub const bad_cookie_fresh: Reply = .{ .rcode = .bad_cookie, .cookie = .echo, .server_cookie = &server_cookie_fresh };

/// The A record with the TC bit set: over UDP, the answer that sends a lookup to TCP.
pub const answer_a_truncated: Reply = .{ .records = &record_a, .ancount = 1, .truncated = true };

/// A reply carrying one MX record, for a question of that type.
pub const answer_mx: Reply = .{ .records = &record_mx, .ancount = 1 };

/// A reply to an ANY question: the A record and the MX record together (RFC 8482 §4.1).
pub const answer_any: Reply = .{ .records = &(record_a ++ record_mx), .ancount = 2 };

/// A reply carrying a CNAME and no record for its target.
pub const cname_only: Reply = .{ .records = &record_cname, .ancount = 1 };

/// A reply whose CNAME target borrows its suffix from the question.
pub const cname_into_question: Reply = .{ .records = &record_cname_into_question, .ancount = 1 };

/// A reply carrying a CNAME and the A record its target owns.
pub const cname_then_a: Reply = .{
    .records = &(record_cname ++ record_cname_target_a),
    .ancount = 2,
};

/// A chain that loops: the question's name aliases to `host.example.net`, which aliases back.
pub const cname_loop: Reply = .{
    .records = &(record_cname ++ record_cname_back),
    .ancount = 2,
};

/// A reply carrying an A record for a name nobody asked about, then the one that was asked about.
pub const injected: Reply = .{ .records = &(record_injected_a ++ record_a), .ancount = 2 };

/// A reply whose only record has an rdlength past the end of the message.
pub const long_rdlength: Reply = .{ .records = &record_long_rdlength, .ancount = 1 };

pub const truncated: Reply = .{ .truncated = true };
pub const name_error: Reply = .{ .rcode = .name_error };
pub const no_data: Reply = .{};
pub const name_error_soa: Reply = .{ .rcode = .name_error, .authority = &record_soa, .nscount = 1 };
pub const no_data_soa: Reply = .{ .authority = &record_soa, .nscount = 1 };
pub const name_error_soa_broken: Reply = .{ .rcode = .name_error, .authority = &record_soa_broken, .nscount = 1 };
pub const server_failure: Reply = .{ .rcode = .server_failure };
pub const format_error: Reply = .{ .rcode = .format_error };

/// How many slots and keys the table tests use.
pub const slot_count = 4;
pub const key_count = 16;

/// A lookup, the buffers a caller provides, and the fake server that answers it.
///
/// It is started in place rather than returned by value, because the lookup holds a pointer to the
/// configuration beside it: a harness returned by value would leave that pointer aimed at the
/// temporary it was built in.
pub const Harness = struct {
    config: Config,
    servers: Servers = undefined,
    /// Whether `servers` was built: a second `start` on one harness keeps what the first lookup
    /// learned, which is how the state shared across lookups is tested.
    servers_ready: bool = false,
    lookup: Lookup = undefined,
    query: [core.constants.query_bytes_max]u8 = @splat(0),
    query_bytes: usize = 0,
    /// Where the message starts inside `query`: zero over UDP, and past the length prefix over
    /// TCP (RFC 7766 §8).
    query_body_offset: usize = 0,
    reply_buffer: [core.constants.udp_payload_bytes_default]u8 = @splat(0),
    now_ns: u64 = 0,

    pub fn start(self: *Harness, text: []const u8, kind: Kind, lookup_seed: u64) !void {
        if (!self.servers_ready) {
            self.servers = Servers.init(&self.config, lookup_seed);
            self.servers_ready = true;
        }
        self.lookup = Lookup.init(&self.config, &self.servers, try Question.from_text(text, kind), lookup_seed);
    }

    pub fn poll(self: *Harness) Action {
        self.now_ns += 1;
        return self.lookup.poll(self.now_ns, &self.query);
    }

    /// Polls, requires a UDP send, remembers the query and tells the lookup it went out.
    pub fn send(self: *Harness) Action {
        const action = self.poll();
        assert(action == .send_udp);
        self.query_bytes = action.send_udp.message_bytes.len;
        self.query_body_offset = 0;
        self.lookup.on_sent(self.now_ns);
        return action;
    }

    /// The same over TCP, where the message the lookup built starts after the length prefix.
    pub fn send_over_tcp(self: *Harness) Action {
        const action = self.poll();
        assert(action == .send_tcp);
        self.query_bytes = action.send_tcp.message_bytes.len;
        self.query_body_offset = core.constants.tcp_prefix_bytes;
        self.lookup.on_sent(self.now_ns);
        return action;
    }

    /// The question section of the query last sent: the name as it went out, with its case.
    fn question_section(self: *const Harness) []const u8 {
        assert(self.query_bytes > core.constants.header_bytes);
        const name_bytes = self.lookup.cased_name().len;
        const question_at = self.query_body_offset + core.constants.header_bytes;
        return self.query[question_at..][0 .. name_bytes + core.constants.question_fixed_bytes];
    }

    /// Builds `reply` around the question that was asked and hands it to the lookup.
    pub fn respond(self: *Harness, reply: Reply, from: Endpoint) Verdict {
        const message = self.build(reply);
        self.now_ns += 1;
        return self.lookup.on_response(message, from, self.now_ns);
    }

    fn build(self: *Harness, reply: Reply) []const u8 {
        const question = self.question_section();
        // The rcode's low four bits go in the header and the rest in the OPT record's TTL
        // (RFC 6891 §6.1.3), so BADCOOKIE forces an OPT record.
        const rcode: u16 = @intFromEnum(reply.rcode);
        var flags: u16 = wire.constants.flag_response |
            wire.constants.flag_recursion_desired |
            wire.constants.flag_recursion_available |
            (rcode & wire.constants.rcode_mask);
        if (reply.truncated) flags |= wire.constants.flag_truncated;
        const extended_high: u8 = @intCast(rcode >> wire.constants.extended_rcode_low_bits);
        const with_opt = reply.cookie != .none or extended_high != 0;

        const header: wire.Header = .{
            .id = reply.id orelse self.lookup.transaction.id,
            .flags = flags,
            .qdcount = 1,
            .ancount = reply.ancount,
            .nscount = reply.nscount,
            .arcount = if (with_opt) 1 else 0,
        };
        wire.header.write(&header, &self.reply_buffer);
        var offset: usize = core.constants.header_bytes;
        offset += self.write_question(question, reply, offset);
        @memcpy(self.reply_buffer[offset..][0..reply.records.len], reply.records);
        offset += reply.records.len;
        @memcpy(self.reply_buffer[offset..][0..reply.authority.len], reply.authority);
        offset += reply.authority.len;
        if (with_opt) offset += self.write_opt(reply, extended_high, offset);
        assert(offset <= self.reply_buffer.len);
        return self.reply_buffer[0..offset];
    }

    /// An OPT record in the additional section: root owner, payload 1232, the extended rcode's
    /// high octet in the TTL, and the COOKIE option the reply asks for.
    fn write_opt(self: *Harness, reply: Reply, extended_high: u8, offset: usize) usize {
        const out = self.reply_buffer[offset..];
        var written: usize = wire.edns.write(core.constants.udp_payload_bytes_default, null, out);
        out[5] = extended_high; // the TTL's high octet (RFC 6891 §6.1.3)
        const option = self.cookie_option(reply, out[written..]);
        written += option;
        wire.integer.write_u16(out, core.constants.opt_record_bytes - 2, @intCast(option)); // rdlength
        return written;
    }

    fn cookie_option(self: *Harness, reply: Reply, out: []u8) usize {
        const client: []const u8 = switch (reply.cookie) {
            .none, .opt_only => return 0,
            .echo, .malformed => &self.servers.state(self.lookup.server_slot()).cookie_client,
            .wrong => &cookie_client_wrong,
        };
        const server: []const u8 = if (reply.cookie == .malformed) &[_]u8{0x00} else reply.server_cookie;
        wire.integer.write_u16(out, 0, wire.constants.cookie_option_code);
        wire.integer.write_u16(out, 2, @intCast(client.len + server.len));
        @memcpy(out[4..][0..client.len], client);
        @memcpy(out[4 + client.len ..][0..server.len], server);
        return 4 + client.len + server.len;
    }

    /// Echoes the question, or the spoof a test asked for: the case folded, or another name.
    fn write_question(self: *Harness, question: []const u8, reply: Reply, offset: usize) usize {
        if (reply.other_name) {
            const other = Name.from_text("other.example") catch unreachable;
            @memcpy(self.reply_buffer[offset..][0..other.len], other.wire());
            const fixed = question[question.len - core.constants.question_fixed_bytes ..];
            @memcpy(self.reply_buffer[offset + other.len ..][0..fixed.len], fixed);
            return other.len + fixed.len;
        }
        @memcpy(self.reply_buffer[offset..][0..question.len], question);
        if (reply.fold_case) {
            for (self.reply_buffer[offset..][0..question.len]) |*byte| {
                byte.* = std.ascii.toLower(byte.*);
            }
        }
        return question.len;
    }
};

/// A whole table, its buffers, and the fake server that answers every lookup in it. Started in
/// place for the same reason `Harness` is: the resolver holds pointers to the arrays beside it.
pub const Table = struct {
    config: Config,
    slots: [slot_count]Slot = @splat(.{}),
    keys: [key_count]MatchKey = @splat(.{}),
    resolver: Resolver = undefined,
    out: [core.constants.query_bytes_max]u8 = @splat(0),
    reply: [core.constants.udp_payload_bytes_default]u8 = @splat(0),
    now_ns: u64 = 0,

    pub fn open(self: *Table) void {
        self.resolver = Resolver.init(&self.slots, &self.keys, &self.config, seed);
    }

    pub fn start(self: *Table, text: []const u8) !Handle {
        return self.resolver.start(try Question.from_text(text, .a));
    }

    pub fn poll(self: *Table) ?Event {
        self.now_ns += 1;
        return self.resolver.poll(self.now_ns, &self.out);
    }

    /// Answers one lookup the way its current server would, with one A record. The server is the
    /// lookup's own: after a timeout it has moved to the next one, and a reply from the server it
    /// no longer holds is not a reply (§7 check 3).
    pub fn answer(self: *Table, handle: Handle) Verdict {
        const lookup = self.resolver.lookup_of(handle);
        const message = self.build(lookup, answer_a);
        self.now_ns += 1;
        return self.resolver.on_datagram(message, lookup.server(), self.now_ns);
    }

    /// A reply carrying one lookup's id and another lookup's question: the cross-talk a table has
    /// to refuse.
    pub fn crosstalk(self: *Table, id_of: Handle, question_of: Handle) Verdict {
        const question_lookup = self.resolver.lookup_of(question_of);
        var reply = answer_a;
        reply.id = self.resolver.lookup_of(id_of).transaction.id;
        const message = self.build(question_lookup, reply);
        self.now_ns += 1;
        return self.resolver.on_datagram(message, question_lookup.server(), self.now_ns);
    }

    /// Builds `reply` around the question `lookup` asked: the rcode's low four bits in the
    /// header, as `Harness.build` does, and no OPT record, so the extended rcodes stay there.
    pub fn build(self: *Table, lookup: *const Lookup, reply: Reply) []const u8 {
        assert(reply.cookie == .none);
        const name = lookup.cased_name();
        const rcode: u16 = @intFromEnum(reply.rcode);
        assert(rcode >> wire.constants.extended_rcode_low_bits == 0);
        var flags: u16 = wire.constants.flag_response | wire.constants.flag_recursion_desired | (rcode & wire.constants.rcode_mask);
        if (reply.truncated) flags |= wire.constants.flag_truncated;
        const header: wire.Header = .{
            .id = reply.id orelse lookup.transaction.id,
            .flags = flags,
            .qdcount = 1,
            .ancount = reply.ancount,
            .nscount = 0,
            .arcount = 0,
        };
        wire.header.write(&header, &self.reply);
        var offset: usize = core.constants.header_bytes;
        offset += wire.question.write(&name, lookup.question.kind, self.reply[offset..]);
        @memcpy(self.reply[offset..][0..reply.records.len], reply.records);
        return self.reply[0 .. offset + reply.records.len];
    }
};
