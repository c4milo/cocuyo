//! The program of docs/design.md §25 step 17: a DNS server for hickory-dns's conformance suite
//! (c4milo/cocuyo#59). It asks each query of one upstream through the engine, validates it from the
//! anchors when it is given them, and writes the reply from what cocuyo returned.
//!
//!     conformance-forward [dnssec <anchor file>] <upstream address>[:<port>] [<port>]
//!
//! It listens over UDP and TCP on every IPv4 address, at `<port>` or 53, and answers one query at
//! a time, which is how the suite's `dig` asks. The engine runs on the main thread alone, so a
//! second thread takes each query over TCP and asks it of the main thread's UDP socket on the
//! loopback (RFC 7766 §8 for the length prefix). The anchor file is the one the suite writes,
//! `/etc/trusted-key.key`: DNSKEY records in zone-file form (`examples/trust_text.zig`). Each query
//! and its end are logged to stderr as `examples/answer_text.zig` writes them.
//!
//! The reply holds what cocuyo keeps of a lookup, and no more:
//!
//! - NOERROR for an answer or no data, NXDOMAIN for a name error, and SERVFAIL for any other end;
//! - AD only when the end is `secure` (RFC 4035 §3.2.3);
//! - a CNAME to the chain's end when one was followed, then the records at the TTL cocuyo gives;
//! - no RRSIG, NSEC or NSEC3, since cocuyo keeps nothing of a message (design §25, walk rule 9).
//!
//! This is developer tooling. It owns its sockets, as the examples do, and is never linked into
//! the library.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io");
const answer_text = @import("answer_text");
const server_text = @import("server_text");
const trust_text = @import("trust_text");

/// The lookup a query asks, and room for the walks for its keys.
const Resolver = io.Resolver(.{ .lookups = lookups_max });
const lookups_max = 8;

const loop_options: rotor.Loop.Options = .{ .operations = Resolver.loop_operations };
var loop_memory: [rotor.Loop.memory_bytes(loop_options)]u8 align(rotor.memory_alignment) = undefined;
var engine: Resolver = undefined;
var cache_memory: cocuyo.cache.Storage(io.constants.cache_slots_default) = undefined;
var trust: trust_text.Trust = .{};

const tick_ns: u64 = 100_000_000;
/// The ticks a query is given before it is answered SERVFAIL: 20 seconds, past the engine's own
/// deadlines.
const ticks_max: usize = 200;
const events_max: usize = 16;
const port_default: u16 = 53;
/// The queries one TCP connection may ask before it is closed.
const queries_per_connection_max: usize = 64;
const loopback = [_]u8{ 127, 0, 0, 1 };
/// A slash and a type's name in a log line's label, as `/NSEC3PARAM`.
const type_text_bytes_max: usize = 16;

/// A query or a reply: the largest UDP payload over IPv4, 65,535 octets less a 20-octet IP header
/// and an 8-octet UDP header, since a TCP query reaches the main thread as a datagram on the
/// loopback. A reply over
/// UDP stays within what the query offers, and past that sets TC (RFC 1035 §4.2.1, RFC 6891
/// §6.2.3). One over TCP is not held to that size: "Some EDNS-aware servers incorrectly limit the
/// TCP response sizes to the advertised UDP response size" (RFC 8906 §3.2.7).
const datagram_bytes_max: usize = 65_507;
const udp_bytes_classic: u16 = 512;
const header_bytes: usize = 12;
const u16_bytes: usize = 2;
const u32_bytes: usize = 4;
/// The fixed part of a record after its owner: type, class, TTL and rdata length.
const record_fixed_bytes: usize = 10;
const class_internet: u16 = 1;
const type_cname: u16 = 5;
const type_ptr: u16 = 12;
const type_opt: u16 = 41;
const type_a: u16 = 1;
const type_aaaa: u16 = 28;

/// The header's flags (RFC 1035 §4.1.1, RFC 4035 §3.2).
const flag_response: u16 = 0x8000;
const flag_truncated: u16 = 0x0200;
const flag_recursion_desired: u16 = 0x0100;
const flag_recursion_available: u16 = 0x0080;
const flag_authentic_data: u16 = 0x0020;
const flag_checking_disabled: u16 = 0x0010;
const opcode_mask: u16 = 0x7800;
const rcode_server_failure: u16 = 2;
const rcode_name_error: u16 = 3;
const rcode_not_implemented: u16 = 4;
const rcode_format_error: u16 = 1;
/// A compressed name's high bits, and a pointer to the question's name, right after the header
/// (RFC 1035 §4.1.4).
const label_pointer_bits: u8 = 0xc0;
const question_pointer: u16 = 0xc000 | header_bytes;
/// The DO bit, in the OPT record's TTL (RFC 3225 §3).
const flag_dnssec_ok: u32 = 0x8000;
/// The OPT record's TTL: the extended rcode's high octet, the version, then the flags (RFC 6891
/// §6.1.3).
const extended_rcode_shift: u5 = 24;
const edns_version_shift: u5 = 16;
const edns_version: u8 = 0;
const rcode_bad_version: u16 = 16;
const rcode_low_bits: u4 = 4;
const rcode_low_mask: u16 = 0xf;

/// A query's question, and what the reply echoes of the query.
const Query = struct {
    id: u16,
    flags: u16,
    question: cocuyo.Question,
    /// Where the question ends: the reply copies the query that far.
    question_end: usize,
    opt: ?Opt,
};

/// A query's OPT record: the payload size it offers, its EDNS version and its DO bit.
const Opt = struct { payload: u16, version: u8, dnssec_ok: bool };

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const command = trust_text.read((try init.minimal.args.toSlice(arena))[1..]);
    const arguments = command.operands;
    if (arguments.len < 1 or arguments.len > 2) {
        std.debug.print("usage: conformance-forward [dnssec <anchor file>] <upstream address>[:<port>] [<port>]\n", .{});
        std.process.exit(2);
    }
    const at = try server_text.place_of(arguments[0]);
    const servers = [_]cocuyo.Server{.{ .endpoint = .{ .address = at.address, .port = at.port orelse cocuyo.constants.port_dns_default } }};
    const config: cocuyo.Config = .{ .servers = &servers, .search = &.{} };
    const port = if (arguments.len == 2) try std.fmt.parseInt(u16, arguments[1], 10) else port_default;

    var engine_seed: [@sizeOf(u64)]u8 = undefined;
    try init.io.randomSecure(&engine_seed);
    const clock: Clock = .init(init.io);
    var loop: rotor.Loop = undefined;
    try loop.init(&loop_memory, loop_options);
    defer loop.deinit();
    var events: [events_max]rotor.Event = undefined;
    try engine.init(&loop, &config, cache_memory.slices(), std.mem.readInt(u64, &engine_seed, .little), clock.read());
    defer {
        engine.deinit();
        loop.drain(&events) catch {};
        engine.close();
    }
    if (command.anchor_path) |path| engine.use_trust(try trust.open(init.io, arena, path, unix_seconds(init.io), clock.read()));

    var address: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = port } };
    const socket = try address.bind(init.io, .{ .mode = .dgram });
    defer socket.close(init.io);
    std.debug.print("conformance-forward: listening on port {d}, upstream {s}, {s}\n", .{ port, arguments[0], if (command.anchor_path == null) "not validating" else "validating" });
    const tcp = try std.Thread.spawn(.{}, serve_tcp, .{ init.io, port });
    tcp.detach();
    var buffer: [datagram_bytes_max]u8 = undefined;
    var out: [datagram_bytes_max]u8 = undefined;
    while (true) {
        const message = try socket.receive(init.io, &buffer);
        // A query from the loopback is the TCP thread's, so its reply is not held to a datagram's
        // size. The suite's clients are never on the loopback.
        const over_tcp = message.from == .ip4 and std.mem.eql(u8, &message.from.ip4.bytes, &loopback);
        const reply = try answer(&loop, &events, clock, message.data, over_tcp, &out) orelse continue;
        try socket.send(init.io, &message.from, reply);
    }
}

/// Serves TCP on `port`: each query, after its two-octet length, is asked of the UDP socket on the
/// loopback, and the reply is written back after its own length (RFC 1035 §4.2.2).
fn serve_tcp(io_handle: std.Io, port: u16) void {
    serve_tcp_or_fail(io_handle, port) catch |err| std.debug.print("conformance-forward: TCP stopped: {t}\n", .{err});
}

fn serve_tcp_or_fail(io_handle: std.Io, port: u16) !void {
    var address: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = port } };
    var server = try address.listen(io_handle, .{ .reuse_address = true });
    defer server.deinit(io_handle);
    var proxy_address: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = loopback, .port = 0 } };
    const proxy = try proxy_address.bind(io_handle, .{ .mode = .dgram });
    defer proxy.close(io_handle);
    const upstream: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = loopback, .port = port } };
    while (true) {
        const stream = server.accept(io_handle) catch continue;
        defer stream.close(io_handle);
        serve_stream(io_handle, stream, &proxy, &upstream) catch {};
    }
}

fn serve_stream(io_handle: std.Io, stream: std.Io.net.Stream, proxy: *const std.Io.net.Socket, upstream: *const std.Io.net.IpAddress) !void {
    var read_buffer: [u16_bytes + datagram_bytes_max]u8 = undefined;
    var write_buffer: [u16_bytes + datagram_bytes_max]u8 = undefined;
    var reader = stream.reader(io_handle, &read_buffer);
    var writer = stream.writer(io_handle, &write_buffer);
    var reply_buffer: [datagram_bytes_max]u8 = undefined;
    for (0..queries_per_connection_max) |_| {
        const length = reader.interface.takeInt(u16, .big) catch return;
        if (length > datagram_bytes_max) return error.TooLong;
        try proxy.send(io_handle, upstream, try reader.interface.take(length));
        const reply = try proxy.receive(io_handle, &reply_buffer);
        try writer.interface.writeInt(u16, @intCast(reply.data.len), .big);
        try writer.interface.writeAll(reply.data);
        try writer.interface.flush();
    }
}

/// The reply to `bytes`, or null for a message that is no query to answer.
fn answer(loop: *rotor.Loop, events: []rotor.Event, clock: Clock, bytes: []const u8, over_tcp: bool, out: []u8) !?[]const u8 {
    if (bytes.len < header_bytes) return null;
    const flags = std.mem.readInt(u16, bytes[u16_bytes..][0..u16_bytes], .big);
    if (flags & flag_response != 0) return null;
    // "NOTIMP is the expected rcode to an unknown or unimplemented opcode", and "there is no
    // requirement that anything other than the DNS header match" (RFC 8906 §3.1.4). So the reply
    // is a header alone, and copies no flag of a message it does not read (§3.1.3, §8.1.4).
    if (flags & opcode_mask != 0) return bare(bytes, flags & opcode_mask, rcode_not_implemented, out);
    const query = read_query(bytes) catch |err| {
        const rcode = if (err == error.NotImplemented) rcode_not_implemented else rcode_format_error;
        return bare(bytes, flags, rcode, out);
    };
    // "If a responder does not implement the VERSION level of the request, then it MUST respond
    // with RCODE=BADVERS", and its own version (RFC 6891 §6.1.3). Nothing is resolved.
    if (query.opt) |opt| if (opt.version != edns_version) return bad_version(&query, bytes, out);
    return try resolve(loop, events, clock, &query, bytes, over_tcp, out);
}

/// Resolves `query` through the engine and writes its reply, SERVFAIL when it has no end within
/// `ticks_max` ticks.
fn resolve(loop: *rotor.Loop, events: []rotor.Event, clock: Clock, query: *const Query, bytes: []const u8, over_tcp: bool, out: []u8) ![]const u8 {
    const flags = query.flags;
    const handle = engine.start(query.question, clock.read()) catch return bare(bytes, flags, rcode_server_failure, out);
    for (0..ticks_max) |_| {
        if (engine.take(clock.read())) |result| {
            assert(result.handle.index == handle.index);
            try log(query, result);
            return write_reply(query, bytes, result, over_tcp, out);
        }
        try tick(loop, events, clock);
    }
    // One query runs at a time, so cancelling every lookup cancels this one. Its end is taken
    // here, so that the next query's end is the next one `take` hands.
    engine.cancel_all(clock.read());
    for (0..ticks_max) |_| {
        if (engine.take(clock.read()) != null) break;
        try tick(loop, events, clock);
    }
    return bare(bytes, flags, rcode_server_failure, out);
}

fn tick(loop: *rotor.Loop, events: []rotor.Event, clock: Clock) !void {
    const count = try loop.tick(events, tick_ns);
    const now = clock.read();
    for (events[0..count]) |event| _ = engine.apply(event, now);
    engine.drive(now);
}

/// Reads the one question of `bytes`, uncompressed, and its OPT record if the additional section
/// holds one.
fn read_query(bytes: []const u8) !Query {
    const qdcount = std.mem.readInt(u16, bytes[4..6], .big);
    if (qdcount != 1) return error.FormatError;
    var text: [cocuyo.limits.name_bytes_max + 1]u8 = undefined;
    var length: usize = 0;
    var at: usize = header_bytes;
    for (0..cocuyo.limits.name_bytes_max) |_| {
        if (at >= bytes.len) return error.FormatError;
        const label = bytes[at];
        at += 1;
        if (label == 0) break;
        if (label & label_pointer_bits != 0 or at + label > bytes.len or length + label + 1 > text.len) return error.FormatError;
        @memcpy(text[length..][0..label], bytes[at..][0..label]);
        length += label;
        text[length] = '.';
        length += 1;
        at += label;
    }
    if (length == 0) {
        text[0] = '.';
        length = 1;
    }
    if (at + 2 * u16_bytes > bytes.len) return error.FormatError;
    const code = std.mem.readInt(u16, bytes[at..][0..u16_bytes], .big);
    const kind = cocuyo.Kind.from_code(code) orelse return error.NotImplemented;
    at += 2 * u16_bytes;
    const question = cocuyo.Question.from_text(text[0..length], kind) catch return error.NotImplemented;
    return .{
        .id = std.mem.readInt(u16, bytes[0..u16_bytes], .big),
        .flags = std.mem.readInt(u16, bytes[u16_bytes..][0..u16_bytes], .big),
        .question = question,
        .question_end = at,
        .opt = find_opt(bytes, at),
    };
}

/// The OPT record of a query whose question ends at `at`: the first record past it, of type 41
/// with the root as owner (RFC 6891 §6.1.2). A query carries nothing else there.
fn find_opt(bytes: []const u8, at: usize) ?Opt {
    const arcount = std.mem.readInt(u16, bytes[10..12], .big);
    if (arcount == 0 or at + 1 + record_fixed_bytes > bytes.len or bytes[at] != 0) return null;
    const record = bytes[at + 1 ..];
    if (std.mem.readInt(u16, record[0..u16_bytes], .big) != type_opt) return null;
    const ttl = std.mem.readInt(u32, record[2 * u16_bytes ..][0..u32_bytes], .big);
    return .{
        .payload = std.mem.readInt(u16, record[u16_bytes..][0..u16_bytes], .big),
        .version = @truncate(ttl >> edns_version_shift),
        .dnssec_ok = ttl & flag_dnssec_ok != 0,
    };
}

/// A reply of `rcode` with no question, for a query that could not be read.
fn bare(bytes: []const u8, flags: u16, rcode: u16, out: []u8) []const u8 {
    @memcpy(out[0..u16_bytes], bytes[0..u16_bytes]);
    std.mem.writeInt(u16, out[u16_bytes..][0..u16_bytes], reply_flags(flags, false) | rcode, .big);
    @memset(out[2 * u16_bytes .. header_bytes], 0);
    return out[0..header_bytes];
}

fn reply_flags(query_flags: u16, authentic: bool) u16 {
    var flags = flag_response | flag_recursion_available | (query_flags & (opcode_mask | flag_recursion_desired | flag_checking_disabled));
    if (authentic) flags |= flag_authentic_data;
    return flags;
}

/// Writes records into a reply, each owner a pointer to the question or a name in full.
const Writer = struct {
    out: []u8,
    at: usize,
    count: u16 = 0,

    fn owner(self: *Writer, name: ?*const cocuyo.Name) void {
        if (name) |full| return self.bytes(full.wire());
        self.integer(u16, question_pointer);
    }

    fn record(self: *Writer, name: ?*const cocuyo.Name, kind_code: u16, ttl_seconds: u32, rdata: []const u8) !void {
        const owner_bytes = if (name) |full| full.wire().len else u16_bytes;
        if (self.at + owner_bytes + record_fixed_bytes + rdata.len > self.out.len) return error.NoRoom;
        self.owner(name);
        self.integer(u16, kind_code);
        self.integer(u16, class_internet);
        self.integer(u32, ttl_seconds);
        self.integer(u16, @intCast(rdata.len));
        self.bytes(rdata);
        self.count += 1;
    }

    fn integer(self: *Writer, comptime T: type, value: T) void {
        std.mem.writeInt(T, self.out[self.at..][0..@sizeOf(T)], value, .big);
        self.at += @sizeOf(T);
    }

    fn bytes(self: *Writer, data: []const u8) void {
        @memcpy(self.out[self.at..][0..data.len], data);
        self.at += data.len;
    }
};

/// The reply to `query` from the lookup's end.
fn write_reply(query: *const Query, bytes: []const u8, result: Resolver.Result, over_tcp: bool, out: []u8) []const u8 {
    const security, const rcode = end_of(result);
    const payload: usize = if (over_tcp) out.len else if (query.opt) |opt| @max(opt.payload, udp_bytes_classic) else udp_bytes_classic;
    const room = out[0..@min(payload, out.len)];
    @memcpy(room[0..query.question_end], bytes[0..query.question_end]);
    var writer: Writer = .{ .out = room, .at = query.question_end };
    var truncated = false;
    if (result.outcome == .answer) answers(&writer, query, &result.outcome.answer) catch {
        truncated = true;
        writer = .{ .out = room, .at = query.question_end };
    };
    const additional: u16 = if (query.opt) |opt| write_opt(&writer, opt, 0) else 0;
    // "validating resolvers SHOULD only set the AD bit when a response both meets the conditions
    // listed in Section 3.2.3 of [RFC4035], and the request contained either a set DO bit or a set
    // AD bit" (RFC 6840 §5.8).
    const asked = query.flags & flag_authentic_data != 0 or (query.opt != null and query.opt.?.dnssec_ok);
    var flags = reply_flags(query.flags, security == .secure and asked) | rcode;
    if (truncated) flags |= flag_truncated;
    std.mem.writeInt(u16, room[u16_bytes..][0..u16_bytes], flags, .big);
    std.mem.writeInt(u16, room[6..8], writer.count, .big);
    std.mem.writeInt(u16, room[8..10], 0, .big);
    std.mem.writeInt(u16, room[10..12], additional, .big);
    return room[0..writer.at];
}

/// Logs the query and its end, as `<name>/<TYPE>` and the lines `examples/answer_text.zig` writes.
fn log(query: *const Query, result: Resolver.Result) !void {
    var text: [cocuyo.limits.name_text_bytes_max]u8 = undefined;
    const name = text[0..query.question.name.write_text(&text)];
    var label: [cocuyo.limits.name_text_bytes_max + type_text_bytes_max]u8 = undefined;
    const labelled = try std.fmt.bufPrint(&label, "{s}/{t}", .{ name, query.question.kind });
    switch (result.outcome) {
        .answer => |found| try answer_text.report(labelled, &found),
        .failure => |failure| answer_text.report_failure(labelled, &failure),
    }
}

/// What the reply says of the lookup's end: its security, and the rcode.
fn end_of(result: Resolver.Result) struct { cocuyo.Security, u16 } {
    return switch (result.outcome) {
        .answer => |found| .{ found.security, 0 },
        .failure => |failure| .{ failure.security, switch (failure.err) {
            error.NameNotFound => rcode_name_error,
            error.NoData => 0,
            else => rcode_server_failure,
        } },
    };
}

/// An OPT record of version 0 that echoes the query's DO bit (RFC 3225 §3), with the high octet
/// of an extended rcode, or none when the reply has no room left. Returns the records it wrote.
fn write_opt(writer: *Writer, opt: Opt, rcode_high: u8) u16 {
    if (writer.at + 1 + record_fixed_bytes > writer.out.len) return 0;
    writer.bytes(&.{0});
    writer.integer(u16, type_opt);
    writer.integer(u16, udp_bytes_classic);
    const ttl = (@as(u32, rcode_high) << extended_rcode_shift) | (if (opt.dnssec_ok) flag_dnssec_ok else 0);
    writer.integer(u32, ttl);
    writer.integer(u16, 0);
    return 1;
}

/// BADVERS, 16: the header's four bits hold 0, and the OPT record the rest (RFC 6891 §6.1.3).
fn bad_version(query: *const Query, bytes: []const u8, out: []u8) []const u8 {
    @memcpy(out[0..query.question_end], bytes[0..query.question_end]);
    var writer: Writer = .{ .out = out, .at = query.question_end };
    const additional = write_opt(&writer, query.opt.?, rcode_bad_version >> rcode_low_bits);
    std.mem.writeInt(u16, out[u16_bytes..][0..u16_bytes], reply_flags(query.flags, false) | (rcode_bad_version & rcode_low_mask), .big);
    std.mem.writeInt(u16, out[6..8], 0, .big);
    std.mem.writeInt(u16, out[8..10], 0, .big);
    std.mem.writeInt(u16, out[10..12], additional, .big);
    return out[0..writer.at];
}

/// The answer section: a CNAME to the chain's end when one was followed, then the addresses, the
/// names or the records, each owned by the chain's end.
fn answers(writer: *Writer, query: *const Query, found: *const cocuyo.Answer) !void {
    var owner: ?*const cocuyo.Name = null;
    if (found.canonical_name) |end| if (!end.equal(&query.question.name)) {
        try writer.record(null, type_cname, found.ttl_seconds, end.wire());
        owner = end;
    };
    for (found.addresses) |*address| {
        const kind_code = if (address.family == .ipv4) type_a else type_aaaa;
        try writer.record(owner, kind_code, found.ttl_seconds, address.slice());
    }
    for (found.names) |*name| try writer.record(owner, type_ptr, found.ttl_seconds, name.wire());
    const records = found.records orelse return;
    for (0..found.record_count) |index| {
        const kept = records.at(index);
        try writer.record(owner, kept.kind_code, kept.ttl_seconds, kept.rdata);
    }
}

/// The wall clock, for the dates of the signatures (docs/design.md §25, Time).
fn unix_seconds(io_handle: std.Io) u64 {
    return @intCast(@divFloor(std.Io.Timestamp.now(io_handle, .real).nanoseconds, std.time.ns_per_s));
}

/// The clock cocuyo is driven by: monotonic, as `examples/udp_rotor.zig` reads it.
const Clock = struct {
    io: std.Io,
    start: std.Io.Timestamp,

    fn init(io_handle: std.Io) Clock {
        return .{ .io = io_handle, .start = .now(io_handle, .awake) };
    }

    fn read(self: Clock) u64 {
        return @intCast(self.start.durationTo(.now(self.io, .awake)).nanoseconds);
    }
};
