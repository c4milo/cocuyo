//! What the fuzz target checks about a message. Every parser runs over it, and what is checked is
//! not "did it parse" — most of these messages must not parse — but that whatever the parser did,
//! it did within the promises the codec makes:
//!
//! - No read outside the message. Zig's own bounds checks catch that as a panic, in Debug and in
//!   ReleaseSafe, which is why cocuyo ships no build mode without them.
//! - Every name that comes back is a name: at least one octet, at most `name_bytes_max`, ending in
//!   a root octet.
//! - Every offset a parser returns is inside the message and strictly ahead of where it started,
//!   so no walk can stand still.
//! - Parsing is a pure function of the bytes: the same message parses the same way twice.
//! - `skip` agrees with `decode` wherever `decode` succeeded.
//!
//! A check returns the name of the promise that broke rather than panicking, so the caller can
//! print the seed that produced it.
const std = @import("std");
const core = @import("core");
const Name = core.Name;
const header_codec = @import("header.zig");
const name_codec = @import("name.zig");
const question_codec = @import("question.zig");
const record_codec = @import("record.zig");
const response_codec = @import("response.zig");
const record_copy = @import("record_copy.zig");
const rdata = @import("rdata/rdata.zig");

/// How many offsets of one message the name decoder is aimed at. Every offset would be thorough
/// and slow; thirty-two spread across the message reaches every structure the generator builds.
const decode_offsets_max = 32;

/// The question the response walk is run against, the same for every message: what matters is the
/// walk's behaviour on hostile bytes, not which name it was asked about.
const question_text = "example.com";

pub fn check(message: []const u8) ?[]const u8 {
    if (header_check(message)) |failure| return failure;
    if (name_sweep(message)) |failure| return failure;
    if (question_check(message)) |failure| return failure;
    if (record_sweep(message)) |failure| return failure;
    return response_check(message);
}

fn header_check(message: []const u8) ?[]const u8 {
    const header = header_codec.parse(message) catch {
        if (message.len >= core.constants.header_bytes) return "a header of twelve octets failed to parse";
        return null;
    };
    if (message.len < core.constants.header_bytes) return "a header parsed out of fewer than twelve octets";
    // The rcode either names a code or does not; either way it must not crash, and the four bits
    // must be four bits.
    _ = header.rcode() catch {};
    if (header.rcode_bits() > core.constants.records_max) return "the rcode bits exceeded four bits";
    return null;
}

fn name_sweep(message: []const u8) ?[]const u8 {
    const step = @max(1, message.len / decode_offsets_max);
    var offset: usize = 0;
    var swept: usize = 0;
    while (swept <= decode_offsets_max and offset < message.len) : (offset += step) {
        swept += 1;
        if (name_at(message, offset)) |failure| return failure;
    }
    return null;
}

fn name_at(message: []const u8, offset: usize) ?[]const u8 {
    var first: Name = Name.empty;
    const end = name_codec.decode(message, offset, &first) catch return null;
    if (first.len < 1 or first.len > core.constants.name_bytes_max) return "a decoded name has an impossible length";
    if (first.bytes[first.len - 1] != 0) return "a decoded name does not end in the root";
    if (end > message.len) return "a name ended past the end of the message";
    if (end <= offset) return "a name ended at or before where it started";

    var second: Name = Name.empty;
    const again = name_codec.decode(message, offset, &second) catch return "a name decoded once and failed twice";
    if (again != end or !std.mem.eql(u8, first.wire(), second.wire())) return "a name decoded differently twice";

    const skipped = name_codec.skip(message, offset) catch return "skip failed where decode succeeded";
    if (skipped != end) return "skip and decode disagreed on where a name ends";
    return null;
}

fn question_check(message: []const u8) ?[]const u8 {
    var name: Name = Name.empty;
    const parsed = question_codec.parse(message, &name) catch return null;
    if (parsed.end > message.len) return "a question ended past the end of the message";
    if (parsed.end <= core.constants.header_bytes) return "a question ended inside the header";
    if (name.len < 1 or name.len > core.constants.name_bytes_max) return "a question name has an impossible length";
    // The question that parsed must match itself, case and all: that is the response check of §7
    // run against the message's own bytes.
    // A type cocuyo does not name is a question it never asks, so there is nothing to match.
    const kind = core.Kind.from_code(parsed.kind_code) orelse return null;
    if (kind.queryable() and !question_codec.matches(message, &name, kind)) {
        return "a question did not match the bytes it was parsed from";
    }
    return null;
}

fn record_sweep(message: []const u8) ?[]const u8 {
    const header = header_codec.parse(message) catch return null;
    var name: Name = Name.empty;
    const parsed = question_codec.parse(message, &name) catch return null;
    var walk = record_codec.Iterator.init(message, parsed.end, header.ancount);
    var previous = parsed.end;
    while (walk.next() catch return null) |record| {
        if (record.end > message.len) return "a record ended past the end of the message";
        if (record.end <= previous) return "a record did not advance the walk";
        if (record.rdata.len > message.len) return "a record's rdata is longer than the message";
        if (walk.walked > core.constants.records_max) return "the walk read more records than the bound";
        previous = record.end;
        if (rdata_check(message, &record)) |failure| return failure;
    }
    return null;
}

fn rdata_check(message: []const u8, record: *const record_codec.Record) ?[]const u8 {
    if (copy_check(message, record)) |failure| return failure;
    if (record.is_kind(.a) or record.is_kind(.aaaa)) {
        const address = record.address() catch return null;
        const expected: usize = if (record.is_kind(.a))
            core.constants.address_v4_bytes
        else
            core.constants.address_v6_bytes;
        if (address.slice().len != expected) return "an address is not its family's width";
        return null;
    }
    if (!record.is_kind(.cname) and !record.is_kind(.ptr)) return null;
    var target: Name = Name.empty;
    record.rdata_name(message, &target) catch return null;
    if (target.len < 1 or target.len > core.constants.name_bytes_max) return "an rdata name has an impossible length";
    return null;
}

/// The copy of docs/design.md §19 step 9 against the typed views: the copy never writes past the
/// room it was given, and every view is run over what it wrote. A record of a type whose layout
/// has no `rest` must read back through its view, because the two walk the same segments. The
/// copy takes a `rest` as it is, so a view may refuse it, as long as it refuses within the rdata.
fn copy_check(message: []const u8, record: *const record_codec.Record) ?[]const u8 {
    var out: [core.constants.rdata_bytes_max]u8 = undefined;
    const written = (record_copy.copy_out(message, record, &out) catch return null) orelse return null;
    if (written > out.len) return "the copy wrote past its buffer";
    const kind = core.Kind.from_code(record.kind_code) orelse return null;
    const parsed = reads_back(kind, out[0..written]) orelse return null;
    if (!parsed and !ends_in_rest(kind)) return "a record the copy accepted did not read back through its view";
    return null;
}

/// Whether the view of `kind` accepts `stored`, walking a TXT's strings and an SVCB's parameters
/// to their end; null for a type with no view.
fn reads_back(kind: core.Kind, stored: []const u8) ?bool {
    return switch (kind) {
        .ns, .cname, .ptr => accepted(rdata.name.whole(stored)),
        .mx => accepted(rdata.Mx.parse(stored)),
        .soa => accepted(rdata.Soa.parse(stored)),
        .srv => accepted(rdata.Srv.parse(stored)),
        .naptr => accepted(rdata.Naptr.parse(stored)),
        .hinfo => accepted(rdata.Hinfo.parse(stored)),
        .txt => txt_reads(stored),
        .sig => accepted(rdata.Sig.parse(stored)),
        .tlsa => accepted(rdata.Tlsa.parse(stored)),
        .uri => accepted(rdata.Uri.parse(stored)),
        .caa => accepted(rdata.Caa.parse(stored)),
        .svcb, .https => svcb_reads(stored),
        .a, .aaaa, .opt, .any => null,
        _ => null,
    };
}

fn ends_in_rest(kind: core.Kind) bool {
    const layout = rdata.layout.of(kind.code());
    return layout[layout.len - 1] == .rest;
}

/// Every string of a TXT, which each take an octet at least, so the rdata's length bounds them.
fn txt_reads(stored: []const u8) bool {
    var strings = rdata.Txt.strings(stored) catch return false;
    for (0..stored.len + 1) |_| {
        const string = strings.next() catch return false;
        if (string == null) return true;
    }
    return false;
}

/// Every parameter of an SVCB, which each take four octets at least.
fn svcb_reads(stored: []const u8) bool {
    const svcb = rdata.Svcb.parse(stored) catch return false;
    var params = svcb.params();
    for (0..stored.len + 1) |_| {
        const param = params.next() catch return false;
        if (param == null) return true;
    }
    return false;
}

/// A record the generator wrote whole (`fuzz_generate.zig`): the first answer is read, the copy
/// takes it, and its view takes the copy, whatever its type's layout.
pub fn check_whole(message: []const u8) ?[]const u8 {
    const header = header_codec.parse(message) catch return "a whole record's header did not parse";
    var name: Name = Name.empty;
    const parsed = question_codec.parse(message, &name) catch return "a whole record's question did not parse";
    var walk = record_codec.Iterator.init(message, parsed.end, header.ancount);
    const found = walk.next() catch return "a whole record did not walk";
    const record = found orelse return "a whole record was not there";
    const kind = core.Kind.from_code(record.kind_code) orelse return "a whole record is of a type the codec does not read";
    if (kind == .a or kind == .aaaa) {
        _ = record.address() catch return "a whole address did not read";
        return null;
    }
    var out: [core.constants.rdata_bytes_max]u8 = undefined;
    const copied = record_copy.copy_out(message, &record, &out) catch return "the copy refused a whole record";
    const written = copied orelse return "a whole record did not fit the copy";
    const read = reads_back(kind, out[0..written]) orelse return null;
    if (!read) return "a whole record's view refused its copy";
    return null;
}

fn accepted(result: anytype) bool {
    _ = result catch return false;
    return true;
}

/// `collect` for a type kept as rdata: the counts and the references stay inside their bounds,
/// and an MX question keeps only MX records that read back.
fn records_check(message: []const u8, kind: core.Kind) ?[]const u8 {
    var chain = Name.from_text(question_text) catch unreachable;
    var collected: response_codec.Answers = undefined;
    const outcome = response_codec.collect(message, &chain, kind, 0, &collected) catch return null;
    if (collected.count > core.constants.records_kept_max) return "more records were kept than there is room for";
    if ((outcome == .answered) != (collected.count > 0)) return "an answer and a count disagree";
    if (collected.records().used > core.constants.rdata_bytes_max) return "the rdata buffer overflowed";
    var index: usize = 0;
    while (index < collected.count) : (index += 1) {
        if (kept_check(&collected, index, kind)) |failure| return failure;
    }
    return null;
}

fn kept_check(collected: *const response_codec.Answers, index: usize, kind: core.Kind) ?[]const u8 {
    const records = collected.records();
    const kept = records.at(index);
    if (kept.rdata.len != records.refs[index].len) return "a kept record's rdata is not its reference";
    if (kind != .mx) return null;
    if (kept.kind_code != core.Kind.mx.code()) return "an MX question kept another type";
    _ = rdata.Mx.parse(kept.rdata) catch return "an MX kept by the collector did not read back";
    return null;
}

fn response_check(message: []const u8) ?[]const u8 {
    if (records_check(message, .mx)) |failure| return failure;
    if (records_check(message, .any)) |failure| return failure;
    var chain = Name.from_text(question_text) catch unreachable;
    var collected: response_codec.Answers = response_codec.Answers.init(.a);
    const outcome = response_codec.collect(message, &chain, .a, 0, &collected) catch return null;
    if (collected.count > core.constants.addresses_max) return "more addresses were collected than there is room for";
    if (outcome == .answered and collected.count == 0) return "an answer was reported with nothing collected";
    if (outcome != .answered and collected.count != 0) return "records were collected without an answer";
    if (chain.len < 1) return "the chain name is not a name";
    for (collected.addresses()) |address| {
        if (address.family != .ipv4) return "an A question collected an address that is not IPv4";
    }
    return null;
}

// Tests.

const testing = std.testing;
const fixtures = rdata.fixtures;

test "a whole record its view refuses is a failure, and one it takes is none" {
    const taken = fixtures.caa_response(&fixtures.caa);
    try testing.expectEqual(@as(?[]const u8, null), check_whole(&taken));
    // A CAA whose tag is empty, which RFC 8659 §4.1 forbids and the copy takes as it is.
    const refused = fixtures.caa_response(&fixtures.caa_tag_zero);
    try testing.expectEqualStrings("a whole record's view refused its copy", check_whole(&refused).?);
    // The same message not marked whole is no failure: a view may refuse a `rest`.
    try testing.expectEqual(@as(?[]const u8, null), check(&refused));
}
