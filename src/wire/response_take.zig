//! Storing one wanted record into `Answers`: an address, a PTR name, or a record copied into the
//! rdata buffer with its names written out (docs/design.md §19 step 9). Split from
//! `response.zig`, which walks the sections and decides what is wanted.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const Kind = core.Kind;
const record_codec = @import("record.zig");
const record_copy = @import("record_copy.zig");
const response = @import("response.zig");
const Answers = response.Answers;

/// Stores one wanted record. Returns whether it was stored: a record that does not fit sets
/// `truncated` rather than failing, because what was already collected is still an answer.
pub fn take(
    message: []const u8,
    record: *const record_codec.Record,
    kind: Kind,
    out: *Answers,
) Error!bool {
    switch (kind.storage()) {
        .names => {
            if (out.count == core.constants.ptr_names_max) return refuse(out);
            try record.rdata_name(message, &out.items.names[out.count]);
        },
        .addresses => {
            if (out.count == core.constants.addresses_max) return refuse(out);
            out.items.addresses[out.count] = try record.address();
        },
        .rdata => return take_rdata(message, record, out),
    }
    out.count += 1;
    response.note_ttl(record.ttl_seconds, out);
    assert(out.count >= 1);
    return true;
}

/// Copies the record into the buffer, names decompressed, and keeps a reference to it. The
/// record's own type is kept, because an ANY question collects records of every type.
fn take_rdata(message: []const u8, record: *const record_codec.Record, out: *Answers) Error!bool {
    if (out.count == core.constants.records_kept_max) return refuse(out);
    const records = &out.items.records;
    const written = try record_copy.copy_out(message, record, records.bytes[records.used..]) orelse
        return refuse(out);
    assert(records.used + written <= core.constants.rdata_bytes_max);
    records.refs[out.count] = .{
        .kind_code = record.kind_code,
        .ttl_seconds = record.ttl_seconds,
        .offset = records.used,
        .len = @intCast(written),
    };
    records.used += @intCast(written);
    out.count += 1;
    response.note_ttl(record.ttl_seconds, out);
    return true;
}

fn refuse(out: *Answers) bool {
    out.truncated = true;
    return false;
}

// Tests. Every kind kept as rdata, driven through `collect` so the owner rule and the chain rule
// apply, then read back through the typed views.

const testing = std.testing;
const fixtures = @import("fixtures.zig");
const rdata = @import("rdata/rdata.zig");
const constants = @import("constants.zig");
const integer = @import("integer.zig");
const Name = core.Name;
const Outcome = response.Outcome;

var test_chain: Name = Name.empty;

fn collect_from(message: []const u8, kind: Kind, out: *Answers) !Outcome {
    test_chain = try Name.from_text("example.com");
    return response.collect(message, &test_chain, kind, 0, out);
}

test "a record with a TTL of zero keeps the answer's TTL at zero, whatever comes after it" {
    // RFC 1035 §3.2.1: zero means the record "should not be cached". The round-robin fixture's
    // two records carry 300; the first is written to zero, then the second, in turn.
    const question = try Name.from_text("example.com");
    const first_ttl_at = response.section_start(&question) + constants.pointer_bytes + constants.record_ttl_offset;
    const record_bytes = fixtures.record_a.len;
    for ([_]usize{ first_ttl_at, first_ttl_at + record_bytes }) |ttl_at| {
        var message = fixtures.answer_a_twice;
        integer.write_u32(&message, ttl_at, 0);
        var collected: Answers = undefined;
        try testing.expectEqual(Outcome.answered, try collect_from(&message, .a, &collected));
        try testing.expectEqual(@as(u8, 2), collected.count);
        try testing.expectEqual(@as(u32, 0), collected.ttl_seconds);
    }
}

test "an MX record is kept with its exchange written out in full, and reads back typed" {
    var collected: Answers = undefined;
    try testing.expectEqual(Outcome.answered, try collect_from(&fixtures.answer_mx, .mx, &collected));
    try testing.expectEqual(@as(u8, 1), collected.count);
    const kept = collected.records().at(0);
    try testing.expectEqual(Kind.mx.code(), kept.kind_code);
    try testing.expectEqual(@as(u32, 300), kept.ttl_seconds);
    try testing.expectEqualSlices(u8, &rdata.fixtures.mx, kept.rdata);
    const mx = try rdata.Mx.parse(kept.rdata);
    try testing.expect(mx.exchange.equal(&try Name.from_text("mail.example.com")));
    try testing.expectEqual(@as(u32, 300), collected.ttl_seconds);
}

test "an SRV target and both SOA names are written out, whatever their RFCs say about compression" {
    var collected: Answers = undefined;
    try testing.expectEqual(Outcome.answered, try collect_from(&fixtures.answer_srv, .srv, &collected));
    const srv = try rdata.Srv.parse(collected.records().at(0).rdata);
    try testing.expectEqual(@as(u16, 5269), srv.port);
    try testing.expect(srv.target.equal(&try Name.from_text("sip.example.com")));

    try testing.expectEqual(Outcome.answered, try collect_from(&fixtures.answer_soa_asked, .soa, &collected));
    const soa = try rdata.Soa.parse(collected.records().at(0).rdata);
    try testing.expect(soa.mname.equal(&try Name.from_text("ns1.example.com")));
    try testing.expect(soa.rname.equal(&try Name.from_text("hostmaster.example.com")));
    try testing.expectEqual(@as(u32, 300), soa.minimum);
}

test "a TXT record is copied as it is" {
    var collected: Answers = undefined;
    try testing.expectEqual(Outcome.answered, try collect_from(&fixtures.answer_txt, .txt, &collected));
    var strings = try rdata.Txt.strings(collected.records().at(0).rdata);
    try testing.expectEqualStrings("hello", (try strings.next()).?);
    try testing.expectEqualStrings("world", (try strings.next()).?);
}

test "an ANY question keeps every record the name owns, each with its own type" {
    var collected: Answers = undefined;
    try testing.expectEqual(Outcome.answered, try collect_from(&fixtures.answer_any, .any, &collected));
    try testing.expectEqual(@as(u8, 3), collected.count);
    const records = collected.records();
    try testing.expectEqual(Kind.a.code(), records.at(0).kind_code);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, records.at(0).rdata);
    try testing.expectEqual(Kind.mx.code(), records.at(1).kind_code);
    try testing.expectEqual(Kind.txt.code(), records.at(2).kind_code);
    try testing.expect(!collected.truncated);
}

test "a CNAME answers a CNAME question and an ANY question, and is followed for neither" {
    var collected: Answers = undefined;
    try testing.expectEqual(Outcome.answered, try collect_from(&fixtures.answer_cname_asked, .cname, &collected));
    try testing.expect(!collected.aliased);
    try testing.expect(test_chain.equal(&try Name.from_text("example.com")));
    const target = try rdata.name.whole(collected.records().at(0).rdata);
    try testing.expect(target.equal(&try Name.from_text("host.example.net")));

    try testing.expectEqual(Outcome.answered, try collect_from(&fixtures.answer_any_cname, .any, &collected));
    try testing.expect(!collected.aliased);
    try testing.expectEqual(Kind.cname.code(), collected.records().at(0).kind_code);
}

test "a record past the count kept, or past the buffer, sets truncated and keeps the rest" {
    var collected: Answers = undefined;
    try testing.expectEqual(Outcome.answered, try collect_from(&fixtures.answer_txt_thirty_three, .txt, &collected));
    try testing.expectEqual(@as(u8, core.constants.records_kept_max), collected.count);
    try testing.expect(collected.truncated);

    try testing.expectEqual(Outcome.answered, try collect_from(&fixtures.answer_txt_two_big, .txt, &collected));
    try testing.expectEqual(@as(u8, 1), collected.count);
    try testing.expect(collected.truncated);
    try testing.expectEqual(@as(usize, 1280), collected.records().at(0).rdata.len);
}

test "a malformed rdata name fails the collection rather than storing half a record" {
    var collected: Answers = undefined;
    try testing.expectError(Error.MalformedMessage, collect_from(&fixtures.answer_mx_name_past_record, .mx, &collected));
    try testing.expectError(Error.MalformedMessage, collect_from(&fixtures.answer_mx_trailing_octet, .mx, &collected));
}

test "an A question still keeps addresses, and a record of another type is not an answer" {
    var collected: Answers = undefined;
    try testing.expectEqual(Outcome.answered, try collect_from(&fixtures.answer_a, .a, &collected));
    try testing.expectEqual(@as(usize, 1), collected.addresses().len);
    try testing.expectEqual(Outcome.no_data, try collect_from(&fixtures.answer_a, .mx, &collected));
    try testing.expectEqual(@as(u8, 0), collected.count);
}
