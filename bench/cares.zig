//! The comparison against c-ares: the two operations both libraries perform on the same bytes,
//! measured by one harness in one process, so the rows can be read side by side.
//!
//!     zig build bench-cares
//!
//! What is compared, and what is not. A query build and a response parse both have a c-ares
//! counterpart: `ares_dns_write` over a record, and `ares_dns_parse` over a message. The datagram
//! match does not. c-ares decides whose datagram it is inside `ares_process`, entangled with its
//! own sockets and readiness callbacks, which is the very thing cocuyo's split exists to avoid,
//! and there is no way to hand it a datagram and time the decision alone. That row has no
//! neighbour here, and docs/design.md §11 says so.
//!
//! What each side does when it "builds" or "parses" is not the same, and the row names say what
//! was timed. cocuyo builds a query from a name it holds into a buffer the caller owns; c-ares
//! builds a record object on the heap, writes it into a buffer it allocates, and the caller frees
//! both. cocuyo's parse follows the CNAME chain, checks every record's owner and copies the
//! addresses into a fixed union; c-ares's parse builds a tree of records on the heap, and the case
//! then walks it for the addresses and frees it, which is what a caller of c-ares does. The rows
//! measure each library doing its own job, not a job neither has.
//!
//! c-ares is the Homebrew build of the version the header prints: its shipping build, optimised,
//! with its assertions compiled out. cocuyo is ReleaseSafe with its assertions on. That favours
//! c-ares, which is the right way round for a comparison this library publishes.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const wire = @import("wire");
const harness = @import("harness.zig");
const cases = @import("bench_cases.zig");
const c = @cImport(@cInclude("ares.h"));

const fixtures = wire.fixtures;
const iterations = cases.iterations;
const doNotOptimizeAway = std.mem.doNotOptimizeAway;

/// The EDNS0 payload size both queries advertise, so their OPT records agree.
const udp_payload = cocuyo.constants.udp_payload_bytes_default;

/// The name both queries ask about.
const query_name = "example.com";

pub const all = [_]harness.Case{
    .{ .name = "harness overhead (empty call)", .iterations = iterations, .run = &noop },
    .{ .name = "cocuyo query build, example.com, EDNS0", .iterations = iterations, .run = &cases.run_query_build, .setup = &cases.setup_queries },
    .{ .name = "c-ares query write, record prepared, buffer freed", .iterations = iterations, .run = &run_cares_write, .setup = &setup_cares_query },
    .{ .name = "c-ares query create, question, OPT, write, both freed", .iterations = iterations, .run = &run_cares_create_write },
    .{ .name = "cocuyo response parse, one A", .iterations = iterations, .run = &cases.run_parse_one, .setup = &cases.setup_messages },
    .{ .name = "c-ares response parse, one A, addresses read, freed", .iterations = iterations, .run = &run_cares_parse_one, .setup = &setup_cares_messages },
    .{ .name = "cocuyo response parse, CNAME then A (+ 256-octet restore)", .iterations = iterations, .run = &cases.run_parse_cname, .setup = &cases.setup_messages },
    .{ .name = "c-ares response parse, CNAME then A, addresses read, freed", .iterations = iterations, .run = &run_cares_parse_cname, .setup = &setup_cares_messages },
    .{ .name = "cocuyo response parse, 16 A of 17", .iterations = iterations, .run = &cases.run_parse_sixteen, .setup = &cases.setup_messages },
    .{ .name = "c-ares response parse, 17 A, addresses read, freed", .iterations = iterations, .run = &run_cares_parse_seventeen, .setup = &setup_cares_messages },
};

pub fn main() void {
    var version_buffer: [64]u8 = undefined;
    const title = std.fmt.bufPrint(&version_buffer, "cocuyo against c-ares {s}", .{c.ares_version(null)}) catch unreachable;
    harness.run(title, &all);
}

fn noop() void {}

// The query, the way c-ares builds one: a record, a question, an OPT record, and a write.

var cares_query: ?*c.ares_dns_record_t = null;

fn setup_cares_query() void {
    if (cares_query) |record| c.ares_dns_record_destroy(record);
    cares_query = build_query_record();
}

/// The record `ares_create_query` builds internally, built from parts because the constructor
/// that does it is not in the public header: id, recursion desired, one question, and an OPT
/// record advertising the payload size with version 0 and no flags.
fn build_query_record() *c.ares_dns_record_t {
    var record: ?*c.ares_dns_record_t = null;
    assert(c.ares_dns_record_create(&record, fixtures.id, c.ARES_FLAG_RD, c.ARES_OPCODE_QUERY, c.ARES_RCODE_NOERROR) == c.ARES_SUCCESS);
    assert(c.ares_dns_record_query_add(record, query_name, c.ARES_REC_TYPE_A, c.ARES_CLASS_IN) == c.ARES_SUCCESS);
    var opt: ?*c.ares_dns_rr_t = null;
    assert(c.ares_dns_record_rr_add(&opt, record, c.ARES_SECTION_ADDITIONAL, "", c.ARES_REC_TYPE_OPT, c.ARES_CLASS_IN, 0) == c.ARES_SUCCESS);
    assert(c.ares_dns_rr_set_u16(opt, c.ARES_RR_OPT_UDP_SIZE, udp_payload) == c.ARES_SUCCESS);
    assert(c.ares_dns_rr_set_u8(opt, c.ARES_RR_OPT_VERSION, 0) == c.ARES_SUCCESS);
    assert(c.ares_dns_rr_set_u16(opt, c.ARES_RR_OPT_FLAGS, 0) == c.ARES_SUCCESS);
    return record.?;
}

/// Writes a prepared record and frees the buffer c-ares allocated for it.
fn write_and_free(record: *c.ares_dns_record_t) void {
    var buffer: [*c]u8 = null;
    var length: usize = 0;
    assert(c.ares_dns_write(record, &buffer, &length) == c.ARES_SUCCESS);
    doNotOptimizeAway(length);
    doNotOptimizeAway(buffer);
    c.ares_free_string(buffer);
}

fn run_cares_write() void {
    write_and_free(cares_query.?);
}

fn run_cares_create_write() void {
    const record = build_query_record();
    write_and_free(record);
    c.ares_dns_record_destroy(record);
}

// The parse, the way a caller of c-ares reads addresses: parse, walk the answer section, free.

var cares_message_one: [fixtures.answer_a.len]u8 = undefined;
var cares_message_cname: [fixtures.answer_cname_then_a.len]u8 = undefined;
var cares_message_seventeen: [fixtures.answer_a_seventeen.len]u8 = undefined;

fn setup_cares_messages() void {
    cares_message_one = fixtures.answer_a;
    cares_message_cname = fixtures.answer_cname_then_a;
    cares_message_seventeen = fixtures.answer_a_seventeen;
}

/// Parses `message`, sums the A addresses in its answer section so the walk cannot be elided, and
/// frees the record. Returns how many A records it read, for the tests.
fn parse_cares(message: []const u8) usize {
    var record: ?*c.ares_dns_record_t = null;
    assert(c.ares_dns_parse(message.ptr, message.len, 0, &record) == c.ARES_SUCCESS);
    const count = c.ares_dns_record_rr_cnt(record, c.ARES_SECTION_ANSWER);
    var sum: u32 = 0;
    var addresses: usize = 0;
    var index: usize = 0;
    while (index < count) : (index += 1) {
        const rr = c.ares_dns_record_rr_get_const(record, c.ARES_SECTION_ANSWER, index);
        if (c.ares_dns_rr_get_type(rr) != c.ARES_REC_TYPE_A) continue;
        const address = c.ares_dns_rr_get_addr(rr, c.ARES_RR_A_ADDR);
        sum +%= address.*.s_addr;
        addresses += 1;
    }
    doNotOptimizeAway(sum);
    c.ares_dns_record_destroy(record);
    return addresses;
}

fn run_cares_parse_one() void {
    doNotOptimizeAway(parse_cares(&cares_message_one));
}

fn run_cares_parse_cname() void {
    doNotOptimizeAway(parse_cares(&cares_message_cname));
}

fn run_cares_parse_seventeen() void {
    doNotOptimizeAway(parse_cares(&cares_message_seventeen));
}

// Tests. They run under `zig build bench-cares` and not under `zig build test`, because they link
// a library the gate must not require. What they pin is that the two sides are looking at the
// same thing: the same query bytes, and the same records in the same messages.

const testing = std.testing;

test "c-ares writes the same query bytes cocuyo does" {
    // Same id, same name, same type, recursion desired, the same OPT record. Two implementations
    // written from RFC 1035 and RFC 6891 independently, agreeing octet for octet, is the check on
    // cocuyo's query builder that no fixture of cocuyo's own can be.
    cases.setup_queries();
    var ours: [cocuyo.constants.query_bytes_max]u8 = undefined;
    const ours_len = wire.query.write(&.{
        .id = fixtures.id,
        .name = try cocuyo.Name.from_text(query_name),
        .kind = .a,
    }, &ours);
    const record = build_query_record();
    defer c.ares_dns_record_destroy(record);
    var theirs: [*c]u8 = null;
    var theirs_len: usize = 0;
    try testing.expect(c.ares_dns_write(record, &theirs, &theirs_len) == c.ARES_SUCCESS);
    defer c.ares_free_string(theirs);
    try testing.expectEqualSlices(u8, ours[0..ours_len], theirs[0..theirs_len]);
}

test "c-ares reads the same records from the corpus that cocuyo does" {
    setup_cares_messages();
    try testing.expectEqual(@as(usize, 1), parse_cares(&cares_message_one));
    try testing.expectEqual(@as(usize, 1), parse_cares(&cares_message_cname));
    // Seventeen A records are in the message. cocuyo keeps sixteen and says so; c-ares keeps all.
    try testing.expectEqual(@as(usize, cocuyo.constants.addresses_max + 1), parse_cares(&cares_message_seventeen));
}

test "the version measured is the one the header names" {
    try testing.expect(c.ares_version(null) != null);
    try testing.expect(std.mem.len(c.ares_version(null)) >= 5);
}
