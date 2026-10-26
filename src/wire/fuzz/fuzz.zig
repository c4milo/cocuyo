//! The fuzz target for the codec: one seed in, one message built by fuzz_generate.zig, every
//! parser run over it by fuzz_check.zig.
//!
//! The gate below is a test, so `zig build test` runs it over `seed_count` seeds and prints
//! nothing unless a seed fails. `zig build fuzz -- --seed <hex>` runs one seed and prints what it
//! built, which is how a failure is reproduced: the seed is the whole input.
//!
//! Zig 0.16 has a coverage-guided fuzzer of its own behind `zig build test --fuzz`, which needs a
//! build with instrumentation. It is not wired here: in Zig 0.16.0 the test runner itself does not
//! compile in fuzz mode (`compiler/test_runner.zig` hands `std.debug.writeStackTrace` a
//! `*builtin.StackTrace`), which a test of nothing but `std.testing.fuzz` showed on 2026-09-26.
//! This gate is portable, deterministic and runs on every host, which is what a check that must
//! pass before every commit needs to be; a guided fuzzer is a good thing to add beside it, not
//! instead of it, once the Zig cocuyo pins can build one.
const std = @import("std");
const limits = @import("../limits.zig");
const generate_module = @import("fuzz_generate.zig");
const check_module = @import("fuzz_check.zig");

pub const Message = generate_module.Message;
pub const Strategy = generate_module.Strategy;
pub const generate = generate_module.generate;
pub const strategy_of = generate_module.strategy_of;
pub const check = check_module.check;

/// How many seeds `zig build test` runs: an alias of the limit in `limits.zig`, kept as the path
/// a consumer reached it by (docs/design.md §17 question 76).
pub const seed_count = limits.fuzz_seed_count;

/// Runs one seed. Returns the promise that broke, or null when the message held up.
pub fn run(seed: u64, out: *Message) ?[]const u8 {
    generate(seed, out);
    return verdict(out);
}

/// What the check says of a message, and of a record written whole, whether it was taken whole.
pub fn verdict(message: *const Message) ?[]const u8 {
    if (check(message.slice())) |failure| return failure;
    if (message.whole) return check_module.check_whole(message.slice());
    return null;
}

/// Runs `count` seeds from `first`. Returns the first seed that failed and what broke.
pub const Failure = struct { seed: u64, what: []const u8 };

pub fn gate(first: u64, count: u64) ?Failure {
    var message: Message = .{};
    var seed = first;
    const last = first + count;
    while (seed < last) : (seed += 1) {
        if (run(seed, &message)) |what| return .{ .seed = seed, .what = what };
    }
    return null;
}

// Tests.

const testing = std.testing;

test "the fuzz gate holds over every seed it runs" {
    if (gate(0, limits.fuzz_seed_count)) |failure| {
        std.debug.print(
            "fuzz: seed 0x{x} broke a promise: {s}\n  reproduce with: zig build fuzz -- --seed 0x{x}\n",
            .{ failure.seed, failure.what, failure.seed },
        );
        return error.FuzzInvariantViolated;
    }
}

test "a seed that built a message reaching the parsers is checked, not merely rejected" {
    // A gate that only ever built unparseable noise would pass while checking nothing, so this
    // pins that some seeds produce messages the record walk actually reads.
    var message: Message = .{};
    var parsed: usize = 0;
    var seed: u64 = 0;
    while (seed < 256) : (seed += 1) {
        if (strategy_of(seed) != .question_then_noise) continue;
        generate(seed, &message);
        if (message.len > 64) parsed += 1;
    }
    try testing.expect(parsed > 0);
}

test "a long question of every name length from the shortest long one to 255 octets is written" {
    // Its class lies past octet 255 of the message from a name of 242 octets on, and its type from
    // 244, where check 5's offsets overflowed once (docs/mutations.md, QO1): the seeds reach each.
    const shortest = @import("../limits.zig").fuzz_question_name_bytes_min;
    var seen: [core.limits.name_bytes_max - shortest + 1]bool = @splat(false);
    var message: Message = .{};
    for (0..limits.fuzz_seed_count) |seed| {
        if (strategy_of(seed) != .long_question) continue;
        generate(seed, &message);
        var name: core.Name = core.Name.empty;
        const parsed = try question_codec.parse(message.slice(), &name);
        try testing.expect(core.Kind.from_code(parsed.kind_code).?.queryable());
        seen[name.len - shortest] = true;
    }
    for (seen) |reached| try testing.expect(reached);
}

test "a long question's answer is owned through a pointer to it, at 255 octets whole and at 256" {
    // A name counts the labels that its pointer reaches (RFC 1035 §3.1, §4.1.4). It holds "255
    // octets or less" (§2.3.4). The record walk's skip measures the owner through its pointer.
    var reached: [2]bool = @splat(false);
    var message: Message = .{};
    for (0..limits.fuzz_seed_count) |seed| {
        if (strategy_of(seed) != .long_question) continue;
        generate(seed, &message);
        const whole = try long_owner_whole(message.slice());
        if (whole == core.limits.name_bytes_max) reached[0] = true;
        if (whole == core.limits.name_bytes_max + 1) reached[1] = true;
    }
    for (reached) |was| try testing.expect(was);
}

/// The length of a long question's owner: labels, then a pointer to the question's name. `skip`
/// and `decode` end it after its pointer at 255 octets or fewer, and refuse it past 255.
fn long_owner_whole(bytes: []const u8) !usize {
    const constants = @import("../constants.zig");
    var name: core.Name = core.Name.empty;
    const question = try question_codec.parse(bytes, &name);
    var pointer_at = question.end;
    for (0..core.limits.labels_max) |_| {
        if (bytes[pointer_at] & constants.label_kind_mask == constants.label_kind_pointer) break;
        pointer_at += 1 + bytes[pointer_at];
    }
    const pointer = generate_module.pointer_to(core.constants.header_bytes);
    try testing.expectEqual(pointer, integer.read_u16(bytes, pointer_at));
    const whole = pointer_at - question.end + name.len;
    var owner: core.Name = core.Name.empty;
    if (whole > core.limits.name_bytes_max) {
        try testing.expectError(error.NameTooLong, name_codec.skip(bytes, question.end));
        try testing.expectError(error.NameTooLong, name_codec.decode(bytes, question.end, &owner));
    } else {
        const end = pointer_at + constants.pointer_bytes;
        try testing.expectEqual(end, try name_codec.skip(bytes, question.end));
        try testing.expectEqual(end, try name_codec.decode(bytes, question.end, &owner));
    }
    return whole;
}

/// The farthest offset a pointer of a maze aims at: every two octets after the header are one.
fn farthest_target(message: *const Message) usize {
    const constants = @import("../constants.zig");
    const bytes = message.slice();
    var farthest: usize = 0;
    var offset: usize = core.constants.header_bytes;
    while (offset + constants.pointer_bytes <= bytes.len) : (offset += constants.pointer_bytes) {
        const pointer = integer.read_u16(bytes, offset);
        farthest = @max(farthest, pointer & constants.pointer_offset_mask);
    }
    return farthest;
}

test "a pointer maze aims its pointers anywhere in the message, past offset 255 too" {
    // A pointer's first octet holds the six high bits of the offset it aims at (RFC 1035 §4.1.4).
    var message: Message = .{};
    var mazes: usize = 0;
    var far: usize = 0;
    for (0..limits.fuzz_seed_count) |seed| {
        if (strategy_of(seed) != .pointer_maze) continue;
        generate(seed, &message);
        const farthest = farthest_target(&message);
        try testing.expect(farthest < message.len);
        mazes += 1;
        if (farthest > std.math.maxInt(u8)) far += 1;
    }
    // Most mazes are longer than 256 octets, and hold hundreds of pointers.
    try testing.expect(far > mazes / 2);
}

test "a long message of 65535 octets is written, and its last answer is owned through the farthest pointer" {
    // The longest message there is (RFC 1035 §4.2.2), and a pointer to offset 16383, the farthest
    // its fourteen bits name (§4.1.4): the gate's seeds reach both, and the walk reads both.
    const constants = @import("../constants.zig");
    var message: Message = .{};
    var longest: usize = 0;
    for (0..limits.fuzz_seed_count) |seed| {
        if (strategy_of(seed) != .long_message) continue;
        generate(seed, &message);
        const bytes = message.slice();
        if (bytes.len == core.limits.message_bytes_max) longest += 1;
        var name: core.Name = core.Name.empty;
        const question = try question_codec.parse(bytes, &name);
        var walk = record_codec.Iterator.init(bytes, question.end, constants.fuzz_long_answers);
        _ = (try walk.next()).?;
        const last = (try walk.next()).?;
        try testing.expectEqual(bytes.len, last.end);
        const pointer = integer.read_u16(bytes, last.owner_offset);
        try testing.expectEqual(constants.pointer_offset_mask, pointer & constants.pointer_offset_mask);
        var owner: core.Name = core.Name.empty;
        try last.owner_name(bytes, &owner);
        try testing.expect(owner.equal(&name));
    }
    try testing.expect(longest > 0);
}

test "a record written whole that its view refuses fails the verdict, and the same record changed does not" {
    const fixtures = rdata.fixtures;
    // A CAA whose tag is empty, which RFC 8659 §4.1 forbids and the copy takes as it is.
    const refused = fixtures.caa_response(&fixtures.caa_tag_zero);
    var message: Message = .{ .len = refused.len, .strategy = .record, .whole = true };
    @memcpy(message.bytes[0..refused.len], &refused);
    try testing.expect(verdict(&message) != null);
    message.whole = false;
    try testing.expectEqual(@as(?[]const u8, null), verdict(&message));
}

// What the readers meet in the lengths strategy.

const records_module = @import("fuzz_generate_records.zig");
const Most = records_module.Most;
const core = @import("core");
const integer = @import("../integer.zig");
const question_codec = @import("../question.zig");
const record_codec = @import("../record.zig");
const record_copy = @import("../record_copy.zig");
const response_opt = @import("../response_opt.zig");
const name_codec = @import("../name.zig");
const edns = @import("../edns.zig");
const rdata = @import("../rdata/rdata.zig");

/// What the readers met in the messages of the lengths strategy. A sixteen-bit length was refused
/// by its reader at 0xFFFF (`high`) and at 0xFFFE (`low`). A one-octet length in a record written
/// whole was read whole at 255, or a label at 63, which marks both. A COOKIE was read or refused
/// as RFC 7873 §4 says, which marks both and the entry of its length in `cookies`.
const Met = struct {
    high: [Most.count]bool = @splat(false),
    low: [Most.count]bool = @splat(false),
    cookies: [records_module.cookie_lengths.len]bool = @splat(false),

    fn note(met: *Met, message: *const Message) !void {
        const most = message.most orelse return error.TestUnexpectedResult;
        const bytes = message.slice();
        const at = message.most_at;
        switch (most) {
            .rdlength => try met.wide(most, bytes, at, rdlength_refused(bytes)),
            .option_length => try met.wide(most, bytes, at, option_refused(bytes)),
            .param_length => try met.wide(most, bytes, at, param_refused(bytes)),
            .string_length, .tag_length, .alpn_length, .label_length => {
                // A record with one octet changed may read or not, so it shows nothing.
                if (!message.whole) return;
                try testing.expect(read_at_most(most, bytes, at));
                met.high[@intFromEnum(most)] = true;
                met.low[@intFromEnum(most)] = true;
            },
            .cookie_length => try met.cookie(bytes, at),
        }
    }

    /// A sixteen-bit length is 0xFFFF or 0xFFFE, and its reader refuses it in every message.
    fn wide(met: *Met, most: Most, bytes: []const u8, at: usize, refused: bool) !void {
        const value = integer.read_u16(bytes, at);
        try testing.expect(value == records_module.wide_most or value == records_module.wide_most - 1);
        try testing.expect(refused);
        const index = @intFromEnum(most);
        if (value == records_module.wide_most) met.high[index] = true else met.low[index] = true;
    }

    /// Every option of the OPT is read whole, and the COOKIE gives the server cookie its length
    /// says, or is refused one octet past the longest.
    fn cookie(met: *Met, bytes: []const u8, at: usize) !void {
        const length = integer.read_u16(bytes, at);
        const lengths = &records_module.cookie_lengths;
        const index = std.mem.indexOfScalar(usize, lengths, length) orelse return error.TestUnexpectedResult;
        const question = try question_name();
        const opt = (try response_opt.find(bytes, &question)) orelse return error.TestUnexpectedResult;
        var options: rdata.Options = .{ .rdata = opt.rdata };
        for (0..opt.rdata.len + 1) |_| {
            if ((try options.next()) == null) break;
        }
        try testing.expectEqual(opt.rdata.len, options.offset);
        const found = edns.find_cookie(opt.rdata);
        if (length > core.constants.cookie_client_bytes + core.limits.cookie_server_bytes_max) {
            try testing.expectError(error.MalformedMessage, found);
        } else {
            try testing.expectEqual(length - core.constants.cookie_client_bytes, (try found).?.server.len);
        }
        met.cookies[index] = true;
        met.high[@intFromEnum(Most.cookie_length)] = true;
        met.low[@intFromEnum(Most.cookie_length)] = true;
    }
};

fn question_name() !core.Name {
    return core.Name.from_text("example.com");
}

/// The first answer of a message whose question parses, as the walk reads it.
fn first_answer(bytes: []const u8) core.Error!?record_codec.Record {
    var name: core.Name = core.Name.empty;
    const question = try question_codec.parse(bytes, &name);
    var walk = record_codec.Iterator.init(bytes, question.end, 1);
    return walk.next();
}

/// The walk refuses the answer, whose rdlength runs past the message.
fn rdlength_refused(bytes: []const u8) bool {
    _ = first_answer(bytes) catch |err| return err == error.TruncatedMessage;
    return false;
}

/// The OPT is found, and both its option walk and the COOKIE reader refuse its one option.
fn option_refused(bytes: []const u8) bool {
    const question = question_name() catch return false;
    const opt = (response_opt.find(bytes, &question) catch return false) orelse return false;
    var options: rdata.Options = .{ .rdata = opt.rdata };
    _ = options.next() catch {
        _ = edns.find_cookie(opt.rdata) catch return true;
        return false;
    };
    return false;
}

/// The answer's rdata as the copy writes it out, its names decompressed (RFC 3597 §4).
fn copied(bytes: []const u8, out: *[core.limits.rdata_bytes_max]u8) ?[]const u8 {
    const record = (first_answer(bytes) catch return null) orelse return null;
    const written = (record_copy.copy_out(bytes, &record, out) catch return null) orelse return null;
    return out[0..written];
}

/// The SVCB reads, and its parameter walk refuses the parameter whose length runs past it.
fn param_refused(bytes: []const u8) bool {
    var out: [core.limits.rdata_bytes_max]u8 = undefined;
    const stored = copied(bytes, &out) orelse return false;
    const svcb = rdata.Svcb.parse(stored) catch return false;
    var params = svcb.params();
    _ = params.next() catch return true;
    return false;
}

/// Whether the reader of a one-octet length reads the field at 255, or the label at 63, whole.
fn read_at_most(most: Most, bytes: []const u8, at: usize) bool {
    var out: [core.limits.rdata_bytes_max]u8 = undefined;
    return switch (most) {
        .string_length => txt_reads_longest(copied(bytes, &out) orelse return false),
        .tag_length => caa_reads_longest(copied(bytes, &out) orelse return false),
        .alpn_length => alpn_reads_longest(copied(bytes, &out) orelse return false),
        .label_length => label_reads_longest(bytes, at),
        else => unreachable,
    };
}

/// A CAA reads, and its tag is 255 octets.
fn caa_reads_longest(stored: []const u8) bool {
    const caa = rdata.Caa.parse(stored) catch return false;
    return caa.tag.len == records_module.narrow_most;
}

/// A string of the TXT is read whole at 255 octets.
fn txt_reads_longest(stored: []const u8) bool {
    var strings = rdata.Txt.strings(stored) catch return false;
    for (0..stored.len + 1) |_| {
        const string = (strings.next() catch return false) orelse return false;
        if (string.len == records_module.narrow_most) return true;
    }
    return false;
}

/// The first parameter is `alpn`, read and checked whole, and its first alpn-id is 255 octets.
fn alpn_reads_longest(stored: []const u8) bool {
    const svcb = rdata.Svcb.parse(stored) catch return false;
    var params = svcb.params();
    const param = (params.next() catch return false) orelse return false;
    var ids: rdata.string.Strings = .{ .rdata = param.value };
    const id = (ids.next() catch return false) orelse return false;
    return id.len == records_module.narrow_most;
}

/// The name decoder reads the name at `at`, and its first label is 63 octets.
fn label_reads_longest(bytes: []const u8, at: usize) bool {
    var name: core.Name = core.Name.empty;
    _ = name_codec.decode(bytes, at, &name) catch return false;
    return name.bytes[0] == records_module.label_most;
}

test "every length field at its most reaches the reader it shares, within the gate's seeds" {
    // 0xFFFF and 0xFFFE for each sixteen-bit length, 255 for each one-octet length, 63 for a
    // label, and each COOKIE length, each met by its reader as a lookup would meet it.
    var met: Met = .{};
    var message: Message = .{};
    for (0..limits.fuzz_seed_count) |seed| {
        if (strategy_of(seed) != .lengths_at_most) continue;
        generate(seed, &message);
        try met.note(&message);
    }
    for (met.high, met.low) |high, low| try testing.expect(high and low);
    for (met.cookies) |reached| try testing.expect(reached);
}
