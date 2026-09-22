//! The generator behind the fuzz target: one seed in, one message out, deterministically.
//!
//! Random bytes alone are a weak fuzzer for a wire format, because almost every random message is
//! rejected by the header check and never reaches the parts worth testing. So the generator mixes
//! pure noise with messages that are structurally plausible and hostile in one place: a header
//! whose counts lie, a name made only of compression pointers, an rdata length reaching past the
//! end, a valid message truncated mid-record.
//!
//! Everything here is a pure function of the seed (CLAUDE.md non-negotiable 4), so a failure is
//! reproduced by its seed alone.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");
const integer = @import("integer.zig");

/// The largest message the generator builds. A UDP answer cocuyo would accept is at most the
/// advertised payload size, and a larger message only exercises the same paths more slowly.
pub const message_bytes_max = core.constants.udp_payload_bytes_default;

/// The smallest message: shorter than a header, so the header check is exercised too.
pub const message_bytes_min = 1;

/// How the bytes of one message are chosen.
pub const Strategy = enum {
    /// Nothing but noise.
    noise,
    /// A plausible header, then noise.
    header_then_noise,
    /// A plausible header and question, then noise where the records go.
    question_then_noise,
    /// A plausible message with one field corrupted.
    corrupted,
    /// A name built only of compression pointers, at offsets the seed chooses.
    pointer_maze,
    /// A plausible message cut short at an offset the seed chooses.
    truncated,

    pub const count = @typeInfo(Strategy).@"enum".fields.len;
};

/// A message the generator produced, and the strategy that produced it.
pub const Message = struct {
    bytes: [message_bytes_max]u8 = @splat(0),
    len: usize = 0,
    strategy: Strategy = .noise,

    pub fn slice(self: *const Message) []const u8 {
        assert(self.len <= self.bytes.len);
        return self.bytes[0..self.len];
    }
};

/// The generator's own stream of words: `core.mix` stepped, which is deterministic and needs no
/// state beyond one word.
pub const Generator = struct {
    word: u64,

    pub fn init(seed: u64) Generator {
        return .{ .word = seed };
    }

    pub fn next(self: *Generator) u64 {
        self.word = core.mix.next(self.word);
        return self.word;
    }

    pub fn byte(self: *Generator) u8 {
        return @truncate(self.next());
    }

    /// A value below `bound`, which must not be zero.
    pub fn below(self: *Generator, bound: usize) usize {
        assert(bound >= 1);
        return @intCast(self.next() % bound);
    }
};

/// Builds the message for `seed` into `out`.
pub fn generate(seed: u64, out: *Message) void {
    var generator = Generator.init(seed);
    const strategy: Strategy = @enumFromInt(generator.below(Strategy.count));
    out.* = .{ .strategy = strategy };
    out.len = message_bytes_min + generator.below(message_bytes_max - message_bytes_min);
    assert(out.len >= message_bytes_min);
    assert(out.len <= message_bytes_max);
    fill_noise(&generator, out);
    switch (strategy) {
        .noise => {},
        .header_then_noise => write_header(&generator, out),
        .question_then_noise => write_question(&generator, out),
        .corrupted => corrupt(&generator, out),
        .pointer_maze => write_pointer_maze(&generator, out),
        .truncated => truncate(&generator, out),
    }
    assert(out.len <= message_bytes_max);
}

fn fill_noise(generator: *Generator, out: *Message) void {
    assert(out.len >= message_bytes_min);
    for (out.bytes[0..out.len]) |*byte| byte.* = generator.byte();
}

/// A header a response could have: QR set, one question, and counts that may or may not match
/// what follows.
fn write_header(generator: *Generator, out: *Message) void {
    if (out.len < core.constants.header_bytes) out.len = core.constants.header_bytes;
    const bytes = out.bytes[0..out.len];
    integer.write_u16(bytes, constants.header_id_offset, @truncate(generator.next()));
    integer.write_u16(bytes, constants.header_flags_offset, constants.flag_response |
        @as(u16, @truncate(generator.next() & constants.rcode_mask)));
    integer.write_u16(bytes, constants.header_qdcount_offset, 1);
    integer.write_u16(bytes, constants.header_ancount_offset, @truncate(generator.next()));
    integer.write_u16(bytes, constants.header_nscount_offset, @truncate(generator.next()));
    integer.write_u16(bytes, constants.header_arcount_offset, @truncate(generator.next()));
}

/// The header above, then a question whose name is labels of lengths the seed chooses. The name
/// may run off the end, which is the point.
fn write_question(generator: *Generator, out: *Message) void {
    write_header(generator, out);
    var offset: usize = core.constants.header_bytes;
    var labels: usize = 0;
    while (labels <= core.constants.labels_max) {
        if (offset >= out.len) return;
        const length = generator.below(core.constants.label_bytes_max + 1);
        if (length == 0) {
            out.bytes[offset] = 0;
            return;
        }
        out.bytes[offset] = @intCast(length);
        offset += 1 + length;
        labels += 1;
    }
}

/// One octet of a plausible message, flipped to something a parser must refuse: a count, a length
/// octet, or a pointer's high octet.
fn corrupt(generator: *Generator, out: *Message) void {
    write_question(generator, out);
    const target = generator.below(out.len);
    out.bytes[target] = generator.byte();
    if (out.len > core.constants.header_bytes) {
        const second = core.constants.header_bytes + generator.below(out.len - core.constants.header_bytes);
        out.bytes[second] = constants.label_kind_pointer | generator.byte();
    }
}

/// Every octet after the header becomes half of a compression pointer, aimed anywhere in the
/// message, including forwards and at itself.
fn write_pointer_maze(generator: *Generator, out: *Message) void {
    write_header(generator, out);
    var offset: usize = core.constants.header_bytes;
    while (offset + constants.pointer_bytes <= out.len) {
        const target = generator.below(out.len);
        out.bytes[offset] = constants.label_kind_pointer |
            @as(u8, @intCast((target >> constants.octet_bits) & constants.label_kind_mask));
        out.bytes[offset + 1] = @truncate(target);
        offset += constants.pointer_bytes;
    }
}

/// A plausible message cut at an offset the seed chooses, so every parser meets an end it did not
/// expect.
fn truncate(generator: *Generator, out: *Message) void {
    write_question(generator, out);
    out.len = message_bytes_min + generator.below(out.len);
    assert(out.len >= message_bytes_min);
}

// Tests.

const testing = std.testing;

test "one seed gives one message, byte for byte" {
    var first: Message = .{};
    var second: Message = .{};
    generate(0x1234_5678, &first);
    generate(0x1234_5678, &second);
    try testing.expectEqual(first.len, second.len);
    try testing.expectEqual(first.strategy, second.strategy);
    try testing.expectEqualSlices(u8, first.slice(), second.slice());
}

test "different seeds give different messages" {
    var first: Message = .{};
    var second: Message = .{};
    generate(1, &first);
    generate(2, &second);
    try testing.expect(first.len != second.len or !std.mem.eql(u8, first.slice(), second.slice()));
}

test "every strategy is reached over a small range of seeds" {
    var seen: [Strategy.count]bool = @splat(false);
    var message: Message = .{};
    var seed: u64 = 0;
    while (seed < 256) : (seed += 1) {
        generate(seed, &message);
        seen[@intFromEnum(message.strategy)] = true;
    }
    for (seen) |reached| try testing.expect(reached);
}

test "every message stays inside the bounds the generator promises" {
    var message: Message = .{};
    var seed: u64 = 0;
    while (seed < 256) : (seed += 1) {
        generate(seed, &message);
        try testing.expect(message.len >= message_bytes_min);
        try testing.expect(message.len <= message_bytes_max);
    }
}
