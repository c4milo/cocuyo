//! The generator behind the fuzz target: one seed in, one message out, deterministically.
//!
//! Random bytes alone are a weak fuzzer for a wire format, because almost every random message is
//! rejected by the header check and never reaches the parts worth testing. So the generator mixes
//! pure noise with messages that are structurally plausible and hostile in one place: a header
//! whose counts lie, a name made only of compression pointers, an rdata length reaching past the
//! end, a valid message truncated mid-record. And since noise almost never makes a record a typed
//! reader takes, it writes one of each type the codec reads, whole or with one octet changed
//! (docs/design.md §19, step 9's gate), and records whose length fields are at their most.
//! `fuzz_generate_records.zig` writes both.
//!
//! Everything here is a pure function of the seed (CLAUDE.md non-negotiable 4), so a failure is
//! reproduced by its seed alone.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const limits = @import("../limits.zig");
const integer = @import("../integer.zig");
const records = @import("fuzz_generate_records.zig");
const Writer = records.Writer;
const record_kinds = records.record_kinds;

/// The largest message of every strategy but the long one. A UDP answer cocuyo would accept is at
/// most the advertised payload size, and a larger message mostly exercises the same paths more
/// slowly.
pub const message_bytes_max = core.constants.udp_payload_bytes_default;

/// The largest message the long strategy builds: the longest there is (RFC 1035 §4.2.2), which a
/// stream carries. Its offsets and sums reach values no message of 1232 octets reaches.
pub const long_message_bytes_max = core.limits.message_bytes_max;

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
    /// A response whose one answer is a record of a type the codec reads, written whole, or with
    /// one octet of its rdata changed.
    record,
    /// A plausible header, and a question of a long name, of a type cocuyo asks. Then an owner of
    /// labels and a pointer to that name, 255 octets whole or one past, and then noise.
    long_question,
    /// A response whose one record holds a length field at its most (`fuzz_generate_records.zig`).
    lengths_at_most,
    /// A response of up to 65535 octets: a name at the farthest offset a pointer names, an answer
    /// whose rdata runs past that name, and an answer at the end owned by a pointer to it.
    long_message,

    pub const count = @typeInfo(Strategy).@"enum".fields.len;
};

/// A message the generator produced, and the strategy that produced it.
pub const Message = struct {
    bytes: [long_message_bytes_max]u8 = @splat(0),
    len: usize = 0,
    strategy: Strategy = .noise,
    /// Whether its record was written whole, which every reader of its type must take.
    whole: bool = false,
    /// The length field at its most, under `lengths_at_most`, and where it is.
    most: ?records.Most = null,
    most_at: usize = 0,

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

    /// One of two, as a coin falls.
    pub fn coin(self: *Generator) bool {
        return self.next() & 1 == 1;
    }

    /// A value below `bound`, which must not be zero.
    pub fn below(self: *Generator, bound: usize) usize {
        assert(bound >= 1);
        return @intCast(self.next() % bound);
    }
};

/// The strategy `generate` uses for `seed`, which costs one word of the stream. A test that reads
/// one strategy skips the other seeds with it, and builds no long message it does not read.
pub fn strategy_of(seed: u64) Strategy {
    var generator = Generator.init(seed);
    return draw_strategy(&generator);
}

fn draw_strategy(generator: *Generator) Strategy {
    return @enumFromInt(generator.below(Strategy.count));
}

/// Builds the message for `seed` into `out`.
pub fn generate(seed: u64, out: *Message) void {
    var generator = Generator.init(seed);
    const strategy = draw_strategy(&generator);
    // Field by field. A short message reaches its first 1232 octets alone, so only those are set to
    // zero: all 65535 octets would cost more than the seed. Each strategy writes every octet up to
    // its length.
    out.strategy = strategy;
    out.whole = false;
    out.most = null;
    out.most_at = 0;
    @memset(out.bytes[0..message_bytes_max], 0);
    if (strategy == .long_message) return write_long_message(&generator, out);
    out.len = limits.fuzz_message_bytes_min + generator.below(message_bytes_max - limits.fuzz_message_bytes_min);
    assert(out.len >= limits.fuzz_message_bytes_min);
    assert(out.len <= message_bytes_max);
    fill_noise(&generator, out);
    switch (strategy) {
        .noise => {},
        .header_then_noise => write_header(&generator, out),
        .question_then_noise => write_question(&generator, out),
        .corrupted => corrupt(&generator, out),
        .pointer_maze => write_pointer_maze(&generator, out),
        .truncated => truncate(&generator, out),
        .record => records.write_record(&generator, out),
        .long_question => write_long_question(&generator, out),
        .lengths_at_most => records.write_lengths_at_most(&generator, out),
        .long_message => unreachable,
    }
    assert(out.len <= message_bytes_max);
}

fn fill_noise(generator: *Generator, out: *Message) void {
    assert(out.len >= limits.fuzz_message_bytes_min);
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
    while (labels <= core.limits.labels_max) {
        if (offset >= out.len) return;
        const length = generator.below(core.limits.label_bytes_max + 1);
        if (length == 0) {
            out.bytes[offset] = 0;
            return;
        }
        out.bytes[offset] = @intCast(length);
        offset += 1 + length;
        labels += 1;
    }
}

/// The header above, then a question whose name is `fuzz_question_name_bytes_min` octets long or
/// more, up to the longest a name can be (RFC 1035 §2.3.4), so its type and class can lie past
/// octet 255 of the message. Its type is one cocuyo asks and its class IN, so check 5's compare
/// reads all of it (docs/design.md §7). After it, the first answer's owner: labels, then a pointer
/// to the question's name (§4.1.4), so the record walk measures the owner through the pointer.
fn write_long_question(generator: *Generator, out: *Message) void {
    write_header(generator, out);
    const lengths = core.limits.name_bytes_max - limits.fuzz_question_name_bytes_min + 1;
    const name_bytes = limits.fuzz_question_name_bytes_min + generator.below(lengths);
    const owner_bytes = owner_label_bytes(generator, name_bytes);
    const end = core.constants.header_bytes + name_bytes + core.constants.question_fixed_bytes;
    out.len = @max(out.len, end + owner_bytes + constants.pointer_bytes);
    var writer: Writer = .{ .bytes = out.bytes[0..out.len], .at = core.constants.header_bytes };
    write_labels(generator, &writer, name_bytes - 1);
    writer.octet(0);
    writer.short(record_kinds[generator.below(record_kinds.len)].code());
    writer.short(core.constants.class_internet);
    assert(writer.at == end);
    write_labels(generator, &writer, owner_bytes);
    writer.short(pointer_to(core.constants.header_bytes));
}

/// The octets of the labels before the owner's pointer to a question name of `name_bytes`. A coin
/// gives the owner 255 octets whole, the most a name holds (RFC 1035 §2.3.4), or 256. The labels
/// take two octets at least, so after a question of 254 octets or more the owner is longer than
/// 255 octets.
fn owner_label_bytes(generator: *Generator, name_bytes: usize) usize {
    assert(name_bytes <= core.limits.name_bytes_max);
    const whole = core.limits.name_bytes_max + @intFromBool(generator.coin());
    return @max(whole - name_bytes, limits.label_wire_bytes_min);
}

/// Labels of noise that take `area_bytes` octets, length octets included, of lengths the seed
/// chooses up to 63 (RFC 1035 §2.3.4). A rest of 64 octets or fewer is the last label, and a
/// longer one leaves at least the octets a label takes.
fn write_labels(generator: *Generator, writer: *Writer, area_bytes: usize) void {
    var rest = area_bytes;
    for (0..core.limits.labels_max) |_| {
        assert(rest >= limits.label_wire_bytes_min);
        // The most octets this label may hold and still leave the next label its own.
        const room = rest -| (1 + limits.label_wire_bytes_min);
        const length = if (rest <= core.limits.label_bytes_max + 1)
            rest - 1
        else
            1 + generator.below(@min(core.limits.label_bytes_max, room));
        writer.octet(@intCast(length));
        writer.noise(generator, length);
        rest -= 1 + length;
        if (rest == 0) return;
    }
    unreachable; // each label takes two octets or more, and a name's labels take 254 at most
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
        // The offset's high bits go in the first octet beside the two that say pointer (RFC 1035
        // §4.1.4): masked with those two, they were lost, and no pointer aimed past offset 255.
        integer.write_u16(out.bytes[0..out.len], offset, pointer_to(generator.below(out.len)));
        offset += constants.pointer_bytes;
    }
}

/// A plausible message cut at an offset the seed chooses, so every parser meets an end it did not
/// expect.
fn truncate(generator: *Generator, out: *Message) void {
    write_question(generator, out);
    out.len = limits.fuzz_message_bytes_min + generator.below(out.len);
    assert(out.len >= limits.fuzz_message_bytes_min);
}

/// The answer at the end of a long message: an A record, its owner a pointer, and its address.
pub const long_tail_bytes: usize = constants.pointer_bytes + core.constants.record_fixed_bytes + core.constants.address_v4_bytes;

/// Where a long message holds its name: the farthest offset a pointer's fourteen bits name.
pub const long_name_at = constants.pointer_offset_mask;

/// A response to `example.com` of up to 65535 octets, half of them the longest. Its first answer's
/// rdata runs from after its fixed fields to the last answer, and holds the question's name at
/// `long_name_at` among noise. The last answer ends the message, and its owner is a pointer to
/// that name (RFC 1035 §4.1.4).
fn write_long_message(generator: *Generator, out: *Message) void {
    const lengths = long_message_bytes_max - limits.fuzz_long_message_bytes_min + 1;
    out.len = if (generator.coin()) long_message_bytes_max else limits.fuzz_long_message_bytes_min + generator.below(lengths);
    fill_noise_by_words(generator, out);
    var writer: Writer = .{ .bytes = out.bytes[0..out.len] };
    writer.short(@truncate(generator.next()));
    writer.short(constants.flag_response);
    for ([_]u16{ 1, constants.fuzz_long_answers, 0, 0 }) |count| writer.short(count);
    writer.slice(records.question_name);
    writer.short(core.Kind.a.code());
    writer.short(core.constants.class_internet);
    // The first answer, of any type, whose rdata is noise but for the name.
    writer.short(pointer_to(core.constants.header_bytes));
    writer.short(@truncate(generator.next()));
    writer.short(core.constants.class_internet);
    writer.long(@truncate(generator.next()));
    const tail_at = out.len - long_tail_bytes;
    writer.short(@intCast(tail_at - writer.at - constants.u16_bytes));
    @memcpy(out.bytes[long_name_at..][0..records.question_name.len], records.question_name);
    writer.at = tail_at;
    writer.short(pointer_to(long_name_at));
    writer.short(core.Kind.a.code());
    writer.short(core.constants.class_internet);
    writer.long(@truncate(generator.next()));
    writer.short(core.constants.address_v4_bytes);
    writer.noise(generator, core.constants.address_v4_bytes);
    assert(writer.at == out.len);
}

/// Noise over the whole message, eight octets to a word of the stream: a long message is too
/// long to draw an octet at a time.
fn fill_noise_by_words(generator: *Generator, out: *Message) void {
    const word_bytes = @sizeOf(u64);
    const words = out.len / word_bytes;
    for (0..words) |word| std.mem.writeInt(u64, out.bytes[word * word_bytes ..][0..word_bytes], generator.next(), .little);
    for (out.bytes[words * word_bytes .. out.len]) |*octet| octet.* = generator.byte();
}

/// A compression pointer to `offset` (RFC 1035 §4.1.4).
pub fn pointer_to(offset: usize) u16 {
    return (@as(u16, constants.label_kind_pointer) << constants.octet_bits) | @as(u16, @intCast(offset));
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

test "the strategy of a seed is the one its message is built with" {
    var message: Message = .{};
    for (0..256) |seed| {
        generate(seed, &message);
        try testing.expectEqual(message.strategy, strategy_of(seed));
    }
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
        const long = message.strategy == .long_message;
        try testing.expect(message.len >= if (long) limits.fuzz_long_message_bytes_min else limits.fuzz_message_bytes_min);
        try testing.expect(message.len <= if (long) long_message_bytes_max else message_bytes_max);
    }
}
