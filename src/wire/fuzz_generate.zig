//! The generator behind the fuzz target: one seed in, one message out, deterministically.
//!
//! Random bytes alone are a weak fuzzer for a wire format, because almost every random message is
//! rejected by the header check and never reaches the parts worth testing. So the generator mixes
//! pure noise with messages that are structurally plausible and hostile in one place: a header
//! whose counts lie, a name made only of compression pointers, an rdata length reaching past the
//! end, a valid message truncated mid-record. And since noise almost never makes a record a typed
//! reader takes, it writes one of each type the codec reads, whole or with one octet changed
//! (docs/design.md §19, step 9's gate).
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
    /// A response whose one answer is a record of a type the codec reads, written whole, or with
    /// one octet of its rdata changed.
    record,

    pub const count = @typeInfo(Strategy).@"enum".fields.len;
};

/// A message the generator produced, and the strategy that produced it.
pub const Message = struct {
    bytes: [message_bytes_max]u8 = @splat(0),
    len: usize = 0,
    strategy: Strategy = .noise,
    /// Whether its record was written whole, which every reader of its type must take.
    whole: bool = false,

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
        .record => write_record(&generator, out),
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

// Records of every type (docs/design.md §19, step 9's gate).

/// The types a record is written in: every type the codec reads but OPT, a pseudo-record, and ANY,
/// a question only.
pub const record_kinds = [_]core.Kind{
    .a,    .ns,  .cname, .soa,  .ptr,  .hinfo, .mx,  .txt, .sig,
    .aaaa, .srv, .naptr, .tlsa, .svcb, .https, .uri, .caa,
};

/// The name every record's response asks about, which the fuzz check asks about too.
const question_name = "\x07example\x03com\x00";

/// The letters a generated label or CAA tag is made of: a tag takes "only ASCII letters and
/// digits" (RFC 8659 §4.1), and a label takes these as well.
const letters = 'z' - 'a' + 1;

/// Octets written one after another into a message.
const Writer = struct {
    bytes: []u8,
    at: usize = 0,

    fn octet(self: *Writer, value: u8) void {
        self.bytes[self.at] = value;
        self.at += 1;
    }

    fn short(self: *Writer, value: u16) void {
        integer.write_u16(self.bytes, self.at, value);
        self.at += constants.u16_bytes;
    }

    fn long(self: *Writer, value: u32) void {
        integer.write_u32(self.bytes, self.at, value);
        self.at += constants.u32_bytes;
    }

    fn slice(self: *Writer, octets: []const u8) void {
        @memcpy(self.bytes[self.at..][0..octets.len], octets);
        self.at += octets.len;
    }

    fn noise(self: *Writer, generator: *Generator, count: usize) void {
        for (0..count) |_| self.octet(generator.byte());
    }

    /// A 16-bit length to be written once what it counts is: its offset.
    fn length_later(self: *Writer) usize {
        const at = self.at;
        self.short(0);
        return at;
    }

    fn length_now(self: *Writer, at: usize) void {
        integer.write_u16(self.bytes, at, @intCast(self.at - at - constants.u16_bytes));
    }
};

/// A response to `example.com` whose one answer is a record of a type the seed chooses, its owner a
/// pointer to the question's name. Half are left whole. The other half have one octet of the rdata
/// changed, which a reader may refuse, but must refuse without a read outside the message.
fn write_record(generator: *Generator, out: *Message) void {
    const kind = record_kinds[generator.below(record_kinds.len)];
    var writer: Writer = .{ .bytes = &out.bytes };
    writer.short(@truncate(generator.next()));
    writer.short(constants.flag_response);
    for ([_]u16{ 1, 1, 0, 0 }) |count| writer.short(count);
    writer.slice(question_name);
    writer.short(kind.code());
    writer.short(core.constants.class_internet);
    writer.short(pointer_to(core.constants.header_bytes));
    writer.short(kind.code());
    writer.short(core.constants.class_internet);
    writer.long(@truncate(generator.next()));
    const length_at = writer.length_later();
    write_rdata(generator, &writer, kind);
    writer.length_now(length_at);
    out.len = writer.at;
    assert(out.len <= message_bytes_max);
    const rdata_start = length_at + constants.u16_bytes;
    out.whole = generator.coin();
    // Any octet but the same one: an XOR with a value that is never zero.
    if (!out.whole) out.bytes[rdata_start + generator.below(out.len - rdata_start)] ^= generator.byte() | 1;
}

fn pointer_to(offset: usize) u16 {
    return (@as(u16, constants.label_kind_pointer) << constants.octet_bits) | @as(u16, @intCast(offset));
}

fn write_rdata(generator: *Generator, writer: *Writer, kind: core.Kind) void {
    switch (kind) {
        .a => writer.noise(generator, core.constants.address_v4_bytes),
        .aaaa => writer.noise(generator, core.constants.address_v6_bytes),
        .ns, .cname, .ptr => write_name(generator, writer),
        .soa => {
            write_name(generator, writer);
            write_name(generator, writer);
            writer.noise(generator, constants.soa_fixed_bytes);
        },
        // Two strings exactly (RFC 1035 §3.3.2).
        .hinfo => {
            write_string(generator, writer, 0);
            write_string(generator, writer, 0);
        },
        .mx, .srv => {
            writer.noise(generator, if (kind == .mx) constants.mx_fixed_bytes else constants.srv_fixed_bytes);
            write_name(generator, writer);
        },
        .txt => for (0..1 + generator.below(constants.fuzz_strings_max)) |_| write_string(generator, writer, 0),
        .sig => {
            writer.noise(generator, constants.sig_fixed_bytes);
            write_name(generator, writer);
            writer.noise(generator, generator.below(constants.fuzz_opaque_bytes_max + 1));
        },
        .naptr => {
            // Flags, services and regexp, then the replacement (RFC 3403 §4.1).
            writer.noise(generator, constants.naptr_fixed_bytes);
            write_string(generator, writer, 0);
            write_string(generator, writer, 0);
            write_string(generator, writer, 0);
            write_name(generator, writer);
        },
        .tlsa => writer.noise(generator, constants.tlsa_fixed_bytes + generator.below(constants.fuzz_opaque_bytes_max + 1)),
        // "The length of the Target field MUST be greater than zero" (RFC 7553 §4.5).
        .uri => writer.noise(generator, constants.uri_fixed_bytes + 1 + generator.below(constants.fuzz_opaque_bytes_max)),
        .caa => write_caa(generator, writer),
        .svcb, .https => write_svcb(generator, writer),
        // The generator writes only the types the codec reads.
        .opt, .any, _ => unreachable,
    }
}

/// A name of one to `fuzz_labels_max` labels of letters, or half the time a pointer to the
/// question's name, which the codec decompresses in every type it reads a name in (RFC 3597 §4,
/// docs/design.md §16 decision 16).
fn write_name(generator: *Generator, writer: *Writer) void {
    if (generator.coin()) return writer.short(pointer_to(core.constants.header_bytes));
    for (0..1 + generator.below(constants.fuzz_labels_max)) |_| {
        const length = 1 + generator.below(constants.fuzz_label_bytes_max);
        writer.octet(@intCast(length));
        write_letters(generator, writer, length);
    }
    writer.octet(0);
}

fn write_letters(generator: *Generator, writer: *Writer, count: usize) void {
    for (0..count) |_| writer.octet('a' + @as(u8, @intCast(generator.below(letters))));
}

/// A `<character-string>` of `least` to `fuzz_string_bytes_max` octets (RFC 1035 §3.3).
fn write_string(generator: *Generator, writer: *Writer, least: usize) void {
    const length = least + generator.below(constants.fuzz_string_bytes_max + 1 - least);
    writer.octet(@intCast(length));
    writer.noise(generator, length);
}

/// Flags, a tag of letters, at least one (RFC 8659 §4.1), and a value.
fn write_caa(generator: *Generator, writer: *Writer) void {
    writer.octet(generator.byte());
    const tag_length = constants.caa_tag_bytes_min + generator.below(constants.fuzz_label_bytes_max);
    writer.octet(@intCast(tag_length));
    write_letters(generator, writer, tag_length);
    writer.noise(generator, generator.below(constants.fuzz_opaque_bytes_max + 1));
}

/// The keys an SVCB is written with, in the strictly increasing order RFC 9460 §2.2 asks for.
const svcb_keys = [_]u16{
    constants.svcb_key_mandatory, constants.svcb_key_alpn,         constants.svcb_key_no_default_alpn,
    constants.svcb_key_port,      constants.svcb_key_ipv4hint,     constants.svcb_key_ech,
    constants.svcb_key_ipv6hint,  constants.fuzz_svcb_key_generic,
};

const mandatory_at = std.mem.indexOfScalar(u16, &svcb_keys, constants.svcb_key_mandatory).?;
const alpn_at = std.mem.indexOfScalar(u16, &svcb_keys, constants.svcb_key_alpn).?;
const no_default_alpn_at = std.mem.indexOfScalar(u16, &svcb_keys, constants.svcb_key_no_default_alpn).?;

comptime {
    // `mandatory` names only keys after it, which is every other one (RFC 9460 §8).
    assert(mandatory_at == 0);
}

/// A priority, a target, and the parameters the seed chooses. `no-default-alpn` comes only with
/// `alpn`, which makes the record "self-consistent" (RFC 9460 §7.1.1), and `mandatory` only with
/// another key to name, since an empty list is malformed (§8).
fn write_svcb(generator: *Generator, writer: *Writer) void {
    writer.short(@truncate(generator.next()));
    write_name(generator, writer);
    var chosen: [svcb_keys.len]bool = undefined;
    for (&chosen) |*on| on.* = generator.coin();
    chosen[no_default_alpn_at] = chosen[no_default_alpn_at] and chosen[alpn_at];
    chosen[mandatory_at] = chosen[mandatory_at] and std.mem.indexOfScalar(bool, chosen[mandatory_at + 1 ..], true) != null;
    for (svcb_keys, chosen) |key, on| {
        if (!on) continue;
        writer.short(key);
        const length_at = writer.length_later();
        write_value(generator, writer, key, &chosen);
        writer.length_now(length_at);
    }
}

/// A value of the format RFC 9460 §7 and §8 give `key`, or any octets for a key with none.
fn write_value(generator: *Generator, writer: *Writer, key: u16, chosen: []const bool) void {
    switch (key) {
        constants.svcb_key_mandatory => for (svcb_keys[mandatory_at + 1 ..], chosen[mandatory_at + 1 ..]) |named, on| {
            if (on) writer.short(named);
        },
        // "at least one alpn-id", each "a sequence of 1-255 octets" (§7.1).
        constants.svcb_key_alpn => for (0..1 + generator.below(constants.fuzz_strings_max)) |_| write_string(generator, writer, 1),
        constants.svcb_key_no_default_alpn => {},
        constants.svcb_key_port => writer.noise(generator, constants.u16_bytes),
        constants.svcb_key_ipv4hint => writer.noise(generator, core.constants.address_v4_bytes * (1 + generator.below(constants.fuzz_hints_max))),
        constants.svcb_key_ipv6hint => writer.noise(generator, core.constants.address_v6_bytes * (1 + generator.below(constants.fuzz_hints_max))),
        else => writer.noise(generator, generator.below(constants.fuzz_opaque_bytes_max + 1)),
    }
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

test "every type is written, whole and with an octet changed, within the gate's seeds" {
    const seeds = @import("fuzz.zig").seed_count;
    var whole: [record_kinds.len]bool = @splat(false);
    var changed: [record_kinds.len]bool = @splat(false);
    var message: Message = .{};
    for (0..seeds) |seed| {
        generate(seed, &message);
        if (message.strategy != .record) continue;
        const kind_code = integer.read_u16(message.slice(), core.constants.header_bytes + question_name.len);
        const index = for (record_kinds, 0..) |kind, at| {
            if (kind.code() == kind_code) break at;
        } else unreachable;
        if (message.whole) whole[index] = true else changed[index] = true;
    }
    for (whole, changed) |was_whole, was_changed| try testing.expect(was_whole and was_changed);
}
