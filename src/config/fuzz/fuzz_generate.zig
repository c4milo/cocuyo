//! The generator behind the text fuzz target (`fuzz.zig`): one seed in, one text out, and, for a
//! text written whole, what its parser must read from it.
//!
//! A text is for one parser: an address (`Address.from_text`), a name (`Name.from_text`), a
//! `resolv.conf`, a hosts file, or an SPKI pin. And it has one of four shapes:
//!
//! - Whole: written from values the generator chose, which the parser must read back as those.
//! - Changed: a whole text with one byte changed, which the parser may take or refuse.
//! - A near miss: a whole text broken one way the grammar refuses, which the parser must refuse.
//!   A file's near miss is a whole file with one bad line in it, which must be skipped.
//! - Noise.
//!
//! Everything here is a pure function of the seed (CLAUDE.md non-negotiable 4), so a failure is
//! reproduced by its seed alone. This file writes addresses and names; `fuzz_generate_files.zig`
//! writes the three kinds of file out of them.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const files = @import("fuzz_generate_files.zig");

pub const Target = enum {
    address,
    name,
    resolv_conf,
    hosts,
    pin,

    pub const count = @typeInfo(Target).@"enum".fields.len;
};

pub const Shape = enum {
    whole,
    changed,
    near_miss,
    noise,

    pub const count = @typeInfo(Shape).@"enum".fields.len;
};

/// What a text written whole, or a file with one bad line, must read back as. A file of no server
/// expects the local one, which is what the parser gives it.
pub const Expected = struct {
    addresses: [constants.fuzz_entries_max]core.Address = undefined,
    address_count: usize = 0,
    names: [constants.fuzz_entries_max]core.Name = undefined,
    name_count: usize = 0,
    pin: core.Pin = undefined,

    pub fn add_address(self: *Expected, address: core.Address) void {
        assert(self.address_count < self.addresses.len);
        self.addresses[self.address_count] = address;
        self.address_count += 1;
    }

    pub fn add_name(self: *Expected, name: core.Name) void {
        assert(self.name_count < self.names.len);
        self.names[self.name_count] = name;
        self.name_count += 1;
    }
};

pub const Text = struct {
    bytes: [constants.fuzz_text_bytes_max]u8 = undefined,
    len: usize = 0,
    target: Target = .address,
    shape: Shape = .noise,
    expected: Expected = .{},

    pub fn slice(self: *const Text) []const u8 {
        assert(self.len <= self.bytes.len);
        return self.bytes[0..self.len];
    }

    pub fn put(self: *Text, bytes: []const u8) void {
        assert(self.len + bytes.len <= self.bytes.len);
        @memcpy(self.bytes[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    pub fn put_byte(self: *Text, byte: u8) void {
        self.put(&.{byte});
    }

    /// Writes a number in decimal.
    pub fn put_decimal(self: *Text, value: u64) void {
        const written = std.fmt.bufPrint(self.bytes[self.len..], "{d}", .{value}) catch unreachable;
        self.len += written.len;
        assert(self.len <= self.bytes.len);
    }
};

/// The generator's own stream of words: `core.mix` stepped, which is deterministic and needs no
/// state beyond one word, as the codec's fuzz target draws them.
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

    pub fn coin(self: *Generator) bool {
        return self.next() & 1 == 1;
    }

    /// A value below `bound`, which must not be zero.
    pub fn below(self: *Generator, bound: usize) usize {
        assert(bound >= 1);
        return @intCast(self.next() % bound);
    }
};

/// Builds the text for `seed` into `out`.
pub fn generate(seed: u64, out: *Text) void {
    var generator = Generator.init(seed);
    out.* = .{
        .target = @enumFromInt(generator.below(Target.count)),
        .shape = @enumFromInt(generator.below(Shape.count)),
    };
    switch (out.shape) {
        .whole => write_whole(&generator, out),
        .changed => {
            write_whole(&generator, out);
            change_one(&generator, out);
        },
        .near_miss => write_near_miss(&generator, out),
        .noise => write_noise(&generator, out),
    }
    assert(out.len <= out.bytes.len);
}

fn write_whole(generator: *Generator, out: *Text) void {
    switch (out.target) {
        .address => out.expected.add_address(write_address(generator, out)),
        .name => out.expected.add_name(write_name(generator, out, .printable)),
        .resolv_conf => files.write_resolv_conf(generator, out, false),
        .hosts => files.write_hosts(generator, out, false),
        .pin => files.write_pin(generator, out),
    }
}

fn write_near_miss(generator: *Generator, out: *Text) void {
    switch (out.target) {
        .address => write_address_near_miss(generator, out),
        .name => write_name_near_miss(generator, out),
        .resolv_conf => files.write_resolv_conf(generator, out, true),
        .hosts => files.write_hosts(generator, out, true),
        .pin => files.write_pin_near_miss(generator, out),
    }
}

/// One byte of a whole text changed to any other.
fn change_one(generator: *Generator, out: *Text) void {
    if (out.len == 0) return;
    const at = generator.below(out.len);
    out.bytes[at] +%= @intCast(1 + generator.below(std.math.maxInt(u8)));
}

/// Printable text and blanks mostly, which reaches past a parser's first check, and any byte at
/// all now and then.
fn write_noise(generator: *Generator, out: *Text) void {
    const length = generator.below(constants.fuzz_noise_bytes_max + 1);
    for (0..length) |_| {
        const byte = generator.byte();
        out.put_byte(if (generator.below(noise_any_byte_one_in) == 0) byte else noise_bytes[byte % noise_bytes.len]);
    }
}

/// What noise is mostly made of: the characters every one of these grammars reads.
const noise_bytes = "0123456789abcdefABCDEF.:[]%/ \t\r\n#;=+-_xyz";
const noise_any_byte_one_in = 8;

// Addresses.

const v4_octets = core.constants.address_v4_bytes;
const v6_groups = core.constants.address_v6_bytes / @sizeOf(u16);
/// The groups before a trailing dotted quad, which fills the last two (RFC 4291 §2.2 form 3).
const v6_groups_before_quad = v6_groups - v4_octets / @sizeOf(u16);
const hex_digits_max = 4;

/// Writes an address, IPv4 or IPv6, in one of the forms the grammar takes, and returns it.
pub fn write_address(generator: *Generator, out: *Text) core.Address {
    if (generator.coin()) return write_v4(generator, out, v4_octets);
    return write_v6(generator, out);
}

/// `count` decimal octets between dots; the address of the first four.
fn write_v4(generator: *Generator, out: *Text, count: usize) core.Address {
    var octets: [v4_octets]u8 = undefined;
    for (0..count) |index| {
        const octet = generator.byte();
        if (index < v4_octets) octets[index] = octet;
        if (index > 0) out.put(".");
        out.put_decimal(octet);
    }
    return core.Address.from_v4(octets);
}

/// Eight groups, a zero as likely as any other value so that runs of zeros come up, written in
/// full or with one run compressed to `::`, and the last two as a dotted quad now and then.
fn write_v6(generator: *Generator, out: *Text) core.Address {
    var groups: [v6_groups]u16 = undefined;
    for (&groups) |*group| group.* = if (generator.coin()) 0 else @truncate(generator.next());
    const quad = generator.coin();
    const limit: usize = if (quad) v6_groups_before_quad else v6_groups;
    const gap = zero_gap(generator, groups[0..limit]);
    write_groups(generator, out, groups[0..limit], gap);
    if (quad) {
        // `::` already ends in the colon a dotted quad follows.
        if (gap == null or gap.?.end != limit) out.put(":");
        write_quad(out, groups[v6_groups_before_quad..]);
    }
    return address_of(groups);
}

/// The last two groups as a dotted quad (RFC 4291 §2.2 form 3).
fn write_quad(out: *Text, groups: []const u16) void {
    for (groups, 0..) |group, index| {
        if (index > 0) out.put(".");
        out.put_decimal(group >> @bitSizeOf(u8));
        out.put(".");
        out.put_decimal(group & std.math.maxInt(u8));
    }
}

fn address_of(groups: [v6_groups]u16) core.Address {
    var octets: [core.constants.address_v6_bytes]u8 = undefined;
    for (groups, 0..) |group, index| std.mem.writeInt(u16, octets[index * @sizeOf(u16) ..][0..@sizeOf(u16)], group, .big);
    return core.Address.from_v6(octets);
}

const Gap = struct { start: usize, end: usize };

/// A run of zero groups to write as `::`, any part of any run, or none. `::` stands for one or
/// more groups of zeros (RFC 4291 §2.2).
fn zero_gap(generator: *Generator, groups: []const u16) ?Gap {
    if (generator.coin()) return null;
    const start = generator.below(groups.len);
    if (groups[start] != 0) return null;
    var end = start + 1;
    while (end < groups.len and groups[end] == 0 and generator.coin()) end += 1;
    return .{ .start = start, .end = end };
}

fn write_groups(generator: *Generator, out: *Text, groups: []const u16, gap: ?Gap) void {
    const start = if (gap) |at| at.start else groups.len;
    for (groups[0..start], 0..) |group, index| {
        if (index > 0) out.put(":");
        write_group(generator, out, group);
    }
    const end = if (gap) |at| at.end else groups.len;
    if (gap != null) out.put("::");
    for (groups[end..], 0..) |group, index| {
        if (index > 0) out.put(":");
        write_group(generator, out, group);
    }
}

/// A group in hexadecimal, in either case, padded with zeros to a width of its own.
fn write_group(generator: *Generator, out: *Text, value: u16) void {
    var digits: [hex_digits_max]u8 = undefined;
    const upper = generator.coin();
    const text = if (upper)
        std.fmt.bufPrint(&digits, "{X}", .{value}) catch unreachable
    else
        std.fmt.bufPrint(&digits, "{x}", .{value}) catch unreachable;
    for (0..generator.below(hex_digits_max - text.len + 1)) |_| out.put("0");
    out.put(text);
}

/// The ways an address is broken, each one the grammar refuses.
const AddressMiss = enum {
    five_octets,
    three_octets,
    octet_too_large,
    octet_leading_zero,
    octet_empty,
    nine_groups,
    group_too_long,
    two_gaps,
    gap_in_full,
    zone,
    brackets,
    prefix,
    trailing_colon,
    quad_not_last,
};

/// Writes an address broken one way the grammar refuses.
pub fn write_address_near_miss(generator: *Generator, out: *Text) void {
    switch (@as(AddressMiss, @enumFromInt(generator.below(@typeInfo(AddressMiss).@"enum".fields.len)))) {
        .five_octets => _ = write_v4(generator, out, v4_octets + 1),
        .three_octets => _ = write_v4(generator, out, v4_octets - 1),
        .octet_too_large, .octet_leading_zero, .octet_empty => |miss| write_v4_miss(generator, out, miss),
        .nine_groups => write_full_groups(generator, out, v6_groups + 1),
        .group_too_long => {
            write_full_groups(generator, out, v6_groups - 1);
            out.put(":1");
            for (0..hex_digits_max) |_| out.put("0");
        },
        .two_gaps => out.put("1::2::3"),
        .gap_in_full => {
            write_full_groups(generator, out, v6_groups);
            out.put("::");
        },
        .zone, .brackets, .prefix => |miss| write_v6_dressed(generator, out, miss),
        .trailing_colon => {
            write_full_groups(generator, out, v6_groups);
            out.put(":");
        },
        .quad_not_last => {
            out.put("::");
            _ = write_v4(generator, out, v4_octets);
            out.put(":1");
        },
    }
}

/// A dotted quad with one octet broken.
fn write_v4_miss(generator: *Generator, out: *Text, miss: AddressMiss) void {
    const broken = generator.below(v4_octets);
    for (0..v4_octets) |index| {
        if (index > 0) out.put(".");
        if (index != broken) {
            out.put_decimal(generator.byte());
            continue;
        }
        switch (miss) {
            .octet_too_large => out.put_decimal(std.math.maxInt(u8) + 1 + generator.below(octet_digits_room)),
            .octet_leading_zero => {
                out.put("0");
                out.put_decimal(generator.below(octet_digits_room));
            },
            else => {},
        }
    }
}

/// How far past 255 a three-digit octet reaches, and a digit or two after a leading zero.
const octet_digits_room = 744;

fn write_full_groups(generator: *Generator, out: *Text, count: usize) void {
    for (0..count) |index| {
        if (index > 0) out.put(":");
        write_group(generator, out, @truncate(generator.next()));
    }
}

/// A whole IPv6 address with a zone, in brackets, or with a prefix length: forms a nameserver
/// line and a hosts line never carry, which the parser refuses (address_text.zig).
fn write_v6_dressed(generator: *Generator, out: *Text, miss: AddressMiss) void {
    if (miss == .brackets) out.put("[");
    _ = write_v6(generator, out);
    switch (miss) {
        .zone => out.put("%eth0"),
        .brackets => out.put("]"),
        .prefix => {
            out.put("/");
            out.put_decimal(generator.below(core.constants.address_v6_bytes * @bitSizeOf(u8) + 1));
        },
        else => unreachable,
    }
}

// Names.

/// Which bytes a label is written with: any a name spelled by the caller may hold, or the letters,
/// digits and `-` of a host name, which a file can hold without a byte it reads as a comment.
pub const Alphabet = enum { printable, host };

/// Writes a name of labels the generator chose, absolute or not, and returns it in wire form,
/// built label by label and not by `Name.from_text`, which is what the check holds it against.
pub fn write_name(generator: *Generator, out: *Text, alphabet: Alphabet) core.Name {
    var name: core.Name = .empty;
    const labels = 1 + generator.below(constants.fuzz_labels_max);
    for (0..labels) |index| {
        if (index > 0) out.put(".");
        const start = out.len;
        // One label of full length now and then, and only the first, so the name stays in bounds.
        const long = index == 0 and generator.below(long_label_one_in) == 0;
        const length = if (long) core.constants.label_bytes_max else 1 + generator.below(constants.fuzz_label_bytes_max);
        for (0..length) |_| out.put_byte(label_byte(generator, alphabet));
        name.append_label(out.bytes[start..out.len]) catch unreachable;
    }
    if (generator.coin()) out.put(".");
    name.terminate() catch unreachable;
    return name;
}

const long_label_one_in = 8;
const host_bytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-";

/// A byte a label may hold: printable ASCII but the separator and the escape (name_text.zig).
fn label_byte(generator: *Generator, alphabet: Alphabet) u8 {
    if (alphabet == .host) return host_bytes[generator.below(host_bytes.len)];
    const byte: u8 = @intCast('!' + generator.below('~' - '!' + 1));
    return if (byte == '.' or byte == '\\') 'a' else byte;
}

/// The ways a name is broken, each one `Name.from_text` refuses.
const NameMiss = enum { empty_label, leading_dot, label_too_long, name_too_long, bad_byte };

fn write_name_near_miss(generator: *Generator, out: *Text) void {
    switch (@as(NameMiss, @enumFromInt(generator.below(@typeInfo(NameMiss).@"enum".fields.len)))) {
        .empty_label => {
            _ = write_name(generator, out, .host);
            if (out.bytes[out.len - 1] != '.') out.put(".");
            out.put(".x");
        },
        .leading_dot => {
            out.put(".");
            _ = write_name(generator, out, .host);
        },
        .label_too_long => for (0..core.constants.label_bytes_max + 1) |_| out.put("a"),
        .name_too_long => for (0..core.constants.name_bytes_max / core.constants.label_bytes_max + 1) |index| {
            if (index > 0) out.put(".");
            for (0..core.constants.label_bytes_max) |_| out.put("b");
        },
        .bad_byte => {
            out.put("a");
            out.put_byte(bad_label_bytes[generator.below(bad_label_bytes.len)]);
            out.put("b");
        },
    }
}

/// Bytes a label spelled by the caller cannot hold: a space, a tab, a control byte, the escape,
/// DEL, and one past ASCII.
const bad_label_bytes = [_]u8{ ' ', '\t', std.ascii.control_code.soh, '\\', std.ascii.control_code.del, "\u{e9}"[0] };

// Tests.

const testing = std.testing;

test "every target and shape comes up, and the same seed builds the same text" {
    var seen_targets: [Target.count]bool = @splat(false);
    var seen_shapes: [Shape.count]bool = @splat(false);
    var text: Text = .{};
    var again: Text = .{};
    for (0..512) |seed| {
        generate(seed, &text);
        generate(seed, &again);
        try testing.expectEqualSlices(u8, text.slice(), again.slice());
        seen_targets[@intFromEnum(text.target)] = true;
        seen_shapes[@intFromEnum(text.shape)] = true;
    }
    for (seen_targets) |seen| try testing.expect(seen);
    for (seen_shapes) |seen| try testing.expect(seen);
}

test "an IPv6 address comes out compressed, with a trailing quad, and in upper case, among others" {
    var compressed = false;
    var quad = false;
    var upper = false;
    var generator = Generator.init(1);
    for (0..512) |_| {
        var text: Text = .{};
        _ = write_v6(&generator, &text);
        const written = text.slice();
        compressed = compressed or std.mem.indexOf(u8, written, "::") != null;
        quad = quad or std.mem.indexOfScalar(u8, written, '.') != null;
        upper = upper or std.mem.indexOfAny(u8, written, "ABCDEF") != null;
    }
    try testing.expect(compressed and quad and upper);
}
