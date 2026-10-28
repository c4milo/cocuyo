//! The records the fuzz generator writes (docs/design.md §19, step 9's gate): one of each type the
//! codec reads, whole or with one octet changed, and records whose length fields are at their
//! most. Split from `fuzz_generate.zig` by the file-length rule.
//!
//! Everything here is a pure function of the generator's stream (CLAUDE.md non-negotiable 4).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const limits = @import("../limits.zig");
const integer = @import("../integer.zig");
const generate_module = @import("fuzz_generate.zig");
const Generator = generate_module.Generator;
const Message = generate_module.Message;
const message_bytes_max = generate_module.message_bytes_max;
const pointer_to = generate_module.pointer_to;

/// The types a record is written in: every type the codec reads but OPT, a pseudo-record, and ANY,
/// a question only.
pub const record_kinds = [_]core.Kind{
    .a,    .ns,  .cname, .soa,  .ptr,  .hinfo, .mx,  .txt, .sig,
    .aaaa, .srv, .naptr, .tlsa, .svcb, .https, .uri, .caa,
};

/// The name every record's response asks about, which the fuzz check asks about too.
pub const question_name = "\x07example\x03com\x00";

/// The letters a generated label or CAA tag is made of: a tag takes "only ASCII letters and
/// digits" (RFC 8659 §4.1), and a label takes these as well.
const letters: usize = 'z' - 'a' + 1;

/// Octets written one after another into a message.
pub const Writer = struct {
    bytes: []u8,
    at: usize = 0,

    pub fn octet(self: *Writer, value: u8) void {
        self.bytes[self.at] = value;
        self.at += 1;
    }

    pub fn short(self: *Writer, value: u16) void {
        integer.write_u16(self.bytes, self.at, value);
        self.at += constants.u16_bytes;
    }

    pub fn long(self: *Writer, value: u32) void {
        integer.write_u32(self.bytes, self.at, value);
        self.at += constants.u32_bytes;
    }

    pub fn slice(self: *Writer, octets: []const u8) void {
        @memcpy(self.bytes[self.at..][0..octets.len], octets);
        self.at += octets.len;
    }

    pub fn noise(self: *Writer, generator: *Generator, count: usize) void {
        for (0..count) |_| self.octet(generator.byte());
    }

    /// A 16-bit length to be written once what it counts is: its offset.
    pub fn length_later(self: *Writer) usize {
        const at = self.at;
        self.short(0);
        return at;
    }

    pub fn length_now(self: *Writer, at: usize) void {
        integer.write_u16(self.bytes, at, @intCast(self.at - at - constants.u16_bytes));
    }
};

/// A response to `example.com` whose one answer is a record of a type the seed chooses, its owner a
/// pointer to the question's name. Half are left whole. The other half have one octet of the rdata
/// changed, which a reader may refuse, but must refuse without a read outside the message.
pub fn write_record(generator: *Generator, out: *Message) void {
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
        .txt => for (0..1 + generator.below(limits.fuzz_strings_max)) |_| write_string(generator, writer, 0),
        .sig => {
            writer.noise(generator, constants.sig_fixed_bytes);
            write_name(generator, writer);
            writer.noise(generator, generator.below(limits.fuzz_opaque_bytes_max + 1));
        },
        .naptr => {
            // Flags, services and regexp, then the replacement (RFC 3403 §4.1).
            writer.noise(generator, constants.naptr_fixed_bytes);
            write_string(generator, writer, 0);
            write_string(generator, writer, 0);
            write_string(generator, writer, 0);
            write_name(generator, writer);
        },
        .tlsa => writer.noise(generator, constants.tlsa_fixed_bytes + generator.below(limits.fuzz_opaque_bytes_max + 1)),
        // "The length of the Target field MUST be greater than zero" (RFC 7553 §4.5).
        .uri => writer.noise(generator, constants.uri_fixed_bytes + 1 + generator.below(limits.fuzz_opaque_bytes_max)),
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
    for (0..1 + generator.below(limits.fuzz_labels_max)) |_| {
        const length = 1 + generator.below(limits.fuzz_label_bytes_max);
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
    const length = least + generator.below(limits.fuzz_string_bytes_max + 1 - least);
    writer.octet(@intCast(length));
    writer.noise(generator, length);
}

/// Flags, a tag of letters, at least one (RFC 8659 §4.1), and a value.
fn write_caa(generator: *Generator, writer: *Writer) void {
    writer.octet(generator.byte());
    const tag_length = limits.caa_tag_bytes_min + generator.below(limits.fuzz_label_bytes_max);
    writer.octet(@intCast(tag_length));
    write_letters(generator, writer, tag_length);
    writer.noise(generator, generator.below(limits.fuzz_opaque_bytes_max + 1));
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
        constants.svcb_key_alpn => for (0..1 + generator.below(limits.fuzz_strings_max)) |_| write_string(generator, writer, 1),
        constants.svcb_key_no_default_alpn => {},
        constants.svcb_key_port => writer.noise(generator, constants.u16_bytes),
        constants.svcb_key_ipv4hint => writer.noise(generator, core.constants.address_v4_bytes * (1 + generator.below(limits.fuzz_hints_max))),
        constants.svcb_key_ipv6hint => writer.noise(generator, core.constants.address_v6_bytes * (1 + generator.below(limits.fuzz_hints_max))),
        else => writer.noise(generator, generator.below(limits.fuzz_opaque_bytes_max + 1)),
    }
}

// Length fields at their most.

/// Which length field a message of the lengths strategy holds at its most. Each is a field the
/// readers of several types share, so a reader added later meets it with no test of its own.
pub const Most = enum {
    /// A record's rdlength at 0xFFFF or 0xFFFE (RFC 1035 §4.1.3), which runs past any message.
    rdlength,
    /// An EDNS option's length at 0xFFFF or 0xFFFE (RFC 6891 §6.1.2), past its OPT's rdata.
    option_length,
    /// An SVCB parameter's length at 0xFFFF or 0xFFFE (RFC 9460 §2.2), past its rdata.
    param_length,
    /// A TXT string of 255 octets, the most its length octet says (RFC 1035 §3.3).
    string_length,
    /// A CAA tag of 255 octets, the most its length octet says (RFC 8659 §4.1).
    tag_length,
    /// An SVCB alpn-id of 255 octets, "a sequence of 1-255 octets" (RFC 9460 §7.1).
    alpn_length,
    /// A name of labels of 63 octets each, the longest a label is (RFC 1035 §2.3.4).
    label_length,
    /// A COOKIE option of a length in `cookie_lengths`, the last option of its OPT (RFC 7873 §4).
    cookie_length,

    pub const count = @typeInfo(Most).@"enum".fields.len;

    /// Whether the field is sixteen bits, written at 0xFFFF or 0xFFFE, and not one octet.
    pub fn wide(most: Most) bool {
        return most == .rdlength or most == .option_length or most == .param_length;
    }
};

/// The largest a sixteen-bit length field holds. The strategy writes it, or one less.
pub const wide_most: u16 = std.math.maxInt(u16);

/// The largest a one-octet length holds, and the longest label (RFC 1035 §2.3.4).
pub const narrow_most: u8 = std.math.maxInt(u8);
pub const label_most: u8 = core.limits.label_bytes_max;

/// The lengths a COOKIE option is written with: the client cookie alone, the shortest and the
/// longest long form, and one octet past the longest (RFC 7873 §4).
pub const cookie_lengths = [_]usize{
    constants.cookie_option_short_bytes,
    limits.cookie_option_long_bytes_min,
    limits.cookie_option_long_bytes_max,
    limits.cookie_option_long_bytes_max + 1,
};

/// The types a record of the lengths strategy is written in, for each field.
const name_kinds = [_]core.Kind{ .ns, .cname, .ptr };
const svcb_kinds = [_]core.Kind{ .svcb, .https };

/// A response to `example.com` whose one record holds a length field at its most, which
/// `out.most` names and `out.most_at` finds. A sixteen-bit length runs past what holds it. An
/// OPT record is written as it is. A one-octet length is in a record that is whole, or has one
/// octet changed.
pub fn write_lengths_at_most(generator: *Generator, out: *Message) void {
    const most: Most = @enumFromInt(generator.below(Most.count));
    const kind: core.Kind = switch (most) {
        .rdlength => record_kinds[generator.below(record_kinds.len)],
        .option_length, .cookie_length => .a,
        .param_length, .alpn_length => svcb_kinds[generator.below(svcb_kinds.len)],
        .string_length => .txt,
        .tag_length => .caa,
        .label_length => name_kinds[generator.below(name_kinds.len)],
    };
    const opt = most == .option_length or most == .cookie_length;
    var writer: Writer = .{ .bytes = &out.bytes };
    write_head(generator, &writer, kind, opt);
    switch (most) {
        .option_length => out.most_at = write_option_most(generator, &writer),
        .cookie_length => out.most_at = write_cookie_most(generator, &writer),
        .rdlength => {
            write_record_head(generator, &writer, kind);
            out.most_at = write_wide_most(generator, &writer);
        },
        else => {
            write_record_head(generator, &writer, kind);
            const length_at = writer.length_later();
            out.most_at = write_rdata_most(generator, &writer, most);
            writer.length_now(length_at);
        },
    }
    out.most = most;
    out.len = writer.at;
    assert(out.len <= message_bytes_max);
    if (most.wide() or opt) return;
    out.whole = generator.coin();
    const rdata_start = out.most_at;
    if (!out.whole) out.bytes[rdata_start + generator.below(out.len - rdata_start)] ^= generator.byte() | 1;
}

/// A response header, then the question for `kind`: one answer, or one additional record for an
/// OPT.
fn write_head(generator: *Generator, writer: *Writer, kind: core.Kind, opt: bool) void {
    writer.short(@truncate(generator.next()));
    writer.short(constants.flag_response);
    for ([_]u16{ 1, @intFromBool(!opt), 0, @intFromBool(opt) }) |count| writer.short(count);
    writer.slice(question_name);
    writer.short(kind.code());
    writer.short(core.constants.class_internet);
}

/// A record's owner, a pointer to the question's name, its type and class, and its TTL.
fn write_record_head(generator: *Generator, writer: *Writer, kind: core.Kind) void {
    writer.short(pointer_to(core.constants.header_bytes));
    writer.short(kind.code());
    writer.short(core.constants.class_internet);
    writer.long(@truncate(generator.next()));
}

/// A sixteen-bit length at its most, 0xFFFF or 0xFFFE, then fewer octets than it says. Returns
/// where the length is.
fn write_wide_most(generator: *Generator, writer: *Writer) usize {
    const at = writer.at;
    writer.short(wide_most - @intFromBool(generator.coin()));
    writer.noise(generator, generator.below(limits.fuzz_opaque_bytes_max + 1));
    return at;
}

/// An OPT record's fields before its rdata (RFC 6891 §6.1.2): the root, the type, a payload size
/// and a TTL of zero.
fn write_opt_head(writer: *Writer) void {
    writer.octet(0);
    writer.short(core.Kind.opt.code());
    writer.short(core.constants.udp_payload_bytes_default);
    writer.long(0);
}

/// An OPT record whose one option's length is at its most: a COOKIE option, or one of any code.
/// Returns where the option's length is.
fn write_option_most(generator: *Generator, writer: *Writer) usize {
    write_opt_head(writer);
    const length_at = writer.length_later();
    writer.short(if (generator.coin()) constants.cookie_option_code else @truncate(generator.next()));
    const at = write_wide_most(generator, writer);
    writer.length_now(length_at);
    return at;
}

/// An OPT record whose last option is a COOKIE of a length in `cookie_lengths`, so its data ends
/// where the rdata does. Half the time a Padding option of zeros comes first (RFC 7830 §3).
/// Returns where the COOKIE's length is.
fn write_cookie_most(generator: *Generator, writer: *Writer) usize {
    write_opt_head(writer);
    const length_at = writer.length_later();
    if (generator.coin()) {
        const padding = generator.below(limits.fuzz_opaque_bytes_max + 1);
        writer.short(constants.padding_option_code);
        writer.short(@intCast(padding));
        for (0..padding) |_| writer.octet(0);
    }
    writer.short(constants.cookie_option_code);
    const at = writer.at;
    const length = cookie_lengths[generator.below(cookie_lengths.len)];
    writer.short(@intCast(length));
    writer.noise(generator, length);
    writer.length_now(length_at);
    return at;
}

/// The rdata of a record whose field `most`, inside the rdata, is at its most. Returns where the
/// field is.
fn write_rdata_most(generator: *Generator, writer: *Writer, most: Most) usize {
    switch (most) {
        .param_length => {
            writer.short(@truncate(generator.next()));
            write_name(generator, writer);
            writer.short(svcb_keys[generator.below(svcb_keys.len)]);
            return write_wide_most(generator, writer);
        },
        .string_length => {
            if (generator.coin()) write_string(generator, writer, 0);
            return write_longest(generator, writer, narrow_most);
        },
        .tag_length => {
            writer.octet(generator.byte());
            const at = writer.at;
            writer.octet(narrow_most);
            write_letters(generator, writer, narrow_most);
            writer.noise(generator, generator.below(limits.fuzz_opaque_bytes_max + 1));
            return at;
        },
        .alpn_length => return write_alpn_most(generator, writer),
        .label_length => return write_labels_most(generator, writer),
        .rdlength, .option_length, .cookie_length => unreachable,
    }
}

/// A length octet of `length` and that many octets of noise. Returns where the length is.
fn write_longest(generator: *Generator, writer: *Writer, length: u8) usize {
    const at = writer.at;
    writer.octet(length);
    writer.noise(generator, length);
    return at;
}

/// An SVCB's priority and target, then its `alpn` parameter, whose first alpn-id is 255 octets.
fn write_alpn_most(generator: *Generator, writer: *Writer) usize {
    writer.short(@truncate(generator.next()));
    write_name(generator, writer);
    writer.short(constants.svcb_key_alpn);
    const length_at = writer.length_later();
    const at = write_longest(generator, writer, narrow_most);
    if (generator.coin()) write_string(generator, writer, 1);
    writer.length_now(length_at);
    return at;
}

/// A name of one to three labels of 63 letters each, and the root: 193 octets at most, under the
/// 255 a name holds (RFC 1035 §2.3.4).
fn write_labels_most(generator: *Generator, writer: *Writer) usize {
    const at = writer.at;
    for (0..1 + generator.below(limits.fuzz_labels_max)) |_| {
        writer.octet(label_most);
        write_letters(generator, writer, label_most);
    }
    writer.octet(0);
    return at;
}

// Tests.

const testing = std.testing;

test "every type is written, whole and with an octet changed, within the gate's seeds" {
    const seeds = constants.fuzz_seeds_default;
    var whole: [record_kinds.len]bool = @splat(false);
    var changed: [record_kinds.len]bool = @splat(false);
    var message: Message = .{};
    for (0..seeds) |seed| {
        if (generate_module.strategy_of(seed) != .record) continue;
        generate_module.generate(seed, &message);
        const kind_code = integer.read_u16(message.slice(), core.constants.header_bytes + question_name.len);
        const index = for (record_kinds, 0..) |kind, at| {
            if (kind.code() == kind_code) break at;
        } else unreachable;
        if (message.whole) whole[index] = true else changed[index] = true;
    }
    for (whole, changed) |was_whole, was_changed| try testing.expect(was_whole and was_changed);
}
