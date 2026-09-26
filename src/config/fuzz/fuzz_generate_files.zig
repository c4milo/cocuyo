//! The files the text fuzz target writes (`fuzz_generate.zig`): a `resolv.conf`, a hosts file and
//! an SPKI pin. A file is written whole from servers, names and entries the generator chose, with
//! comment and blank lines between the lines that count, blanks and tabs between the fields, and
//! either line ending. Its near miss is the same file with one line whose address is broken, which
//! the parser must skip and take the rest (docs/design.md §10).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const generate = @import("fuzz_generate.zig");
const Generator = generate.Generator;
const Text = generate.Text;

/// Writes a `resolv.conf` of up to `fuzz_entries_max` nameservers, a search line now and then, and
/// an options line now and then, and records the servers and the search list it must give. With
/// `bad_line`, one nameserver line among them carries an address the grammar refuses.
pub fn write_resolv_conf(generator: *Generator, out: *Text, bad_line: bool) void {
    const servers = generator.below(constants.fuzz_entries_max + 1);
    const bad_at = if (bad_line) generator.below(servers + 1) else null;
    for (0..servers + 1) |index| {
        write_filler(generator, out);
        if (bad_at == index) write_bad_nameserver(generator, out);
        if (index == servers) break;
        out.put(constants.keyword_nameserver);
        write_blanks(generator, out);
        out.expected.add_address(generate.write_address(generator, out));
        write_line_end(generator, out);
    }
    if (servers == 0) out.expected.add_address(core.Address.from_v4(constants.nameserver_default));
    if (generator.coin()) write_search(generator, out);
    if (generator.coin()) write_options(generator, out);
    write_filler(generator, out);
}

/// `search` and one name or more: the last such line is the list (`resolv.conf(5)`).
fn write_search(generator: *Generator, out: *Text) void {
    out.put(constants.keyword_search);
    for (0..1 + generator.below(constants.fuzz_entries_max)) |_| {
        write_blanks(generator, out);
        out.expected.add_name(generate.write_name(generator, out, .host));
    }
    write_line_end(generator, out);
}

/// `options` and tokens the parser knows, each with a value inside its bounds or past them.
fn write_options(generator: *Generator, out: *Text) void {
    out.put(constants.keyword_options);
    for (0..1 + generator.below(option_names.len)) |_| {
        write_blanks(generator, out);
        const option = option_names[generator.below(option_names.len)];
        out.put(option);
        if (option[option.len - 1] == ':') out.put_decimal(generator.below(option_value_room));
    }
    write_line_end(generator, out);
}

const option_names = [_][]const u8{ "ndots:", "timeout:", "attempts:", "rotate", constants.option_use_vc, "inet6", "edns0" };
/// Values up to past every bound an option keeps, so a clamp is reached as well as the range.
const option_value_room = std.math.maxInt(u16);

fn write_bad_nameserver(generator: *Generator, out: *Text) void {
    out.put(constants.keyword_nameserver);
    write_blanks(generator, out);
    generate.write_address_near_miss(generator, out);
    write_line_end(generator, out);
}

/// Writes a hosts file of up to `fuzz_entries_max` lines, each an address, a name and an alias
/// now and then, and records each address and its first name. The names are made distinct by
/// their first label, so the check can find each one. With `bad_line`, one more line carries an
/// address the grammar refuses.
pub fn write_hosts(generator: *Generator, out: *Text, bad_line: bool) void {
    const entries = 1 + generator.below(constants.fuzz_entries_max);
    const bad_at = if (bad_line) generator.below(entries + 1) else null;
    for (0..entries + 1) |index| {
        write_filler(generator, out);
        if (bad_at == index) write_bad_host(generator, out);
        if (index == entries) break;
        write_blanks_maybe(generator, out);
        out.expected.add_address(generate.write_address(generator, out));
        write_blanks(generator, out);
        out.expected.add_name(write_host_name(generator, out, index));
        if (generator.coin()) {
            write_blanks(generator, out);
            _ = generate.write_name(generator, out, .host);
        }
        if (generator.coin()) out.put(" # a comment");
        write_line_end(generator, out);
    }
}

/// A name whose first label starts with `h` and the entry's index, then the generator's labels.
fn write_host_name(generator: *Generator, out: *Text, index: usize) core.Name {
    const start = out.len;
    out.put("h");
    out.put_decimal(index);
    out.put(".");
    _ = generate.write_name(generator, out, .host);
    return core.Name.from_text(out.bytes[start..out.len]) catch unreachable;
}

fn write_bad_host(generator: *Generator, out: *Text) void {
    generate.write_address_near_miss(generator, out);
    out.put(" bad.example");
    write_line_end(generator, out);
}

/// Comment lines, blank lines and a line of an unknown keyword, none of which counts.
fn write_filler(generator: *Generator, out: *Text) void {
    for (0..generator.below(constants.fuzz_filler_lines_max + 1)) |_| {
        out.put(filler_lines[generator.below(filler_lines.len)]);
        write_line_end(generator, out);
    }
}

const filler_lines = [_][]const u8{ "# a comment", "; another", "", " \t", "sortlist 192.0.2.0" };

fn write_blanks(generator: *Generator, out: *Text) void {
    for (0..1 + generator.below(blanks_max)) |_| out.put(if (generator.coin()) " " else "\t");
}

fn write_blanks_maybe(generator: *Generator, out: *Text) void {
    if (generator.coin()) write_blanks(generator, out);
}

const blanks_max = 3;

fn write_line_end(generator: *Generator, out: *Text) void {
    out.put(if (generator.coin()) "\n" else "\r\n");
}

/// An SPKI pin: the base64 of 32 octets the generator chose (RFC 7858 §4.2, RFC 4648 §4).
pub fn write_pin(generator: *Generator, out: *Text) void {
    for (&out.expected.pin) |*octet| octet.* = generator.byte();
    var encoded: [pin_text_bytes]u8 = undefined;
    out.put(std.base64.standard.Encoder.encode(&encoded, &out.expected.pin));
}

const pin_text_bytes = std.base64.standard.Encoder.calcSize(core.constants.spki_pin_bytes);

/// The ways a pin is broken, each one the reader refuses (spki_pin.zig).
const PinMiss = enum { short, long, url_safe, unpadded, pad_bits };

pub fn write_pin_near_miss(generator: *Generator, out: *Text) void {
    write_pin(generator, out);
    assert(out.len == pin_text_bytes);
    // The last character before the padding, whose low two bits are pad bits (RFC 4648 §3.5).
    const last = std.base64.standard_no_pad.Encoder.calcSize(core.constants.spki_pin_bytes) - 1;
    switch (@as(PinMiss, @enumFromInt(generator.below(@typeInfo(PinMiss).@"enum".fields.len)))) {
        .short => {
            std.mem.copyForwards(u8, out.bytes[0 .. out.len - 1], out.bytes[1..out.len]);
            out.len -= 1;
        },
        .long => out.put("A"),
        .url_safe => out.bytes[generator.below(last)] = if (generator.coin()) '-' else '_',
        .unpadded => out.len -= 1,
        .pad_bits => {
            const alphabet = std.base64.standard_alphabet_chars;
            const value = std.mem.indexOfScalar(u8, &alphabet, out.bytes[last]).?;
            out.bytes[last] = alphabet[value | 1];
        },
    }
}
