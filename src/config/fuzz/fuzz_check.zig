//! What the text fuzz target checks about a text (`fuzz.zig`). The parser the text was built for
//! runs over it, and what is checked is that whatever it did, it did within its promises:
//!
//! - It reads nothing outside the text and trips no assertion. Zig's bounds checks and cocuyo's
//!   assertions stay on in every build, so either is a panic the gate reports.
//! - It reads the same text the same way twice.
//! - What it takes, it gives back. An accepted name written out reads back as itself, and an
//!   accepted pin encodes to the text it was read from, since a pin has one spelling (spki_pin.zig).
//!   An address with a colon is IPv6, and one without is IPv4.
//! - A text written whole reads back as written: the address, the name, a `resolv.conf`'s servers
//!   and search list in order, each hosts line's address and name, the pin.
//! - A near miss is refused, and a file with one bad line gives the rest as if it were not there.
//!
//! A check returns the name of the promise that broke, so the gate can print the seed.
const std = @import("std");
const core = @import("core");
const resolv_conf = @import("../resolv_conf.zig");
const hosts_parser = @import("../hosts.zig");
const spki_pin = @import("../spki_pin.zig");
const generate = @import("fuzz_generate.zig");
const Text = generate.Text;

/// The memory the file parsers fill, twice over so a text is read twice apart. The gate holds it,
/// so a seed does not build it anew.
pub const Scratch = struct {
    resolv_conf: resolv_conf.Storage = .{},
    resolv_conf_again: resolv_conf.Storage = .{},
    hosts: hosts_parser.Storage = .{},
    hosts_again: hosts_parser.Storage = .{},
};

pub fn check(text: *const Text, scratch: *Scratch) ?[]const u8 {
    return switch (text.target) {
        .address => check_address(text),
        .name => check_name(text),
        .resolv_conf => check_resolv_conf(text, scratch),
        .hosts => check_hosts(text, scratch),
        .pin => check_pin(text),
    };
}

fn check_address(text: *const Text) ?[]const u8 {
    const parsed = core.Address.from_text(text.slice());
    const again = core.Address.from_text(text.slice());
    if ((parsed == null) != (again == null)) return "an address reads the same twice";
    if (parsed) |address| {
        if (!address.equal(&again.?)) return "an address reads the same twice";
        const colon = std.mem.indexOfScalar(u8, text.slice(), ':') != null;
        if ((address.family == .ipv6) != colon) return "an address with a colon is IPv6, and one without IPv4";
    }
    switch (text.shape) {
        .whole => {
            const address = parsed orelse return "an address written whole is read";
            if (!address.equal(&text.expected.addresses[0])) return "an address written whole reads back as written";
        },
        .near_miss => if (parsed != null) return "an address the grammar refuses is refused",
        .changed, .noise => {},
    }
    return null;
}

fn check_name(text: *const Text) ?[]const u8 {
    const parsed: ?core.Name = core.Name.from_text(text.slice()) catch null;
    const again: ?core.Name = core.Name.from_text(text.slice()) catch null;
    if ((parsed == null) != (again == null)) return "a name reads the same twice";
    if (parsed) |name| {
        if (!std.mem.eql(u8, name.wire(), again.?.wire())) return "a name reads the same twice";
        if (round_trip(&name)) |failure| return failure;
    }
    switch (text.shape) {
        .whole => {
            const name = parsed orelse return "a name written whole is read";
            if (!std.mem.eql(u8, name.wire(), text.expected.names[0].wire())) return "a name written whole reads back as written";
        },
        .near_miss => if (parsed != null) return "a name the grammar refuses is refused",
        .changed, .noise => {},
    }
    return null;
}

/// An accepted name, written out as text, reads back as itself.
fn round_trip(name: *const core.Name) ?[]const u8 {
    var buffer: [core.constants.name_text_bytes_max]u8 = undefined;
    const written = name.write_text(&buffer);
    const again = core.Name.from_text(buffer[0..written]) catch return "a name written out reads back";
    if (!std.mem.eql(u8, again.wire(), name.wire())) return "a name written out reads back as itself";
    return null;
}

fn check_resolv_conf(text: *const Text, scratch: *Scratch) ?[]const u8 {
    const config = resolv_conf.parse(text.slice(), &scratch.resolv_conf);
    const again = resolv_conf.parse(text.slice(), &scratch.resolv_conf_again);
    if (!same_config(&config, &again)) return "a resolv.conf reads the same twice";
    // A file that names no server means the local one (resolv_conf.zig).
    if (config.servers.len == 0) return "a resolv.conf gives a server";
    return switch (text.shape) {
        .whole, .near_miss => expect_config(text, &config),
        .changed, .noise => null,
    };
}

fn same_config(one: *const core.Config, other: *const core.Config) bool {
    if (one.servers.len != other.servers.len or one.search.len != other.search.len) return false;
    for (one.servers, other.servers) |a, b| {
        if (!a.endpoint.equal(&b.endpoint)) return false;
    }
    for (one.search, other.search) |a, b| {
        if (!std.mem.eql(u8, a.wire(), b.wire())) return false;
    }
    return one.ndots == other.ndots and one.attempts == other.attempts and
        one.timeout_ns == other.timeout_ns and one.rotate == other.rotate and one.use_tcp == other.use_tcp;
}

fn expect_config(text: *const Text, config: *const core.Config) ?[]const u8 {
    const expected = &text.expected;
    if (config.servers.len != expected.address_count) return "a resolv.conf gives every server written, and no other";
    for (config.servers, expected.addresses[0..expected.address_count]) |server, address| {
        if (!server.endpoint.address.equal(&address)) return "a resolv.conf gives each server as written, in order";
    }
    if (config.search.len != expected.name_count) return "a resolv.conf gives the search list written";
    for (config.search, expected.names[0..expected.name_count]) |name, written| {
        if (!std.mem.eql(u8, name.wire(), written.wire())) return "a resolv.conf gives each search name as written";
    }
    return null;
}

fn check_hosts(text: *const Text, scratch: *Scratch) ?[]const u8 {
    const table = hosts_parser.parse(text.slice(), &scratch.hosts);
    const again = hosts_parser.parse(text.slice(), &scratch.hosts_again);
    if (table.entries.len != again.entries.len or !std.mem.eql(u8, table.names, again.names)) {
        return "a hosts file reads the same twice";
    }
    for (table.entries) |*entry| {
        if (entry_failure(&table, entry)) |failure| return failure;
    }
    return switch (text.shape) {
        .whole, .near_miss => expect_hosts(text, &table),
        .changed, .noise => null,
    };
}

/// Every entry names at least one name, and each is a whole wire name inside the table's arena.
fn entry_failure(table: *const hosts_parser.Hosts, entry: *const hosts_parser.Entry) ?[]const u8 {
    if (entry.name_count == 0) return "a hosts line gives a name";
    for (entry.names[0..entry.name_count]) |ref| {
        if (@as(usize, ref.offset) + ref.len > table.names.len) return "a hosts name lies inside the table";
        if (!is_wire_name(table.names[ref.offset..][0..ref.len])) return "a hosts name is a name";
    }
    return null;
}

/// Labels of one to 63 octets, then the root octet, and nothing after it (RFC 1035 §3.1).
fn is_wire_name(bytes: []const u8) bool {
    var at: usize = 0;
    for (0..bytes.len) |_| {
        if (at >= bytes.len) return false;
        const length = bytes[at];
        if (length == 0) return at + 1 == bytes.len;
        if (length > core.constants.label_bytes_max) return false;
        at += 1 + length;
    }
    return false;
}

fn expect_hosts(text: *const Text, table: *const hosts_parser.Hosts) ?[]const u8 {
    const expected = &text.expected;
    if (table.entries.len != expected.address_count) return "a hosts file gives every line written, and no other";
    for (table.entries, 0..) |entry, index| {
        if (!entry.address.equal(&expected.addresses[index])) return "a hosts line gives its address as written";
        const first = entry.names[0];
        const name = table.names[first.offset..][0..first.len];
        if (!std.mem.eql(u8, name, expected.names[index].wire())) return "a hosts line gives its name as written";
    }
    return null;
}

fn check_pin(text: *const Text) ?[]const u8 {
    const parsed: ?core.Pin = spki_pin.from_base64(text.slice()) catch null;
    if (parsed) |pin| {
        var encoded: [pin_text_bytes]u8 = undefined;
        const spelled = std.base64.standard.Encoder.encode(&encoded, &pin);
        if (!std.mem.eql(u8, spelled, text.slice())) return "a pin has one spelling: it encodes to the text it was read from";
    }
    switch (text.shape) {
        .whole => {
            const pin = parsed orelse return "a pin written whole is read";
            if (!std.mem.eql(u8, &pin, &text.expected.pin)) return "a pin written whole reads back as written";
        },
        .near_miss => if (parsed != null) return "a pin the reader refuses is refused",
        .changed, .noise => {},
    }
    return null;
}

const pin_text_bytes = std.base64.standard.Encoder.calcSize(core.constants.spki_pin_bytes);
