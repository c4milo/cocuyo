//! A DoH server's URI template, split when the engine opens a connection to the server (docs/
//! design.md §24, DoH over HTTP/3): the port the connection goes to, the name its certificate is
//! checked against, the authority each GET names, and the path's template, which the transport
//! expands for each request. RFC 3986 says what the URI is made of. The engine is the driver §22
//! left the template to.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const constants = @import("constants.zig");

/// A template split at the end of its authority.
pub const Template = struct {
    /// `host[:port]` as the template writes it: each GET's `:authority` (RFC 9114 §4.3.1).
    authority: []const u8,
    /// The host alone: the name the certificate is checked against (RFC 9110 §4.3.4).
    host: []const u8,
    /// The port the connection goes to: "establishing a QUIC connection to that address on the
    /// indicated port" (RFC 9114 §3.1), which "If the port subcomponent is empty or not given" is
    /// 443 (RFC 9110 §4.2.2).
    port: u16,
    /// The rest: the template of the path and the query, which the transport expands.
    path: []const u8,
};

/// Splits `text`, or null for a template the transport refuses.
pub fn split(text: []const u8) ?Template {
    // DoH "MUST be used with the https URI scheme" (RFC 8484 §5), and "schemes are
    // case-insensitive" (RFC 3986 §3.1).
    const scheme = "https://";
    if (text.len < scheme.len or !std.ascii.eqlIgnoreCase(text[0..scheme.len], scheme)) return null;
    const rest = text[scheme.len..];
    // The authority "is terminated by the next slash ("/"), question mark ("?"), or number sign
    // ("#") character, or by the end of the URI" (RFC 3986 §3.2). An expression ends it too: the
    // name the certificate is checked against cannot change with a query.
    const end = std.mem.indexOfAny(u8, rest, "/?#{") orelse rest.len;
    const authority = rest[0..end];
    const colon = std.mem.lastIndexOfScalar(u8, authority, ':');
    const host = host_of(authority[0 .. colon orelse authority.len]) orelse return null;
    const port = if (colon) |at| port_of(authority[at + 1 ..]) orelse return null else constants.port_https_default;
    return .{ .authority = authority, .host = host, .port = port, .path = rest[end..] };
}

/// `port = *DIGIT` (RFC 3986 §3.2.3): the default when empty, and refused when it names no port a
/// datagram can go to.
fn port_of(text: []const u8) ?u16 {
    if (text.len == 0) return constants.port_https_default;
    for (text) |octet| if (!std.ascii.isDigit(octet)) return null;
    const port = std.fmt.parseInt(u16, text, decimal) catch return null;
    return if (port == 0) null else port;
}

/// `host`, a registered name, or null: `authority = [ userinfo "@" ] host [ ":" port ]` (RFC 3986
/// §3.2).
fn host_of(host: []const u8) ?[]const u8 {
    if (host.len == 0) return null;
    // `:authority` "MUST NOT include the deprecated userinfo subcomponent" (RFC 9114 §4.3.1).
    // An IP literal, which starts with "[" (RFC 3986 §3.2.2), and pct-encoded octets fail here,
    // since a registered name the session checks holds neither.
    for (host) |octet| if (!is_unreserved(octet) and !is_sub_delim(octet)) return null;
    // "If host matches the rule for IPv4address, then it should be considered an IPv4 address
    // literal and not a reg-name" (RFC 3986 §3.2.2). The session checks a name, not an address.
    if (is_ipv4(host)) return null;
    _ = cocuyo.Name.from_text(host) catch return null;
    return host;
}

/// `IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet` (RFC 3986 §3.2.2).
fn is_ipv4(host: []const u8) bool {
    var parts = std.mem.splitScalar(u8, host, '.');
    var count: usize = 0;
    // Bounded by the host's octets: each part takes one at least, or the host is not one.
    for (0..host.len + 1) |_| {
        const part = parts.next() orelse break;
        if (!is_dec_octet(part)) return false;
        count += 1;
    }
    return count == ipv4_parts;
}

const ipv4_parts = 4;

/// `dec-octet`: 0 to 255, in decimal, with no leading zero (RFC 3986 §3.2.2).
fn is_dec_octet(part: []const u8) bool {
    if (part.len == 0 or part.len > dec_octet_digits_max) return false;
    for (part) |octet| if (!std.ascii.isDigit(octet)) return false;
    if (part.len > 1 and part[0] == '0') return false;
    const value = std.fmt.parseInt(u16, part, decimal) catch return false;
    return value <= std.math.maxInt(u8);
}

const dec_octet_digits_max = 3;
const decimal = 10;

/// `unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"` (RFC 3986 §2.3).
fn is_unreserved(octet: u8) bool {
    return std.ascii.isAlphanumeric(octet) or octet == '-' or octet == '.' or octet == '_' or octet == '~';
}

/// `sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="` (RFC 3986 §2.2).
fn is_sub_delim(octet: u8) bool {
    return std.mem.indexOfScalar(u8, "!$&'()*+,;=", octet) != null;
}

// Tests.

const testing = std.testing;

test "RFC 8484's template splits into its authority, its host, port 443 and its path" {
    // RFC 8484 §4.1.1's template.
    const template = split("https://dnsserver.example.net/dns-query{?dns}").?;
    try testing.expectEqualStrings("dnsserver.example.net", template.authority);
    try testing.expectEqualStrings("dnsserver.example.net", template.host);
    try testing.expectEqual(@as(u16, 443), template.port);
    try testing.expectEqualStrings("/dns-query{?dns}", template.path);
}

test "the scheme is https in any case, and a port stays in the authority" {
    const template = split("HTTPS://dns.example:8443/q{?dns}").?;
    try testing.expectEqualStrings("dns.example:8443", template.authority);
    try testing.expectEqualStrings("dns.example", template.host);
    try testing.expectEqual(@as(u16, 8443), template.port);
    try testing.expectEqualStrings("/q{?dns}", template.path);
    // An empty port is the default (RFC 9110 §4.2.2).
    try testing.expectEqual(@as(u16, 443), split("https://dns.example:/q{?dns}").?.port);
    // An expression ends the authority.
    try testing.expectEqualStrings("dns.example", split("https://dns.example{?dns}").?.authority);
}

test "a template whose authority the session cannot check is refused" {
    const refused_splits = [_][]const u8{
        "http://dns.example/q{?dns}", // not https (RFC 8484 §5)
        "https://user@dns.example/q{?dns}", // userinfo (RFC 9114 §4.3.1)
        "https://192.0.2.1/q{?dns}", // an IPv4 address (RFC 3986 §3.2.2)
        "https://[2001:db8::1]/q{?dns}", // an IP literal
        "https://dns.example:x/q{?dns}", // a port that is not digits (§3.2.3)
        "https://dns.example:+443/q{?dns}",
        "https://dns.example:4_43/q{?dns}",
        "https://dns.example:0/q{?dns}", // no port a datagram goes to
        "https://dns.example:65536/q{?dns}",
        "https://", // no host
        "https:/dns.example/q{?dns}",
        "https://dns%2Eexample/q{?dns}", // pct-encoded octets in the name
    };
    for (refused_splits) |template| try testing.expectEqual(@as(?Template, null), split(template));
}

test "a host that is not an IPv4address by RFC 3986's grammar is a registered name" {
    // A dec-octet has no leading zero and is 255 at most (RFC 3986 §3.2.2), so neither of these is
    // an address, and each is checked as a name.
    try testing.expectEqualStrings("01.2.3.4", split("https://01.2.3.4/q{?dns}").?.host);
    try testing.expectEqualStrings("256.1.1.1", split("https://256.1.1.1/q{?dns}").?.host);
}

// The template's fuzz test: seeded, like the text parsers' gate (docs/design.md §13), and here
// because the template lives in this module. A template is built from a scheme in either case, a
// host, a port or none, and a path. Written whole, `split` must give back each part. Broken one way
// the grammar refuses, it must be refused. With one byte changed, `split` may take it or refuse
// it, and what it takes must still be a whole of its parts.

const fuzz_seeds = 4096;
const fuzz_text_bytes = 128;
const fuzz_scheme = "https://";
const fuzz_hosts = [_][]const u8{ "dns.example", "a-b.c_d.example", "x", "resolver.example.net", "01.2.3.4", "256.1.1.1" };
const fuzz_paths = [_][]const u8{ "/dns-query{?dns}", "{?dns}", "/q?dns={dns}", "", "#frag", "/" };

const FuzzMiss = enum { scheme_http, userinfo, ipv4_host, ip_literal, port_zero, port_past, port_letter, empty_host, empty_label };

const Fuzz = struct {
    word: u64,

    fn next(self: *Fuzz) u64 {
        self.word = cocuyo.core.mix.next(self.word);
        return self.word;
    }

    fn below(self: *Fuzz, bound: usize) usize {
        return @intCast(self.next() % bound);
    }

    fn coin(self: *Fuzz) bool {
        return self.next() & 1 == 1;
    }

    fn pick(self: *Fuzz, comptime Choice: type) Choice {
        return @enumFromInt(self.below(@typeInfo(Choice).@"enum".fields.len));
    }
};

const FuzzShape = enum { whole, changed, near_miss };
const FuzzPort = enum { none, empty, given };

const Built = struct {
    bytes: [fuzz_text_bytes]u8 = undefined,
    len: usize = 0,
    host: []const u8 = "",
    port: u16 = constants.port_https_default,
    path: []const u8 = "",

    fn put(self: *Built, part: []const u8) void {
        @memcpy(self.bytes[self.len..][0..part.len], part);
        self.len += part.len;
    }

    fn put_port(self: *Built, port: u64) void {
        self.len += (std.fmt.bufPrint(self.bytes[self.len..], ":{d}", .{port}) catch unreachable).len;
    }

    fn text(self: *const Built) []const u8 {
        return self.bytes[0..self.len];
    }
};

fn fuzz_whole(fuzz: *Fuzz, built: *Built) void {
    built.put(if (fuzz.coin()) fuzz_scheme else "HtTpS://");
    built.host = fuzz_hosts[fuzz.below(fuzz_hosts.len)];
    built.put(built.host);
    switch (fuzz.pick(FuzzPort)) {
        .none => {},
        .empty => built.put(":"),
        .given => {
            built.port = @intCast(1 + fuzz.below(std.math.maxInt(u16)));
            built.put_port(built.port);
        },
    }
    built.path = fuzz_paths[fuzz.below(fuzz_paths.len)];
    built.put(built.path);
}

fn fuzz_miss(fuzz: *Fuzz, built: *Built) void {
    const miss = fuzz.pick(FuzzMiss);
    built.put(if (miss == .scheme_http) "http://" else fuzz_scheme);
    switch (miss) {
        .userinfo => built.put("user@dns.example"),
        .ipv4_host => built.put("192.0.2.1"),
        .ip_literal => built.put("[2001:db8::1]"),
        .empty_host => {},
        .empty_label => built.put("dns..example"),
        else => built.put(fuzz_hosts[fuzz.below(fuzz_hosts.len)]),
    }
    switch (miss) {
        .port_zero => built.put(":0"),
        .port_past => built.put_port(@as(u64, std.math.maxInt(u16)) + 1 + fuzz.below(std.math.maxInt(u16))),
        .port_letter => built.put(":44a"),
        else => {},
    }
    built.put(fuzz_paths[fuzz.below(fuzz_paths.len)]);
}

/// What a template `split` took must still be its parts: the authority and the path are the text
/// after the scheme, the host starts the authority, and the port is one a datagram can go to.
fn fuzz_whole_again(written: []const u8, template: Template) bool {
    return fuzz_scheme.len + template.authority.len + template.path.len == written.len and
        std.mem.startsWith(u8, template.authority, template.host) and template.port != 0;
}

test "templates split into their parts, near misses are refused, and a changed byte panics nothing" {
    for (0..fuzz_seeds) |seed| {
        var fuzz: Fuzz = .{ .word = seed };
        var built: Built = .{};
        switch (fuzz.pick(FuzzShape)) {
            .whole => {
                fuzz_whole(&fuzz, &built);
                const template = split(built.text()) orelse return error.TestUnexpectedResult;
                try testing.expectEqualStrings(built.host, template.host);
                try testing.expectEqual(built.port, template.port);
                try testing.expectEqualStrings(built.path, template.path);
                try testing.expect(fuzz_whole_again(built.text(), template));
            },
            .changed => {
                fuzz_whole(&fuzz, &built);
                built.bytes[fuzz.below(built.len)] +%= @intCast(1 + fuzz.below(std.math.maxInt(u8)));
                if (split(built.text())) |template| try testing.expect(fuzz_whole_again(built.text(), template));
            },
            .near_miss => {
                fuzz_miss(&fuzz, &built);
                try testing.expectEqual(@as(?Template, null), split(built.text()));
            },
        }
    }
}
