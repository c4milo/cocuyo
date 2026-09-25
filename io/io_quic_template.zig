//! A DoH server's URI template, split once when a connection starts and expanded for each request
//! (docs/design.md §24, DoH over HTTP/3). RFC 3986 says what the URI it expands to is made of, and
//! RFC 6570 how it expands, with `dns` the one variable defined (RFC 8484 §4.1). The engine is the
//! driver §22 left the template to.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");

/// A template split at the end of its authority.
pub const Template = struct {
    /// `host[:port]` as the template writes it: each GET's `:authority` (RFC 9114 §4.3.1).
    authority: []const u8,
    /// The host alone: the name the certificate is checked against (RFC 9110 §4.3.4).
    host: []const u8,
    /// The rest: the template of the path and the query.
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
    const host = host_of(authority) orelse return null;
    return .{ .authority = authority, .host = host, .path = rest[end..] };
}

/// The host of `authority`, a registered name, or null. `authority = [ userinfo "@" ] host [ ":"
/// port ]` and `port = *DIGIT` (RFC 3986 §3.2, §3.2.3).
fn host_of(authority: []const u8) ?[]const u8 {
    const colon = std.mem.lastIndexOfScalar(u8, authority, ':');
    const host = authority[0 .. colon orelse authority.len];
    if (colon) |at| {
        for (authority[at + 1 ..]) |octet| if (!std.ascii.isDigit(octet)) return null;
    }
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

/// Where an expansion is written, and whether it has run out of room.
const Out = struct {
    bytes: []u8,
    len: usize = 0,
    full: bool = false,

    fn put(out: *Out, text: []const u8) void {
        if (out.full or text.len > out.bytes.len - out.len) {
            out.full = true;
            return;
        }
        @memcpy(out.bytes[out.len..][0..text.len], text);
        out.len += text.len;
    }
};

/// Expands `path`, a split template's path, with `dns`, into `out`, and returns the `:path`, or
/// null for a template the transport refuses or an `out` too short. An empty path is "/" (RFC 9114
/// §4.3.1). An expansion that starts with anything but "/" or "?" would carry on the authority, and
/// is refused.
pub fn expand(path: []const u8, dns: []const u8, out: []u8) ?[]const u8 {
    assert(dns.len > 0);
    if (out.len == 0) return null;
    var writer: Out = .{ .bytes = out[1..] };
    var named = false;
    var at: usize = 0;
    // Bounded by the template: each pass takes one literal character or one expression.
    for (0..path.len) |_| {
        if (at == path.len) break;
        at = if (path[at] == '{') expression_at(path, at, dns, &writer, &named) else literal_at(path, at, &writer);
        if (at == refused) return null;
    }
    // A GET carries the query only in `dns` (RFC 8484 §4.1).
    if (writer.full or !named) return null;
    const expanded = writer.bytes[0..writer.len];
    if (expanded.len > 0 and expanded[0] == '/') return expanded;
    if (expanded.len > 0 and expanded[0] != '?') return null;
    out[0] = '/';
    return out[0 .. expanded.len + 1];
}

/// What `expression_at` and `literal_at` return for a template the transport refuses.
const refused = std.math.maxInt(usize);

/// Copies the literal character at `at`, and returns where the next one starts. A literal a URI
/// allows is copied, and one it does not is pct-encoded (RFC 6570 §3.1). A fragment is not part of
/// the request, so "#" refuses the template.
fn literal_at(path: []const u8, at: usize, out: *Out) usize {
    const octet = path[at];
    if (octet == '%') {
        // A pct-encoded triplet is copied as it is.
        if (at + pct_encoded_bytes > path.len) return refused;
        const triplet = path[at..][0..pct_encoded_bytes];
        if (!is_pct_encoded(triplet)) return refused;
        out.put(triplet);
        return at + pct_encoded_bytes;
    }
    if (octet < ascii_end) {
        if (octet == '#' or !is_literal_ascii(octet)) return refused;
        out.put(path[at..][0..1]);
        return at + 1;
    }
    return literal_unicode_at(path, at, out);
}

const pct_encoded_bytes = 3;
const ascii_end = 0x80;

/// The ASCII of `literals` (RFC 6570 §2.1): "any Unicode character except: CTL, SP, DQUOTE, "'",
/// "%" (aside from pct-encoded), "<", ">", "\", "^", "`", "{", "|", "}"". Each of these a URI
/// allows as it is.
fn is_literal_ascii(octet: u8) bool {
    if (std.ascii.isControl(octet) or octet == ' ') return false;
    return std.mem.indexOfScalar(u8, "\"'%<>\\^`{|}", octet) == null;
}

/// A character past ASCII: `ucschar` or `iprivate` (RFC 6570 §2.1), written as the pct-encoded
/// triplets of its UTF-8 (§3.1).
fn literal_unicode_at(path: []const u8, at: usize, out: *Out) usize {
    const len = std.unicode.utf8ByteSequenceLength(path[at]) catch return refused;
    if (at + len > path.len) return refused;
    const sequence = path[at..][0..len];
    const point = std.unicode.utf8Decode(sequence) catch return refused;
    if (!is_ucschar_or_iprivate(point)) return refused;
    for (sequence) |octet| {
        var triplet: [pct_encoded_bytes]u8 = undefined;
        _ = std.fmt.bufPrint(&triplet, "%{X:0>2}", .{octet}) catch unreachable;
        out.put(&triplet);
    }
    return at + len;
}

/// `ucschar` and `iprivate` (RFC 6570 §1.5): three ranges of the BMP, where `iprivate`'s
/// E000-F8FF joins `ucschar`'s F900-FDCF, and past it every plane's code points but its last two,
/// apart from the start of plane 14.
fn is_ucschar_or_iprivate(point: u21) bool {
    if (point < plane_one) {
        return within(point, bmp_first, bmp_first_last) or within(point, bmp_second, bmp_second_last) or
            within(point, bmp_third, bmp_third_last);
    }
    if (point >= plane_fourteen and point < plane_fourteen_first) return false;
    return point & plane_offset_mask <= plane_offset_max;
}

fn within(point: u21, first: u21, last: u21) bool {
    return point >= first and point <= last;
}

const plane_one = 0x10000;
const bmp_first = 0xA0;
const bmp_first_last = 0xD7FF;
const bmp_second = 0xE000;
const bmp_second_last = 0xFDCF;
const bmp_third = 0xFDF0;
const bmp_third_last = 0xFFEF;
const plane_fourteen = 0xE0000;
const plane_fourteen_first = 0xE1000;
const plane_offset_mask = 0xFFFF;
const plane_offset_max = 0xFFFD;

/// How an operator expands (RFC 6570 Appendix A's table): what goes first, what goes between two
/// defined variables, and whether a variable goes as `name=value`.
const Operator = struct { first: []const u8, separator: []const u8, named: bool };

/// The operator an expression starts with, and its length. Any other first character is a
/// varname's, and a character no varname holds refuses the template there (RFC 6570 §2.3): "#", a
/// fragment, which is not part of the request, and the operators reserved for later, "=", ",",
/// "!", "@" and "|" (§2.2).
fn operator_of(body: []const u8) struct { operator: Operator, len: usize } {
    assert(body.len > 0);
    const table = [_]struct { u8, Operator }{
        .{ '+', .{ .first = "", .separator = ",", .named = false } },
        .{ '.', .{ .first = ".", .separator = ".", .named = false } },
        .{ '/', .{ .first = "/", .separator = "/", .named = false } },
        .{ ';', .{ .first = ";", .separator = ";", .named = true } },
        .{ '?', .{ .first = "?", .separator = "&", .named = true } },
        .{ '&', .{ .first = "&", .separator = "&", .named = true } },
    };
    for (table) |entry| if (body[0] == entry[0]) return .{ .operator = entry[1], .len = 1 };
    return .{ .operator = .{ .first = "", .separator = ",", .named = false }, .len = 0 };
}

/// Expands the expression at `at`, and returns where the template goes on. Only `dns` is defined,
/// so every other variable is skipped (RFC 6570 §2.3, §3.2.1), and `dns` is written as it is: it
/// is base64url, whose every character is unreserved, which no operator encodes (§3.2.1).
fn expression_at(path: []const u8, at: usize, dns: []const u8, out: *Out, named: *bool) usize {
    const close = std.mem.indexOfScalarPos(u8, path, at, '}') orelse return refused;
    const body = path[at + 1 .. close];
    if (body.len == 0) return refused;
    const found = operator_of(body);
    var specs = std.mem.splitScalar(u8, body[found.len..], ',');
    var defined: usize = 0;
    // Bounded by the expression's octets: each variable takes one at least.
    for (0..body.len + 1) |_| {
        const spec = specs.next() orelse break;
        const variable = variable_of(spec) orelse return refused;
        if (!std.mem.eql(u8, variable.name, "dns")) continue;
        // A prefix would cut the query.
        if (variable.prefix) return refused;
        out.put(if (defined == 0) found.operator.first else found.operator.separator);
        if (found.operator.named) out.put("dns=");
        out.put(dns);
        defined += 1;
        named.* = true;
    }
    return close + 1;
}

/// A `varspec`'s name, and whether it has a prefix modifier: `varspec = varname [ modifier-level4
/// ]`, `prefix = ":" max-length`, `explode = "*"` (RFC 6570 §2.3, §2.4). Null when it is none.
fn variable_of(spec: []const u8) ?struct { name: []const u8, prefix: bool } {
    if (std.mem.endsWith(u8, spec, "*")) {
        const name = spec[0 .. spec.len - 1];
        return if (is_varname(name)) .{ .name = name, .prefix = false } else null;
    }
    const colon = std.mem.indexOfScalar(u8, spec, ':') orelse {
        return if (is_varname(spec)) .{ .name = spec, .prefix = false } else null;
    };
    const name = spec[0..colon];
    if (!is_varname(name) or !is_max_length(spec[colon + 1 ..])) return null;
    return .{ .name = name, .prefix = true };
}

/// `varname = varchar *( ["."] varchar )` (RFC 6570 §2.3): runs of varchars, one dot between two.
fn is_varname(name: []const u8) bool {
    if (name.len == 0) return false;
    var runs = std.mem.splitScalar(u8, name, '.');
    // Bounded by the name's octets: each run but the last ends at a dot.
    for (0..name.len + 1) |_| {
        const run = runs.next() orelse return true;
        if (!is_varchars(run)) return false;
    }
    return true;
}

/// One varchar or more: `varchar = ALPHA / DIGIT / "_" / pct-encoded` (RFC 6570 §2.3).
fn is_varchars(run: []const u8) bool {
    if (run.len == 0) return false;
    var at: usize = 0;
    // Bounded by the run: each pass takes one octet at least.
    for (0..run.len) |_| {
        if (at == run.len) break;
        at = varchar_end(run, at) orelse return false;
    }
    return at == run.len;
}

fn varchar_end(run: []const u8, at: usize) ?usize {
    const octet = run[at];
    if (octet != '%') return if (std.ascii.isAlphanumeric(octet) or octet == '_') at + 1 else null;
    if (at + pct_encoded_bytes > run.len or !is_pct_encoded(run[at..][0..pct_encoded_bytes])) return null;
    return at + pct_encoded_bytes;
}

/// `pct-encoded = "%" HEXDIG HEXDIG` (RFC 3986 §2.1).
fn is_pct_encoded(triplet: *const [pct_encoded_bytes]u8) bool {
    const digits = triplet[1..];
    return triplet[0] == '%' and std.ascii.isHex(digits[0]) and std.ascii.isHex(digits[1]);
}

/// `max-length = %x31-39 0*3DIGIT`, a positive integer below 10,000 (RFC 6570 §2.4.1).
fn is_max_length(text: []const u8) bool {
    if (text.len == 0 or text.len > max_length_digits_max or text[0] == '0') return false;
    for (text) |octet| if (!std.ascii.isDigit(octet)) return false;
    return true;
}

const max_length_digits_max = 4;

// Tests.

const testing = std.testing;

fn expect_path(template: []const u8, dns: []const u8, expected: []const u8) !void {
    const split_template = split(template) orelse return error.Refused;
    var out: [expanded_bytes_test]u8 = undefined;
    try testing.expectEqualStrings(expected, expand(split_template.path, dns, &out) orelse return error.Refused);
}

fn expect_refused(template: []const u8) !void {
    const split_template = split(template) orelse return;
    var out: [expanded_bytes_test]u8 = undefined;
    try testing.expectEqual(@as(?[]const u8, null), expand(split_template.path, "AAAB", &out));
}

const expanded_bytes_test = 256;

test "RFC 8484's examples expand to the authority and the path it shows" {
    // RFC 8484 §4.1.1: "https://dnsserver.example.net/dns-query{?dns}", and the GET for
    // "www.example.com".
    const template = split("https://dnsserver.example.net/dns-query{?dns}").?;
    try testing.expectEqualStrings("dnsserver.example.net", template.authority);
    try testing.expectEqualStrings("dnsserver.example.net", template.host);
    try expect_path(
        "https://dnsserver.example.net/dns-query{?dns}",
        "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB",
        "/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB",
    );
}

test "each operator puts dns where RFC 6570's table says" {
    // RFC 6570 Appendix A: first, separator, and name=value for ";", "?" and "&".
    try expect_path("https://d.example/q/{dns}", "X", "/q/X");
    try expect_path("https://d.example/q{+dns}", "X", "/qX");
    try expect_path("https://d.example/q{.dns}", "X", "/q.X");
    try expect_path("https://d.example{/dns}", "X", "/X");
    try expect_path("https://d.example/q{;dns}", "X", "/q;dns=X");
    try expect_path("https://d.example/q{?dns}", "X", "/q?dns=X");
    try expect_path("https://d.example/q?a=1{&dns}", "X", "/q?a=1&dns=X");
    // Undefined variables are skipped, and a second defined one takes the separator (§3.2.1).
    try expect_path("https://d.example/q{?other,dns}", "X", "/q?dns=X");
    try expect_path("https://d.example/q{?dns,dns}", "X", "/q?dns=X&dns=X");
    // An explode changes nothing for a string (§2.4.2).
    try expect_path("https://d.example/q{?dns*}", "X", "/q?dns=X");
    // An empty path is "/" (RFC 9114 §4.3.1).
    try expect_path("https://d.example{?dns}", "X", "/?dns=X");
}

test "a literal a URI does not allow is pct-encoded, and one it does is copied" {
    // RFC 6570 §3.1: a character outside ASCII goes as the triplets of its UTF-8.
    try expect_path("https://d.example/caf\xc3\xa9{?dns}", "X", "/caf%C3%A9?dns=X");
    try expect_path("https://d.example/a%2Fb{?dns}", "X", "/a%2Fb?dns=X");
}

test "the scheme is https in any case, and a port stays in the authority" {
    const template = split("HTTPS://dns.example:8443/q{?dns}").?;
    try testing.expectEqualStrings("dns.example:8443", template.authority);
    try testing.expectEqualStrings("dns.example", template.host);
    try testing.expectEqualStrings("/q{?dns}", template.path);
}

test "a template whose authority the session cannot check is refused" {
    const refused_splits = [_][]const u8{
        "http://dns.example/q{?dns}", // not https (RFC 8484 §5)
        "https://user@dns.example/q{?dns}", // userinfo (RFC 9114 §4.3.1)
        "https://192.0.2.1/q{?dns}", // an IPv4 address (RFC 3986 §3.2.2)
        "https://[2001:db8::1]/q{?dns}", // an IP literal
        "https://dns.example:x/q{?dns}", // a port that is not digits (§3.2.3)
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

test "a template that cannot carry the query, or carries on the authority, is refused" {
    try expect_refused("https://d.example/q{?other}"); // no dns (RFC 8484 §4.1)
    try expect_refused("https://d.example/q{?DNS}"); // names are case-sensitive (RFC 6570 §2.3)
    try expect_refused("https://d.example/q{?dns:3}"); // a prefix cuts the query
    try expect_refused("https://d.example/q{#dns}"); // a fragment is not sent
    try expect_refused("https://d.example/q#f{?dns}");
    try expect_refused("https://d.example/q{=dns}"); // reserved operators (§2.2)
    try expect_refused("https://d.example/q{?dns");
    try expect_refused("https://d.example/q{}{?dns}");
    try expect_refused("https://d.example/q{?d-ns,dns}"); // "-" is no varchar (§2.3)
    try expect_refused("https://d.example/q<{?dns}"); // a character literals exclude (§2.1)
    try expect_refused("https://d.example/q%zz{?dns}"); // "%" is only a pct-encoded triplet's
    try expect_refused("https://d.example/q%2{?dns}");
    try expect_refused("https://d.example{dns}"); // it would carry on the authority
    try expect_refused("https://d.example{&dns}");
}

test "an expansion longer than its buffer is refused" {
    const template = split("https://d.example/dns-query{?dns}").?;
    var out: [8]u8 = undefined;
    try testing.expectEqual(@as(?[]const u8, null), expand(template.path, "AAAAAAAAAAAA", &out));
}
