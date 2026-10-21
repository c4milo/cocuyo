//! A DoH request as colibri's request and response, and an exchange's end as the engine reads it
//! (docs/design.md §24, rules 21 and 22): a GET whose path carries the query in `dns` (RFC 8484
//! §4.1), with the field lines request rule 12 asks for, and a response whose content is a DNS
//! message in no content coding, with its `Age` (RFC 8484 §5.1). Split from `io_doh_channel.zig`.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const client = @import("client");
const doh = @import("doh");
const constants = @import("io_doh_channel_constants.zig");

/// What an exchange's end gives the engine: a DNS message and its `Age` in seconds.
pub const Answer = struct { message: []const u8, age_seconds: u32 };

/// How an exchange ended: its answer, or the reason its request failed, which the lookup keeps as
/// its cause (docs/design.md §5, The cause of a failure; §16 decision 51).
pub const Outcome = union(enum) { answer: Answer, failed: cocuyo.Reason };

/// The GET's own field lines: a DNS message is what it accepts (RFC 8484 §4.1), and "identity" asks
/// for no content coding (RFC 9110 §12.5.3, request rule 12).
const fields = [_]client.Field{
    .{ .name = "accept", .value = "application/dns-message" },
    .{ .name = "accept-encoding", .value = "identity" },
};

/// The response fields the engine reads, and where each is in a response's `wanted`.
const wanted_names = [_][]const u8{ "content-type", "content-encoding", "age" };
const content_type_at = 0;
const content_encoding_at = 1;
const age_at = 2;

/// A request's place on the channel. It holds the request and the response that colibri holds from
/// `request` until the exchange ends, the engine's request slot, and colibri's id for the exchange.
/// It also holds the memory the two name: the GET's path, the values wanted, and the answer buffer.
pub const Exchange = struct {
    live: bool = false,
    /// Whether a connection of the channel came up while the exchange was live, and whether a
    /// server took part in one: a TCP link that connected, or a QUIC datagram that came. colibri
    /// does not say which connection an exchange's end came from, so its reason rests on these
    /// (docs/design.md §5, The cause of a failure; §16 decision 51).
    up: bool = false,
    heard: bool = false,
    index: u16 = 0,
    id: client.Id = 0,
    request: client.Request = undefined,
    response: client.Response = undefined,
    path: [doh.constants.doh_request_bytes_max]u8 = undefined,
    wanted: [wanted_names.len]client.Wanted = undefined,
    values: [constants.values_bytes]u8 = undefined,
    answer: [cocuyo.constants.message_bytes_max]u8 = undefined,
};

/// Whether the template's path, expanded with a `dns` value at its longest, fits a GET's path: the
/// check a channel makes at its start, so every request's expansion fits after it.
pub fn fits(template_path: []const u8) bool {
    var longest: [cocuyo.wire.constants.dns_variable_bytes_max]u8 = @splat('A');
    var path: [doh.constants.doh_request_bytes_max]u8 = undefined;
    return doh.template.expand(template_path, &longest, &path) != null;
}

/// Makes `slot` the GET for `message`, a query without its prefix, for request slot `index`, with
/// the response colibri writes. The path carries the query in `dns` (RFC 8484 §4.1), and never
/// goes into a compression table: a table that indexed it would let the query be probed through
/// what compresses (RFC 7541 §7.1.3, RFC 9204 §7.1.3, request rule 12).
pub fn make(slot: *Exchange, index: u16, template_path: []const u8, message: []const u8) void {
    assert(!slot.live);
    var variable: [cocuyo.wire.constants.dns_variable_bytes_max]u8 = undefined;
    const dns = cocuyo.wire.doh.dns_variable(message, &variable);
    // `fits` expanded the template with a longer value when the channel started, so this one fits.
    const path = doh.template.expand(template_path, dns, &slot.path) orelse unreachable;
    for (&slot.wanted, wanted_names) |*wanted, name| wanted.* = .{ .name = name };
    slot.request = .{
        .method = "GET",
        .path = path,
        .fields = &fields,
        .never_indexed = .{ .path = true },
    };
    slot.response = .{
        .wanted = &slot.wanted,
        .values = &slot.values,
        .body = &slot.answer,
    };
    slot.index = index;
    assert(slot.request.path.len > 0);
    assert(slot.response.outcome == .pending);
}

/// How an exchange ended, as the engine reads it: its answer, or the reason its request failed. A
/// whole response that holds no DNS message is `status`: the server answered with HTTP that the
/// engine cannot read as DNS. Every other end has the reason of colibri's outcome, and of what the
/// channel's connections did while the exchange was live (docs/design.md §5, The cause of a
/// failure).
pub fn outcome_of(slot: *const Exchange) Outcome {
    const outcome = slot.response.outcome;
    // An exchange ends once, and colibri says how before it says that it ended.
    assert(outcome != .pending);
    if (outcome != .response) return .{ .failed = reason_of(outcome, slot.up, slot.heard) };
    // A whole response came over a connection that came up.
    assert(slot.up);
    const answer = answer_of(slot) orelse return .{ .failed = .status };
    return .{ .answer = answer };
}

/// The reason of an end that is not a whole response (rule 22). `up` says whether a connection of
/// the channel came up while the exchange was live, and `heard` whether a server took part in one.
fn reason_of(outcome: client.Outcome, up: bool, heard: bool) cocuyo.Reason {
    // A reset, or a response that colibri refused, needs a stream on a connection that came up.
    assert(up or outcome == .refused or outcome == .closed or outcome == .invalid);
    // colibri gave up on it: no connection came up, and each one that the channel tried failed. A
    // server that took part refused the handshake, and with none the connect failed.
    if (!up and (outcome == .refused or outcome == .closed)) return if (heard) .handshake else .connect;
    return switch (outcome) {
        .pending, .response => unreachable,
        // The server processed none of the request: it refused the stream (RFC 9113 §8.7), a
        // GOAWAY left it unprocessed (RFC 9113 §6.8), or an HTTP/1.1 connection closed before the
        // request went out.
        .refused => .reset,
        // The server reset the stream (RFC 9113 §6.4).
        .reset => .reset,
        // A connection that came up ended before the response was whole.
        .closed => .closed,
        // colibri refused the response: its protocol's rules make it malformed (RFC 9113 §8.1.1),
        // or it did not fit the memory the engine gave. Content past 65,535 octets is no DNS
        // message (RFC 8484 §6).
        .malformed, .too_large => .status,
        // A request that the protocol refuses to send: no server took part.
        .invalid => .local,
    };
}

/// What an ended exchange gives the engine: its answer, or null for a failed request. "A successful
/// HTTP response with a 2xx status code ... is used for any valid DNS response", and "HTTP responses
/// with non-successful HTTP status codes do not contain replies to the original DNS question" (RFC
/// 8484 §4.2.1). Content that is not a DNS message, or was coded, is none either (request rule 12),
/// and so is every end that is not a whole response (rule 22). The TTLs are lowered by the `Age`
/// (RFC 8484 §5.1), which the lookup does.
fn answer_of(slot: *const Exchange) ?Answer {
    const response = &slot.response;
    if (response.outcome != .response) return null;
    if (response.status < constants.status_success_first or response.status > constants.status_success_last) return null;
    if (!doh.response.is_dns_message(slot.wanted[content_type_at].value)) return null;
    if (slot.wanted[content_encoding_at].value) |coding| {
        if (!doh.response.is_identity(coding)) return null;
    }
    assert(response.body_len <= slot.answer.len);
    return .{ .message = response.content_received(), .age_seconds = doh.response.age_seconds(slot.wanted[age_at].value) };
}

// Tests. The ends of a whole response are `io_doh_channel_test.zig`'s, over colibri's server.

const testing = std.testing;

test "each end of colibri's that is not a whole response gives its reason" {
    // docs/design.md §5, The cause of a failure: once a connection came up.
    try testing.expectEqual(cocuyo.Reason.reset, reason_of(.reset, true, true));
    try testing.expectEqual(cocuyo.Reason.reset, reason_of(.refused, true, true));
    try testing.expectEqual(cocuyo.Reason.closed, reason_of(.closed, true, true));
    try testing.expectEqual(cocuyo.Reason.status, reason_of(.malformed, true, true));
    try testing.expectEqual(cocuyo.Reason.status, reason_of(.too_large, true, true));
    try testing.expectEqual(cocuyo.Reason.local, reason_of(.invalid, true, true));
    // With no connection up: a handshake when a server took part, a connect when none did.
    for ([_]client.Outcome{ .refused, .closed }) |outcome| {
        try testing.expectEqual(cocuyo.Reason.handshake, reason_of(outcome, false, true));
        try testing.expectEqual(cocuyo.Reason.connect, reason_of(outcome, false, false));
    }
    try testing.expectEqual(cocuyo.Reason.local, reason_of(.invalid, false, false));
}
