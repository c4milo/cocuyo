//! A DoH request as colibri's exchange, and an exchange's end as the engine reads it (docs/design.md
//! §24, rules 21 and 22): a GET whose path carries the query in `dns` (RFC 8484 §4.1), with the
//! field lines request rule 12 asks for, and a response whose content is a DNS message in no
//! content coding, with its `Age` (RFC 8484 §5.1). Split from `io_doh_channel.zig`.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const client = @import("client");
const doh = @import("doh");
const constants = @import("io_doh_channel_constants.zig");

/// What an exchange's end gives the engine: a DNS message and its `Age` in seconds.
pub const Answer = struct { message: []const u8, age_seconds: u32 };

/// The GET's own field lines: a DNS message is what it accepts (RFC 8484 §4.1), and "identity" asks
/// for no content coding (RFC 9110 §12.5.3, request rule 12).
const fields = [_]client.Field{
    .{ .name = "accept", .value = "application/dns-message" },
    .{ .name = "accept-encoding", .value = "identity" },
};

/// The response fields the engine reads, and where each is in an exchange's `wanted`.
const wanted_names = [_][]const u8{ "content-type", "content-encoding", "age" };
const content_type_at = 0;
const content_encoding_at = 1;
const age_at = 2;

/// A request's place on the channel: the exchange colibri holds from `request` until its end, the
/// request slot of the engine's it carries, colibri's id for it, and the memory the exchange names:
/// the GET's path, the values of the fields wanted, and the answer buffer.
pub const Exchange = struct {
    live: bool = false,
    index: u16 = 0,
    id: client.Id = 0,
    exchange: client.HttpExchange = undefined,
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

/// Makes `slot` the GET for `message`, a query without its prefix, for request slot `index`, and
/// returns the exchange colibri takes. The path carries the query in `dns` (RFC 8484 §4.1), and
/// never goes into a compression table: a table that indexed it would let the query be probed
/// through what compresses (RFC 7541 §7.1.3, RFC 9204 §7.1.3, request rule 12).
pub fn make(slot: *Exchange, index: u16, template_path: []const u8, message: []const u8) *client.HttpExchange {
    assert(!slot.live);
    var variable: [cocuyo.wire.constants.dns_variable_bytes_max]u8 = undefined;
    const dns = cocuyo.wire.doh.dns_variable(message, &variable);
    // `fits` expanded the template with a longer value when the channel started, so this one fits.
    const path = doh.template.expand(template_path, dns, &slot.path) orelse unreachable;
    for (&slot.wanted, wanted_names) |*wanted, name| wanted.* = .{ .name = name };
    slot.exchange = .{
        .method = "GET",
        .path = path,
        .fields = &fields,
        .never_indexed = .{ .path = true },
        .wanted = &slot.wanted,
        .values = &slot.values,
        .body = &slot.answer,
    };
    slot.index = index;
    assert(slot.exchange.path.len > 0);
    return &slot.exchange;
}

/// What an ended exchange gives the engine: its answer, or null for a failed request. "A successful
/// HTTP response with a 2xx status code ... is used for any valid DNS response", and "HTTP responses
/// with non-successful HTTP status codes do not contain replies to the original DNS question" (RFC
/// 8484 §4.2.1). Content that is not a DNS message, or was coded, is none either (request rule 12),
/// and so is every end that is not a whole response (rule 22). The TTLs are lowered by the `Age`
/// (RFC 8484 §5.1), which the lookup does.
pub fn answer_of(slot: *const Exchange) ?Answer {
    const exchange = &slot.exchange;
    if (exchange.outcome != .response) return null;
    if (exchange.status < constants.status_success_first or exchange.status > constants.status_success_last) return null;
    if (!doh.response.is_dns_message(slot.wanted[content_type_at].value)) return null;
    if (slot.wanted[content_encoding_at].value) |coding| {
        if (!doh.response.is_identity(coding)) return null;
    }
    assert(exchange.body_len <= slot.answer.len);
    return .{ .message = exchange.content_received(), .age_seconds = doh.response.age_seconds(slot.wanted[age_at].value) };
}
