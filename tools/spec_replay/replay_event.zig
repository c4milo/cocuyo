//! The events of the lookup's transcript, as the replay spells them, and what each hands the
//! lookup (spec/lean/Spec/Tokens.lean). Split from `replay.zig` by the file-length rule.
const std = @import("std");
const core = @import("core");
const resolver = @import("resolver");
const fixtures = @import("fixtures.zig");

/// What the caller tells a lookup: the model's `Event`, spelt as the transcript spells it.
pub const Event = enum {
    init,
    poll,
    expire,
    sent,
    send_failed,
    tcp_connected,
    // A failed connection or request and its reason (docs/design.md §16 decision 51). A stream
    // never takes `status` or `reset`.
    tcp_failed_connect,
    tcp_failed_handshake,
    tcp_failed_local,
    tcp_failed_closed,
    request_failed_connect,
    request_failed_handshake,
    request_failed_local,
    request_failed_closed,
    request_failed_status,
    request_failed_reset,
    cancel,
    reply_unmatched,
    reply_answer,
    reply_cname,
    reply_nxdomain,
    reply_nodata,
    reply_yxdomain,
    reply_servfail,
    reply_formerr,
    reply_truncated,
    reply_badcookie,
    // A message with AD set, of a kind the lookup acts on (docs/design.md §25, Stage A).
    reply_ad_answer,
    reply_ad_cname,
    reply_ad_nxdomain,
    reply_ad_nodata,
    reply_ad_truncated,
    // A message the lookup acts on, and the validator's verdict on it (docs/design.md §25, step
    // 11), then how the walk for its keys ended.
    reply_secure_answer,
    reply_secure_cname,
    reply_secure_nxdomain,
    reply_secure_nodata,
    reply_secure_truncated,
    reply_insecure_answer,
    reply_insecure_cname,
    reply_insecure_nxdomain,
    reply_insecure_nodata,
    reply_insecure_truncated,
    reply_bogus_answer,
    reply_bogus_cname,
    reply_bogus_nxdomain,
    reply_bogus_nodata,
    reply_bogus_truncated,
    reply_keys_wanted_answer,
    reply_keys_wanted_cname,
    reply_keys_wanted_nxdomain,
    reply_keys_wanted_nodata,
    reply_keys_wanted_truncated,
    keys_ready,
    keys_failed_bogus,
    keys_failed_timeout,
    keys_failed_failed,
};

/// The reason a failed connection or request carries: the last word of its event's name.
pub fn reason_of(event: Event) resolver.Reason {
    const name = @tagName(event);
    const at = std.mem.lastIndexOfScalar(u8, name, '_') orelse unreachable;
    return std.meta.stringToEnum(resolver.Reason, name[at + 1 ..]) orelse unreachable;
}

/// The verdict a checked reply's event names: its second word.
pub fn verdict_of(event: Event) ?[]const u8 {
    const name = @tagName(event);
    for ([_][]const u8{ "secure", "insecure", "bogus", "keys_wanted" }) |verdict| {
        if (std.mem.startsWith(u8, name["reply_".len..], verdict) and name.len > "reply_".len + verdict.len and
            name["reply_".len + verdict.len] == '_' and checked_reply(name["reply_".len + verdict.len + 1 ..]) != null)
            return verdict;
    }
    return null;
}

fn checked_reply(word: []const u8) ?fixtures.Reply {
    return std.meta.stringToEnum(fixtures.Reply, word);
}

/// The reply a checked reply's event names: its last word.
pub fn checked_reply_of(event: Event) fixtures.Reply {
    const name = @tagName(event);
    const verdict = verdict_of(event).?;
    return checked_reply(name["reply_".len + verdict.len + 1 ..]).?;
}

/// What the validator says of `reply` under `verdict`: a secure message ends as the model's reply
/// means it to, the proof giving the negative (docs/design.md §25 item 13).
pub fn validation_of(verdict: []const u8, reply: fixtures.Reply) core.Validation {
    if (std.mem.eql(u8, verdict, "insecure")) return .insecure;
    if (std.mem.eql(u8, verdict, "bogus")) return .{ .bogus = .signature };
    if (std.mem.eql(u8, verdict, "keys_wanted")) return .{ .keys_wanted = core.Name.root };
    const ending: core.validation.Ending = switch (reply) {
        .answer => .answer,
        .cname => .alias,
        .nxdomain => .name_error,
        .nodata, .truncated => .no_data,
        else => unreachable,
    };
    return .{ .secure = .{ .ending = ending, .ttl_seconds = std.math.maxInt(u32) } };
}

/// Whether a reply's message has AD set: the model's `replyAd`.
pub fn authentic_of(event: Event) bool {
    return std.mem.startsWith(u8, @tagName(event), "reply_ad_");
}

pub fn reply_of(event: Event) fixtures.Reply {
    return switch (event) {
        .reply_ad_answer => .answer,
        .reply_ad_cname => .cname,
        .reply_ad_nxdomain => .nxdomain,
        .reply_ad_nodata => .nodata,
        .reply_ad_truncated => .truncated,
        .reply_unmatched => .unmatched,
        .reply_answer => .answer,
        .reply_cname => .cname,
        .reply_nxdomain => .nxdomain,
        .reply_nodata => .nodata,
        .reply_yxdomain => .yxdomain,
        .reply_servfail => .servfail,
        .reply_formerr => .formerr,
        .reply_truncated => .truncated,
        .reply_badcookie => .badcookie,
        else => unreachable,
    };
}
