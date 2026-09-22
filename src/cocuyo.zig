//! cocuyo: a DNS resolver library. It builds query bytes and parses response bytes, and owns no
//! socket, no file descriptor, no thread, no timer and no allocator. The caller does the sending
//! and the receiving; cocuyo says what to do next.
//!
//! This file is the public surface and holds no logic: each module of docs/design.md §2 is
//! re-exported here, and the names a consumer reaches for are flattened alongside them as each
//! step of §15 lands them.
pub const core = @import("core");
pub const wire = @import("wire");
pub const resolver = @import("resolver");
pub const resolv_conf = @import("config");
pub const cache = @import("cache");

// The names a consumer reaches for, flattened. Everything else is behind the module it belongs to.
pub const Address = core.Address;
pub const Endpoint = core.Endpoint;
pub const Family = core.Family;
pub const Name = core.Name;
pub const Kind = core.Kind;
pub const Question = core.Question;
pub const Config = core.Config;
pub const Error = core.Error;
pub const constants = core.constants;

pub const Lookup = resolver.Lookup;
pub const Resolver = resolver.Resolver;
pub const Action = resolver.Action;
pub const Answer = resolver.Answer;
pub const Failure = resolver.Failure;
pub const Verdict = resolver.Verdict;
pub const Handle = resolver.Handle;
pub const Slot = resolver.Slot;
pub const MatchKey = resolver.MatchKey;
pub const Event = resolver.Event;

pub const Cache = cache.Cache;
pub const Hit = cache.Hit;

/// The length a TCP length prefix describes (RFC 7766 §8). A caller reads two octets, calls this,
/// reads that many more, and hands them to `on_response`.
pub const message_len = wire.message_len;

test {
    _ = core;
    _ = wire;
    _ = resolver;
    _ = resolv_conf;
    _ = cache;
}
