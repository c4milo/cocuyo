//! One entry of a cache: what the caller's memory holds for each slot (docs/design.md §18). It is
//! `Cache.Slot`, and a file of its own, so that the type declares it and no name is said twice.
const core = @import("core");
const wire = @import("wire");
const Name = core.Name;
const Kind = core.Kind;
const cache = @import("cache.zig");
const Outcome = cache.Outcome;
const Links = @import("cache_chain.zig").Links;
const cache_failure = @import("cache_failure.zig");

/// One entry. The name is stored folded: it is the key, and what a hit hands back.
pub const Slot = struct {
    name: Name,
    answers: wire.Answers,
    /// The end of the CNAME chain the answers were reached through, when `aliased` says there
    /// was one: what a lookup that went out reports as the canonical name, kept so that a hit
    /// reports it too (docs/design.md §17 question 13).
    canonical: Name,
    /// The CNAME links that reached `canonical`, when `aliased` says there was a chain, so that a
    /// hit reports them as a lookup that went out does (docs/design.md §5, §17 question 122).
    aliases: core.Aliases,
    expires_ns: u64,
    hash: u32,
    links: Links,
    kind: Kind,
    outcome: Outcome,
    /// The error of a `failed` entry, and how often its time was doubled (§16 decision 60): one
    /// octet, which fits in padding the slot had.
    kept: cache_failure.Kept,
    /// Whether the servers said they validated what the entry holds (docs/design.md §25, Stage A
    /// rule 5): an answer's or a negative's, and `unchecked` for a failure.
    security: core.Security,
    absolute: bool,
    aliased: bool,
    visited: bool,
    occupied: bool,

    pub const empty: Slot = .{
        .name = Name.root,
        .answers = wire.Answers.init(.a),
        .canonical = Name.root,
        .aliases = .{},
        .expires_ns = 0,
        .hash = 0,
        .links = .{},
        .kind = .a,
        .outcome = .answered,
        .kept = .{},
        .security = .unchecked,
        .absolute = false,
        .aliased = false,
        .visited = false,
        .occupied = false,
    };
};
