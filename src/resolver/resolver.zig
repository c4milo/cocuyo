//! resolver: the state machine. `Lookup` drives one lookup and `Resolver` holds a bounded table of
//! them plus the code that decides which lookup an inbound datagram belongs to (docs/design.md §5
//! and §7).
//!
//! It reads `core` and `wire` and nothing else. It cannot reach the config parser: the state
//! machine takes a server list and a search list, whoever produced them, and
//! `zig build graph-check` is what shows the compiler enforces that.
//!
//! Steps 3 and 4 of §15 fill this module.
pub const entropy = @import("entropy.zig");
pub const servers = @import("servers.zig");
pub const policy = @import("lookup_policy.zig");
pub const lookup = @import("lookup.zig");
pub const table = @import("table.zig");
pub const table_keys = @import("table_keys.zig");
pub const table_slots = @import("table_slots.zig");
pub const constants = @import("constants.zig");

pub const Lookup = lookup.Lookup;
pub const Action = lookup.Action;
pub const Answer = lookup.Answer;
pub const Failure = lookup.Failure;
pub const Verdict = lookup.Verdict;
pub const State = lookup.State;
pub const Resolver = table.Resolver;
pub const Slot = table.Slot;
pub const MatchKey = table.MatchKey;
pub const Handle = table.Handle;
pub const Event = table.Event;

pub const Entropy = entropy.Entropy;
pub const Servers = servers.Servers;
pub const Transaction = entropy.Transaction;

test {
    _ = entropy;
    _ = servers;
    _ = policy;
    _ = lookup;
    _ = table;
    _ = table_keys;
    _ = table_slots;
    _ = constants;
    _ = @import("lookup_poll.zig");
    _ = @import("lookup_response.zig");
    _ = @import("fixtures.zig");
    _ = @import("lookup_records_test.zig");
    _ = @import("lookup_cookie_test.zig");
    _ = @import("lookup_init_test.zig");
    _ = @import("lookup_negative_test.zig");
    _ = @import("lookup_config_test.zig");
}
