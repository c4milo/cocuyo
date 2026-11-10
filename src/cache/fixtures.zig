//! What the cache's tests build on: a table of a few slots, questions and answers.
const core = @import("core");
const wire = @import("wire");
const cache = @import("cache.zig");
const constants = @import("constants.zig");

pub const second: u64 = constants.ns_per_s;

/// One seed for every test, so a test that depends on where a name lands says so by naming it.
pub const seed: u64 = 1;

/// A table of `slot_count` slots and the smallest key index the load factor allows: a power of
/// two at least `keys_per_slot_min` entries a slot.
pub fn Fixture(comptime slot_count: usize) type {
    return struct {
        slots: [slot_count]cache.Cache.Slot = undefined,
        keys: [cache.Cache.keys_for(slot_count)]cache.Cache.Key = undefined,

        pub fn init(self: *@This()) cache.Cache {
            return cache.Cache.init(&self.slots, &self.keys, seed, constants.ttl_seconds_max_default);
        }
    };
}

pub fn question(text: []const u8) core.Question {
    return core.Question.parse(text, .a) catch unreachable;
}

/// One A record, `192.0.2.<last>` (RFC 5737), with the TTL given.
pub fn answers_v4(last: u8, ttl_seconds: u32) wire.Answers {
    return wire.fixtures.answers_address(core.Address.from_v4(.{ 192, 0, 2, last }), ttl_seconds);
}
