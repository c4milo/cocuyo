//! The results a consumer takes: a bounded queue the engine fills as lookups end and the
//! consumer drains after every tick (docs/design.md §19 step 13). One result per slot at most,
//! so the queue is the slot count and never overflows.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");

pub const Outcome = union(enum) {
    answer: cocuyo.Answer,
    failure: cocuyo.Failure,
};

pub const Result = struct {
    handle: cocuyo.Handle,
    outcome: Outcome,
};

pub fn Queue(comptime capacity: u16) type {
    return struct {
        const Self = @This();

        items: [capacity]Result = undefined,
        head: u16 = 0,
        count: u16 = 0,

        pub fn push(self: *Self, result: Result) void {
            assert(self.count < capacity);
            const at = (self.head + self.count) % capacity;
            self.items[at] = result;
            self.count += 1;
        }

        pub fn pop(self: *Self) ?Result {
            if (self.count == 0) return null;
            const result = self.items[self.head];
            self.head = (self.head + 1) % capacity;
            self.count -= 1;
            return result;
        }

        pub fn len(self: *const Self) usize {
            return self.count;
        }
    };
}

// Tests.

const testing = std.testing;

test "results come out in the order they went in, and the queue wraps" {
    var queue: Queue(3) = .{};
    const failure: cocuyo.Failure = .{ .err = cocuyo.Error.Timeout, .server_index = 0, .attempts_made = 1, .negative_ttl_seconds = 0 };
    var index: u32 = 0;
    while (index < 5) : (index += 1) {
        queue.push(.{ .handle = .{ .index = @intCast(index), .generation = 1 }, .outcome = .{ .failure = failure } });
        if (index >= 2) try testing.expectEqual(@as(u32, index - 2), queue.pop().?.handle.index);
    }
    try testing.expectEqual(@as(usize, 2), queue.len());
    try testing.expectEqual(@as(u32, 3), queue.pop().?.handle.index);
    try testing.expectEqual(@as(u32, 4), queue.pop().?.handle.index);
    try testing.expectEqual(@as(?Result, null), queue.pop());
}
