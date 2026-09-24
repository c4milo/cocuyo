//! What waits to go out on one connection, oldest first (docs/design.md §19 step 13, the stream's
//! rule 9; over TLS, §21's TLS rule 2): a ring of entries, each a lookup's query or records a TLS
//! session made of its own accord. Split out of `io_tcp_queue.zig`.
//!
//! Over TLS the entries at the front are sealed: the head once it is in flight, and the records
//! the session made after it. Records the session makes go after what is sealed already and ahead
//! of every query that is not, because a record's nonce is its sequence number and records go
//! out in the order they were sealed (RFC 9846 §5.3).
const std = @import("std");
const assert = std.debug.assert;

/// The slot an entry of the session's own records names: no table slot is this large.
pub const records: u16 = std.math.maxInt(u16);

pub const Entry = struct {
    /// The table slot whose query this is, or `records`.
    slot: u16,
    /// Over TLS, where this entry's sealed records end in the connection's records buffer, once
    /// it is sealed.
    end: u16 = 0,

    pub fn is_query(entry: Entry) bool {
        return entry.slot != records;
    }
};

/// A ring as long as the table, and room for the session's own records beside it.
pub fn Queue(comptime capacity: u16) type {
    return struct {
        const Self = @This();

        items: [capacity]Entry = undefined,
        head: u16 = 0,
        count: u16 = 0,
        /// How many entries at the front are sealed.
        sealed: u16 = 0,

        pub fn push(queue: *Self, entry: Entry) void {
            assert(queue.count < capacity);
            assert(!entry.is_query() or !queue.contains(entry.slot));
            queue.slot_at(queue.count).* = entry;
            queue.count += 1;
        }

        /// Puts `entry` after the sealed entries and seals it (RFC 9846 §5.3).
        pub fn insert_sealed(queue: *Self, entry: Entry) void {
            assert(queue.count < capacity);
            insert_after_sealed(queue, entry);
        }

        pub fn first(queue: *const Self) ?Entry {
            if (queue.count == 0) return null;
            return queue.items[queue.head];
        }

        pub fn first_pointer(queue: *Self) *Entry {
            assert(queue.count > 0);
            return &queue.items[queue.head];
        }

        /// The head went whole: it leaves, and so does its seal.
        pub fn pop(queue: *Self) void {
            assert(queue.count > 0);
            queue.head = (queue.head + 1) % capacity;
            queue.count -= 1;
            if (queue.sealed > 0) queue.sealed -= 1;
        }

        pub fn at(queue: *const Self, position: u16) Entry {
            assert(position < queue.count);
            return queue.items[(queue.head + position) % capacity];
        }

        pub fn slot_at(queue: *Self, position: u16) *Entry {
            return &queue.items[(queue.head + position) % capacity];
        }

        /// Whether `slot`'s query waits here.
        pub fn contains(queue: *const Self, slot: u16) bool {
            return position_of(queue, slot) != null;
        }

        /// Takes `slot`'s query out, keeping the order of the rest. Only a query not yet sealed
        /// leaves this way: a sealed one is in flight, and goes to its end.
        pub fn remove(queue: *Self, slot: u16) void {
            assert(slot != records);
            remove_slot(queue, slot);
        }

        /// Every sealed entry's end, moved down by `by` when the sealed bytes move to the front of
        /// the records buffer.
        pub fn shift_ends(queue: *Self, by: u16) void {
            shift_sealed_ends(queue, by);
        }
    };
}

fn insert_after_sealed(queue: anytype, entry: Entry) void {
    assert(queue.sealed <= queue.count);
    var position = queue.count;
    while (position > queue.sealed) : (position -= 1) {
        queue.slot_at(position).* = queue.slot_at(position - 1).*;
    }
    queue.slot_at(queue.sealed).* = entry;
    queue.count += 1;
    queue.sealed += 1;
}

fn position_of(queue: anytype, slot: u16) ?u16 {
    var position: u16 = 0;
    while (position < queue.count) : (position += 1) {
        if (queue.at(position).slot == slot) return position;
    }
    return null;
}

fn remove_slot(queue: anytype, slot: u16) void {
    var kept: u16 = 0;
    var position: u16 = 0;
    while (position < queue.count) : (position += 1) {
        const entry = queue.at(position);
        if (entry.slot == slot) {
            assert(position >= queue.sealed);
            continue;
        }
        queue.slot_at(kept).* = entry;
        kept += 1;
    }
    assert(kept + 1 == queue.count);
    queue.count = kept;
}

fn shift_sealed_ends(queue: anytype, by: u16) void {
    var position: u16 = 0;
    while (position < queue.sealed) : (position += 1) {
        const entry = queue.slot_at(position);
        assert(entry.end >= by);
        entry.end -= by;
    }
}

// Tests.

const testing = std.testing;

test "a queue keeps its order through a removal from the middle, and wraps" {
    var queue: Queue(3) = .{};
    queue.push(.{ .slot = 4 });
    queue.push(.{ .slot = 5 });
    queue.push(.{ .slot = 6 });
    queue.remove(5);
    try testing.expectEqual(@as(u16, 4), queue.first().?.slot);
    queue.pop();
    queue.push(.{ .slot = 7 });
    try testing.expectEqual(@as(u16, 6), queue.first().?.slot);
    try testing.expect(queue.contains(7) and !queue.contains(5));
    queue.pop();
    try testing.expectEqual(@as(u16, 7), queue.first().?.slot);
}

test "records sealed while a query is in flight go after it and ahead of the queries not sealed" {
    var queue: Queue(6) = .{};
    queue.push(.{ .slot = 1 });
    queue.push(.{ .slot = 2 });
    // The head is sealed as it goes.
    queue.sealed = 1;
    queue.insert_sealed(.{ .slot = records, .end = 10 });
    queue.insert_sealed(.{ .slot = records, .end = 20 });
    try testing.expectEqual(@as(u16, 3), queue.sealed);
    try testing.expectEqual(@as(u16, 1), queue.at(0).slot);
    try testing.expectEqual(records, queue.at(1).slot);
    try testing.expectEqual(records, queue.at(2).slot);
    try testing.expectEqual(@as(u16, 2), queue.at(3).slot);
    queue.pop();
    try testing.expectEqual(@as(u16, 2), queue.sealed);
    queue.shift_ends(10);
    try testing.expectEqual(@as(u16, 0), queue.at(0).end);
    try testing.expectEqual(@as(u16, 10), queue.at(1).end);
}
