//! Tests of the walks for keys under a validating table (`table_walks.zig`), through the table
//! fixture and a `Trust` whose walks a test scripts (docs/design.md §25, step 12).
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const Name = core.Name;
const Kind = core.Kind;
const Question = core.Question;
const Validation = core.Validation;
const validation = core.validation;
const fixtures = @import("fixtures.zig");
const table_module = @import("table.zig");
const Event = table_module.Event;
const Handle = table_module.Handle;
const Trust = table_module.Trust;
const limits = @import("limits.zig");
const Stub = @import("table_memory.zig").Stub;

const servers = fixtures.servers_two;
const Table = fixtures.Table;
const slot_count = fixtures.slot_count;

/// The walks a test scripts: each joins when `joins` says, asks one DS question, and ends as
/// `ends_with` says once its answer comes.
const Scripted = struct {
    const walks_count: usize = 2;

    verdict: Validation = .{ .keys_wanted = Name.root },
    /// The walk a `keys_wanted` joins, or null for every walk busy.
    joins: ?u8 = 0,
    /// Whether a walk ends as it is joined, with no question.
    ready_at_join: bool = false,
    ends_with: validation.End = .ready,
    asking: [walks_count]bool = @splat(false),
    running: [walks_count]bool = @splat(false),
    ended: [walks_count]?validation.End = @splat(null),
    answered_count: usize = 0,
    failed_with: ?validation.Walked = null,
    released_count: usize = 0,

    fn trust(self: *Scripted) Trust {
        return .{
            .context = self,
            .validate = validate,
            .join = join,
            .next_question = next_question,
            .answered = answered,
            .question_failed = question_failed,
            .end = end,
            .release = release,
        };
    }

    fn of(context: *anyopaque) *Scripted {
        return @ptrCast(@alignCast(context));
    }

    fn validate(context: *anyopaque, asked: *const Name, kind: Kind, message: []const u8, now_ns: u64) Validation {
        _ = asked;
        _ = kind;
        _ = message;
        _ = now_ns;
        return of(context).verdict;
    }

    fn join(context: *anyopaque, target: *const Name, now_ns: u64) ?u8 {
        _ = target;
        _ = now_ns;
        const self = of(context);
        const walk = self.joins orelse return null;
        if (self.running[walk]) return walk;
        self.running[walk] = true;
        if (self.ready_at_join) self.ended[walk] = .ready else self.asking[walk] = true;
        return walk;
    }

    fn next_question(context: *anyopaque) ?validation.Asked {
        const self = of(context);
        for (&self.asking, 0..) |*asking, walk| {
            if (!asking.*) continue;
            asking.* = false;
            const question = Question.from_text("example.", .ds) catch unreachable;
            return .{ .walk = @intCast(walk), .question = question };
        }
        return null;
    }

    fn answered(context: *anyopaque, walk: u8, message: []const u8, now_ns: u64) void {
        _ = now_ns;
        const self = of(context);
        std.debug.assert(message.len >= core.constants.header_bytes);
        self.answered_count += 1;
        self.ended[walk] = self.ends_with;
    }

    fn question_failed(context: *anyopaque, walk: u8, failure: validation.Walked) void {
        const self = of(context);
        self.failed_with = failure;
        self.ended[walk] = .{ .failed = failure };
    }

    fn end(context: *anyopaque, walk: u8) ?validation.End {
        return of(context).ended[walk];
    }

    fn release(context: *anyopaque, walk: u8) void {
        const self = of(context);
        self.ended[walk] = null;
        self.running[walk] = false;
        self.released_count += 1;
    }
};

/// A table that validates under `scripted`.
fn validating(table: *Table, scripted: *Scripted) void {
    table.open();
    table.resolver.validate_with(scripted.trust());
}

/// Sends every query the table asks for, frees each walk's lookup a poll hands `walked` for, and
/// returns the handle of the one lookup that is not in `known`, the walk's, or null.
fn send_all(table: *Table, known: []const Handle) !?Handle {
    var stranger: ?Handle = null;
    while (table.poll()) |event| {
        if (event.action == .walked) {
            try testing.expect(std.mem.indexOfScalar(Handle, known, event.handle) == null);
            table.resolver.release(event.handle);
            continue;
        }
        try testing.expect(event.action == .send_udp);
        table.resolver.on_sent(event.handle, table.now_ns);
        if (std.mem.indexOfScalar(Handle, known, event.handle) == null) stranger = event.handle;
    }
    return stranger;
}

/// Fills the table as far as the consumer may, sends each lookup's query, and answers each with
/// a message whose keys are wanted.
fn fill_waiting(table: *Table, handles: *[slot_count - limits.trust_slots_min]Handle) !void {
    for (handles) |*handle| handle.* = try table.start("example.com.");
    try testing.expectError(error.NoSlot, table.start("example.com."));
    try testing.expectEqual(@as(?Handle, null), try send_all(table, handles));
    for (handles) |handle| {
        _ = table.answer(handle);
        try testing.expect(table.resolver.lookup_of(handle).state == .awaiting_keys);
    }
}

test "a table full of lookups that wait for keys still fetches them, in the slot kept for it" {
    var table: Table = .{ .config = .{ .servers = &servers } };
    var scripted: Scripted = .{};
    var stub: Stub = .{};
    table.open();
    table.resolver.remember_with(stub.memory());
    table.resolver.validate_with(scripted.trust());
    var handles: [slot_count - limits.trust_slots_min]Handle = undefined;
    try fill_waiting(&table, &handles);

    // The walk's question goes out in the reserved slot, as a lookup the consumer never started.
    // Its answer goes to the walk, whatever a validator would make of it, and the memory is not
    // asked for it.
    const walk = (try send_all(&table, &handles)).?;
    try testing.expectEqual(@as(usize, slot_count), table.resolver.in_flight());
    _ = table.answer(walk);
    try testing.expectEqual(@as(usize, 1), scripted.answered_count);
    try testing.expectEqual(@as(usize, 1), scripted.released_count);
    try testing.expectEqual(@as(u32, handles.len), stub.recalls);
    scripted.verdict = .insecure;

    // Each lookup that waited asks its server again. The walk's slot waits for the driver, and a
    // poll hands `walked` for it: the end goes neither to the consumer nor to the memory.
    for (handles) |handle| try testing.expect(table.resolver.lookup_of(handle).state == .query_ready);
    try testing.expectEqual(@as(usize, slot_count), table.resolver.in_flight());
    try testing.expectEqual(@as(?Handle, null), try send_all(&table, &handles));
    try testing.expectEqual(@as(usize, slot_count - limits.trust_slots_min), table.resolver.in_flight());
    try testing.expectEqual(@as(u32, 0), stub.writes);
    for (handles) |handle| {
        _ = table.answer(handle);
        const event = table.poll().?;
        try testing.expectEqual(handle, event.handle);
        try testing.expect(event.action == .done);
    }
}

test "a walk's question that runs out of time fails each lookup that waits on it" {
    var table: Table = .{ .config = .{ .servers = &servers } };
    var scripted: Scripted = .{};
    validating(&table, &scripted);
    var handles: [slot_count - limits.trust_slots_min]Handle = undefined;
    try fill_waiting(&table, &handles);
    const walk = (try send_all(&table, &handles)).?;

    // Each try of the walk's question runs out, on every server, and its end never reaches the
    // consumer: only the lookups that waited on it end, with its failure.
    var ended: usize = 0;
    for (0..core.limits.attempts_max * core.limits.servers_max) |_| {
        const deadline = table.resolver.next_deadline_ns() orelse break;
        table.now_ns = deadline;
        while (table.poll()) |event| switch (event.action) {
            .send_udp => table.resolver.on_sent(event.handle, table.now_ns),
            .failed => |failure| {
                try testing.expect(event.handle.index != walk.index);
                try testing.expectEqual(core.Error.Timeout, failure.err);
                ended += 1;
            },
            .walked => {
                try testing.expectEqual(walk, event.handle);
                table.resolver.release(walk);
            },
            else => return error.Unexpected,
        };
    }
    try testing.expectEqual(@as(?validation.Walked, .timeout), scripted.failed_with);
    try testing.expectEqual(handles.len, ended);
    // The driver freed the walk's slot: the table holds the lookups that ended, for the consumer to
    // free.
    try testing.expectEqual(handles.len, table.resolver.in_flight());
}

test "a cancelled walk's lookup fails its walk, and a poll hands walked for it" {
    var table: Table = .{ .config = .{ .servers = &servers } };
    var scripted: Scripted = .{};
    validating(&table, &scripted);
    var handles: [slot_count - limits.trust_slots_min]Handle = undefined;
    try fill_waiting(&table, &handles);
    const walk = (try send_all(&table, &handles)).?;
    table.resolver.cancel(walk);
    // The poll that reaches the cancelled lookup tells its walk, and hands `walked`.
    const event = table.poll().?;
    try testing.expectEqual(walk, event.handle);
    try testing.expect(event.action == .walked);
    try testing.expectEqual(@as(?validation.Walked, .failed), scripted.failed_with);
    for (handles) |handle| {
        const ended = table.poll().?;
        try testing.expect(ended.action == .failed);
        try testing.expectEqual(handle, ended.handle);
    }
    // Until the driver frees it, the slot is the walks' and not the consumer's.
    for (handles) |handle| table.resolver.release(handle);
    try testing.expectEqual(@as(usize, 1), table.resolver.in_flight());
    table.resolver.release(walk);
    try testing.expectEqual(@as(usize, 0), table.resolver.in_flight());
    // The released slot is the walks' to keep again: the consumer may take every slot but it.
    for (0..slot_count - limits.trust_slots_min) |_| _ = try table.start("example.com.");
    try testing.expectError(error.NoSlot, table.start("example.com."));
}

test "a walk that holds the kept slot leaves the consumer every other" {
    var table: Table = .{ .config = .{ .servers = &servers } };
    var scripted: Scripted = .{};
    validating(&table, &scripted);
    var handles: [slot_count - limits.trust_slots_min]Handle = undefined;
    try fill_waiting(&table, &handles);
    _ = (try send_all(&table, &handles)).?;
    table.resolver.cancel(handles[0]);
    table.resolver.release(handles[0]);
    _ = try table.start("other.example.");
    try testing.expectError(error.NoSlot, table.start("example.com."));
}

test "a lookup whose keys every walk is too busy to fetch reads the message as bogus" {
    var table: Table = .{ .config = .{ .servers = &servers } };
    var scripted: Scripted = .{ .joins = null };
    validating(&table, &scripted);
    const handle = try table.start("example.com.");
    _ = try send_all(&table, &.{handle});
    _ = table.answer(handle);
    // A bogus answer over UDP asks the same server over TCP (§25, what the lookup does with it).
    try testing.expect(table.resolver.lookup_of(handle).state == .tcp_needed);
    try testing.expect(!scripted.asking[0]);
    try testing.expectEqual(@as(usize, slot_count - 1), table.resolver.slots.items.len - table.resolver.in_flight());
}

test "a walk's end reaches the lookups that wait on it, and no other" {
    var table: Table = .{ .config = .{ .servers = &servers } };
    var scripted: Scripted = .{};
    validating(&table, &scripted);
    const first = try table.start("one.example.");
    const second = try table.start("two.example.");
    try testing.expectEqual(@as(?Handle, null), try send_all(&table, &.{ first, second }));
    _ = table.answer(first);
    scripted.joins = 1;
    _ = table.answer(second);

    // Both walks ask, the first walk first, and its answer ends it: its lookup asks again, and
    // the other waits on.
    var walks: [Scripted.walks_count]Handle = undefined;
    for (&walks) |*walk| {
        const event = table.poll().?;
        try testing.expect(event.action == .send_udp);
        walk.* = event.handle;
        table.resolver.on_sent(event.handle, table.now_ns);
    }
    _ = table.answer(walks[0]);
    try testing.expect(scripted.running[1]);
    try testing.expect(table.resolver.lookup_of(first).state == .query_ready);
    try testing.expect(table.resolver.lookup_of(second).state == .awaiting_keys);
}

test "a walk that ends as it is joined hands its end at once" {
    var table: Table = .{ .config = .{ .servers = &servers } };
    var scripted: Scripted = .{ .ready_at_join = true };
    validating(&table, &scripted);
    const handle = try table.start("example.com.");
    _ = try send_all(&table, &.{handle});
    _ = table.answer(handle);
    try testing.expect(table.resolver.lookup_of(handle).state == .query_ready);
    try testing.expectEqual(@as(usize, 1), scripted.released_count);
}

const https: core.Https = .{ .template = "https://dns.example/dns-query{?dns}" };
const servers_https = [_]core.Server{
    .{ .endpoint = servers[0].endpoint, .https = https },
    .{ .endpoint = servers[1].endpoint, .https = https },
};

/// Sends the one request a poll asks for, and answers it as its server would.
fn request_answered(table: *Table, handle: Handle) !void {
    const event = table.poll().?;
    try testing.expectEqual(handle, event.handle);
    table.resolver.on_sent(handle, table.now_ns);
    const message = table.build(table.resolver.lookup_of(handle), fixtures.answer_a);
    const transaction = event.action.send_request.transaction;
    try testing.expectEqual(.accepted, table.resolver.on_request_answer(handle, transaction, message, 0, table.now_ns));
}

test "over DoH, a request's answer reaches the walk it was asked for" {
    var table: Table = .{ .config = .{ .servers = &servers_https } };
    var scripted: Scripted = .{};
    validating(&table, &scripted);
    const handle = try table.start("example.com.");
    try request_answered(&table, handle);
    try testing.expect(table.resolver.lookup_of(handle).state == .awaiting_keys);

    // The walk's question goes out as a request of a lookup the consumer never started.
    const walk = table.poll().?;
    try testing.expect(walk.handle.index != handle.index);
    table.resolver.on_sent(walk.handle, table.now_ns);
    const message = table.build(table.resolver.lookup_of(walk.handle), fixtures.answer_a);
    _ = table.resolver.on_request_answer(walk.handle, walk.action.send_request.transaction, message, 0, table.now_ns);
    try testing.expectEqual(@as(usize, 1), scripted.answered_count);
    try testing.expect(table.resolver.lookup_of(handle).state == .query_ready);
}
