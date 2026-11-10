//! The table with a memory under it (`table_memory.zig`), through the stub that file holds: what
//! a hit hands a lookup, and what an end writes back (docs/design.md §20). Split from
//! `table_memory.zig` by the file-length rule.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const wire = @import("wire");
const Error = core.Error;
const Name = core.Name;
const Kind = core.Kind;
const table_module = @import("table.zig");
const lookup_module = @import("lookup.zig");
const memory_module = @import("table_memory.zig");
const Stub = memory_module.Stub;
const fixtures = @import("fixtures.zig");
const Table = fixtures.Table;
const ready_module = @import("table_ready.zig");

/// Drives one lookup to its answer and returns the answers it holds, so a test has a real
/// `wire.Answers` to put in the stub.
fn answered_once(rig: *Table) !wire.Answers {
    const handle = try rig.start("example.com.");
    const sent = rig.poll().?;
    rig.resolver.on_sent(sent.handle, rig.now_ns);
    try testing.expectEqual(lookup_module.Verdict.accepted, rig.answer(handle));
    const end = rig.poll().?;
    try testing.expect(end.action == .done);
    const answers = rig.resolver.lookup_of(handle).answers;
    rig.resolver.release(handle);
    return answers;
}

test "a question the memory holds is answered at its first poll, and nothing is sent" {
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } };
    rig.open();
    const answers = try answered_once(&rig);
    var stub: Stub = .{ .held = .{ .answered = .{ .answers = &answers, .ttl_seconds = 42, .canonical_name = null, .security = .unchecked } } };
    rig.resolver.use_memory(stub.memory());

    const handle = try rig.start("example.com.");
    const event = rig.poll().?;
    try testing.expectEqual(@as(u32, 1), stub.recalls);
    try testing.expect(event.action == .done);
    // No query went out, so the server's latency took no sample: the one it has is the first
    // lookup's (docs/design.md §5).
    try testing.expectEqual(@as(u64, 1), rig.resolver.servers.samples(0));
    // The life it has left, not the life it was given.
    try testing.expectEqual(@as(u32, 42), event.action.done.ttl_seconds);
    // Read back from the memory, so it is not written to it again.
    try testing.expectEqual(@as(u32, 0), stub.writes);
    try testing.expectEqual(core.Kind.a, event.action.done.kind);
    try testing.expectEqual(@as(?*const core.Name, null), event.action.done.canonical_name);

    // Offered again, as a table that has not been told the answer was read does: the memory is
    // asked once per lookup, and asking a lookup that has already ended would be asking a
    // question whose answer it is holding.
    ready_module.offer(&rig.resolver, handle.index);
    const twice = rig.poll().?;
    try testing.expect(twice.action == .done);
    try testing.expectEqual(@as(u32, 1), stub.recalls);
    rig.resolver.release(handle);
}

test "a question the memory holds is answered over TCP too, before any connection" {
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } };
    rig.open();
    const answers = try answered_once(&rig);
    var stub: Stub = .{ .held = .{ .answered = .{ .answers = &answers, .ttl_seconds = 42, .canonical_name = null, .security = .unchecked } } };
    rig.resolver.use_memory(stub.memory());
    // Every query over TCP (§19 step 11): the lookup starts waiting for its connection.
    rig.config.use_tcp = true;
    const handle = try rig.start("example.com.");
    try testing.expect(rig.poll().?.action == .done);
    try testing.expectEqual(@as(u32, 1), stub.recalls);
    rig.resolver.release(handle);
}

test "a lookup that ended before its first poll is not asked about" {
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } };
    rig.open();
    const answers = try answered_once(&rig);
    var stub: Stub = .{ .held = .{ .answered = .{ .answers = &answers, .ttl_seconds = 42, .canonical_name = null, .security = .unchecked } } };
    rig.resolver.use_memory(stub.memory());
    const handle = try rig.start("example.com.");
    rig.resolver.cancel(handle);
    try testing.expectEqual(core.Error.Canceled, rig.poll().?.action.failed.err);
    try testing.expectEqual(@as(u32, 0), stub.recalls);
    rig.resolver.release(handle);
}

test "an answer reached through a chain is written with the chain's end" {
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } };
    rig.open();
    var stub: Stub = .{};
    rig.resolver.use_memory(stub.memory());

    const handle = try rig.start("example.com.");
    const sent = rig.poll().?;
    rig.resolver.on_sent(sent.handle, rig.now_ns);
    const lookup = rig.resolver.lookup_of(handle);
    const message = rig.build(lookup, fixtures.cname_then_a);
    rig.now_ns += 1;
    try testing.expectEqual(lookup_module.Verdict.accepted, rig.resolver.on_datagram(message, lookup.server(), rig.now_ns));
    const end = rig.poll().?;
    try testing.expect(end.action == .done);

    // What the memory is given is what a lookup that went out reports.
    const target = try core.Name.from_text("host.example.net");
    try testing.expect(end.action.done.canonical_name.?.equal(&target));
    try testing.expect(stub.written.?.answered.canonical_name.?.equal(&target));
    // And its links (docs/design.md §5, §17 question 122).
    try testing.expectEqual(@as(u8, 1), stub.written.?.answered.aliases.count);
    rig.resolver.release(handle);
}

test "a walk's end is written under the name asked with the bound a negative on the way put on it" {
    // `example` is asked as `example.one.net` first, whose NXDOMAIN carries no SOA, then as
    // `example`, which answers. The end rests on a negative no cache keeps (RFC 2308 §5), so it
    // is written with a TTL of zero, which no cache keeps either (docs/design.md §5).
    const search = [_]core.Name{try core.Name.from_text("one.net")};
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &search, .ndots = 1 } };
    rig.open();
    var stub: Stub = .{};
    rig.resolver.use_memory(stub.memory());

    const handle = try rig.start("example");
    for ([_]fixtures.Reply{ fixtures.name_error, fixtures.answer_a }) |reply| {
        const sent = rig.poll().?;
        rig.resolver.on_sent(sent.handle, rig.now_ns);
        const lookup = rig.resolver.lookup_of(handle);
        const message = rig.build(lookup, reply);
        rig.now_ns += 1;
        try testing.expectEqual(lookup_module.Verdict.accepted, rig.resolver.on_datagram(message, lookup.server(), rig.now_ns));
    }
    const end = rig.poll().?;
    try testing.expectEqual(@as(u32, 0), end.action.done.ttl_seconds);
    try testing.expectEqual(@as(u32, 1), stub.writes);
    try testing.expectEqual(@as(u32, 0), stub.written.?.answered.ttl_seconds);
    try testing.expectEqual(@as(u32, 0), stub.written.?.answered.answers.ttl_seconds);
    rig.resolver.release(handle);
}

test "a recalled answer reports the chain's end it was remembered with" {
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } };
    rig.open();
    const answers = try answered_once(&rig);
    const target = try core.Name.from_text("host.example.net");
    var aliases: core.Aliases = .{};
    try testing.expect(aliases.append(&try core.Name.from_text("example.com"), 60));
    var stub: Stub = .{ .held = .{ .answered = .{
        .answers = &answers,
        .ttl_seconds = 42,
        .canonical_name = &target,
        .aliases = &aliases,
        .security = .unchecked,
    } } };
    rig.resolver.use_memory(stub.memory());

    const handle = try rig.start("example.com.");
    const event = rig.poll().?;
    try testing.expect(event.action == .done);
    try testing.expect(event.action.done.canonical_name.?.equal(&target));
    // The links, copied into the lookup's own storage, as the end is.
    try testing.expectEqual(@as(u8, 1), event.action.done.aliases.count);
    try testing.expect(event.action.done.aliases != &aliases);
    rig.resolver.release(handle);
}

test "a recalled negative reports the chain that reached the name with no data" {
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } };
    rig.open();
    const target = try core.Name.from_text("host.example.net");
    var aliases: core.Aliases = .{};
    try testing.expect(aliases.append(&try core.Name.from_text("example.com"), 60));
    var stub: Stub = .{ .held = .{ .negative = .{
        .outcome = .no_data,
        .ttl_seconds = 42,
        .security = .unchecked,
        .canonical_name = &target,
        .aliases = &aliases,
    } } };
    rig.resolver.use_memory(stub.memory());

    const handle = try rig.start("example.com.");
    const failed = rig.poll().?.action.failed;
    try testing.expectEqual(core.Error.NoData, failed.err);
    try testing.expect(failed.canonical_name.?.equal(&target));
    try testing.expectEqual(@as(u8, 1), failed.aliases.count);
    rig.resolver.release(handle);
}

test "a negative the memory holds comes back as that failure, with what is left of it" {
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } };
    rig.open();
    var stub: Stub = .{ .held = .{ .negative = .{ .outcome = .name_not_found, .ttl_seconds = 7, .security = .unchecked } } };
    rig.resolver.use_memory(stub.memory());

    const handle = try rig.start("example.com.");
    const event = rig.poll().?;
    try testing.expect(event.action == .failed);
    try testing.expectEqual(Error.NameNotFound, event.action.failed.err);
    try testing.expectEqual(@as(u32, 7), event.action.failed.negative_ttl_seconds);
    try testing.expectEqual(@as(u32, 0), stub.writes);
    rig.resolver.release(handle);
}

test "an end is written back once, however many polls produce it" {
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } };
    rig.open();
    var stub: Stub = .{};
    rig.resolver.use_memory(stub.memory());

    const handle = try rig.start("example.com.");
    const sent = rig.poll().?;
    rig.resolver.on_sent(sent.handle, rig.now_ns);
    try testing.expectEqual(lookup_module.Verdict.accepted, rig.answer(handle));
    const end = rig.poll().?;
    try testing.expect(end.action == .done);
    try testing.expectEqual(@as(u32, 1), stub.writes);
    try testing.expect(stub.written.? == .answered);

    // Offered again, as a table that has not been told the answer was read does.
    ready_module.offer(&rig.resolver, handle.index);
    const again = rig.poll().?;
    try testing.expect(again.action == .done);
    try testing.expectEqual(@as(u32, 1), stub.writes);
    rig.resolver.release(handle);
}

test "a cancel is no resolution failure, and is not written back" {
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } };
    rig.open();
    var stub: Stub = .{};
    rig.resolver.use_memory(stub.memory());

    const handle = try rig.start("example.com.");
    rig.resolver.cancel(handle);
    const event = rig.poll().?;
    try testing.expect(event.action == .failed);
    try testing.expectEqual(Error.Canceled, event.action.failed.err);
    try testing.expectEqual(@as(u32, 0), stub.writes);
    rig.resolver.release(handle);
}

test "the resolution failures of RFC 9520 §2 are written as failed, and nothing else" {
    const written = [_]Error{
        Error.Timeout,      Error.AllServersFailed, Error.ServerFailure,
        Error.Refused,      Error.NotImplemented,   Error.FormatError,
        Error.ChainTooLong, Error.Bogus,
    };
    for (written) |err| try testing.expect(memory_module.resolution_failure(err));
    const kept_out = [_]Error{
        Error.NameNotFound, Error.NoData,    Error.NameTooLong,
        Error.Canceled,     Error.NoServers, Error.MalformedMessage,
    };
    for (kept_out) |err| try testing.expect(!memory_module.resolution_failure(err));
}

/// Drives one lookup to `AllServersFailed`: its one server answers SERVFAIL on every pass.
fn failed_once(rig: *Table) !lookup_module.Failure {
    const handle = try rig.start("example.com.");
    var passes: usize = 0;
    while (passes < rig.config.attempts) : (passes += 1) {
        const sent = rig.poll().?;
        try testing.expect(sent.action == .send_udp);
        rig.resolver.on_sent(sent.handle, rig.now_ns);
        const lookup = rig.resolver.lookup_of(handle);
        const message = rig.build(lookup, fixtures.server_failure);
        rig.now_ns += 1;
        try testing.expectEqual(lookup_module.Verdict.accepted, rig.resolver.on_datagram(message, lookup.server(), rig.now_ns));
    }
    const end = rig.poll().?;
    try testing.expect(end.action == .failed);
    rig.resolver.release(handle);
    return end.action.failed;
}

test "a lookup whose servers all fail is written back as failed, with its error" {
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } };
    rig.open();
    var stub: Stub = .{};
    rig.resolver.use_memory(stub.memory());
    const failure = try failed_once(&rig);
    try testing.expectEqual(Error.AllServersFailed, failure.err);
    try testing.expectEqual(@as(u32, 1), stub.writes);
    try testing.expectEqual(Error.AllServersFailed, stub.written.?.failed);
}

test "a failure the memory holds ends the lookup at its first poll, and nothing is sent" {
    // "the resolver MUST NOT send any corresponding outgoing queries until after the cache
    // entries expire" (RFC 9520 §3.2).
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } };
    rig.open();
    var stub: Stub = .{ .held = .{ .failed = Error.AllServersFailed } };
    rig.resolver.use_memory(stub.memory());

    const handle = try rig.start("example.com.");
    const event = rig.poll().?;
    try testing.expectEqual(@as(u32, 1), stub.recalls);
    try testing.expect(event.action == .failed);
    const failure = event.action.failed;
    try testing.expectEqual(Error.AllServersFailed, failure.err);
    // The memory keeps no cause, and no pass was made (docs/design.md §17 question 89).
    try testing.expectEqual(@as(?lookup_module.Cause, null), failure.cause);
    try testing.expectEqual(@as(u8, 0), failure.attempts_made);
    try testing.expectEqual(@as(u32, 0), failure.negative_ttl_seconds);
    try testing.expectEqual(@as(u64, 0), rig.resolver.servers.samples(0));
    // Read back from the memory, so it is not written to it again.
    try testing.expectEqual(@as(u32, 0), stub.writes);
    rig.resolver.release(handle);
}

/// Starts a lookup of `text` on `rig`, and answers it with `reply`, AD set, from its server.
fn answered_with_ad(rig: *Table, text: []const u8, reply: fixtures.Reply) !void {
    const handle = try rig.start(text);
    rig.resolver.on_sent(rig.poll().?.handle, rig.now_ns);
    const lookup = rig.resolver.lookup_of(handle);
    var signed = reply;
    signed.authentic_data = true;
    const message = rig.build(lookup, signed);
    rig.now_ns += 1;
    _ = rig.resolver.on_datagram(message, lookup.server(), rig.now_ns);
    _ = rig.poll().?;
    rig.resolver.release(handle);
}

test "an end is written with its status, and a negative with its own (docs/design.md §25 rule 5)" {
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{}, .authenticated_data = .always } };
    rig.open();
    var stub: Stub = .{};
    rig.resolver.use_memory(stub.memory());
    try answered_with_ad(&rig, "example.com.", fixtures.answer_a);
    try testing.expectEqual(core.Security.authenticated, stub.written.?.answered.security);
    try answered_with_ad(&rig, "nothing.example.", fixtures.name_error_soa);
    try testing.expectEqual(core.Security.authenticated, stub.written.?.negative.security);
}

/// A trust whose validator calls every message secure, and whose walks never run: what a table
/// needs to validate, here, where no message is read.
const Secure = struct {
    fn trust(context: *anyopaque) table_module.Trust {
        return .{
            .context = context,
            .validate = validate,
            .join = join,
            .next_question = next_question,
            .answered = answered,
            .question_failed = question_failed,
            .end = end,
            .release = release,
        };
    }

    fn validate(context: *anyopaque, asked: *const Name, kind: Kind, message: []const u8, now_ns: u64) core.Validation {
        _ = .{ context, asked, kind, message, now_ns };
        return .{ .secure = .{ .ending = .answer, .ttl_seconds = std.math.maxInt(u32) } };
    }

    fn join(context: *anyopaque, target: *const Name, now_ns: u64) ?u8 {
        _ = .{ context, target, now_ns };
        return null;
    }

    fn next_question(context: *anyopaque) ?core.validation.Asked {
        _ = context;
        return null;
    }

    fn answered(context: *anyopaque, walk: u8, message: []const u8, now_ns: u64) void {
        _ = .{ context, walk, message, now_ns };
        unreachable;
    }

    fn question_failed(context: *anyopaque, walk: u8, failure: core.validation.Walked) void {
        _ = .{ context, walk, failure };
        unreachable;
    }

    fn end(context: *anyopaque, walk: u8) ?core.validation.End {
        _ = .{ context, walk };
        unreachable;
    }

    fn release(context: *anyopaque, walk: u8) void {
        _ = .{ context, walk };
        unreachable;
    }
};

/// What the first poll of `kind` for example.com does over a memory that holds `held`, in a table
/// that validates when `validating` says.
fn first_poll(held: memory_module.Remembered, kind: Kind, validating: bool) !lookup_module.Action {
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_two } };
    var stub: Stub = .{ .held = held };
    var context: u8 = 0;
    rig.open();
    rig.resolver.use_memory(stub.memory());
    if (validating) rig.resolver.use_trust(Secure.trust(&context));
    _ = try rig.resolver.start(&try core.Question.from_text("example.com.", kind));
    const event = rig.poll().?;
    try testing.expectEqual(@as(u32, 1), stub.recalls);
    return event.action;
}

/// The TTL of a test's negative, which no test reads.
const negative_ttl_seconds: u32 = 7;

fn negative_of(security: core.Security) memory_module.Remembered {
    return .{ .negative = .{ .outcome = .no_data, .ttl_seconds = negative_ttl_seconds, .security = security } };
}

test "a validating table takes only an end a validating table wrote (docs/design.md §25 step 13)" {
    try testing.expect((try first_poll(negative_of(.secure), .a, true)) == .failed);
    try testing.expect((try first_poll(negative_of(.insecure), .a, true)) == .failed);
    // An end no validator read is a miss, and the lookup asks.
    try testing.expect((try first_poll(negative_of(.unchecked), .a, true)) == .send_udp);
    try testing.expect((try first_poll(negative_of(.authenticated), .a, true)) == .send_udp);
    // An RRSIG is never signed, so a validating lookup for one ends `unchecked` too (item 15).
    try testing.expect((try first_poll(negative_of(.unchecked), .rrsig, true)) == .failed);
    // A table that validates nothing takes each of them.
    for (std.enums.values(core.Security)) |security| {
        try testing.expect((try first_poll(negative_of(security), .a, false)) == .failed);
    }
}

test "a validating table hands back the security that a recalled end was stored with" {
    // §25 step 13: an entry holds its end's security, and a hit reports it.
    for ([_]core.Security{ .secure, .insecure }) |security| {
        try testing.expectEqual(security, (try first_poll(negative_of(security), .a, true)).failed.security);
    }
    try testing.expectEqual(core.Security.unchecked, (try first_poll(negative_of(.unchecked), .rrsig, true)).failed.security);
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } };
    rig.open();
    const answers = try answered_once(&rig);
    for ([_]core.Security{ .secure, .insecure }) |security| {
        const held: memory_module.Remembered = .{ .answered = .{ .answers = &answers, .ttl_seconds = 42, .canonical_name = null, .security = security } };
        try testing.expectEqual(security, (try first_poll(held, .a, true)).done.security);
    }
}

test "a Bogus failure is taken by a validating table alone" {
    const bogus: memory_module.Remembered = .{ .failed = Error.Bogus };
    const taken = try first_poll(bogus, .a, true);
    try testing.expectEqual(Error.Bogus, taken.failed.err);
    try testing.expect((try first_poll(bogus, .a, false)) == .send_udp);
    // Another failure is a server's, whoever wrote it.
    try testing.expect((try first_poll(.{ .failed = Error.Timeout }, .a, false)) == .failed);
}
