//! The replay: drives the Zig `Lookup` down the transcript the Lean model writes
//! (spec/lean/Main.lean) and fails on the first line where the two disagree about what the lookup
//! answers or the state it lands in (spec/README.md).
//!
//! The state is the model's, read off the lookup's fields: the stage, where the walk over servers,
//! passes, candidates and CNAME hops stands, and the four flags the model keeps. So each line
//! checks the abstraction and not only what the caller sees, and a field that drifts is caught at
//! the event that moved it rather than at the one, later, that reads it.
//!
//! The transcript is a depth-first walk. A line at depth `d` is one event applied to the lookup as
//! the line at depth `d - 1` above it left it, so the replay keeps one frame per depth: the lookup,
//! the per-server state it shares, and the clock. Each line restores its parent's frame, applies
//! its event, compares, and saves its own.
//!
//! Time is the model's two kinds of poll. `poll` comes before the deadline, at the instant the
//! last event came at, and `expire` comes at the deadline the lookup is waiting for. Every other
//! event comes at the same instant as the one before it, so the clock never goes backwards.
//!
//! `zig build spec` runs this over the whole transcript, and `zig build test` runs the tests
//! below, which replay the committed slice in `lookup_gate.txt` without Lean.
//!
//! This is developer tooling. It is never linked into the library, so it allocates and reads the
//! filesystem.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const resolver = @import("resolver");
const Lookup = resolver.Lookup;
const Servers = resolver.servers.Servers;
const fixtures = @import("fixtures.zig");

/// The deepest line the replay can follow. The walk over spec/lean/Main.lean's configurations went
/// 168 deep when it was measured on 2026-09-23; this leaves room for a model that grows.
const depth_max = 512;

/// The seed every lookup of the replay starts from. One seed is enough: the model abstracts the
/// server order and the entropy away, so another seed walks the same tree.
const seed = 0x5eed_5eed;

/// The longest line of a transcript: an event, an answer and a state, and room to spare.
const line_bytes_max = 256;

/// The longest state a line writes: the longest stage, four counters and the flags.
pub const state_bytes_max = 64;

/// How a configuration's queries go: the model's `transportToken` (spec/lean/Spec/Tokens.lean).
const Transport = enum { udp, tcp, https, quic };

/// The search list; a configuration with `candidates` names takes `candidates - 1` of it.
const search_all = [_][]const u8{ "a.test", "b.test" };

/// The name asked about, with one dot and `ndots` at one, so it is tried as written first and the
/// search list after (docs/design.md §5).
const name_relative = "example.com";
const name_absolute = "example.com.";
const ndots = 1;

/// What the caller tells a lookup: the model's `Event`, spelt as the transcript spells it.
pub const Event = enum {
    init,
    poll,
    expire,
    sent,
    send_failed,
    tcp_connected,
    tcp_failed,
    request_failed,
    cancel,
    reply_unmatched,
    reply_answer,
    reply_cname,
    reply_nxdomain,
    reply_nodata,
    reply_servfail,
    reply_formerr,
    reply_truncated,
    reply_badcookie,
};

/// What a lookup answers: the model's `Out`, with each failure spelt out.
pub const Out = enum {
    send_udp,
    connect_tcp,
    send_tcp,
    send_request,
    wait,
    done,
    failed_name_not_found,
    failed_no_data,
    failed_timeout,
    failed_all_servers_failed,
    failed_chain_too_long,
    failed_canceled,
    failed_no_servers,
    /// A failure the model has no name for, which is a disagreement whatever the model said.
    failed_other,
    accepted,
    ignored,
    none,
};

pub const Error = error{ Malformed, TooDeep, Mismatch, WrongHops, Empty };

const Frame = struct { lookup: Lookup, servers: Servers, now_ns: u64 };

/// Where the replay and the model parted: the line, what each said, and the events that led there.
pub const Mismatch = struct {
    line: usize,
    depth: usize,
    expected_out: Out,
    got_out: Out,
    expected_state: [state_bytes_max]u8,
    expected_state_len: usize,
    got_state: [state_bytes_max]u8,
    got_state_len: usize,
};

pub const Replay = struct {
    config: core.Config = .{ .servers = &.{} },
    search: [search_all.len]core.Name = undefined,
    question: core.Question = undefined,
    servers: Servers = undefined,
    lookup: Lookup = undefined,
    now_ns: u64 = 0,
    frames: [depth_max]Frame = undefined,
    path: [depth_max]Event = undefined,
    /// The depth of the last line, which bounds the depth of the next.
    depth: usize = 0,
    hops_checked: bool = false,
    configured: bool = false,
    started: bool = false,
    config_text: [line_bytes_max]u8 = undefined,
    config_len: usize = 0,
    lines: usize = 0,
    events: usize = 0,
    configs: usize = 0,
    mismatch: ?Mismatch = null,
    query: [core.constants.query_bytes_max]u8 = undefined,
    reply: [core.constants.udp_payload_bytes_default]u8 = undefined,

    /// Replays one line of the transcript.
    pub fn line(self: *Replay, text: []const u8) Error!void {
        self.lines += 1;
        if (text.len == 0) return;
        if (text.len > line_bytes_max) return error.Malformed;
        var fields = std.mem.tokenizeScalar(u8, text, ' ');
        const first = fields.next() orelse return error.Malformed;
        if (std.mem.eql(u8, first, "hops")) return self.check_hops(&fields);
        if (!self.hops_checked) return error.WrongHops;
        if (std.mem.eql(u8, first, "config")) return self.configure(text, &fields);
        const depth = std.fmt.parseInt(usize, first, 10) catch return error.Malformed;
        const event = parse(Event, fields.next()) orelse return error.Malformed;
        const out = parse(Out, fields.next()) orelse return error.Malformed;
        const state = fields.rest();
        if (state.len == 0 or state.len > state_bytes_max) return error.Malformed;
        return self.step(depth, event, out, state);
    }

    /// Whether the transcript held anything to replay.
    pub fn finish(self: *const Replay) Error!void {
        if (self.events == 0) return error.Empty;
    }

    /// The model's walk counts CNAME hops against the limit it was given; this build's is fixed.
    fn check_hops(self: *Replay, fields: *std.mem.TokenIterator(u8, .scalar)) Error!void {
        const hops = std.fmt.parseInt(u8, fields.next() orelse "", 10) catch return error.Malformed;
        if (hops != core.constants.cname_hops_max) return error.WrongHops;
        self.hops_checked = true;
    }

    fn configure(self: *Replay, text: []const u8, fields: *std.mem.TokenIterator(u8, .scalar)) Error!void {
        const server_count = try count(fields.next(), 0, fixtures.servers.len);
        const attempts = try count(fields.next(), 1, core.constants.attempts_max);
        const candidates = try count(fields.next(), 1, search_all.len + 1);
        const transport = parse(Transport, fields.next()) orelse return error.Malformed;
        if (fields.next() != null) return error.Malformed;
        for (search_all[0 .. candidates - 1], 0..) |entry, index| {
            self.search[index] = core.Name.from_text(entry) catch unreachable;
        }
        const servers: []const core.Server = switch (transport) {
            .udp, .tcp => &fixtures.servers,
            .https => &fixtures.servers_https,
            .quic => &fixtures.servers_quic,
        };
        self.config = .{
            .servers = servers[0..server_count],
            .attempts = @intCast(attempts),
            .search = self.search[0 .. candidates - 1],
            .ndots = ndots,
            .use_tcp = transport == .tcp,
        };
        const name = if (candidates == 1) name_absolute else name_relative;
        self.question = core.Question.from_text(name, .a) catch unreachable;
        @memcpy(self.config_text[0..text.len], text);
        self.config_len = text.len;
        self.configured = true;
        self.started = false;
        self.depth = 0;
        self.configs += 1;
    }

    fn step(self: *Replay, depth: usize, event: Event, expected_out: Out, expected_state: []const u8) Error!void {
        if (!self.configured) return error.Malformed;
        if (depth >= depth_max) return error.TooDeep;
        if (depth > self.depth + 1) return error.Malformed;
        if ((event == .init) != (depth == 0)) return error.Malformed;
        if ((event == .init) == self.started) return error.Malformed;
        if (event == .init) self.start() else self.restore(depth - 1);
        self.path[depth] = event;
        const got_out = if (event == .init) Out.none else self.apply(event);
        var got_buffer: [state_bytes_max]u8 = undefined;
        const got_state = state_text(&self.lookup, &got_buffer);
        self.save(depth);
        self.depth = depth;
        self.events += 1;
        if (got_out == expected_out and std.mem.eql(u8, got_state, expected_state)) return;
        var mismatch: Mismatch = .{
            .line = self.lines,
            .depth = depth,
            .expected_out = expected_out,
            .got_out = got_out,
            .expected_state = undefined,
            .expected_state_len = expected_state.len,
            .got_state = got_buffer,
            .got_state_len = got_state.len,
        };
        @memcpy(mismatch.expected_state[0..expected_state.len], expected_state);
        self.mismatch = mismatch;
        return error.Mismatch;
    }

    fn start(self: *Replay) void {
        self.servers = Servers.init(&self.config, seed);
        self.lookup.init_in_place(&self.config, &self.servers, self.question, seed);
        self.now_ns = 0;
        self.started = true;
    }

    fn save(self: *Replay, depth: usize) void {
        self.frames[depth] = .{ .lookup = self.lookup, .servers = self.servers, .now_ns = self.now_ns };
    }

    fn restore(self: *Replay, depth: usize) void {
        const frame = &self.frames[depth];
        self.lookup = frame.lookup;
        self.servers = frame.servers;
        self.now_ns = frame.now_ns;
        assert(self.lookup.config == &self.config);
        assert(self.lookup.servers == &self.servers);
    }

    fn apply(self: *Replay, event: Event) Out {
        const lookup = &self.lookup;
        switch (event) {
            .init => unreachable,
            .poll => return out_of(lookup.poll(self.now_ns, &self.query)),
            .expire => {
                assert(lookup.is_waiting());
                self.now_ns = @max(self.now_ns, lookup.deadline_ns);
                return out_of(lookup.poll(self.now_ns, &self.query));
            },
            .sent => lookup.on_sent(self.now_ns),
            .send_failed => lookup.on_send_failed(self.now_ns),
            .tcp_connected => lookup.on_tcp_connected(self.now_ns),
            .tcp_failed => lookup.on_tcp_failed(self.now_ns),
            .request_failed => lookup.on_request_failed(lookup.transaction.number, self.now_ns),
            .cancel => lookup.cancel(),
            else => return self.respond(reply_of(event)),
        }
        return .none;
    }

    fn respond(self: *Replay, reply: fixtures.Reply) Out {
        const message = fixtures.build(&self.lookup, reply, &self.reply);
        const verdict = if (self.config.sends_requests())
            self.lookup.on_request_answer(transaction_of(&self.lookup, reply), message, 0, self.now_ns)
        else
            self.lookup.on_response(message, self.source(), self.now_ns);
        return switch (verdict) {
            .accepted => .accepted,
            .ignored => .ignored,
        };
    }

    /// Where a reply comes from: the server the lookup is on, on the port of the transport it is
    /// waiting on. A lookup with no server has none, and any address will do for the stray reply
    /// the model sends it.
    fn source(self: *const Replay) core.Endpoint {
        if (self.config.server_count() == 0) return fixtures.servers[0].endpoint;
        if (self.lookup.state == .awaiting_tcp) return self.lookup.server_tcp();
        return self.lookup.server();
    }

    /// Prints where the replay parted from the model.
    pub fn report(self: *const Replay, err: Error) void {
        std.debug.print("spec replay: {s} at line {d}\n", .{ @errorName(err), self.lines });
        const mismatch = self.mismatch orelse return;
        std.debug.print("  {s}\n  path:", .{self.config_text[0..self.config_len]});
        for (self.path[0 .. mismatch.depth + 1]) |event| std.debug.print(" {s}", .{@tagName(event)});
        std.debug.print("\n  the model: {s} {s}\n  the lookup: {s} {s}\n", .{
            @tagName(mismatch.expected_out), mismatch.expected_state[0..mismatch.expected_state_len],
            @tagName(mismatch.got_out),      mismatch.got_state[0..mismatch.got_state_len],
        });
    }
};

/// The lookup's state as the model writes one (spec/lean/Spec/Tokens.lean, `stateToken`).
pub fn state_text(lookup: *const Lookup, out: *[state_bytes_max]u8) []const u8 {
    return switch (lookup.state) {
        .done => "done - -",
        .failed => std.fmt.bufPrint(out, "failed {s} -", .{
            @tagName(failed_out(lookup.failure))["failed_".len..],
        }) catch unreachable,
        else => running_text(lookup, out),
    };
}

fn running_text(lookup: *const Lookup, out: *[state_bytes_max]u8) []const u8 {
    const flags = lookup.flags;
    return std.fmt.bufPrint(out, "{s} {d}/{d}/{d}/{d} {c}{c}{c}{c}", .{
        @tagName(lookup.state),
        lookup.server_index,
        lookup.round,
        lookup.candidate_index,
        lookup.cname_hops,
        flag(flags.edns_enabled, 'E'),
        flag(flags.had_no_data, 'N'),
        flag(flags.had_server_failure, 'F'),
        flag(flags.cookie_retried, 'K'),
    }) catch unreachable;
}

fn flag(set: bool, letter: u8) u8 {
    return if (set) letter else '-';
}

fn parse(comptime T: type, token: ?[]const u8) ?T {
    return std.meta.stringToEnum(T, token orelse return null);
}

fn count(token: ?[]const u8, min: usize, max: usize) Error!usize {
    const value = std.fmt.parseInt(usize, token orelse return error.Malformed, 10) catch
        return error.Malformed;
    if (value < min or value > max) return error.Malformed;
    return value;
}

/// The transaction a DoH answer names: the lookup's own, and for the reply the model calls
/// unmatched, one the lookup is not on, since over DoH the id is not what is checked (§22).
fn transaction_of(lookup: *const Lookup, reply: fixtures.Reply) u16 {
    const number = lookup.transaction.number;
    return if (reply == .unmatched) number -% 1 else number;
}

fn reply_of(event: Event) fixtures.Reply {
    return switch (event) {
        .reply_unmatched => .unmatched,
        .reply_answer => .answer,
        .reply_cname => .cname,
        .reply_nxdomain => .nxdomain,
        .reply_nodata => .nodata,
        .reply_servfail => .servfail,
        .reply_formerr => .formerr,
        .reply_truncated => .truncated,
        .reply_badcookie => .badcookie,
        else => unreachable,
    };
}

fn out_of(action: resolver.Action) Out {
    return switch (action) {
        .send_udp => .send_udp,
        .connect_tcp => .connect_tcp,
        .send_tcp => .send_tcp,
        .send_request => .send_request,
        .wait => .wait,
        .done => .done,
        .failed => |failure| failed_out(failure.err),
    };
}

fn failed_out(err: core.Error) Out {
    return switch (err) {
        error.NameNotFound => .failed_name_not_found,
        error.NoData => .failed_no_data,
        error.Timeout => .failed_timeout,
        error.AllServersFailed => .failed_all_servers_failed,
        error.ChainTooLong => .failed_chain_too_long,
        error.Canceled => .failed_canceled,
        error.NoServers => .failed_no_servers,
        else => .failed_other,
    };
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const arguments = try init.minimal.args.toSlice(gpa);
    if (arguments.len != 2) {
        std.debug.print("usage: spec-replay <transcript>\n", .{});
        return error.Usage;
    }
    const replay = try gpa.create(Replay);
    replay.* = .{};
    const file = try std.Io.Dir.cwd().openFile(init.io, arguments[1], .{});
    defer file.close(init.io);
    var buffer: [line_bytes_max]u8 = undefined;
    var file_reader = file.reader(init.io, &buffer);
    while (try file_reader.interface.takeDelimiter('\n')) |text| {
        replay.line(text) catch |err| {
            replay.report(err);
            return err;
        };
    }
    replay.finish() catch |err| {
        replay.report(err);
        return err;
    };
    std.debug.print("spec replay: {d} events over {d} configurations agree with the model\n", .{
        replay.events, replay.configs,
    });
}

// Tests.

const testing = std.testing;

fn replay_text(replay: *Replay, text: []const u8) Error!void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |one| try replay.line(one);
    try replay.finish();
}

test "the committed slice of the model's transcript replays against the lookup" {
    const replay = try testing.allocator.create(Replay);
    defer testing.allocator.destroy(replay);
    replay.* = .{};
    replay_text(replay, @embedFile("lookup_gate.txt")) catch |err| {
        replay.report(err);
        return err;
    };
    try testing.expectEqual(@as(usize, 5), replay.configs);
    try testing.expect(replay.events > 2900);
}

test "a line where the lookup answers otherwise than the model is a mismatch" {
    const replay = try testing.allocator.create(Replay);
    defer testing.allocator.destroy(replay);
    replay.* = .{};
    const text = "hops 8\nconfig 1 1 1 udp\n0 init none query_ready 0/0/0/0 E---\n" ++
        "1 poll send_tcp query_ready 0/0/0/0 E---\n";
    try testing.expectError(error.Mismatch, replay_text(replay, text));
    try testing.expectEqual(Out.send_udp, replay.mismatch.?.got_out);
    try testing.expectEqual(@as(usize, 4), replay.mismatch.?.line);
}

test "a line where the lookup's state drifts from the model's is a mismatch, whatever it answers" {
    const replay = try testing.allocator.create(Replay);
    defer testing.allocator.destroy(replay);
    replay.* = .{};
    const text = "hops 8\nconfig 1 1 1 udp\n0 init none query_ready 0/0/0/0 E---\n" ++
        "1 poll send_udp query_ready 0/0/0/0 ----\n";
    try testing.expectError(error.Mismatch, replay_text(replay, text));
    const mismatch = replay.mismatch.?;
    try testing.expectEqualStrings("query_ready 0/0/0/0 E---", mismatch.got_state[0..mismatch.got_state_len]);
}

test "a line in the wrong place, a transcript for other hops, and an empty one are refused" {
    const replay = try testing.allocator.create(Replay);
    defer testing.allocator.destroy(replay);
    const cases = [_]struct { text: []const u8, err: Error }{
        .{ .text = "hops 7\n", .err = error.WrongHops },
        .{ .text = "config 1 1 1 udp\n", .err = error.WrongHops },
        .{ .text = "hops 8\nconfig 1 1 1 udp\n2 poll send_udp query_ready 0/0/0/0 E---\n", .err = error.Malformed },
        .{ .text = "hops 8\nconfig 1 1 1 udp\n1 poll send_udp query_ready 0/0/0/0 E---\n", .err = error.Malformed },
        .{ .text = "hops 8\nconfig 1 1 1 udp\n0 init none\n", .err = error.Malformed },
        .{ .text = "hops 8\nconfig 4 1 1 udp\n", .err = error.Malformed },
        .{ .text = "hops 8\nconfig 1 1 1 carrier-pigeon\n", .err = error.Malformed },
        .{ .text = "hops 8\nconfig 1 1 1\n", .err = error.Malformed },
        .{ .text = "hops 8\nconfig 1 1 1 udp tcp\n", .err = error.Malformed },
        .{ .text = "hops 8\nconfig 1 1 1 udp\n", .err = error.Empty },
    };
    for (cases) |case| {
        replay.* = .{};
        try testing.expectError(case.err, replay_text(replay, case.text));
    }
}
