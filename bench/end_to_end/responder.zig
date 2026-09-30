//! The responder both stacks are measured against: a process of its own on a loopback datagram
//! socket, which answers every query with one A record for whatever name it asked, so what is
//! measured is the two stacks and the kernel between them, and nothing of a network. A process
//! and not a thread, so that the kernel's counts of the stacks' process (`kernel.zig`) hold none
//! of its calls.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const wire = cocuyo.wire;
const harness = @import("../harness.zig");
const constants = @import("constants.zig");
const udp = @import("udp.zig");

const header_bytes = cocuyo.constants.header_bytes;
const question_fixed_bytes = cocuyo.constants.question_fixed_bytes;

/// What the responder shares with the process that started it, in a page mapped shared before
/// the fork.
const Shared = struct {
    stopping: std.atomic.Value(bool) = .init(false),
    /// Set by the responder once it is in its receive loop. `start` waits for it, because a fork
    /// returns before the child runs: a row that began first had its earliest queries wait in
    /// the socket's buffer until the responder got there, and that start-up delay landed in the
    /// latencies of the first row alone.
    serving: std.atomic.Value(bool) = .init(false),
    /// How many queries were answered. A row that gives up reads it while the responder still
    /// runs: it is what tells a query c-ares never sent from a reply it never took. The responder
    /// counts a reply before it sends it, so a process that has the reply reads a count that holds
    /// it.
    answered: std.atomic.Value(u64) = .init(0),
};

pub const Responder = struct {
    socket: udp.Socket,
    port: u16,
    child: ?std.c.pid_t = null,
    page: []align(std.heap.page_size_min) u8 = &.{},

    /// Forks the responder. Call it before this process starts a thread: the child is a copy of
    /// the thread that forks and of nothing else.
    pub fn start(self: *Responder) !void {
        self.socket = try udp.open(0);
        errdefer udp.close(self.socket);
        self.port = udp.port_of(self.socket);
        self.page = try std.posix.mmap(null, @sizeOf(Shared), .{ .READ = true, .WRITE = true }, .{ .TYPE = .SHARED, .ANONYMOUS = true }, -1, 0);
        errdefer std.posix.munmap(self.page);
        const shared = self.shared_page();
        shared.* = .{};
        const parent = std.c.getpid();
        const pid = std.c.fork();
        if (pid < 0) return error.ForkFailed;
        if (pid == 0) serve(self.socket, shared, parent);
        self.child = pid;
        const deadline = harness.now_ns() + constants.responder_start_ns_max;
        while (!shared.serving.load(.acquire)) {
            if (harness.now_ns() >= deadline) {
                // The `errdefer`s above close the socket and the page; the child is killed here.
                _ = std.c.kill(pid, .KILL);
                _ = std.c.waitpid(pid, null, 0);
                self.child = null;
                return error.ResponderDidNotStart;
            }
            std.atomic.spinLoopHint();
        }
    }

    /// Stops the responder with a datagram to its own socket, waits for it to exit, and closes
    /// the socket and the page.
    pub fn stop(self: *Responder) void {
        self.shared_page().stopping.store(true, .seq_cst);
        const to = udp.loopback(self.port);
        udp.send(self.socket, "stop", &to) catch {};
        if (self.child) |pid| _ = std.c.waitpid(pid, null, 0);
        self.child = null;
        udp.close(self.socket);
        std.posix.munmap(self.page);
    }

    /// How many queries the responder has answered.
    pub fn answered(self: *const Responder) u64 {
        return self.shared_page().answered.load(.monotonic);
    }

    fn shared_page(self: *const Responder) *Shared {
        assert(self.page.len >= @sizeOf(Shared));
        return @ptrCast(@alignCast(self.page.ptr));
    }
};

/// The responder's life: answer until told to stop, or until the process that started it is
/// gone, which a receive that times out finds. Then leave with `_exit`, which runs nothing of
/// the parent's: its exit handlers and its buffers are its own.
fn serve(socket: udp.Socket, shared: *Shared, parent: std.c.pid_t) noreturn {
    udp.receive_timeout(socket, constants.responder_poll_ms);
    var query: [constants.datagram_bytes_max]u8 = undefined;
    var reply: [constants.datagram_bytes_max]u8 = undefined;
    var from: udp.Address = undefined;
    shared.serving.store(true, .release);
    while (!shared.stopping.load(.seq_cst)) {
        const bytes = udp.receive(socket, &query, &from) orelse {
            if (std.c.getppid() != parent) break;
            continue;
        };
        const len = build_reply(bytes, &reply) orelse continue;
        // Counted first. Counted after the send, the reply could reach the asker before the
        // count moved, and a test that read the count as its last reply came found one short.
        _ = shared.answered.fetchAdd(1, .monotonic);
        udp.send(socket, reply[0..len], &from) catch {
            _ = shared.answered.fetchSub(1, .monotonic);
            continue;
        };
    }
    std.c._exit(0);
}

/// The reply to `query`: its header with QR and RA set and the counts of one answer, its
/// question as it came, and one A record owned by the question's name. Null for a datagram that
/// is not a query, which is dropped.
pub fn build_reply(query: []const u8, reply: []u8) ?usize {
    const question_len = question_length(query) orelse return null;
    const copied = header_bytes + question_len;
    @memcpy(reply[0..copied], query[0..copied]);
    var header = wire.header.parse(query) catch return null;
    header.flags = (header.flags | wire.constants.flag_response | wire.constants.flag_recursion_available) &
        ~@as(u16, wire.constants.rcode_mask);
    // qdcount stays one; ancount is one; nothing in the other two sections.
    header.ancount = 1;
    header.nscount = 0;
    header.arcount = 0;
    wire.header.write(&header, reply);
    var at = copied;
    at += write(reply[at..], &constants.record_head);
    at += write(reply[at..], &ttl_octets());
    at += write(reply[at..], &constants.record_rdlength);
    at += write(reply[at..], &constants.answer_v4);
    assert(at <= reply.len);
    return at;
}

fn write(out: []u8, bytes: []const u8) usize {
    @memcpy(out[0..bytes.len], bytes);
    return bytes.len;
}

fn ttl_octets() [4]u8 {
    var octets: [4]u8 = undefined;
    std.mem.writeInt(u32, &octets, constants.answer_ttl_seconds, .big);
    return octets;
}

/// The octets of the question section after the header: the name to its end, then the type and
/// class. Null when the datagram is too short to hold one question.
fn question_length(query: []const u8) ?usize {
    if (query.len < header_bytes) return null;
    const name_end = wire.name.skip(query, header_bytes) catch return null;
    const end = name_end + question_fixed_bytes;
    if (end > query.len) return null;
    return end - header_bytes;
}

// Tests.

const testing = std.testing;

test "a process that has a reply reads a count that holds it" {
    var responder: Responder = .{ .socket = undefined, .port = 0 };
    try responder.start();
    defer responder.stop();
    const socket = try udp.open(0);
    defer udp.close(socket);
    var query: [cocuyo.constants.query_bytes_max]u8 = undefined;
    const len = wire.query.write(&.{ .id = 0x1234, .name = try cocuyo.Name.from_text("h1.example."), .kind = .a }, &query);
    const to = udp.loopback(responder.port);
    var reply: [constants.datagram_bytes_max]u8 = undefined;
    var from: udp.Address = undefined;
    for (0..constants.test_count_exchanges) |exchange| {
        try udp.send(socket, query[0..len], &to);
        _ = udp.receive(socket, &reply, &from) orelse return error.NoReply;
        try testing.expectEqual(@as(u64, exchange + 1), responder.answered());
    }
}
