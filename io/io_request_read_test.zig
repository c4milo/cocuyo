//! The engine reads a request transport after it moves (docs/design.md §24, request rule 17): a
//! request the transport holds back because the connection's stream identifiers have run out
//! drains the connection in the drive that took it, and is answered on a new one. The replay's
//! walks hold the rest of the rule: what the transport held while a send was in flight is told at
//! the send's end.
const std = @import("std");
const testing = std.testing;
const tcp_test = @import("io_request_tcp_test.zig");
const sim_test = @import("io_sim_test.zig");
const question = sim_test.question;

test "a request held back for want of stream identifiers drains its connection at once, and is answered on a new one" {
    // "A client that is unable to establish a new stream identifier can establish a new
    // connection for new streams" (RFC 9113 §5.1.1).
    var rig: tcp_test.Rig = .{};
    try tcp_test.start(&rig, 190, .{ .{}, .{} }, 0);
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    const connection = &rig.engine.h2.connections[0];
    try testing.expect(connection.state == .up);
    connection.transport.inner.spent = true;
    _ = try rig.engine.start(question("example.org."), rig.loop.now());
    // The take asked for the stream, was refused, and read the transport's GOAWAY: the connection,
    // with no stream on it, closes, and the request waits for the new one (request rules 13 and
    // 17).
    try testing.expect(connection.state == .closing);
    try testing.expectEqual(@as(u16, 1), connection.queue_len);
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expect(connection.state == .up and !connection.transport.inner.spent);
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}
