//! A stream's messages (docs/design.md §19 step 13, the stream's rule 11). A stream carries no
//! message boundaries, so each message is a two-octet length and that many octets after it (RFC
//! 1035 §4.2.2). A connection takes each chunk whole into its frame, and hands every whole message
//! in the frame to the table before the chunk's event ends. Split out of `io_tcp.zig` by the
//! file-length rule.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const constants = @import("constants.zig");
const limits = @import("limits.zig");
const tcp = @import("io_tcp.zig");
const tls_module = @import("io_tls.zig");

/// One chunk of a connection's stream: taken whole, and every whole message it ends handed over.
pub fn take_chunk(self: anytype, at: u8, event: rotor.Event, count: u32, now_ns: u64) void {
    const connection = &self.connections[at];
    const buffer = self.loop.provided_buffer(constants.tcp_group_id, event.flags.buffer_id);
    const chunk = buffer[0..count];
    // Over TLS the chunk is records, which the session opens into the frame (§21, TLS rule 7).
    if (tls_module.speaks(self)) {
        tls_module.take(self, at, chunk, now_ns);
        self.loop.give_back_buffer(constants.tcp_group_id, event.flags.buffer_id);
        return;
    }
    // The frame holds a partial message at most, and room for a chunk past it (rule 11). `deliver`
    // handed over every whole message, and failed a prefix that says more than `message_bytes`.
    assert(chunk.len <= limits.tcp_chunk_bytes_max);
    assert(connection.used + chunk.len <= connection.frame.len);
    @memcpy(connection.frame[connection.used..][0..chunk.len], chunk);
    connection.used += chunk.len;
    self.loop.give_back_buffer(constants.tcp_group_id, event.flags.buffer_id);
    _ = deliver(self, at, now_ns);
}

/// Hands over every whole message the frame holds, oldest first, and keeps the partial message
/// after them. So no message waits for a chunk that may not come (the stream's rule 11). False
/// when a prefix says more than the connection assembles, which ends the connection.
pub fn deliver(self: anytype, at: u8, now_ns: u64) bool {
    const connection = &self.connections[at];
    const from = self.config.servers[connection.server].tcp_endpoint();
    const prefix = cocuyo.constants.tcp_prefix_bytes;
    var start: usize = 0;
    var delivered: usize = 0;
    while (delivered < limits.tcp_messages_per_frame_max) : (delivered += 1) {
        // That message can never be whole, and the stream cannot be read past it: the connection
        // is no good to anybody.
        if (too_long(connection, start)) {
            end(self, at, now_ns);
            return false;
        }
        const length = whole_len(connection, start) orelse break;
        _ = self.resolver.on_datagram(connection.frame[start + prefix ..][0..length], from, now_ns);
        start += prefix + length;
    }
    // Each message is at least its prefix, so the bound never leaves a whole message behind.
    assert(whole_len(connection, start) == null and !too_long(connection, start));
    const rest = connection.used - start;
    std.mem.copyForwards(u8, connection.frame[0..rest], connection.frame[start..connection.used]);
    connection.used = rest;
    return true;
}

/// Ends a connection whose stream cannot be read past a message. In the clear it closes at once.
/// Over TLS the peer is still there, so the session says `close_notify` first (§21, TLS rule 5).
fn end(self: anytype, at: u8, now_ns: u64) void {
    if (tls_module.speaks(self)) tls_module.quit(self, at, now_ns) else tcp.fail(self, at, .closed, now_ns);
}

/// Whether the prefix at `start` in the frame says more than the connection assembles.
fn too_long(connection: anytype, start: usize) bool {
    const prefix = cocuyo.constants.tcp_prefix_bytes;
    if (connection.used - start < prefix) return false;
    return cocuyo.message_len(connection.frame[start..][0..prefix]) > @TypeOf(connection.*).message_bytes_max;
}

/// The length of the message at `start` in the frame once all of it has arrived, and null before.
fn whole_len(connection: anytype, start: usize) ?usize {
    const prefix = cocuyo.constants.tcp_prefix_bytes;
    if (connection.used - start < prefix) return null;
    // `usize`, not the `u16` the prefix reads as: with the prefix's two octets a message of
    // 65534 or 65535 octets passes 65535, and a prefix can say either (RFC 1035 §4.2.2).
    const length: usize = cocuyo.message_len(connection.frame[start..][0..prefix]);
    if (connection.used - start < prefix + length) return null;
    return length;
}
