//! The message a receive of the replay brings for a lookup: one whole frame on a stream, and one
//! datagram on a socket. Split from `engine_world.zig` by the file-length rule.
const std = @import("std");
const cocuyo = @import("cocuyo");
const core = @import("core");
const rotor = @import("rotor");
const io = @import("io");
const fixtures = @import("fixtures.zig");
const world_module = @import("engine_world.zig");
const earlier_world = @import("engine_world_earlier.zig");

const Error = world_module.Error;
const operation = world_module.operation;
const origin_of = world_module.origin_of;
const kind_of = world_module.kind_of;

/// A message on the receive `op` names by its token, for the lookup in `slot`: on a stream, one whole
/// frame, length and all, in one buffer of the stream's group (RFC 7766 §8); on a socket, one
/// datagram from its server, laid out in the datagram group as rotor lays one out.
pub fn message(self: anytype, op: []const u8, slot: usize, reply: fixtures.Reply, earlier: bool) Error!void {
    const loop_slot = try operation(self, op);
    const user_data = self.loop.slots[loop_slot].user_data;
    const current = self.engine.resolver.lookup_of(self.engine.handles[slot]);
    // An earlier try's message is built from that try (`engine_world_earlier.zig`).
    var viewed: cocuyo.Lookup = undefined;
    if (earlier) viewed = try earlier_world.view(self, current, kind_of(self, user_data) orelse return error.Malformed, user_data);
    const lookup = if (earlier) &viewed else current;
    var body_buffer: [io.limits.buffer_bytes_max]u8 = undefined;
    const room = rotor.datagram.payload_capacity(io.limits.buffer_bytes_max, self.loop.group_options);
    const body = if (reply == .cut) fixtures.build_cut(lookup, room, &body_buffer) else fixtures.build(lookup, reply, &body_buffer);
    const kind = kind_of(self, user_data) orelse return error.Malformed;
    // Only a datagram comes cut, and it comes with the kernel's mark (the datagram's rule 6).
    if (reply == .cut and kind != .udp_receive) return error.Malformed;
    const group_id: rotor.BufferGroup = switch (kind) {
        .tcp_receive => self.engine.tcp_group.id,
        .udp_receive => self.engine.group.id,
        else => return error.Malformed,
    };
    const buffer_id = self.loop.groups[@intFromEnum(group_id)].take() orelse return error.NoBuffer;
    const buffer = self.loop.provided_buffer(group_id, buffer_id);
    var length: u32 = undefined;
    if (kind == .tcp_receive) {
        length = stream_frame(self, body, buffer);
    } else {
        const server: u8 = @intCast(origin_of(self, user_data).index);
        const peer = rotor.Network.server_address(server);
        length = rotor.buffers.write_delivery(buffer, self.loop.group_options, &peer, body);
        const metadata = buffer[rotor.constants.prefix_head_bytes..][0..@sizeOf(rotor.datagram.Received)];
        const received: *rotor.datagram.Received = @ptrCast(@alignCast(metadata));
        received.flags.truncated = reply == .cut;
    }
    var event = rotor.Event.success(user_data, length);
    event.flags = .{ .buffer = true, .more = true, .buffer_id = buffer_id };
    _ = self.engine.apply(event, self.now_ns);
}

/// One whole frame, length and all (RFC 7766 §8), and over TLS in a data record of its own
/// (RFC 7858 §3.3).
fn stream_frame(self: anytype, body: []const u8, buffer: []u8) u32 {
    const prefix = core.constants.tcp_prefix_bytes;
    var frame: [512 + prefix]u8 = undefined;
    std.mem.writeInt(u16, frame[0..prefix], @intCast(body.len), .big);
    @memcpy(frame[prefix..][0..body.len], body);
    const framed = frame[0 .. prefix + body.len];
    if (!self.config.uses_tls()) {
        @memcpy(buffer[0..framed.len], framed);
        return @intCast(framed.len);
    }
    return @intCast(rotor.tls.write_record(rotor.constants.tls_content_application, framed, buffer));
}
