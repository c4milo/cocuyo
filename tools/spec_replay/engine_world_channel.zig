//! The model's channel events, replayed on the engine (spec/tla/engine/EngineChannel.tla,
//! `ChanStep`): what a channel says, queued on the twin's channel (`sim.channel`) and said at the
//! engine's next read, and what a TCP link's send has left (docs/design.md §24, DoH over colibri's
//! client). Split from `engine_world.zig`, which routes these events here.
//!
//! This is developer tooling. It is never linked into the library.
const std = @import("std");
const rotor = @import("rotor");
const io = @import("io");
const world_module = @import("engine_world.zig");

const Error = world_module.Error;

/// What a channel says, as the model names the step: queued on the twin's channel, which says it at
/// the engine's next read and is due at once, so the replay brings that read by firing the engine's
/// timer (EngineChannel.tla, `ChanStep`). A link's step names the link, and the rest the channel.
pub fn step(self: anytype, parts: *std.mem.SplitIterator(u8, .scalar)) Error!void {
    if (comptime !@TypeOf(self.engine).Doh.enabled) return error.Malformed;
    const name = parts.next() orelse return error.Malformed;
    const named = try world_module.number(parts.next());
    const end: rotor.channel.End = .{
        .index = @intCast(try world_module.number(parts.next())),
        .answer = std.mem.eql(u8, parts.next() orelse "", "answer"),
    };
    const link: world_module.Channel.Link = if (named % 2 == 0) .quic else .tcp;
    const said: rotor.channel.Step = if (std.mem.eql(u8, name, "open"))
        .{ .open = link }
    else if (std.mem.eql(u8, name, "close"))
        .{ .close = link }
    else if (std.mem.eql(u8, name, "octets"))
        .{ .octets = link }
    else if (std.mem.eql(u8, name, "newTicket"))
        .{ .ticket = link }
    else if (std.mem.eql(u8, name, "finished"))
        .{ .finished = end }
    else if (std.mem.eql(u8, name, "hold"))
        .{ .hold = end }
    else if (std.mem.eql(u8, name, "closed"))
        .closed
    else
        return error.Malformed;
    const server = switch (said) {
        .open, .close, .octets, .ticket => named / 2,
        else => named,
    };
    self.engine.doh.slots[server].channel.say(said, self.now_ns);
    const Resolver = @TypeOf(self.engine);
    var user_data = Resolver.user_data(.timer, self.engine.timer_generation);
    if (self.engine.timer_handle) |handle| {
        user_data = self.loop.slots[handle.index].user_data;
        self.loop.end(handle.index);
    }
    _ = self.engine.apply(rotor.Event.success(user_data, 0), self.now_ns);
}

/// What is left of the octets a TCP link's send of opening `index` carries, if the opening is still
/// the link's (docs/design.md §24, rule 19, request rule 15). A datagram's send reports none.
pub fn link_left(self: anytype, index: usize) ?u32 {
    if (comptime !@TypeOf(self.engine).Doh.enabled) return null;
    const target = index & io.constants.quic_server_mask;
    if (target % 2 == 0) return null;
    const link = &self.engine.doh.slots[target / 2].links[target % 2];
    const incarnation: u32 = @truncate(index >> io.constants.quic_incarnation_shift);
    if (!link.talks() or link.incarnation != incarnation) return null;
    return link.made - link.sent;
}
