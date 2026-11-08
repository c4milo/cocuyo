//! The message for a lookup's open earlier try, which a connection it stays on or the socket that
//! try went out from brings (docs/design.md §5, Tries kept open; §16 decision 66). The model names
//! the receive; the try is the newest open at that receive's server over its transport. Split from
//! `engine_world.zig` by the file-length rule.
const cocuyo = @import("cocuyo");
const io = @import("io");

pub const Error = error{Malformed};

/// The lookup as its open earlier try at the receive's server left it, which the message is built
/// from: that try's id, server, case and cookie.
pub fn view(self: anytype, lookup: *const cocuyo.Lookup, kind: io.Kind, user_data: u64) Error!cocuyo.Lookup {
    const index: usize = @intCast(user_data & io.constants.index_mask);
    const stream = kind == .tcp_receive;
    const server: u8 = if (!stream) @intCast(index & io.constants.receive_index_mask) else server: {
        // An engine with no TCP connection has no stream to receive on.
        if (comptime !@TypeOf(self.engine).keeps_tcp) return error.Malformed;
        break :server self.engine.connections[index & io.constants.tcp_slot_mask].server;
    };
    const at = lookup.earlier_try_at(server, if (stream) .stream else .datagram) orelse return error.Malformed;
    return lookup.viewed_as(at);
}
