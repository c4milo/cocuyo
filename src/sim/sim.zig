//! sim: the deterministic twin of rotor's surface (docs/design.md §19 step 13, rotor decision
//! 10). What rotor's facade names, this file names, so the build hands this module to the
//! engine as its `rotor` and the engine runs on a virtual clock, a virtual network and the
//! scripted servers of `sim_server.zig`, driven by one seed. Test-only: nothing a consumer
//! imports reaches it (docs/design.md §2).
const types = @import("sim_types.zig");
const loop_module = @import("sim_loop.zig");
const network = @import("sim_network.zig");

pub const Loop = loop_module.Loop;
pub const Registry = loop_module.Registry;
pub const Remote = loop_module.Remote;
pub const sync = network;
pub const buffers = @import("sim_buffers.zig");
/// The twin's TLS: a session the engine drives in place of chapulin's, and the server side a
/// scripted server answers it with (docs/design.md §21). Real rotor has no such thing, which is
/// how the engine's tests tell the twin from it.
pub const tls = @import("sim_tls.zig");
/// The twin's QUIC: a connection the engine drives in place of colibri's, and the server side a
/// scripted server answers it with (docs/design.md §24).
pub const quic = @import("sim_quic.zig");
pub const files_block = false;
pub const supported = true;

pub const constants = @import("constants.zig");
pub const datagram = struct {
    pub const Outbound = types.Outbound;
    pub const Received = types.Received;
    pub const GroupOptions = types.GroupOptions;
    pub const Delivery = types.Delivery;
    pub const prefix_bytes = types.prefix_bytes;
    pub const payload_capacity = types.payload_capacity;
};
pub const memory_alignment = constants.memory_alignment;
pub const Address = types.Address;
pub const Code = types.EventCode;
pub const Delivery = types.Delivery;
pub const Descriptor = types.Descriptor;
pub const Error = types.Error;
pub const Event = types.Event;
pub const Handle = types.Handle;
pub const LoopId = types.LoopId;
pub const Message = types.Message;
pub const Operation = types.Operation;

/// The scripted servers and the network's tables, for a test to set up and to read.
pub const server = @import("sim_server.zig");
pub const Network = network.Network;

test {
    _ = types;
    _ = loop_module;
    _ = network;
    _ = buffers;
    _ = server;
    _ = tls;
    _ = quic;
    _ = @import("sim_loop_quic.zig");
    _ = @import("sim_scenarios_test.zig");
}
