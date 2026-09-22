//! The types rotor's surface names, in the shapes rotor gives them (rotor's `core/operation.zig`,
//! `core/event.zig`, `core/handle.zig` and `core/datagram.zig` at the commit cocuyo pins), so
//! the engine compiles against this module as it compiles against rotor (docs/design.md §19
//! step 13, rotor decision 1). Nothing here is behaviour; the loop is `sim_loop.zig`.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

pub const Descriptor = i32;
pub const LoopId = u16;

pub const Message = extern struct {
    payload: u64,
    tag: u32,
    reserved: u32 = 0,
};

pub const Address = extern struct {
    family: Family,
    reserved: u8 = 0,
    port: u16,
    scope_id: u32 = 0,
    bytes: [ipv6_bytes]u8,

    pub const Family = enum(u8) { ipv4 = 4, ipv6 = 6 };
    pub const ipv4_bytes = 4;
    pub const ipv6_bytes = 16;

    pub fn ipv4(octets: [ipv4_bytes]u8, port: u16) Address {
        var address: Address = .{ .family = .ipv4, .port = port, .bytes = @splat(0) };
        address.bytes[0..ipv4_bytes].* = octets;
        return address;
    }

    pub fn ipv6(octets: [ipv6_bytes]u8, port: u16, scope_id: u32) Address {
        return .{ .family = .ipv6, .port = port, .scope_id = scope_id, .bytes = octets };
    }

    pub fn equal(self: *const Address, other: *const Address) bool {
        return self.family == other.family and self.port == other.port and
            std.mem.eql(u8, &self.bytes, &other.bytes);
    }
};

pub const Operation = struct {
    user_data: u64,
    timeout_ns: u64 = 0,
    descriptor_registered: bool = false,
    kind: Kind,

    pub const Code = enum(u8) {
        accept,
        connect,
        receive,
        send,
        shutdown,
        close,
        read,
        write,
        fdatasync,
        timer,
        post,
        nop,
        receive_from,
        send_to,
    };

    pub const Kind = union(Code) {
        accept: Accept,
        connect: Connect,
        receive: Receive,
        send: Send,
        shutdown: Shutdown,
        close: Close,
        read: Read,
        write: Write,
        fdatasync: Fdatasync,
        timer: Timer,
        post: Post,
        nop: void,
        receive_from: ReceiveFrom,
        send_to: SendTo,
    };

    pub const Accept = struct { listener: Descriptor, multishot: bool = false };
    pub const Connect = struct { socket: Descriptor, address: *const Address };
    pub const Receive = struct { socket: Descriptor, target: Target, multishot: bool = false };
    pub const Target = union(enum) { buffer: Buffer, group: u16 };
    pub const Send = struct { socket: Descriptor, buffer: ConstBuffer };
    pub const Shutdown = struct { socket: Descriptor, how: How };
    pub const How = enum(u8) { receive, send, both };
    pub const Close = struct { descriptor: Descriptor };
    pub const Read = struct { file: Descriptor, buffer: Buffer, offset: u64 };
    pub const Write = struct { file: Descriptor, buffer: ConstBuffer, offset: u64 };
    pub const Fdatasync = struct { file: Descriptor };
    pub const Timer = struct { after_ns: u64, repeat_ns: u64 = 0 };
    pub const Post = struct { target: LoopId, message: Message };
    pub const ReceiveFrom = struct { socket: Descriptor, group: u16 };
    pub const SendTo = struct {
        socket: Descriptor,
        buffer: ConstBuffer,
        to: *const Outbound,
    };
    pub const Buffer = struct { bytes: []u8, registered: ?u16 = null };

    // One call per kind, as rotor builds them: the common shape, with the rest set on the
    // result. The parameters are named apart from the kinds, because Zig lets nothing shadow a
    // declaration.

    pub fn accept(user_data: u64, listener: Descriptor, multishot: bool) Operation {
        return .{ .user_data = user_data, .kind = .{ .accept = .{ .listener = listener, .multishot = multishot } } };
    }
    pub fn connect(user_data: u64, socket: Descriptor, address: *const Address) Operation {
        return .{ .user_data = user_data, .kind = .{ .connect = .{ .socket = socket, .address = address } } };
    }
    pub fn receive(user_data: u64, socket: Descriptor, bytes: []u8) Operation {
        return .{ .user_data = user_data, .kind = .{ .receive = .{ .socket = socket, .target = .{ .buffer = .{ .bytes = bytes } } } } };
    }
    pub fn receive_group(user_data: u64, socket: Descriptor, group: u16) Operation {
        return .{ .user_data = user_data, .kind = .{ .receive = .{ .socket = socket, .target = .{ .group = group }, .multishot = true } } };
    }
    pub fn send(user_data: u64, socket: Descriptor, bytes: []const u8) Operation {
        return .{ .user_data = user_data, .kind = .{ .send = .{ .socket = socket, .buffer = .{ .bytes = bytes } } } };
    }
    pub fn shutdown(user_data: u64, socket: Descriptor, how: How) Operation {
        return .{ .user_data = user_data, .kind = .{ .shutdown = .{ .socket = socket, .how = how } } };
    }
    pub fn close(user_data: u64, closing: Descriptor) Operation {
        return .{ .user_data = user_data, .kind = .{ .close = .{ .descriptor = closing } } };
    }
    pub fn read(user_data: u64, file: Descriptor, bytes: []u8, offset: u64) Operation {
        return .{ .user_data = user_data, .kind = .{ .read = .{ .file = file, .buffer = .{ .bytes = bytes }, .offset = offset } } };
    }
    pub fn write(user_data: u64, file: Descriptor, bytes: []const u8, offset: u64) Operation {
        return .{ .user_data = user_data, .kind = .{ .write = .{ .file = file, .buffer = .{ .bytes = bytes }, .offset = offset } } };
    }
    pub fn fdatasync(user_data: u64, file: Descriptor) Operation {
        return .{ .user_data = user_data, .kind = .{ .fdatasync = .{ .file = file } } };
    }
    pub fn timer(user_data: u64, after_ns: u64, repeat_ns: u64) Operation {
        return .{ .user_data = user_data, .kind = .{ .timer = .{ .after_ns = after_ns, .repeat_ns = repeat_ns } } };
    }
    pub fn post(user_data: u64, target: LoopId, message: Message) Operation {
        return .{ .user_data = user_data, .kind = .{ .post = .{ .target = target, .message = message } } };
    }
    pub fn receive_from(user_data: u64, socket: Descriptor, group: u16) Operation {
        return .{ .user_data = user_data, .kind = .{ .receive_from = .{ .socket = socket, .group = group } } };
    }
    pub fn send_to(user_data: u64, socket: Descriptor, bytes: []const u8, to: *const Outbound) Operation {
        return .{ .user_data = user_data, .kind = .{ .send_to = .{ .socket = socket, .buffer = .{ .bytes = bytes }, .to = to } } };
    }
    pub const ConstBuffer = struct { bytes: []const u8, registered: ?u16 = null };

    pub fn code(operation: *const Operation) Code {
        return std.meta.activeTag(operation.kind);
    }

    pub fn descriptor(operation: *const Operation) ?Descriptor {
        // The captures are named apart from the constructors above, which they would shadow.
        return switch (operation.kind) {
            .accept => |kind| kind.listener,
            .connect => |kind| kind.socket,
            .receive => |kind| kind.socket,
            .send => |kind| kind.socket,
            .shutdown => |kind| kind.socket,
            .close => |kind| kind.descriptor,
            .read => |kind| kind.file,
            .write => |kind| kind.file,
            .fdatasync => |kind| kind.file,
            .receive_from => |kind| kind.socket,
            .send_to => |kind| kind.socket,
            .timer, .post, .nop => null,
        };
    }
};

/// Why an event failed, as rotor numbers them: a negative `result` holds the code. Named apart
/// from `Operation.Code` here, where rotor has them in two files; the facade exports it as `Code`.
pub const EventCode = enum(u8) {
    canceled = 1,
    timeout,
    would_block,
    system_resources,
    descriptor_limit,
    connection_reset,
    connection_refused,
    connection_aborted,
    connection_timed_out,
    broken_pipe,
    not_connected,
    network_unreachable,
    input_output,
    no_space_left,
    buffers_exhausted,
    mailbox_full,
    loop_not_found,
    unexpected,
    message_too_long,
    unsupported,
};

pub const Error = error{
    Canceled,
    Timeout,
    WouldBlock,
    SystemResources,
    DescriptorLimit,
    ConnectionReset,
    ConnectionRefused,
    ConnectionAborted,
    ConnectionTimedOut,
    BrokenPipe,
    NotConnected,
    NetworkUnreachable,
    InputOutput,
    NoSpaceLeft,
    BuffersExhausted,
    MailboxFull,
    LoopNotFound,
    MessageTooLong,
    Unsupported,
    Unexpected,
};

pub const Event = extern struct {
    user_data: u64,
    result: i32,
    flags: Flags,

    pub const Flags = packed struct(u32) {
        buffer: bool = false,
        more: bool = false,
        reserved_kernel: u2 = 0,
        message: bool = false,
        reserved: u11 = 0,
        buffer_id: u16 = 0,
    };

    pub fn success(user_data: u64, count: u32) Event {
        assert(count <= constants.transfer_bytes_max);
        return .{ .user_data = user_data, .result = @intCast(count), .flags = .{} };
    }

    pub fn failure(user_data: u64, code: EventCode) Event {
        const event: Event = .{ .user_data = user_data, .result = result_of(code), .flags = .{} };
        assert(event.result < 0);
        return event;
    }

    pub fn is_final(event: Event) bool {
        return !event.flags.more and !event.flags.message;
    }

    pub fn outcome(event: Event) Error!u32 {
        assert(!event.flags.message);
        if (event.result >= 0) return @intCast(event.result);
        return error_of(code_of(event.result));
    }
};

pub fn result_of(code: EventCode) i32 {
    const result = -@as(i32, @intFromEnum(code));
    assert(result < 0);
    return result;
}

pub fn code_of(result: i32) EventCode {
    assert(result < 0);
    return @enumFromInt(@as(u8, @intCast(-result)));
}

pub fn error_of(code: EventCode) Error {
    return switch (code) {
        .canceled => error.Canceled,
        .timeout => error.Timeout,
        .would_block => error.WouldBlock,
        .system_resources => error.SystemResources,
        .descriptor_limit => error.DescriptorLimit,
        .connection_reset => error.ConnectionReset,
        .connection_refused => error.ConnectionRefused,
        .connection_aborted => error.ConnectionAborted,
        .connection_timed_out => error.ConnectionTimedOut,
        .broken_pipe => error.BrokenPipe,
        .not_connected => error.NotConnected,
        .network_unreachable => error.NetworkUnreachable,
        .input_output => error.InputOutput,
        .no_space_left => error.NoSpaceLeft,
        .buffers_exhausted => error.BuffersExhausted,
        .mailbox_full => error.MailboxFull,
        .loop_not_found => error.LoopNotFound,
        .message_too_long => error.MessageTooLong,
        .unsupported => error.Unsupported,
        .unexpected => error.Unexpected,
    };
}

pub const Handle = packed struct(u64) {
    index: u32,
    generation: u32,

    pub const none: Handle = .{ .index = 0, .generation = 0 };

    pub fn is_none(handle: Handle) bool {
        return handle.generation == 0;
    }
};

// Datagrams: the metadata beside a payload, and the group buffer's layout.

pub const Ecn = enum(u8) { not_ect = 0, ect1 = 1, ect0 = 2, ce = 3 };
pub const metadata_bytes = 64;
const addresses = 2;
const described_bytes = @sizeOf(u16) + @sizeOf(Ecn) + @sizeOf(u8);
const reserved_bytes = metadata_bytes - addresses * @sizeOf(Address) - described_bytes;

pub const Received = extern struct {
    peer: Address,
    local: Address,
    segment_bytes: u16,
    ecn: Ecn,
    flags: Flags,
    reserved: [reserved_bytes]u8 = @splat(0),

    pub const Flags = packed struct(u8) {
        local: bool = false,
        ecn: bool = false,
        truncated: bool = false,
        reserved: u5 = 0,
    };
};

pub const Outbound = extern struct {
    peer: Address,
    local: Address,
    segment_bytes: u16,
    ecn: Ecn,
    flags: Flags,
    reserved: [reserved_bytes]u8 = @splat(0),

    pub const Flags = packed struct(u8) {
        peer: bool = false,
        local: bool = false,
        ecn: bool = false,
        reserved: u5 = 0,
    };
};

pub const GroupOptions = struct {
    name_reserve: u32 = constants.name_reserve_default,
    control_reserve: u32 = constants.control_reserve_default,
};

/// The octets before the payload in a group buffer, as rotor lays them out.
pub fn prefix_bytes(options: GroupOptions) u32 {
    assert(options.name_reserve >= @sizeOf(Address));
    const prefix = constants.prefix_head_bytes + options.name_reserve + options.control_reserve;
    assert(prefix < constants.transfer_bytes_max);
    return prefix;
}

pub fn payload_capacity(buffer_bytes: u32, options: GroupOptions) u32 {
    const prefix = prefix_bytes(options);
    assert(buffer_bytes > prefix);
    return buffer_bytes - prefix;
}

pub const Delivery = struct { from: Received, bytes: []u8 };

comptime {
    assert(@sizeOf(Received) == metadata_bytes);
    assert(@sizeOf(Outbound) == metadata_bytes);
    assert(@sizeOf(Handle) == @sizeOf(u64));
    assert(prefix_bytes(.{}) == 192);
}

// Tests.

const testing = std.testing;

test "an event's outcome is its count or its named error" {
    try testing.expectEqual(@as(u32, 7), try Event.success(1, 7).outcome());
    try testing.expectError(error.Canceled, Event.failure(1, .canceled).outcome());
    try testing.expectError(error.ConnectionRefused, Event.failure(1, .connection_refused).outcome());
    try testing.expect(Event.success(1, 0).is_final());
}

test "the prefix and the payload capacity are rotor's" {
    try testing.expectEqual(@as(u32, 2048 - 192), payload_capacity(2048, .{}));
}

test "addresses build and compare" {
    const one = Address.ipv4(.{ 192, 0, 2, 53 }, 53);
    var two = one;
    try testing.expect(one.equal(&two));
    two.port = 54;
    try testing.expect(!one.equal(&two));
}
