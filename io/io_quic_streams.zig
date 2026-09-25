//! The streams of one of `cocuyo_quic`'s connections (docs/design.md §24, colibri under the request
//! interface). colibri reads a request's bytes through a stream provider at every send that
//! carries them, retransmissions included, until the server has them all or the stream is reset,
//! so each request is copied here and kept that long, whatever the engine's slot does meanwhile.
//! An answer and a reset are read off each stream's state, and told once. A stream the engine
//! cancelled is read to its end, or past the server's reset, and tells nobody: colibri frees its
//! place in the table only once both of its halves have ended.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const quic = @import("quic");
const constants = @import("io_quic_constants.zig");

const StreamId = quic.stream.StreamId;
const send = quic.connection_stream_send;
const read = quic.connection_stream_read;

/// What a stream said: its answer, `len` octets long, which the call copied as far as `out` held,
/// or its reset.
pub const Said = union(enum) { answered: struct { stream: u64, len: usize }, reset: u64 };

/// One request's stream: its bytes, kept while colibri may read them, and what it has told. A DoQ
/// request is a query and its prefix, and a DoH one the HEADERS frame of a GET.
pub fn Slot(comptime bytes_max: usize) type {
    return struct {
        live: bool = false,
        id: u64 = 0,
        len: u16 = 0,
        bytes: [bytes_max]u8 = undefined,
        /// The engine heard the stream's end, or cancelled the stream: it is nobody's to tell.
        told: bool = false,
        cancelled: bool = false,
        /// colibri reads its bytes no more: the server has them all, or the stream was reset.
        sent: bool = false,
    };
}

pub fn Streams(comptime capacity: u16, comptime bytes_max: usize) type {
    return struct {
        const Self = @This();

        slots: [capacity]Slot(bytes_max) = @splat(.{}),

        /// The provider colibri reads each request's bytes through.
        pub fn provider(self: *Self) quic.stream.stream_provider.StreamProvider {
            return .{ .context = self, .vtable = &vtable };
        }

        const vtable: quic.stream.stream_provider.VTable = .{ .read = read_bytes };

        fn read_bytes(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
            const self: *Self = @ptrCast(@alignCast(context));
            return provide(&self.slots, stream_id, offset, output);
        }

        pub fn open(self: *Self, connection: *quic.Connection, bytes: []const u8) error{Failed}!?u64 {
            return open_stream(&self.slots, connection, bytes);
        }

        pub fn cancel(self: *Self, connection: *quic.Connection, stream_id: u64) void {
            cancel_stream(&self.slots, connection, stream_id);
        }

        pub fn next(self: *Self, connection: *quic.Connection, out: []u8) ?Said {
            return next_said(&self.slots, connection, out);
        }

        /// A slot for a stream `h3` opens, or null when every one is taken.
        pub fn free(self: *Self) ?*Slot(bytes_max) {
            for (&self.slots) |*slot| if (!slot.live) return slot;
            return null;
        }

        /// The stream `h3` ended or reset, which the engine hears once: nobody's to tell again.
        pub fn tell(self: *Self, stream_id: u64) void {
            const slot = slot_of(&self.slots, stream_id) orelse return;
            slot.told = true;
            release_if_done(slot);
        }

        /// A stream `h3` cancelled: its reset ends what colibri reads of it (RFC 9000 §3.1).
        pub fn cancelled(self: *Self, stream_id: u64) void {
            const slot = slot_of(&self.slots, stream_id) orelse return;
            slot.cancelled = true;
            slot.sent = true;
            release_if_done(slot);
        }

        /// Frees each slot whose stream has been told and whose bytes colibri reads no more.
        /// Over DoH `h3` reads the streams, so only their sending halves are read here.
        pub fn sweep(self: *Self, connection: *quic.Connection) void {
            for (&self.slots) |*slot| {
                if (!slot.live) continue;
                if (sending_ended(connection, slot.id)) slot.sent = true;
                release_if_done(slot);
            }
        }
    };
}

/// Whether colibri reads stream `stream_id`'s bytes no more: the server has them all, or the
/// stream was reset, or it is gone (RFC 9000 §3.1).
fn sending_ended(connection: *quic.Connection, stream_id: u64) bool {
    return switch (connection.streams.lookup(.{ .value = stream_id })) {
        .live => |stream| switch (stream.sending.state) {
            .data_recvd, .reset_sent, .reset_recvd => true,
            else => false,
        },
        .closed, .unopened => true,
    };
}

/// The octets of stream `stream_id`'s request from `offset`, as many as fit.
fn provide(slots: anytype, stream_id: u64, offset: u64, output: []u8) usize {
    const slot = slot_of(slots, stream_id) orelse return 0;
    if (offset >= slot.len) return 0;
    const left = slot.bytes[@intCast(offset)..slot.len];
    const written = @min(left.len, output.len);
    @memcpy(output[0..written], left[0..written]);
    return written;
}

fn slot_of(slots: anytype, stream_id: u64) ?*std.meta.Elem(@TypeOf(slots)) {
    for (slots) |*slot| {
        if (slot.live and slot.id == stream_id) return slot;
    }
    return null;
}

/// A new stream carrying `bytes`, then FIN (RFC 9250 §4.2). Null when every slot is taken, or the
/// server's stream credit or colibri's table has no room for one yet.
fn open_stream(slots: anytype, connection: *quic.Connection, bytes: []const u8) error{Failed}!?u64 {
    assert(bytes.len <= cocuyo.constants.query_bytes_max);
    const slot = for (slots) |*slot| {
        if (!slot.live) break slot;
    } else return null;
    const id = send.open(connection, .bidirectional) catch |err| switch (err) {
        error.StreamLimitReached, error.Full => return null,
        error.IdentifiersExhausted => return error.Failed,
    };
    slot.* = .{ .live = true, .id = id.value, .len = @intCast(bytes.len) };
    @memcpy(slot.bytes[0..bytes.len], bytes);
    send.supply(connection, id, bytes.len, true) catch return error.Failed;
    return id.value;
}

/// STOP_SENDING and a reset, with DOQ_REQUEST_CANCELLED (RFC 9250 §4.3.1). A half that has ended
/// already refuses its frame, which changes nothing.
fn cancel_stream(slots: anytype, connection: *quic.Connection, stream_id: u64) void {
    const slot = slot_of(slots, stream_id) orelse return;
    const id: StreamId = .{ .value = stream_id };
    slot.cancelled = true;
    send.stop_sending(connection, id, constants.doq_request_cancelled) catch {};
    send.reset(connection, id, constants.doq_request_cancelled) catch {};
    slot.sent = true;
}

/// The first stream that has something to tell: an answer whole, or a reset. Cancelled streams are
/// drained on the way.
fn next_said(slots: anytype, connection: *quic.Connection, out: []u8) ?Said {
    for (slots) |*slot| {
        if (!slot.live) continue;
        const said = hear(connection, slot, out);
        release_if_done(slot);
        if (said) |told| return told;
    }
    return null;
}

fn release_if_done(slot: anytype) void {
    if ((slot.told or slot.cancelled) and slot.sent) slot.live = false;
}

fn hear(connection: *quic.Connection, slot: anytype, out: []u8) ?Said {
    const id: StreamId = .{ .value = slot.id };
    const stream = switch (connection.streams.lookup(id)) {
        .live => |stream| stream,
        // Both halves ended, which a stream the engine was not told of cannot do.
        .closed, .unopened => {
            slot.sent = true;
            if (slot.told or slot.cancelled) return null;
            slot.told = true;
            return .{ .reset = slot.id };
        },
    };
    switch (stream.sending.state) {
        .data_recvd, .reset_sent, .reset_recvd => slot.sent = true,
        else => {},
    }
    if (slot.told) return null;
    return switch (stream.receiving.state) {
        .data_recvd => answer(connection, slot, stream.receiving.final_size.?, out),
        .reset_recvd => ended(connection, slot),
        else => null,
    };
}

/// The whole answer, copied as far as `out` holds, which ends the stream's receiving half (RFC 9000
/// §3.2, "Data Read"). An answer longer than `out` fails the engine's connection, so what is past
/// it is never read.
fn answer(connection: *quic.Connection, slot: anytype, final_size: u64, out: []u8) ?Said {
    assert(out.len >= 1);
    const id: StreamId = .{ .value = slot.id };
    const window = out[0..@intCast(@min(out.len, @max(final_size, 1)))];
    _ = read.read(connection, id, window) catch return ended(connection, slot);
    slot.told = true;
    if (slot.cancelled) return null;
    return .{ .answered = .{ .stream = slot.id, .len = @intCast(final_size) } };
}

/// The server reset the stream: one read reports it, which ends the receiving half (RFC 9000
/// §3.2, "Reset Read").
fn ended(connection: *quic.Connection, slot: anytype) ?Said {
    var nothing: [1]u8 = undefined;
    _ = read.read(connection, .{ .value = slot.id }, &nothing) catch {};
    slot.told = true;
    if (slot.cancelled) return null;
    return .{ .reset = slot.id };
}
