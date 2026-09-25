//! chapulin's hooks: the two functions a chapulin object leaves to the image that links it,
//! `ch_rand_bytes` and `ch_assert_fail`. The owner ruled on 2026-09-24 that an image defines them
//! once, for every chapulin object and every user of chapulin it links, and that each is safe to
//! call from several threads at once (docs/design.md §21, §24; chapulin's docs/porting.md).
//!
//! So they live here, in a module of their own that the image binds, rather than in cocuyo's
//! session. A user of chapulin, cocuyo's DoT session or a consumer's own, points `ch_rand_bytes`
//! at its stream with `enter` before a call that can draw, and takes it away with `leave` after.
//! The stream is thread-local, so a thread per core draws each from its own. An image that binds
//! its own module with this surface in place of this one gets no second definition.
//!
//! chapulin draws only during a handshake: when it starts, and once it speaks P-256, when a
//! HelloRetryRequest asks for that group. A draw with no stream entered is a programmer's error,
//! the caller's, and stops the program.
const std = @import("std");
const assert = std.debug.assert;

/// The stream `ch_rand_bytes` draws from on this thread, and null between the calls that can draw.
threadlocal var drawing: ?*std.Random.ChaCha = null;

/// Points `ch_rand_bytes` at `stream` on this thread until `leave`.
pub fn enter(stream: *std.Random.ChaCha) void {
    assert(drawing == null);
    drawing = stream;
}

pub fn leave() void {
    assert(drawing != null);
    drawing = null;
}

export fn ch_rand_bytes(bytes: [*]u8, count: usize) void {
    const stream = drawing orelse @panic("chapulin drew randomness outside a handshake");
    stream.fill(bytes[0..count]);
}

export fn ch_assert_fail(condition: [*:0]const u8, file: [*:0]const u8, line: c_int) noreturn {
    std.debug.panic("chapulin: {s} at {s}:{d}", .{ condition, file, line });
}

// Tests.

const testing = std.testing;
const seed_bytes = std.Random.ChaCha.secret_seed_length;
const drawn_bytes = 32;

/// What `ch_rand_bytes` gives with `stream` entered, as chapulin would call it.
fn drawn_with(stream: *std.Random.ChaCha) [drawn_bytes]u8 {
    var bytes: [drawn_bytes]u8 = undefined;
    enter(stream);
    defer leave();
    ch_rand_bytes(&bytes, bytes.len);
    return bytes;
}

test "a draw comes from the stream entered, and each user's from its own" {
    var first = std.Random.ChaCha.init(@splat(1));
    var second = std.Random.ChaCha.init(@splat(2));
    var first_copy = std.Random.ChaCha.init(@splat(1));
    var second_copy = std.Random.ChaCha.init(@splat(2));
    var expected: [drawn_bytes]u8 = undefined;
    first_copy.fill(&expected);
    try testing.expectEqualSlices(u8, &expected, &drawn_with(&first));
    second_copy.fill(&expected);
    try testing.expectEqualSlices(u8, &expected, &drawn_with(&second));
    try testing.expectEqual(@as(?*std.Random.ChaCha, null), drawing);
}

/// One thread's draw, from a stream of its own, entered while another thread holds another.
fn draw_on_thread(seed: [seed_bytes]u8, out: *[drawn_bytes]u8) void {
    var stream = std.Random.ChaCha.init(seed);
    out.* = drawn_with(&stream);
}

test "a thread draws from its own stream while another thread has entered a different one" {
    var mine = std.Random.ChaCha.init(@splat(3));
    enter(&mine);
    var theirs: [drawn_bytes]u8 = undefined;
    const thread = try std.Thread.spawn(.{}, draw_on_thread, .{ @as([seed_bytes]u8, @splat(4)), &theirs });
    thread.join();
    leave();
    var expected_stream = std.Random.ChaCha.init(@splat(4));
    var expected: [drawn_bytes]u8 = undefined;
    expected_stream.fill(&expected);
    try testing.expectEqualSlices(u8, &expected, &theirs);
}
