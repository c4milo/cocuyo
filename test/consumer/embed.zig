//! What a consumer that runs its own loop writes (docs/design.md §24): its rotor, bound into
//! `cocuyo_rotor` by its build, and cocuyo's resolver on that loop beside an operation of its
//! own. Every event goes to the resolver's `apply` first, and to the consumer when `apply` says it
//! is not the resolver's.
//!
//! `zig build consumer-check` builds this and does not run it: what it shows is that the
//! consumer's `rotor.Loop` is the type the resolver takes. The twin's tests show the rest.
const std = @import("std");
const rotor = @import("rotor");
const cocuyo = @import("cocuyo");
const dns = @import("cocuyo_rotor");

const Resolver = dns.Resolver(.{ .lookups = 2, .cache_slots = 2 });

/// The consumer's own tag, which is not the resolver's, in the same high bits of `user_data`.
const own_tag: u64 = Resolver.tag + 1;
/// The consumer's own operations: one timer.
const own_operations = 1;
const loop_options: rotor.Loop.Options = .{ .operations = own_operations + Resolver.loop_operations };
const events_max = 16;
const seed = 1;
const now_ns = 1;

var loop_memory: [rotor.Loop.memory_bytes(loop_options)]u8 align(rotor.memory_alignment) = undefined;
var resolver: Resolver = undefined;

pub fn main() !void {
    var loop: rotor.Loop = undefined;
    try loop.init(&loop_memory, loop_options);
    defer loop.deinit();

    const servers = [_]cocuyo.Server{
        .{ .endpoint = .{ .address = cocuyo.Address.from_v4(.{ 127, 0, 0, 1 }) } },
    };
    const config: cocuyo.Config = .{ .servers = &servers, .search = &.{} };
    // The resolver borrows the consumer's loop; it never makes one.
    try resolver.init(&loop, &config, seed, now_ns);
    defer resolver.deinit();

    const own: rotor.Operation = .{
        .user_data = own_tag << dns.constants.tag_shift,
        .kind = .{ .timer = .{ .after_ns = 1 } },
    };
    var handles: [1]rotor.Handle = undefined;
    _ = loop.submit(&.{own}, &handles);
    _ = try resolver.start(try cocuyo.Question.from_text("example.com.", .a), now_ns);

    var events: [events_max]rotor.Event = undefined;
    const count = try loop.tick(&events, 0);
    var mine: usize = 0;
    for (events[0..count]) |event| {
        if (resolver.apply(event, now_ns)) continue;
        mine += 1;
    }
    resolver.drive(now_ns);
    if (resolver.take(now_ns)) |result| std.debug.print("{any}\n", .{result.handle});
    std.debug.print("{d} of {d} events were the consumer's own\n", .{ mine, count });
}
