//! What an engine example validates under, with the word `dnssec` and an anchor file on its
//! command line (docs/design.md §25 step 15, §17 questions 96, 97 and 102). The plain DNS, DoT,
//! DoQ and DoH examples share it.
//!
//! Without the word, an example validates nothing, as a consumer that never calls `use_trust`.
//!
//! With the word, the next argument names a file of DS and DNSKEY records in zone-file form, as
//! `cocuyo.trust_anchors.parse` reads them. The root's DS records are the usual anchors. The
//! example then validates every lookup from those anchors down, over `cocuyo_dnssec`'s verifier,
//! which is chapulin's cryptography. Each answer says `secure` or `insecure`, and a failure the
//! validator refused says `Bogus`.
//!
//! The word comes after `cpu`, where an example takes that word, and before the names.
//!
//! What cocuyo does not read, the example hands in (§25, Time): the wall clock, for the dates of
//! the signatures, and the memory of the key store.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const verifier = @import("cocuyo_dnssec");

/// The word that turns validation on. A lookup of the one-label name `dnssec` is written
/// `dnssec.`, with the root's dot.
pub const word = "dnssec";

/// The largest anchor file the example reads. The root's anchors take a few hundred octets.
const file_bytes_max = 16384;

/// What the command line says after the words before this one: the anchor file, when the word
/// came first, and the arguments after it.
pub const Command = struct {
    anchor_path: ?[]const u8,
    operands: []const [:0]const u8,
};

/// Reads the word from `operands`. Only the first operand can be the word, and only when it is
/// the word exactly and a file follows it.
pub fn read(operands: []const [:0]const u8) Command {
    const given: Command = if (operands.len >= 2 and std.mem.eql(u8, operands[0], word))
        .{ .anchor_path = operands[1], .operands = operands[2..] }
    else
        .{ .anchor_path = null, .operands = operands };
    assert(given.operands.len <= operands.len);
    return given;
}

/// The key store and the memory it names: the anchors, their rdata, the entries and the verifier.
/// Started in place, since the store names the memory beside it, and it must not move once
/// started.
pub const Trust = struct {
    anchors: [cocuyo.trust_anchors.anchors_max]cocuyo.Anchor = undefined,
    rdata: [cocuyo.trust_anchors.anchors_max * cocuyo.limits.rdata_bytes_max]u8 = undefined,
    entries: [cocuyo.constants.key_store_zones_default]cocuyo.KeyStore.Entry = undefined,
    chapulin: verifier.Chapulin = .{},
    store: cocuyo.KeyStore = undefined,

    /// Reads the anchors from the file at `path`, and starts the store: the time of day is
    /// `unix_seconds` at `now_ns`. Returns the store for `use_trust`.
    pub fn open(self: *Trust, io: std.Io, arena: std.mem.Allocator, path: []const u8, clock: cocuyo.Clock) !*cocuyo.KeyStore {
        const text = try std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(file_bytes_max));
        const anchors = try cocuyo.trust_anchors.parse(text, &self.anchors, &self.rdata);
        assert(anchors.len >= 1);
        self.chapulin = .{};
        self.store.init(&self.entries, anchors, self.chapulin.verifier(), self.chapulin.hasher(), clock);
        return &self.store;
    }
};

// Tests.

const testing = std.testing;

test "the word takes the file after it, and only first" {
    // The store over chapulin compiles, and with it the image's one hook.
    _ = &Trust.open;
    const with = [_][:0]const u8{ "dnssec", "root.ds", "example.com", "9.9.9.9" };
    const given = read(&with);
    try testing.expectEqualStrings("root.ds", given.anchor_path.?);
    try testing.expectEqual(@as(usize, 2), given.operands.len);
    const without = [_][:0]const u8{ "example.com", "dnssec", "root.ds" };
    try testing.expectEqual(@as(?[]const u8, null), read(&without).anchor_path);
    try testing.expectEqual(@as(usize, 3), read(&without).operands.len);
    // The word alone, with no file after it, is a name to ask for.
    const alone = [_][:0]const u8{"dnssec"};
    try testing.expectEqual(@as(?[]const u8, null), read(&alone).anchor_path);
}
