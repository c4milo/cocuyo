//! Hand-written records and a recording `Hash` for the tests of `dnssec`. Exempt from the
//! magic-numbers rule by name, like every corpus (tools/lint/magic_numbers.zig), and test-only.
const std = @import("std");
const core = @import("core");
const wire = @import("wire");
const Name = core.Name;
const Hash = @import("dnssec.zig").Hash;
const nsec = @import("dnssec_nsec.zig");
const nsec3 = @import("dnssec_nsec3_proof.zig");
const base32 = @import("dnssec_base32.zig");

/// A `Hash` that keeps what it was fed, for a test to compare.
pub const Recorded = struct {
    octets: [recorded_bytes]u8 = undefined,
    len: usize = 0,

    pub fn hash(self: *Recorded) Hash {
        return .{ .context = self, .update = update };
    }

    fn update(context: *anyopaque, octets: []const u8) void {
        const self: *Recorded = @ptrCast(@alignCast(context));
        @memcpy(self.octets[self.len..][0..octets.len], octets);
        self.len += octets.len;
    }

    pub fn slice(self: *const Recorded) []const u8 {
        return self.octets[0..self.len];
    }
};

/// What a test records: an RRSIG's head and a few records, or a DS digest's input.
const recorded_bytes: usize = 1024;

/// An RRSIG over A, algorithm 13, 2 labels, original TTL 300, signed by `Example.COM`, with a
/// signature of four octets.
pub const rrsig_a = [_]u8{ 0x00, 0x01, 13, 2, 0x00, 0x00, 0x01, 0x2c, 0x5f, 0x00, 0x00, 0x00, 0x5e, 0x00, 0x00, 0x00, 0x12, 0x34 } ++
    "\x07Example\x03COM\x00".* ++ [_]u8{ 0xde, 0xad, 0xbe, 0xef };

/// A type bit map of window 0 that sets the types of `codes`, each below 256 (RFC 4034 §4.1.2).
fn map(comptime codes: []const u8) [2 + octets_for(codes)]u8 {
    var bytes: [2 + octets_for(codes)]u8 = @splat(0);
    bytes[1] = octets_for(codes);
    for (codes) |code| bytes[2 + code / 8] |= @as(u8, 0x80) >> @intCast(code % 8);
    return bytes;
}

fn octets_for(comptime codes: []const u8) u8 {
    var highest: u8 = 0;
    for (codes) |code| highest = @max(highest, code);
    return highest / 8 + 1;
}

/// The maps of RFC 4035 Appendix A's zone, by what they hold. A 1, NS 2, CNAME 5, SOA 6, HINFO 13,
/// MX 15, AAAA 28, DNAME 39, DS 43, RRSIG 46, NSEC 47, DNSKEY 48, NXNAME 128.
pub const ns = map(&.{ 2, 46, 47 });
pub const apex = map(&.{ 2, 6, 15, 46, 47, 48 });
pub const address = map(&.{ 1, 46, 47 });
pub const alias = map(&.{ 5, 46, 47 });
pub const mail = map(&.{ 15, 46, 47 });
pub const secure_cut = map(&.{ 2, 43, 46, 47 });
pub const everything = map(&.{ 1, 13, 28, 46, 47 });
pub const redirect = map(&.{ 39, 46, 47 });
pub const compact = map(&.{ 46, 47, 128 });
pub const nothing = map(&.{ 46, 47 });

/// An NSEC record at `owner` of RFC 4035 Appendix A's zone, signed by `example.` over its own
/// labels, naming `next` and the types of `types`.
pub fn record(owner: []const u8, next: []const u8, types: []const u8) !nsec.Record {
    const owner_name = try Name.from_text(owner);
    const wildcard: u8 = if (owner[0] == '*') 1 else 0;
    return .{
        .owner = owner_name,
        .signer = try Name.from_text("example"),
        .labels = owner_name.label_count() - wildcard,
        .nsec = .{ .next = try Name.from_text(next), .types = try wire.rdata.TypeBitmaps.parse(types) },
    };
}

/// The name right after `text` in canonical order: a label of one zero octet in front (RFC 9824
/// §3.1).
pub fn epsilon(text: []const u8) !Name {
    var name: Name = Name.empty;
    try name.append_label(&.{0});
    try name.terminate();
    return name.concat(&try Name.from_text(text));
}

/// The maps of RFC 5155 Appendix A's zone, by what they hold. NSEC3 sets no bit for itself, and
/// NSEC3PARAM is 51.
pub const apex3 = map(&.{ 2, 6, 15, 46, 48, 51 });
pub const mail3 = map(&.{ 15, 46 });
pub const secure_cut3 = map(&.{ 2, 43, 46 });
pub const address3 = map(&.{ 1, 46 });
pub const alias3 = map(&.{ 5, 46 });
pub const ns3 = map(&.{ 2, 15, 46 });
pub const redirect3 = map(&.{ 15, 39, 46 });
pub const nxname3 = map(&.{128});

/// RFC 5155 Appendix A's parameters: SHA-1, 12 iterations, and the salt "aabbccdd".
const salt = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
const iterations: u16 = 12;

fn decoded(comptime text: []const u8) nsec3.Hash {
    @setEvalBranchQuota(10_000);
    var out: nsec3.Hash = undefined;
    const written = base32.decode(text, &out).?;
    if (written != out.len) @compileError("not a hash of 20 octets");
    return out;
}

/// An NSEC3 record of RFC 5155 Appendix A's zone at the hash `owner`, signed by `example.`,
/// naming the hash `next`, with the map `types` and the flags `flags`.
pub fn record3(comptime owner: []const u8, comptime next: []const u8, types: []const u8, flags: u8) !nsec3.Record {
    const next_hashed = &struct {
        const bytes = decoded(next);
    }.bytes;
    return .{
        .owner = try Name.from_text(owner ++ ".example"),
        .signer = try Name.from_text("example"),
        .nsec3 = .{
            .hash_algorithm = 1,
            .flags = flags,
            .iterations = iterations,
            .salt = &salt,
            .next_hashed = next_hashed,
            .types = try wire.rdata.TypeBitmaps.parse(types),
        },
    };
}

/// The hashes RFC 5155 Appendix A and B print, by name. A name they print no hash for hashes to
/// zero octets, which no owner of the example matches.
const printed = [_][2][]const u8{
    .{ "example", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom" },
    .{ "ns1.example", "2t7b4g4vsa5smi47k61mv5bv1a22bojr" },
    .{ "x.w.example", "b4um86eghhds6nea196smvmlo4ors995" },
    .{ "c.x.w.example", "0va5bpr2ou0vk0lbqeeljri88laipsfh" },
    .{ "*.x.w.example", "92pqneegtaue7pjatc3l3qnk738c6v5m" },
    .{ "y.w.example", "ji6neoaepv8b5o6k4ev33abha8ht9fgc" },
    .{ "c.example", "4g6p9u5gvfshp30pqecj98b3maqbn1ck" },
    .{ "z.w.example", "qlu7gtfaeh0ek0c05ksfhdpbcgglbe03" },
    .{ "w.example", "k8udemvp1j2f7eg6jebps17vp3n8i58h" },
    .{ "*.w.example", "r53bq7cc2uvmubfu5ocmm6pers9tk9en" },
};

/// A `Hasher` that looks the hash up in `printed`, and requires the name in lowercase and the
/// example's salt and iterations.
pub const Hashes = struct {
    computed: usize = 0,

    pub fn hasher(self: *Hashes) nsec3.Hasher {
        return .{ .context = self, .compute = compute };
    }

    fn compute(context: *anyopaque, name: []const u8, given_salt: []const u8, given_iterations: u16, out: *nsec3.Hash) void {
        const self: *Hashes = @ptrCast(@alignCast(context));
        self.computed += 1;
        std.debug.assert(std.mem.eql(u8, given_salt, &salt) and given_iterations == iterations);
        for (name) |octet| std.debug.assert(!std.ascii.isUpper(octet));
        out.* = @splat(0);
        inline for (printed) |entry| {
            const wire_name = (Name.from_text(entry[0]) catch unreachable).wire();
            if (std.mem.eql(u8, wire_name, name)) out.* = comptime decoded(entry[1]);
        }
    }
};
