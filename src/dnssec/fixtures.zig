//! Hand-written records and a recording `Hash` for the tests of `dnssec`. Exempt from the
//! magic-numbers rule by name, like every corpus (tools/lint/magic_numbers.zig), and test-only.
const std = @import("std");
const core = @import("core");
const wire = @import("wire");
const Name = core.Name;
const dnssec = @import("dnssec.zig");
const Hash = dnssec.Hash;
const canonical = @import("dnssec_canonical.zig");
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
pub fn map(comptime codes: []const u8) [2 + octets_for(codes)]u8 {
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

/// The tests' verifier (docs/design.md §25 step 9). It takes algorithms 5, 7, 8 and 13, and calls
/// a signature valid when it is the 64-bit FNV-1a sum of the signed data, then the public key. A
/// digest of type 1 or 2 is the same sum over its input. No cryptography: a test signs as a
/// server does with `sign`, and any changed octet changes the sum.
pub const Sums = struct {
    state: std.hash.Fnv1a_64 = .init(),
    /// The checks and the digests that ended, for a test to count the work.
    checked: usize = 0,
    digested: usize = 0,

    pub fn verifier(self: *Sums) dnssec.Verifier {
        return .{
            .context = self,
            .checks = checks,
            .digests = digests,
            .check_begin = check_begin,
            .check_end = check_end,
            .digest_begin = begin,
            .digest_end = digest_end,
        };
    }

    fn checks(context: *anyopaque, algorithm: u8) bool {
        _ = context;
        return algorithm == 5 or algorithm == 7 or algorithm == 8 or algorithm == 13;
    }

    fn digests(context: *anyopaque, digest_type: u8) bool {
        _ = context;
        return digest_type == 1 or digest_type == 2;
    }

    /// A signature of another length than a sum's is of a form the algorithm refuses.
    fn check_begin(context: *anyopaque, algorithm: u8, public_key: []const u8, signature: []const u8) ?Hash {
        _ = public_key;
        if (signature.len != @sizeOf(Sum)) return null;
        return begin(context, algorithm);
    }

    fn begin(context: *anyopaque, number: u8) Hash {
        _ = number;
        const self: *Sums = @ptrCast(@alignCast(context));
        self.state = .init();
        return .{ .context = self, .update = update };
    }

    fn update(context: *anyopaque, octets: []const u8) void {
        const self: *Sums = @ptrCast(@alignCast(context));
        self.state.update(octets);
    }

    fn check_end(context: *anyopaque, public_key: []const u8, signature: []const u8) bool {
        const self: *Sums = @ptrCast(@alignCast(context));
        self.checked += 1;
        self.state.update(public_key);
        var sum: Sum = undefined;
        std.mem.writeInt(u64, &sum, self.state.final(), .big);
        return std.mem.eql(u8, &sum, signature);
    }

    fn digest_end(context: *anyopaque, out: *[dnssec.constants.digest_bytes]u8) usize {
        const self: *Sums = @ptrCast(@alignCast(context));
        self.digested += 1;
        std.mem.writeInt(u64, out[0..8], self.state.final(), .big);
        return 8;
    }
};

pub const Sum = [8]u8;

/// The signature `Sums` takes over what `rrsig_head`, an RRSIG's rdata without its signature,
/// signs for `records` at `owner`, under `public_key`. Zero octets when it signs nothing, as a
/// Labels field above the owner's labels does.
pub fn sign(rrsig_head: []const u8, owner: *const Name, kind: core.Kind, records: []const []const u8, public_key: []const u8) Sum {
    var sums: Sums = .{};
    const hash = Sums.begin(&sums, 0);
    canonical.signed_data(rrsig_head, owner, kind, core.constants.class_internet, canonical.Written{ .records = records }, hash) catch
        return @splat(0);
    sums.state.update(public_key);
    var sum: Sum = undefined;
    std.mem.writeInt(u64, &sum, sums.state.final(), .big);
    return sum;
}

/// What an RRSIG says beside its signature. The defaults are RFC 4035 Appendix A's: algorithm 5,
/// 3600 seconds, the dates 2004-05-09T18:36:19Z and 2004-04-09T18:36:19Z, key 38519, signer
/// `example`. Labels null counts the owner's.
pub const Signing = struct {
    /// The type covered, when it is not the RRset's.
    covered: ?core.Kind = null,
    /// The TTL of the RRSIG record itself.
    ttl: u32 = 3600,
    algorithm: u8 = 5,
    labels: ?u8 = null,
    original_ttl: u32 = 3600,
    expiration: u32 = 1084127779,
    inception: u32 = 1081535779,
    key_tag: u16 = 38519,
    signer: []const u8 = "example",
    public_key: []const u8,
    /// Octets of the sum to leave out of the signature, which makes its form one the tests'
    /// verifier refuses.
    cut: usize = 0,
};

/// A response built record by record, its names written in full, as a test's server sends it.
pub const message_bytes_max: usize = 4096;

pub const Builder = struct {
    bytes: [message_bytes_max]u8 = undefined,
    len: usize = 0,
    counts: [2]u16 = .{ 0, 0 },
    section: usize = 0,

    /// A response to `question` of `kind`: QR, AA and RCODE `rcode`, and one question.
    pub fn init(question: []const u8, kind: core.Kind, rcode: u4) Builder {
        return init_name(&(Name.from_text(question) catch unreachable), kind, rcode);
    }

    /// A response to `question` as written, its case kept.
    pub fn init_name(question: *const Name, kind: core.Kind, rcode: u4) Builder {
        var self: Builder = .{};
        const header = [_]u8{ 0x12, 0x34, 0x84, rcode, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
        self.put(&header);
        self.put(question.wire());
        self.put_u16(kind.code());
        self.put_u16(core.constants.class_internet);
        return self;
    }

    /// Records from here on go to the authority section.
    pub fn authority(self: *Builder) void {
        self.section = 1;
    }

    pub fn record(self: *Builder, owner: []const u8, kind: core.Kind, ttl: u32, rdata: []const u8) void {
        self.record_wire((Name.from_text(owner) catch unreachable).wire(), kind, ttl, rdata);
    }

    /// A record whose owner is written as `owner` holds it, a compression pointer allowed.
    pub fn record_wire(self: *Builder, owner: []const u8, kind: core.Kind, ttl: u32, rdata: []const u8) void {
        self.put(owner);
        self.put_u16(kind.code());
        self.put_u16(core.constants.class_internet);
        self.put_u32(ttl);
        self.put_u16(@intCast(rdata.len));
        self.put(rdata);
        self.counts[self.section] += 1;
    }

    /// The records of `records` at `owner`, then an RRSIG over them by `signing`.
    pub fn rrset(self: *Builder, owner: []const u8, kind: core.Kind, records: []const []const u8, signing: Signing) void {
        for (records) |rdata| self.record(owner, kind, 3600, rdata);
        self.rrsig(owner, kind, records, signing);
    }

    /// An RRSIG at `owner` over `records`, the RRset of `kind` there, by `signing`.
    pub fn rrsig(self: *Builder, owner: []const u8, kind: core.Kind, records: []const []const u8, signing: Signing) void {
        self.rrsig_name(&(Name.from_text(owner) catch unreachable), kind, records, signing);
    }

    /// `rrsig` at `owner` as written, its case kept. A wildcard owner's `*` is no label it counts.
    pub fn rrsig_name(self: *Builder, owner_name: *const Name, kind: core.Kind, records: []const []const u8, signing: Signing) void {
        const owner = owner_name.wire();
        var rdata: [64 + 256]u8 = undefined;
        std.mem.writeInt(u16, rdata[0..2], (signing.covered orelse kind).code(), .big);
        rdata[2] = signing.algorithm;
        rdata[3] = signing.labels orelse owner_name.label_count() - @intFromBool(owner[0] == 1 and owner[1] == '*');
        std.mem.writeInt(u32, rdata[4..8], signing.original_ttl, .big);
        std.mem.writeInt(u32, rdata[8..12], signing.expiration, .big);
        std.mem.writeInt(u32, rdata[12..16], signing.inception, .big);
        std.mem.writeInt(u16, rdata[16..18], signing.key_tag, .big);
        const signer = (Name.from_text(signing.signer) catch unreachable).wire();
        @memcpy(rdata[18..][0..signer.len], signer);
        const head = 18 + signer.len;
        const sum = sign(rdata[0..head], owner_name, kind, records, signing.public_key);
        @memcpy(rdata[head..][0..sum.len], &sum);
        self.record_wire(owner, .rrsig, signing.ttl, rdata[0 .. head + sum.len - signing.cut]);
    }

    pub fn message(self: *Builder) []const u8 {
        std.mem.writeInt(u16, self.bytes[6..8], self.counts[0], .big);
        std.mem.writeInt(u16, self.bytes[8..10], self.counts[1], .big);
        return self.bytes[0..self.len];
    }

    fn put(self: *Builder, octets: []const u8) void {
        @memcpy(self.bytes[self.len..][0..octets.len], octets);
        self.len += octets.len;
    }

    fn put_u16(self: *Builder, value: u16) void {
        var octets: [2]u8 = undefined;
        std.mem.writeInt(u16, &octets, value, .big);
        self.put(&octets);
    }

    fn put_u32(self: *Builder, value: u32) void {
        var octets: [4]u8 = undefined;
        std.mem.writeInt(u32, &octets, value, .big);
        self.put(&octets);
    }
};

/// A DS rdata under the tests' digest: tag, algorithm, type and the 8 octets of `Sums`.
pub const DsRdata = [12]u8;

/// The DS of `key` at `owner`, of `algorithm` and `digest_type`, under the tests' digest.
pub fn ds_of(owner: *const Name, key: []const u8, algorithm: u8, digest_type: u8) DsRdata {
    var sums: Sums = .{};
    const verifier = sums.verifier();
    const hash = verifier.digest_begin(verifier.context, digest_type);
    dnssec.ds_input(owner, key, hash);
    var digest: [dnssec.constants.digest_bytes]u8 = undefined;
    _ = verifier.digest_end(verifier.context, &digest);
    var rdata: DsRdata = undefined;
    std.mem.writeInt(u16, rdata[0..2], dnssec.key_tag(key), .big);
    rdata[2] = algorithm;
    rdata[3] = digest_type;
    @memcpy(rdata[4..], digest[0..8]);
    return rdata;
}

/// An RSA/SHA-256 zone key's rdata, its exponent 65537 and a modulus of `modulus_bytes` octets.
pub fn rsa_key(comptime modulus_bytes: usize) [4 + 4 + modulus_bytes]u8 {
    return [_]u8{ 0x01, 0x00, 3, 8, 3, 1, 0, 1 } ++ [_]u8{0xc1} ** modulus_bytes;
}

/// An RRSIG over an A set by `key`, signer `example`, with a signature of `signature_bytes`.
pub fn rsa_rrsig(out: []u8, key: []const u8, signature_bytes: usize) !wire.rdata.Rrsig {
    const signer = "\x07example\x00";
    const head = 18;
    std.mem.writeInt(u16, out[0..2], 1, .big);
    out[2] = 8;
    out[3] = 2;
    std.mem.writeInt(u32, out[4..8], 3600, .big);
    std.mem.writeInt(u32, out[8..12], 1084127779, .big);
    std.mem.writeInt(u32, out[12..16], 1081535779, .big);
    std.mem.writeInt(u16, out[16..18], dnssec.key_tag(key), .big);
    @memcpy(out[head..][0..signer.len], signer);
    @memset(out[head + signer.len ..][0..signature_bytes], 0x5a);
    return wire.rdata.Rrsig.parse(out[0 .. head + signer.len + signature_bytes]);
}
