//! The twin's signed tree (docs/design.md §25 step 14): its zones, the names each holds, and the
//! records at them. `sim_signed.zig` answers from it and writes the DNSKEY and DS sets from the
//! keys. Exempt from the magic-numbers rule by name, like every corpus; test-only.
const core = @import("core");
const dnssec = @import("dnssec");
const map = dnssec.fixtures.map;

pub const Zone = enum(u8) { root, example, signed, plain };

/// One zone: its apex, the zone that delegates it, whether it is signed, and its names in
/// canonical order, the apex first (RFC 4034 §6.1).
pub const Info = struct {
    apex: []const u8,
    parent: ?Zone,
    signed: bool,
    nodes: []const Node,
};

/// One name a zone holds.
pub const Node = struct {
    owner: []const u8,
    /// The rdata of the NSEC record at the name: the next owner, then the type bit map (RFC 4034
    /// §4.1). Empty in a zone that is not signed.
    nsec: []const u8 = &.{},
    /// The RRsets at the name, the DNSKEY and DS sets apart.
    sets: []const Set = &.{},
    /// The signed child this name delegates to, whose keys the DS set at the name names.
    delegates: ?Zone = null,
    apex: bool = false,

    pub fn set(self: *const Node, kind: core.Kind) ?*const Set {
        for (self.sets) |*held| if (held.kind == kind) return held;
        return null;
    }
};

pub const Set = struct { kind: core.Kind, records: []const []const u8 };

/// The TTL of every record of the tree, and of every RRSIG.
pub const ttl_seconds: u32 = 3600;

/// The instant the signatures are made for, 2027-01-15T08:00:00Z. A test pins the key store's
/// time of day here.
pub const now_seconds: u32 = 1_800_000_000;
/// The signatures hold from a day before it to 30 days after it, and an expired one ended an hour
/// before it.
pub const inception_seconds: u32 = now_seconds - 86_400;
pub const expiration_seconds: u32 = now_seconds + 30 * 86_400;
pub const expired_seconds: u32 = now_seconds - 3600;

/// The algorithm every key signs with: ECDSA P-256 with SHA-256 (RFC 6605), which the tests'
/// verifier takes.
pub const algorithm: u8 = 13;
/// The DS digest type: SHA-256 (RFC 4509).
pub const digest_type: u8 = 2;

/// The DNSKEY rdata of `zone`'s key `generation`: the Zone Key and SEP flags, protocol 3, the
/// algorithm, and a public key of eight octets that names the zone and the generation.
pub fn key(zone: Zone, generation: u1) *const [12]u8 {
    return &keys[@intFromEnum(zone)][generation];
}

const keys = blk: {
    var all: [zones.len][2][12]u8 = undefined;
    for (&all, 0..) |*zone_keys, zone| {
        for (zone_keys, 0..) |*rdata, generation| {
            rdata.* = .{ 0x01, 0x01, 3, algorithm, zone, generation, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a };
        }
    }
    break :blk all;
};

/// The keys a zone publishes at once: the old and the new, while one replaces the other.
pub const published_max: usize = 2;

/// Where the public key starts in a DNSKEY rdata: after the flags, the protocol and the
/// algorithm (RFC 4034 §2.1).
pub const public_key_at: usize = 4;

/// The longest rdata of the tree, an NSEC record's: what a lie copies to change.
pub const rdata_bytes_max: usize = 64;

/// A zone's SOA: the root as MNAME and RNAME, serial 1, then refresh, retry, expire and a
/// minimum of 300 seconds, the negative TTL (RFC 2308 §5).
const soa = [_]u8{ 0, 0 } ++ [_]u8{ 0, 0, 0, 1, 0, 0, 0x0e, 0x10, 0, 0, 0x02, 0x58, 0, 0x01, 0x51, 0x80, 0, 0, 0x01, 0x2c };
const soa_set = [_]Set{.{ .kind = .soa, .records = &.{&soa} }};

/// The bit maps: the apex of a signed zone, a signed delegation, an unsigned one, and the name
/// that holds the data.
const apex_map = map(&.{ 2, 6, 46, 47, 48 });
const signed_cut_map = map(&.{ 2, 43, 46, 47 });
const plain_cut_map = map(&.{ 2, 46, 47 });
const data_map = map(&.{ 1, 28, 46, 47 });

const root_wire = "\x00";
const example_wire = "\x07example\x00";
const plain_wire = "\x05plain\x07example\x00";
const signed_wire = "\x06signed\x07example\x00";
const www_signed_wire = "\x03www\x06signed\x07example\x00";

pub const address_signed_v4 = [_]u8{ 192, 0, 2, 80 };
pub const address_signed_v6 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 11 ++ [_]u8{0x80};
pub const address_plain_v4 = [_]u8{ 192, 0, 2, 81 };

const root_nodes = [_]Node{
    .{ .owner = ".", .nsec = example_wire ++ apex_map, .sets = &soa_set, .apex = true },
    .{ .owner = "example", .nsec = root_wire ++ signed_cut_map, .delegates = .example },
};

const example_nodes = [_]Node{
    .{ .owner = "example", .nsec = plain_wire ++ apex_map, .sets = &soa_set, .apex = true },
    .{ .owner = "plain.example", .nsec = signed_wire ++ plain_cut_map },
    .{ .owner = "signed.example", .nsec = example_wire ++ signed_cut_map, .delegates = .signed },
};

const signed_nodes = [_]Node{
    .{ .owner = "signed.example", .nsec = www_signed_wire ++ apex_map, .sets = &soa_set, .apex = true },
    .{ .owner = "www.signed.example", .nsec = signed_wire ++ data_map, .sets = &.{
        .{ .kind = .a, .records = &.{&address_signed_v4} },
        .{ .kind = .aaaa, .records = &.{&address_signed_v6} },
    } },
};

const plain_nodes = [_]Node{
    .{ .owner = "plain.example", .sets = &soa_set, .apex = true },
    .{ .owner = "www.plain.example", .sets = &.{.{ .kind = .a, .records = &.{&address_plain_v4} }} },
};

/// The zones, by `Zone`.
pub const zones = [_]Info{
    .{ .apex = ".", .parent = null, .signed = true, .nodes = &root_nodes },
    .{ .apex = "example", .parent = .root, .signed = true, .nodes = &example_nodes },
    .{ .apex = "signed.example", .parent = .example, .signed = true, .nodes = &signed_nodes },
    .{ .apex = "plain.example", .parent = .example, .signed = false, .nodes = &plain_nodes },
};
