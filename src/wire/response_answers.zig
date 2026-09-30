//! What a response's answers are collected into, split from `response.zig`: the addresses, the
//! PTR names or the records kept of every other type, which share storage because one question
//! asks for one type (docs/design.md §9 and §19 step 9).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Name = core.Name;
const Kind = core.Kind;
const Address = core.Address;

/// What was collected. The addresses, the PTR names and the kept records share storage, because
/// one question asks for one type and no response can fill more than one of them
/// (docs/design.md §9 and §19 step 9).
///
/// The chain's name is not here: it is the caller's, passed to `collect` by pointer and left
/// holding the canonical name. A lookup already holds the name it is asking about, so keeping a
/// second copy here would cost 256 octets per lookup slot to say the same thing twice.
pub const Answers = struct {
    /// The type of the question these answers answer. It decides which list in `items` is in use
    /// (`Kind.storage`): addresses for A and AAAA, a name for PTR, raw records for every other
    /// type. The three share memory that does not record which one it holds, so every read checks
    /// this field (docs/design.md §16 decision 34).
    kind: Kind,
    items: Items,
    count: u8,
    /// The smallest TTL over every record used, which is what a cache above cocuyo would honour.
    /// Before any record, the smallest of nothing: `ttl_none`, the largest a TTL can be.
    ttl_seconds: u32,
    /// Whether the chain moved: a CNAME was followed.
    aliased: bool,
    /// How many CNAMEs were followed, counting the ones followed before this message, so a lookup
    /// carries the bound across a chain that spans several responses.
    hops_used: u8,
    /// Whether records were dropped for want of room, here or in the record walk.
    truncated: bool,

    /// An `extern union`, so that changing lists writes `kind` and none of the storage. A bare
    /// union changes its member only by being assigned whole, and a safe build fills every octet
    /// of an assignment to `undefined` with 0xAA (decision 34).
    pub const Items = extern union {
        addresses: [core.constants.addresses_max]Address,
        names: [core.constants.ptr_names_max]Name,
        records: Records,
    };

    /// An empty collection for a question, its list zeroed, so nothing here is ever read
    /// uninitialised. It writes the whole list, so it is for a collection made once, as a cache's
    /// slots are; a collection that answers question after question is `reset`.
    pub fn init(kind: Kind) Answers {
        assert(kind.queryable());
        return .{
            .kind = kind,
            .items = switch (kind.storage()) {
                .names => .{ .names = @splat(Name.root) },
                .addresses => .{ .addresses = @splat(.{ .family = .ipv4, .octets = @splat(0) }) },
                .rdata => .{ .records = Records.empty },
            },
            .count = 0,
            .ttl_seconds = ttl_none,
            .aliased = false,
            .hops_used = 0,
            .truncated = false,
        };
    }

    /// Empties `self` for a question of `kind`, writing `kind` and the counts and none of the
    /// storage: nothing reads past `count`, nor past `used`, which `Records.at` asserts. Clearing
    /// two kilooctets on every response is what §11 measured at 25 ns a parse, and on Linux a
    /// safe build's fill of them stores a byte at a time (decision 34).
    pub fn reset(self: *Answers, kind: Kind) void {
        assert(kind.queryable());
        self.kind = kind;
        if (kind.storage() == .rdata) self.items.records.used = 0;
        self.count = 0;
        self.ttl_seconds = ttl_none;
        self.aliased = false;
        self.hops_used = 0;
        self.truncated = false;
        assert(self.count == 0);
    }

    /// Lowers every TTL by `seconds`, and never below zero: the time an HTTP cache held a DoH
    /// answer is gone from its lifetime (RFC 8484 §5.1).
    pub fn age(self: *Answers, kind: Kind, seconds: u32) void {
        assert(kind == self.kind);
        self.ttl_seconds -|= seconds;
        if (kind.storage() != .rdata) return;
        for (self.items.records.refs[0..self.count]) |*ref| ref.ttl_seconds -|= seconds;
    }

    /// Copies `src` into `dst` for a question of `kind`: the scalars and the storage in use, and
    /// nothing past `count` or `used`, so a cache put costs what the answer holds and not what
    /// the union can hold.
    pub fn assign(dst: *Answers, src: *const Answers, kind: Kind) void {
        assert(kind.queryable());
        assert(src.kind == kind);
        dst.kind = src.kind;
        dst.count = src.count;
        dst.ttl_seconds = src.ttl_seconds;
        dst.aliased = src.aliased;
        dst.hops_used = src.hops_used;
        dst.truncated = src.truncated;
        switch (kind.storage()) {
            .addresses => @memcpy(dst.items.addresses[0..src.count], src.addresses()),
            .names => @memcpy(dst.items.names[0..src.count], src.names()),
            .rdata => {
                const from = src.records();
                assert(from.used <= core.constants.rdata_bytes_max);
                const to = &dst.items.records;
                @memcpy(to.refs[0..src.count], from.refs[0..src.count]);
                @memcpy(to.bytes[0..from.used], from.bytes[0..from.used]);
                to.used = from.used;
            },
        }
    }

    /// The addresses collected for an A or AAAA question.
    pub fn addresses(self: *const Answers) []const Address {
        assert(self.kind.storage() == .addresses);
        assert(self.count <= core.constants.addresses_max);
        return self.items.addresses[0..self.count];
    }

    /// The names collected for a PTR question.
    pub fn names(self: *const Answers) []const Name {
        assert(self.kind.storage() == .names);
        assert(self.count <= core.constants.ptr_names_max);
        return self.items.names[0..self.count];
    }

    /// The records kept for a question of any other type, `count` of them.
    pub fn records(self: *const Answers) *const Records {
        assert(self.kind.storage() == .rdata);
        assert(self.count <= core.constants.records_kept_max);
        return &self.items.records;
    }
};

/// The records of one type that are neither addresses nor PTR names: a reference each into a
/// buffer holding its rdata with every name written out in full (docs/design.md §19 step 9).
pub const Records = extern struct {
    refs: [core.constants.records_kept_max]Ref,
    bytes: [core.constants.rdata_bytes_max]u8,
    /// Octets of `bytes` in use.
    used: u16,

    pub const Ref = extern struct { kind_code: u16, ttl_seconds: u32, offset: u16, len: u16 };

    pub const empty: Records = .{
        .refs = @splat(.{ .kind_code = 0, .ttl_seconds = 0, .offset = 0, .len = 0 }),
        .bytes = @splat(0),
        .used = 0,
    };

    /// The record at `index`, which the owning `Answers.count` bounds.
    pub fn at(self: *const Records, index: usize) Kept {
        assert(index < core.constants.records_kept_max);
        const ref = self.refs[index];
        assert(ref.offset + ref.len <= self.used);
        return .{
            .kind_code = ref.kind_code,
            .ttl_seconds = ref.ttl_seconds,
            .rdata = self.bytes[ref.offset..][0..ref.len],
        };
    }
};

/// One kept record: its type as the octets said it, its TTL, and its rdata, self-contained, for
/// the typed views of `wire.rdata`.
pub const Kept = struct { kind_code: u16, ttl_seconds: u32, rdata: []const u8 };

/// The smallest TTL of no record at all: the largest a TTL, "a 32-bit unsigned integer" (RFC 8767
/// §4), can be, so the first record noted is the smallest so far whatever it is.
pub const ttl_none = std.math.maxInt(u32);

const testing = std.testing;

/// An octet no fill writes: not 0xAA, which a safe build writes over `undefined`, and not zero.
const untouched: u8 = 0x5a;

test "changing lists writes the kind and none of the storage" {
    var answers: Answers = undefined;
    @memset(std.mem.asBytes(&answers.items), untouched);
    answers.reset(.a);
    try testing.expectEqual(Kind.a, answers.kind);
    try testing.expectEqual(@as(u8, 0), answers.count);
    // A switch that assigned the union whole would have written every octet of it
    // (docs/design.md §16 decision 34).
    for (std.mem.asBytes(&answers.items)) |octet| try testing.expectEqual(untouched, octet);
    answers.reset(.mx);
    try testing.expectEqual(Kind.mx, answers.kind);
    try testing.expectEqual(@as(u16, 0), answers.items.records.used);
    for (answers.items.records.bytes) |octet| try testing.expectEqual(untouched, octet);
}

test "copying answers writes what they hold and nothing past it" {
    var from = Answers.init(.a);
    from.items.addresses[0] = Address.from_v4(.{ 192, 0, 2, 1 });
    from.items.addresses[1] = Address.from_v4(.{ 192, 0, 2, 2 });
    from.count = 2;
    var to: Answers = undefined;
    @memset(std.mem.asBytes(&to.items), untouched);
    to.assign(&from, .a);
    try testing.expectEqual(Kind.a, to.kind);
    try testing.expectEqualSlices(u8, std.mem.sliceAsBytes(from.addresses()), std.mem.sliceAsBytes(to.addresses()));
    // A copy that switched lists first would have written the whole union before it.
    const held = 2 * @sizeOf(Address);
    for (std.mem.asBytes(&to.items)[held..]) |octet| try testing.expectEqual(untouched, octet);
}
