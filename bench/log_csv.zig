//! The DNS log of Mendeley Data c4n7fckkz3, version 3: a national ISP's primary DNS server over
//! about a day, one row per question, with the injected exfiltration traffic marked (the
//! dataset's `dataset_description.txt`). Each row is comma-separated, and the first five fields
//! are the ones read here: the client's address, anonymised; the registered domain; the time in
//! milliseconds since the epoch; whether the row is attack traffic; and the name asked.
//!
//! Attack rows are dropped: they are traffic someone injected, not a workload a cache serves.
//! Names are folded to lower case, because a DNS name compares without regard to case (RFC 1035
//! §2.3.3, as clarified by RFC 4343), and a trailing dot is dropped. Each name and each client
//! becomes a dense index in order of first appearance, which is what the replays read.
const std = @import("std");
const Id = @import("trace_recording.zig").Id;

/// The longest name read, in text. A name is at most 255 octets on the wire (RFC 1035 §2.3.4),
/// and in text an octet may be written as `\DDD`, four characters for one (RFC 1035 §5.1): the
/// log's tunnelling rows do exactly that.
const name_bytes_max = 4 * 255;

/// The fields a row needs, of the more it carries.
const fields_read = 5;

pub const Row = struct {
    client: []const u8,
    time_ms: u64,
    attack: bool,
    name: []const u8,
};

pub const ParseError = error{Malformed};

/// The first five fields of one line.
pub fn parse_line(line: []const u8) ParseError!Row {
    var fields: [fields_read][]const u8 = undefined;
    var split = std.mem.splitScalar(u8, line, ',');
    for (&fields) |*field| field.* = split.next() orelse return error.Malformed;
    const time_ms = std.fmt.parseInt(u64, fields[2], 10) catch return error.Malformed;
    const attack = if (std.mem.eql(u8, fields[3], "True")) true else if (std.mem.eql(u8, fields[3], "False")) false else return error.Malformed;
    const name = std.mem.trimEnd(u8, fields[4], ".");
    if (fields[0].len == 0 or name.len == 0 or name.len > name_bytes_max) return error.Malformed;
    return .{ .client = fields[0], .time_ms = time_ms, .attack = attack, .name = name };
}

pub const Log = struct {
    /// Per question kept: the name, when, and who asked.
    names: std.ArrayList(Id) = .empty,
    times_ns: std.ArrayList(u64) = .empty,
    clients: std.ArrayList(u32) = .empty,
    /// Per name: a hash of its text, for a TTL the log does not carry.
    name_hashes: std.ArrayList(u64) = .empty,
    name_ids: std.StringHashMapUnmanaged(Id) = .empty,
    client_ids: std.StringHashMapUnmanaged(u32) = .empty,
    attack_rows: usize = 0,
    first_ms: ?u64 = null,
    last_ms: u64 = 0,

    pub const AddError = error{ OutOfMemory, OutOfOrder };

    /// One row: dropped if it is attack traffic, kept otherwise.
    pub fn add(self: *Log, gpa: std.mem.Allocator, row: Row) AddError!void {
        if (row.attack) {
            self.attack_rows += 1;
            return;
        }
        const first = self.first_ms orelse row.time_ms;
        if (row.time_ms < self.last_ms) return error.OutOfOrder;
        self.first_ms = first;
        self.last_ms = row.time_ms;
        var folded: [name_bytes_max]u8 = undefined;
        const name = std.ascii.lowerString(&folded, row.name);
        try self.names.append(gpa, try self.name_id(gpa, name));
        try self.times_ns.append(gpa, (row.time_ms - first) * std.time.ns_per_ms);
        try self.clients.append(gpa, try self.client_id(gpa, row.client));
    }

    pub fn name_count(self: *const Log) usize {
        return self.name_hashes.items.len;
    }

    pub fn client_count(self: *const Log) usize {
        return self.client_ids.count();
    }

    fn name_id(self: *Log, gpa: std.mem.Allocator, name: []const u8) error{OutOfMemory}!Id {
        const entry = try self.name_ids.getOrPut(gpa, name);
        if (entry.found_existing) return entry.value_ptr.*;
        entry.key_ptr.* = try gpa.dupe(u8, name);
        entry.value_ptr.* = @intCast(self.name_hashes.items.len);
        try self.name_hashes.append(gpa, std.hash.Wyhash.hash(0, name));
        return entry.value_ptr.*;
    }

    fn client_id(self: *Log, gpa: std.mem.Allocator, client: []const u8) error{OutOfMemory}!u32 {
        const entry = try self.client_ids.getOrPut(gpa, client);
        if (entry.found_existing) return entry.value_ptr.*;
        entry.key_ptr.* = try gpa.dupe(u8, client);
        entry.value_ptr.* = @intCast(self.client_ids.count() - 1);
        return entry.value_ptr.*;
    }
};

/// The buffer a line is read through: well past the longest row the dataset has.
const line_buffer_bytes = 1 << 16;

/// Reads the log at `path`, keeping every row that is not attack traffic.
pub fn load(io: std.Io, gpa: std.mem.Allocator, path: []const u8) !Log {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var buffer: [line_buffer_bytes]u8 = undefined;
    var file_reader = file.reader(io, &buffer);
    var log: Log = .{};
    while (try file_reader.interface.takeDelimiter('\n')) |line| {
        if (line.len == 0) continue;
        try log.add(gpa, try parse_line(line));
    }
    return log;
}

// Tests.

const testing = std.testing;

test "a row gives its client, its time, its flag and its name, and more fields are ignored" {
    const row = try parse_line("186.169.253.58,spamhaus.org,1624438273058,False,1.2.3.4.zen.spamhaus.org.,18,5");
    try testing.expectEqualStrings("186.169.253.58", row.client);
    try testing.expectEqual(@as(u64, 1624438273058), row.time_ms);
    try testing.expect(!row.attack);
    try testing.expectEqualStrings("1.2.3.4.zen.spamhaus.org", row.name);
    try testing.expect((try parse_line("a,b,1,True,x.example")).attack);
}

test "a row missing a field, with a bad time or flag, or with no name is refused" {
    try testing.expectError(error.Malformed, parse_line("a,b,1,False"));
    try testing.expectError(error.Malformed, parse_line("a,b,soon,False,x.example"));
    try testing.expectError(error.Malformed, parse_line("a,b,1,maybe,x.example"));
    try testing.expectError(error.Malformed, parse_line("a,b,1,False,."));
    try testing.expectError(error.Malformed, parse_line(",b,1,False,x.example"));
}

test "the log folds case, keeps one index a name and a client, and drops attack rows" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var log: Log = .{};
    try log.add(gpa, try parse_line("c1,x,1000,False,WWW.Example.COM"));
    try log.add(gpa, try parse_line("c2,x,1002,True,exfil.example"));
    try log.add(gpa, try parse_line("c2,x,1003,False,www.example.com."));
    try log.add(gpa, try parse_line("c1,x,1003,False,other.example"));
    try testing.expectEqualSlices(Id, &.{ 0, 0, 1 }, log.names.items);
    try testing.expectEqualSlices(u64, &.{ 0, 3 * std.time.ns_per_ms, 3 * std.time.ns_per_ms }, log.times_ns.items);
    try testing.expectEqualSlices(u32, &.{ 0, 1, 0 }, log.clients.items);
    try testing.expectEqual(@as(usize, 1), log.attack_rows);
    try testing.expectEqual(@as(usize, 2), log.name_count());
    try testing.expectEqual(@as(usize, 2), log.client_count());
}

test "a log whose time goes backward is refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var log: Log = .{};
    try log.add(arena.allocator(), try parse_line("c1,x,1000,False,a.example"));
    try testing.expectError(error.OutOfOrder, log.add(arena.allocator(), try parse_line("c1,x,999,False,b.example")));
}

test "a name written with escapes may run past 255 characters, and not past four times that" {
    const escaped = "a\\198" ** 60 ++ ".example";
    try testing.expect(escaped.len > 255);
    _ = try parse_line("c,x,1,True," ++ escaped);
    try testing.expectError(error.Malformed, parse_line("c,x,1,True," ++ "a" ** (4 * 255 + 1)));
}
