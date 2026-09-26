//! `zig build dnslib-check -- <directory>`: the codec against another decoder's reading of
//! responses real servers sent (c4milo/cocuyo#22). dnslib (github.com/paulc/dnslib, BSD-2-Clause)
//! keeps a test directory of such responses, each with dnslib's reading of it (`check_text.zig`).
//! cocuyo walks every record of every section and compares it with the line dnslib printed for it
//! (`check_record.zig`). Each section must hold as many records as dnslib printed, and no octet may
//! follow the last.
//!
//! The directory is not in this repository. `tools/dnslib/run.sh` fetches it at a pinned commit,
//! requires its tree to be the pinned one, and runs this. So the check runs when asked and in CI's
//! `dnslib` job, and the gate needs no network: it runs this file's tests alone.
//!
//! This is developer tooling. It is never linked into the library.
const std = @import("std");
const core = @import("core");
const wire = @import("wire");
const text = @import("check_text.zig");
const record_check = @import("check_record.zig");
const Kind = core.Kind;
const Section = text.Section;
const Tally = record_check.Tally;

/// Why a file disagrees with cocuyo: a record's own mismatch, or one of the whole message.
pub const Mismatch = record_check.Mismatch || error{
    /// A section holds more or fewer records than dnslib printed, or octets follow the last.
    Count,
};

/// The record lines one file holds at most, over its three sections: far more than any response
/// in dnslib's directory, whose largest sections hold tens.
const lines_max = 1024;
/// The octets one response takes at most: a message over TCP is at most 65,535 (RFC 1035 §4.2.2).
const message_bytes_max = std.math.maxInt(u16);
/// The octets one file takes at most: the response in hexadecimal, twice its octets, and the text
/// dnslib printed for it, which is shorter than that again.
const file_bytes_max = 4 * message_bytes_max;
/// The files the directory holds at most. It held 66 at the pinned commit.
const files_max = 4096;

/// Where a check stopped: the section, and the record's place in it counted from 0.
pub const Place = struct {
    section: Section = .answer,
    index: usize = 0,
    line: []const u8 = "",
};

/// One file of dnslib's directory against cocuyo's reading of the response in it.
pub fn check_file(bytes: []const u8, tally: *Tally, place: *Place) Mismatch!void {
    var lines: [lines_max][]const u8 = undefined;
    const file = text.read(bytes, &lines) catch return Mismatch.Text;
    var message_buffer: [message_bytes_max]u8 = undefined;
    const message = text.octets(file.response_hex, &message_buffer) catch return Mismatch.Text;
    const header = wire.header.parse(message) catch return Mismatch.Codec;
    if (header.qdcount != 1) return Mismatch.Count;
    var question_name: core.Name = .empty;
    var offset = (wire.question.parse(message, &question_name) catch return Mismatch.Codec).end;
    const counts = std.EnumArray(Section, u16).init(.{
        .answer = header.ancount,
        .authority = header.nscount,
        .additional = header.arcount,
    });
    for (std.enums.values(Section)) |section| {
        place.* = .{ .section = section };
        offset = try check_section(message, offset, counts.get(section), file.sections.get(section), tally, place);
    }
    if (offset != message.len) return Mismatch.Count;
}

/// The records of one section against its lines, and the offset after the section.
fn check_section(
    message: []const u8,
    offset: usize,
    count: u16,
    lines: []const []const u8,
    tally: *Tally,
    place: *Place,
) Mismatch!usize {
    var records = wire.record.Iterator.init(message, offset, count);
    var end = offset;
    var printed: usize = 0;
    for (0..@as(usize, count) + 1) |_| {
        const record = (records.next() catch return Mismatch.Codec) orelse break;
        end = record.end;
        // The OPT pseudo-record belongs to the message rather than to a name (RFC 6891 §6.1.1),
        // and dnslib prints it as comments, which are not record lines.
        if (record.kind_code == Kind.opt.code()) continue;
        if (printed == lines.len) return Mismatch.Count;
        place.index = printed;
        place.line = lines[printed];
        try record_check.check(message, &record, lines[printed], tally);
        printed += 1;
    }
    if (records.truncated or printed != lines.len) return Mismatch.Count;
    return end;
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const arguments = try init.minimal.args.toSlice(arena);
    if (arguments.len != 2) {
        std.debug.print("usage: dnslib-check <dnslib's test directory>\n", .{});
        return error.Usage;
    }
    var directory = try std.Io.Dir.cwd().openDir(init.io, arguments[1], .{ .iterate = true });
    defer directory.close(init.io);
    const names = try file_names(init.io, directory, arena);
    var tally: Tally = .{};
    var failures: usize = 0;
    for (names) |name| {
        const bytes = try directory.readFileAlloc(init.io, name, arena, .limited(file_bytes_max));
        var place: Place = .{};
        check_file(bytes, &tally, &place) catch |mismatch| {
            failures += 1;
            std.debug.print("{s}: {s} record {d}: {s}\n  {s}\n", .{ name, @tagName(place.section), place.index, @errorName(mismatch), place.line });
        };
    }
    std.debug.print("dnslib: {d} responses, {d} records agree ({d} typed, {d} generic, {d} copied), {d} disagree\n", .{
        names.len - failures, tally.records, tally.typed, tally.generic, tally.copied, failures,
    });
    if (failures != 0 or names.len == 0) return error.Disagree;
}

/// The directory's files, in name order so a report reads the same on every machine. The `dig`
/// directory beside them holds dig's own output, which is not in this format, and is left out.
fn file_names(io: std.Io, directory: std.Io.Dir, arena: std.mem.Allocator) ![]const []const u8 {
    var names: std.ArrayList([]const u8) = .empty;
    var iterator = directory.iterate();
    for (0..files_max + 1) |_| {
        const entry = try iterator.next(io) orelse break;
        if (entry.kind != .file) continue;
        if (names.items.len == files_max) return error.TooManyFiles;
        try names.append(arena, try arena.dupe(u8, entry.name));
    }
    std.mem.sort([]const u8, names.items, {}, less_than);
    return names.items;
}

fn less_than(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.lessThan(u8, left, right);
}

// Tests. The message is the codec's own fixture of an A answer with an SOA under it, and the text
// is what dnslib prints for it.

const testing = std.testing;

fn dnslib_file(comptime message: anytype, comptime sections: []const u8) []const u8 {
    return comptime ";; RESPONSE: " ++ std.fmt.bytesToHex(message, .lower) ++ "\n" ++ sections;
}

const answer_line = "example.com.  300  IN  A  192.0.2.1\n";
const authority_line = "example.com.  300  IN  SOA  ns.example.com. admin.example.com. 1 7200 900 1209600 60\n";

test "a response agrees with dnslib's reading of it, section by section" {
    const file = dnslib_file(wire.fixtures.answer_a_with_soa, ";; ANSWER SECTION:\n" ++ answer_line ++
        ";; AUTHORITY SECTION:\n" ++ authority_line ++ ";; ADDITIONAL SECTION:\n;; OPT PSEUDOSECTION\n\n");
    var tally: Tally = .{};
    var place: Place = .{};
    try check_file(file, &tally, &place);
    try testing.expectEqual(Tally{ .records = 2, .typed = 2 }, tally);
}

test "a section that holds more or fewer records than dnslib printed, or trailing octets, is a mismatch" {
    const answer = ";; ANSWER SECTION:\n" ++ answer_line;
    const authority = ";; AUTHORITY SECTION:\n" ++ authority_line;
    const message = wire.fixtures.answer_a_with_soa;
    const cases = .{
        .{ dnslib_file(message, answer), Mismatch.Count, Section.authority },
        .{ dnslib_file(message, answer ++ answer_line ++ authority), Mismatch.Count, Section.answer },
        .{ dnslib_file(message ++ [_]u8{0}, answer ++ authority), Mismatch.Count, Section.additional },
        .{ dnslib_file(message, answer ++ ";; AUTHORITY SECTION:\nexample.com. 300 IN SOA ns.example.com. admin.example.com. 2 7200 900 1209600 60\n"), Mismatch.Rdata, Section.authority },
        .{ "; no response\n", Mismatch.Text, Section.answer },
    };
    inline for (cases) |case| {
        var tally: Tally = .{};
        var place: Place = .{};
        try testing.expectError(case[1], check_file(case[0], &tally, &place));
        try testing.expectEqual(case[2], place.section);
    }
}

test "the OPT pseudo-record is walked over, not compared" {
    const opt = [_]u8{ 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00 };
    // The same answer with the OPT record added, and ARCOUNT, the header's last octet, made 1.
    const message = comptime with_opt: {
        var bytes = wire.fixtures.answer_a_with_soa ++ opt;
        bytes[core.constants.header_bytes - 1] = 1;
        break :with_opt bytes;
    };
    const file = dnslib_file(message, ";; ANSWER SECTION:\n" ++ answer_line ++ ";; AUTHORITY SECTION:\n" ++
        authority_line ++ ";; ADDITIONAL SECTION:\n;; OPT PSEUDOSECTION\n; EDNS: version: 0, flags: do; udp: 4096\n");
    var tally: Tally = .{};
    var place: Place = .{};
    try check_file(file, &tally, &place);
    try testing.expectEqual(@as(usize, 2), tally.records);
}

test {
    _ = text;
    _ = record_check;
}

