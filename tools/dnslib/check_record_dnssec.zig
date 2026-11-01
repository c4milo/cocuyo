//! The DNSSEC types of the dnslib check: DS, DNSKEY, RRSIG, NSEC and NSEC3PARAM, each read from
//! the copy and compared with the text dnslib wrote for it (docs/design.md §25, step 6). Split
//! from `check_record.zig` by the file-length rule.
const std = @import("std");
const core = @import("core");
const wire = @import("wire");
const record = @import("check_record.zig");
const rdata = wire.rdata;
const Mismatch = record.Mismatch;
const type_agrees = record.type_agrees;
const arity = record.arity;
const number = record.number;
const same_number = record.same_number;
const same_name = record.same_name;
const same_hex = record.same_hex;

/// The digits of a signature time written as a date (RFC 4034 §3.2).
const date_digits: usize = 14;

/// The longest base64 text a key's fields hold: an rdata's octets, four characters for each three.
const base64_text_bytes_max: usize = (core.limits.rdata_bytes_max + 2) / 3 * 4;

/// Key tag, algorithm, digest type, then the digest in hexadecimal (RFC 4034 §5.3).
pub fn check_ds(copy: []const u8, fields: []const []const u8) Mismatch!void {
    if (fields.len < 4) return Mismatch.Text;
    const ds = rdata.Ds.parse(copy) catch return Mismatch.Codec;
    try same_number(ds.key_tag, fields[0]);
    try same_number(ds.algorithm, fields[1]);
    try same_number(ds.digest_type, fields[2]);
    try same_hex(ds.digest, fields[3..]);
}

/// Flags, protocol, algorithm, then the key in base64 (RFC 4034 §2.2).
pub fn check_dnskey(copy: []const u8, fields: []const []const u8) Mismatch!void {
    if (fields.len < 4) return Mismatch.Text;
    const key = rdata.Dnskey.parse(copy) catch return Mismatch.Codec;
    try same_number(key.flags, fields[0]);
    try same_number(key.protocol, fields[1]);
    try same_number(key.algorithm, fields[2]);
    try same_base64(key.public_key, fields[3..]);
}

/// Hash algorithm, flags, iterations, then the salt in hexadecimal, or `-` for none (RFC 5155 §4.3).
pub fn check_nsec3param(copy: []const u8, fields: []const []const u8) Mismatch!void {
    try arity(fields, 4);
    const param = rdata.Nsec3Param.parse(copy) catch return Mismatch.Codec;
    try same_number(param.hash_algorithm, fields[0]);
    try same_number(param.flags, fields[1]);
    try same_number(param.iterations, fields[2]);
    if (std.mem.eql(u8, fields[3], "-")) {
        if (param.salt.len != 0) return Mismatch.Rdata;
        return;
    }
    try same_hex(param.salt, fields[3..]);
}

/// Type covered, algorithm, labels, original TTL, expiration, inception, key tag, signer, then the
/// signature in base64 (RFC 4034 §3.2).
pub fn check_rrsig(copy: []const u8, fields: []const []const u8) Mismatch!void {
    if (fields.len < 9) return Mismatch.Text;
    const sig = rdata.Rrsig.parse(copy) catch return Mismatch.Codec;
    if (!type_agrees(fields[0], sig.type_covered)) return Mismatch.Rdata;
    try same_number(sig.algorithm, fields[1]);
    try same_number(sig.labels, fields[2]);
    try same_number(sig.original_ttl, fields[3]);
    if (try seconds_of(fields[4]) != sig.expiration) return Mismatch.Rdata;
    if (try seconds_of(fields[5]) != sig.inception) return Mismatch.Rdata;
    try same_number(sig.key_tag, fields[6]);
    try same_name(&sig.signer, fields[7]);
    try same_base64(sig.signature, fields[8..]);
}

/// The next owner name, then each type the map holds, by mnemonic, in increasing order of its
/// code (RFC 4034 §4.2). A type cocuyo does not name may be printed by any mnemonic cocuyo does
/// not know, as `type_agrees` says.
pub fn check_nsec(copy: []const u8, fields: []const []const u8) Mismatch!void {
    if (fields.len < 1) return Mismatch.Text;
    const nsec = rdata.Nsec.parse(copy) catch return Mismatch.Codec;
    try same_name(&nsec.next, fields[0]);
    const bytes = nsec.types.bytes;
    var listed: usize = 1;
    var at: usize = 0;
    // Bounded: each pass reads one block of the map, which the view checked.
    for (0..bytes.len + 1) |_| {
        if (at == bytes.len) break;
        const bitmap = bytes[at + 2 ..][0..bytes[at + 1]];
        listed = try agrees_window(bytes[at], bitmap, fields, listed);
        at += 2 + bitmap.len;
    }
    if (listed != fields.len) return Mismatch.Rdata;
}

/// Each type one block of a map holds against the mnemonics from `from` on, in order. Returns
/// where the next block's mnemonics start.
fn agrees_window(window: u8, bitmap: []const u8, fields: []const []const u8, from: usize) Mismatch!usize {
    var listed = from;
    for (bitmap, 0..) |octet, index| {
        for (0..8) |bit| {
            if (octet & (@as(u8, 0x80) >> @intCast(bit)) == 0) continue;
            if (listed == fields.len) return Mismatch.Rdata;
            const code: u16 = @as(u16, window) * 256 + @as(u16, @intCast(index * 8 + bit));
            if (!type_agrees(fields[listed], code)) return Mismatch.Rdata;
            listed += 1;
        }
    }
    return listed;
}

/// A signature time as RFC 4034 §3.2 writes one: YYYYMMDDHHmmSS in UTC, "always exactly 14"
/// digits, or the seconds since 1970 in decimal. A time past 2106 is kept modulo 2^32, as the
/// field is (RFC 4034 §3.1.5).
fn seconds_of(field: []const u8) Mismatch!u32 {
    if (field.len != date_digits) return number(u32, field);
    const year = try number(i64, field[0..4]);
    const month = try number(u8, field[4..6]);
    const day = try number(u8, field[6..8]);
    const hour = try number(u8, field[8..10]);
    const minute = try number(u8, field[10..12]);
    const second = try number(u8, field[12..14]);
    if (month < 1 or month > 12 or day < 1 or day > 31 or hour > 23 or minute > 59 or second > 59) return Mismatch.Text;
    const days = days_from_civil(year, month, day);
    const seconds = days * 86_400 + @as(i64, hour) * 3_600 + @as(i64, minute) * 60 + second;
    return @truncate(@as(u64, @bitCast(seconds)));
}

/// The days from 1970-01-01 to a date of the proleptic Gregorian calendar.
fn days_from_civil(year: i64, month: u8, day: u8) i64 {
    const y = if (month <= 2) year - 1 else year;
    const era = @divFloor(y, 400);
    const year_of_era = y - era * 400;
    const shifted_month: i64 = if (month > 2) month - 3 else month + 9;
    const day_of_year = @divFloor(153 * shifted_month + 2, 5) + day - 1;
    const day_of_era = year_of_era * 365 + @divFloor(year_of_era, 4) - @divFloor(year_of_era, 100) + day_of_year;
    return era * 146_097 + day_of_era - 719_468;
}

/// Whether `octets` are what the base64 `fields` write, split as a master file may split them.
fn same_base64(octets: []const u8, fields: []const []const u8) Mismatch!void {
    var joined: [base64_text_bytes_max]u8 = undefined;
    var len: usize = 0;
    for (fields) |field| {
        if (field.len > joined.len - len) return Mismatch.Text;
        @memcpy(joined[len..][0..field.len], field);
        len += field.len;
    }
    var decoded: [base64_text_bytes_max]u8 = undefined;
    const size = std.base64.standard.Decoder.calcSizeForSlice(joined[0..len]) catch return Mismatch.Text;
    std.base64.standard.Decoder.decode(decoded[0..size], joined[0..len]) catch return Mismatch.Text;
    if (!std.mem.eql(u8, decoded[0..size], octets)) return Mismatch.Rdata;
}

// Tests.

const testing = std.testing;
const rdata_fixtures = wire.rdata.fixtures;
const Tally = record.Tally;
const owner_line = record.owner_line;
const one_answer = record.one_answer;
const check_one = record.check_one;

test "DS, DNSKEY, RRSIG, NSEC, NSEC3PARAM and DNAME read as dnslib writes them" {
    // RFC 4034 §5.4's DS and DNSKEY (docs/design.md §25, step 6).
    var tally: Tally = .{};
    const ds = one_answer(43, &rdata_fixtures.ds_example);
    try check_one(&ds, owner_line ++ "DS 60485 5 1 2BB183AF5F22588179A53B0A 98631FAD1A292118", &tally);
    try testing.expectError(Mismatch.Rdata, check_one(&ds, owner_line ++ "DS 60485 5 2 2BB183AF5F22588179A53B0A98631FAD1A292118", &tally));
    try testing.expectError(Mismatch.Rdata, check_one(&ds, owner_line ++ "DS 60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292119", &tally));
    var key_bytes: [rdata_fixtures.dnskey_example_bytes]u8 = undefined;
    const key = rdata_fixtures.dnskey_example(&key_bytes);
    var dnskey_message: [wire.fixtures.answer_offset + 12 + rdata_fixtures.dnskey_example_bytes]u8 = undefined;
    @memcpy(&dnskey_message, &one_answer(48, &([_]u8{0} ** rdata_fixtures.dnskey_example_bytes)));
    @memcpy(dnskey_message[dnskey_message.len - key.len ..], key);
    try check_one(&dnskey_message, owner_line ++ "DNSKEY 256 3 5 AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/ 2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw==", &tally);
    try testing.expectError(Mismatch.Rdata, check_one(&dnskey_message, owner_line ++ "DNSKEY 256 3 5 AQOeiiR0", &tally));
    const param = one_answer(51, rdata_fixtures.nsec3[0 .. wire.constants.nsec3_fixed_bytes + 4]);
    try check_one(&param, owner_line ++ "NSEC3PARAM 1 1 12 AABBCCDD", &tally);
    try testing.expectError(Mismatch.Rdata, check_one(&param, owner_line ++ "NSEC3PARAM 1 1 12 -", &tally));
    const dname = one_answer(39, &rdata_fixtures.name_example);
    try check_one(&dname, owner_line ++ "DNAME example.com.", &tally);
    // RFC 4034 §4.3's NSEC, and each way its list can disagree.
    const nsec = one_answer(47, &rdata_fixtures.nsec_example);
    try check_one(&nsec, owner_line ++ "NSEC host.example.com. A MX RRSIG NSEC TYPE1234", &tally);
    // A label of one zero octet, written as an escape (RFC 1035 §5.1), as dnslib prints it.
    const zero_next = "\x01\x00\x07example\x03com\x00".* ++ rdata_fixtures.nsec_example[rdata_fixtures.nsec_example_next_bytes..].*;
    const escaped = one_answer(47, &zero_next);
    try check_one(&escaped, owner_line ++ "NSEC \\000.example.com. A MX RRSIG NSEC TYPE1234", &tally);
    try testing.expectError(Mismatch.Rdata, check_one(&escaped, owner_line ++ "NSEC \\001.example.com. A MX RRSIG NSEC TYPE1234", &tally));
    try testing.expectError(Mismatch.Rdata, check_one(&nsec, owner_line ++ "NSEC host.example.com. A MX RRSIG NSEC", &tally));
    try testing.expectError(Mismatch.Rdata, check_one(&nsec, owner_line ++ "NSEC host.example.com. A MX RRSIG NSEC TYPE1234 TYPE1235", &tally));
    try testing.expectError(Mismatch.Rdata, check_one(&nsec, owner_line ++ "NSEC host.example.com. A NS RRSIG NSEC TYPE1234", &tally));
    // fixtures.sig: covers type 0, algorithm 13, 2 labels, TTL 0, expiration 0x5f000000 and
    // inception 0x5e000000, which are 2020-07-04T04:05:20Z and 2019-12-22T23:45:04Z, key tag
    // 0x1234, signer example.com, and the signature DE AD BE EF.
    const rrsig = one_answer(46, &rdata_fixtures.sig);
    try check_one(&rrsig, owner_line ++ "RRSIG TYPE0 13 2 0 20200704040520 20191222234504 4660 example.com. 3q2+7w==", &tally);
    try check_one(&rrsig, owner_line ++ "RRSIG TYPE0 13 2 0 1593835520 1577058304 4660 example.com. 3q2+7w==", &tally);
    try testing.expectError(Mismatch.Rdata, check_one(&rrsig, owner_line ++ "RRSIG TYPE0 13 2 0 20200704040521 20191222234504 4660 example.com. 3q2+7w==", &tally));
    try testing.expectError(Mismatch.Rdata, check_one(&rrsig, owner_line ++ "RRSIG A 13 2 0 20200704040520 20191222234504 4660 example.com. 3q2+7w==", &tally));
    try testing.expectError(Mismatch.Rdata, check_one(&rrsig, owner_line ++ "RRSIG TYPE0 13 2 0 20200704040520 20191222234504 4660 example.com. 3q2+7A==", &tally));
}
