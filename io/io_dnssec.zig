//! `cocuyo_dnssec`: the verifier of docs/design.md §25 over chapulin, through colibri's `dnssec`
//! module (§16 decision 35, as amended; §25 step 10). It fills in `dnssec.Verifier`, the
//! signatures and the DS digests, and `dnssec.nsec3.Hasher`, NSEC3's iterated SHA-1. The library
//! in `src/` holds no cryptography: each hash and each signature here is chapulin's.
//!
//! The `dnssec` import is colibri's, which a consumer that validates binds, as it binds colibri's
//! `quic` into `cocuyo_quic`. The image defines chapulin's hook once, through `chapulin_hooks`.
//! One check or one digest runs at a time, as `Verifier` asks, so the state is one `Hash`.
const std = @import("std");
const assert = std.debug.assert;
const colibri = @import("dnssec");
/// cocuyo's own `dnssec`, which the build binds here and registers nowhere, so the verifier fills
/// in its interfaces and no consumer reaches its internals.
const validation = @import("validation");
const hooks = @import("chapulin_hooks");

comptime {
    // The image's one `ch_assert_fail`, which chapulin's object leaves to it.
    _ = hooks;
}

pub const Chapulin = struct {
    /// The check or the digest running now.
    hash: colibri.Hash = .{},
    /// The algorithm of the check running now, which its end verifies under.
    algorithm: ?colibri.Algorithm = null,

    pub fn verifier(self: *Chapulin) validation.Verifier {
        return .{
            .context = self,
            .checks = checks,
            .digests = digests,
            .check_begin = check_begin,
            .check_end = check_end,
            .digest_begin = digest_begin,
            .digest_end = digest_end,
        };
    }

    /// NSEC3's hash of a name, over the same state (RFC 5155 §5).
    pub fn hasher(self: *Chapulin) validation.nsec3.Hasher {
        return .{ .context = self, .compute = compute };
    }

    /// The algorithms colibri checks: 8, 10, 13, 14 and 15. RSA/SHA-1 (5) and NSEC3RSASHA1 (7) are
    /// not among them, so a zone signed with them alone is insecure (§17 question 22).
    fn checks(context: *anyopaque, algorithm: u8) bool {
        _ = context;
        return colibri.algorithm(algorithm) != null;
    }

    /// The DS digest types colibri computes: SHA-1, SHA-256 and SHA-384 (RFC 9904 §4).
    fn digests(context: *anyopaque, digest_type: u8) bool {
        _ = context;
        return colibri.digest_type(digest_type) != null;
    }

    fn check_begin(context: *anyopaque, algorithm: u8, public_key: []const u8, signature: []const u8) ?validation.Hash {
        const self: *Chapulin = @ptrCast(@alignCast(context));
        const chosen = colibri.algorithm(algorithm) orelse unreachable;
        // A key or a signature of a form the algorithm refuses is a check that failed.
        self.hash = colibri.Hash.init(chosen, public_key, signature) catch return null;
        self.algorithm = chosen;
        return .{ .context = self, .update = update };
    }

    fn check_end(context: *anyopaque, public_key: []const u8, signature: []const u8) bool {
        const self: *Chapulin = @ptrCast(@alignCast(context));
        const chosen = self.algorithm orelse unreachable;
        self.algorithm = null;
        var digest: [colibri.constants.protocol.digest_len_max]u8 = undefined;
        const written = self.hash.final(&digest);
        colibri.verify(chosen, public_key, written, signature) catch return false;
        return true;
    }

    fn digest_begin(context: *anyopaque, digest_type: u8) validation.Hash {
        const self: *Chapulin = @ptrCast(@alignCast(context));
        assert(self.algorithm == null);
        self.hash = colibri.Hash.digest(colibri.digest_type(digest_type) orelse unreachable);
        return .{ .context = self, .update = update };
    }

    fn digest_end(context: *anyopaque, out: *[validation.constants.digest_bytes]u8) usize {
        const self: *Chapulin = @ptrCast(@alignCast(context));
        var digest: [colibri.constants.protocol.digest_len_max]u8 = undefined;
        const written = self.hash.final(&digest);
        // A DS digest is SHA-384's 48 octets at most (RFC 6605 §2).
        assert(written.len <= out.len);
        @memcpy(out[0..written.len], written);
        return written.len;
    }

    fn update(context: *anyopaque, octets: []const u8) void {
        const self: *Chapulin = @ptrCast(@alignCast(context));
        self.hash.update(octets);
    }

    /// IH(salt, x, 0) = H(x || salt), and IH(salt, x, k) = H(IH(salt, x, k - 1) || salt), with
    /// SHA-1 for hash algorithm 1 (RFC 5155 §5). `name` comes in canonical form.
    fn compute(context: *anyopaque, name: []const u8, salt: []const u8, iterations: u16, out: *validation.nsec3.Hash) void {
        const self: *Chapulin = @ptrCast(@alignCast(context));
        assert(self.algorithm == null);
        round(self, name, salt, out);
        for (0..iterations) |_| {
            const previous = out.*;
            round(self, &previous, salt, out);
        }
    }

    fn round(self: *Chapulin, input: []const u8, salt: []const u8, out: *validation.nsec3.Hash) void {
        self.hash = colibri.Hash.digest(.sha1);
        self.hash.update(input);
        self.hash.update(salt);
        var digest: [colibri.constants.protocol.digest_len_max]u8 = undefined;
        const written = self.hash.final(&digest);
        assert(written.len == out.len);
        @memcpy(out, written);
    }
};
