//! The table fixture of `fixtures.zig`: a whole table, its buffers and the fake server that answers
//! every lookup in it. Split from `fixtures.zig` by the file-length rule.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const Config = core.Config;
const Question = core.Question;
const fixtures = @import("fixtures.zig");
const table_module = @import("table.zig");
const slots_module = @import("table_slots.zig");
const Resolver = table_module.Resolver;
const Event = table_module.Event;
const MatchKey = table_module.MatchKey;
const Handle = slots_module.Handle;
const Slot = slots_module.Slot;
const lookup_module = @import("lookup.zig");
const Lookup = lookup_module.Lookup;
const Verdict = lookup_module.Verdict;
const Reply = fixtures.Reply;
const slot_count = fixtures.slot_count;
const key_count = fixtures.key_count;
const seed = fixtures.seed;
const answer_a = fixtures.answer_a;

/// A whole table, its buffers, and the fake server that answers every lookup in it. Started in
/// place for the same reason `Harness` is: the resolver holds pointers to the arrays beside it.
pub const Table = struct {
    config: Config,
    slots: [slot_count]Slot = @splat(.{}),
    keys: [key_count]MatchKey = @splat(.{}),
    resolver: Resolver = undefined,
    out: [core.limits.query_bytes_max]u8 = @splat(0),
    reply: [core.constants.udp_payload_bytes_default]u8 = @splat(0),
    now_ns: u64 = 0,

    pub fn open(self: *Table) void {
        self.resolver = Resolver.init(&self.slots, &self.keys, &self.config, seed);
    }

    pub fn start(self: *Table, text: []const u8) !Handle {
        return self.resolver.start(try Question.from_text(text, .a));
    }

    pub fn poll(self: *Table) ?Event {
        self.now_ns += 1;
        return self.resolver.poll(self.now_ns, &self.out);
    }

    /// Answers one lookup the way its current server would, with one A record. The server is the
    /// lookup's own: after a timeout it has moved to the next one, and a reply from the server it
    /// no longer holds is not a reply (§7 check 3).
    pub fn answer(self: *Table, handle: Handle) Verdict {
        const lookup = self.resolver.lookup_of(handle);
        const message = self.build(lookup, answer_a);
        self.now_ns += 1;
        return self.resolver.on_datagram(message, lookup.server(), self.now_ns);
    }

    /// A reply carrying one lookup's id and another lookup's question: the cross-talk a table has
    /// to refuse.
    pub fn crosstalk(self: *Table, id_of: Handle, question_of: Handle) Verdict {
        const question_lookup = self.resolver.lookup_of(question_of);
        var reply = answer_a;
        reply.id = self.resolver.lookup_of(id_of).transaction.id;
        const message = self.build(question_lookup, reply);
        self.now_ns += 1;
        return self.resolver.on_datagram(message, question_lookup.server(), self.now_ns);
    }

    /// Builds `reply` around the question `lookup` asked: the rcode's low four bits in the
    /// header, as `Harness.build` does, and no OPT record, so the extended rcodes stay there.
    pub fn build(self: *Table, lookup: *const Lookup, reply: Reply) []const u8 {
        assert(reply.cookie == .none);
        const name = lookup.cased_name();
        const rcode: u16 = @intFromEnum(reply.rcode);
        assert(rcode >> wire.constants.extended_rcode_low_bits == 0);
        var flags: u16 = wire.constants.flag_response | wire.constants.flag_recursion_desired | (rcode & wire.constants.rcode_mask);
        if (reply.truncated) flags |= wire.constants.flag_truncated;
        if (reply.authentic_data) flags |= wire.constants.flag_authentic_data;
        const header: wire.Header = .{
            .id = reply.id orelse lookup.transaction.id,
            .flags = flags,
            .qdcount = 1,
            .ancount = reply.ancount,
            .nscount = 0,
            .arcount = 0,
        };
        wire.header.write(&header, &self.reply);
        var offset: usize = core.constants.header_bytes;
        offset += wire.question.write(&name, lookup.question.kind, self.reply[offset..]);
        @memcpy(self.reply[offset..][0..reply.records.len], reply.records);
        return self.reply[0 .. offset + reply.records.len];
    }
};
