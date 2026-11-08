//! The tries a lookup keeps open (docs/design.md §5, Tries kept open; §16 decision 66). A try is
//! one send of a query. The current try is the lookup's own fields, as before. When its deadline
//! passes, the lookup keeps it here and moves on, so an answer that comes late still counts. A
//! new name closes every try: an answer to one of them would answer another question.
//!
//! A response to an earlier try passes the checks of §7 against that try. The lookup loads the
//! try into its own fields, runs the same checks the current try's response runs, and puts its
//! own fields back. `spec/lean/Spec/Lookup.lean` is the model, `earlierHeard` above all.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const lookup_module = @import("lookup.zig");
const Lookup = lookup_module.Lookup;
const Flags = lookup_module.Flags;
const limits = @import("limits.zig");
const CookieForm = @import("servers.zig").CookieForm;
const entropy_module = @import("entropy.zig");

/// What the checks of §7 read of one try, and its send for the sample (§5).
pub const Try = struct {
    /// When its query went out: what an answer to it measures its server's latency from.
    sent_at_ns: u64,
    /// The pattern its question was cased with (check 5).
    case_seed: u64,
    /// The client cookie its query carried (check 6). "It is RECOMMENDED that a client keep the
    /// Client Cookie it is expecting in a reply until there is no longer an outstanding request
    /// associated with that Client Cookie" (RFC 7873 §7.1).
    cookie_client: [core.constants.cookie_client_bytes]u8,
    /// Its id (check 2), and its number, which an answer over DoH or DoQ names (§22, §23).
    id: u16,
    number: u16,
    /// Its server, as a position in the lookup's order (check 3).
    position: u8,
    cookie_form: CookieForm,
    marks: Marks,

    /// Its flags in one octet, so a try takes 32 octets and not 40.
    pub const Marks = packed struct(u8) {
        /// Whether it went on a stream, over TCP or TLS, and not as a datagram or a request.
        stream: bool,
        edns_enabled: bool,
        query_mixed: bool,
        reply_marked: bool,
        unused: u4 = 0,
    };

    comptime {
        assert(@sizeOf(Try) == 32);
    }
};

/// The earlier tries, oldest first, at most `tries_open_max`. `epoch` moves at each change, so
/// that the table keys their ids again only when they change.
pub const Tries = struct {
    items: [limits.tries_open_max]Try = undefined,
    count: u8 = 0,
    epoch: u8 = 0,

    comptime {
        assert(limits.tries_open_max <= std.math.maxInt(u8));
    }

    pub fn slice(self: *const Tries) []const Try {
        assert(self.count <= limits.tries_open_max);
        return self.items[0..self.count];
    }

    /// Closes every try: a new name, or the end.
    pub fn clear(self: *Tries) void {
        if (self.count == 0) return;
        self.count = 0;
        self.epoch +%= 1;
        assert(self.slice().len == 0);
    }

    /// Keeps a try open. The bound of RFC 9520 §3.1 holds the queries of one name to
    /// `tries_open_max`, so a list already full here is a programmer error.
    pub fn push(self: *Tries, kept: Try) void {
        assert(self.count < limits.tries_open_max);
        self.items[self.count] = kept;
        self.count += 1;
        self.epoch +%= 1;
        assert(self.count <= limits.tries_open_max);
    }

    /// Closes the try at `index`, and keeps the order of the rest.
    pub fn remove(self: *Tries, index: usize) void {
        assert(index < self.count);
        const count_before = self.count;
        std.mem.copyForwards(Try, self.items[index .. self.count - 1], self.items[index + 1 .. self.count]);
        self.count -= 1;
        self.epoch +%= 1;
        assert(self.count + 1 == count_before);
    }

    /// The newest try at `position` on a stream, or null.
    pub fn stream_at(self: *const Tries, position: u8) ?usize {
        var index: usize = self.count;
        while (index > 0) {
            index -= 1;
            const kept = &self.items[index];
            if (kept.marks.stream and kept.position == position) return index;
        }
        assert(index == 0);
        return null;
    }

    /// The newest try whose number is `number`, or null.
    pub fn numbered(self: *const Tries, number: u16) ?usize {
        var index: usize = self.count;
        while (index > 0) {
            index -= 1;
            if (self.items[index].number == number) return index;
        }
        assert(index == 0);
        return null;
    }
};

/// The current try, as the lookup's own fields hold it once its query went out.
pub fn current(self: *const Lookup) Try {
    assert(self.state == .awaiting_udp or self.state == .awaiting_tcp);
    assert(self.sent_at_ns <= self.now_ns_seen);
    return .{
        .sent_at_ns = self.sent_at_ns,
        .case_seed = self.transaction.case_seed,
        .cookie_client = self.cookie_client,
        .id = self.transaction.id,
        .number = self.transaction.number,
        .position = self.server_index,
        .cookie_form = self.cookie_form,
        .marks = .{
            .stream = self.state == .awaiting_tcp,
            .edns_enabled = self.flags.edns_enabled,
            .query_mixed = self.flags.query_mixed,
            .reply_marked = self.flags.reply_marked,
        },
    };
}

/// Keeps the current try open: its deadline passed, and the lookup moves on (§5, Tries kept open).
pub fn keep_current(self: *Lookup) void {
    const kept = current(self);
    self.tries.push(kept);
    assert(self.tries.count >= 1);
}

/// The lookup's own fields that a loaded try replaces.
pub const Saved = struct {
    state: lookup_module.State,
    server_index: u8,
    transaction: entropy_module.Transaction,
    sent_at_ns: u64,
    cookie_form: CookieForm,
    cookie_client: [core.constants.cookie_client_bytes]u8,
    flags: Flags,
    candidate_index: u8,
    cname_hops: u8,
};

pub fn save(self: *const Lookup) Saved {
    return .{
        .state = self.state,
        .server_index = self.server_index,
        .transaction = self.transaction,
        .sent_at_ns = self.sent_at_ns,
        .cookie_form = self.cookie_form,
        .cookie_client = self.cookie_client,
        .flags = self.flags,
        .candidate_index = self.candidate_index,
        .cname_hops = self.cname_hops,
    };
}

/// Puts back every field `load` replaced: a response to an earlier try that moved nothing.
pub fn restore(self: *Lookup, saved: *const Saved) void {
    self.state = saved.state;
    restore_position(self, saved);
    self.flags.reply_marked = saved.flags.reply_marked;
    assert(self.state == saved.state and self.server_index == saved.server_index);
}

/// Puts back the current try's server and transaction, after a response to an earlier try that
/// moved the lookup on the current name: it waits for keys, or follows a CNAME. The model keeps
/// the server the lookup is on there (`earlierChecked`, `onReply`).
pub fn restore_position(self: *Lookup, saved: *const Saved) void {
    self.server_index = saved.server_index;
    self.transaction = saved.transaction;
    self.sent_at_ns = saved.sent_at_ns;
    self.cookie_form = saved.cookie_form;
    self.cookie_client = saved.cookie_client;
    self.flags.edns_enabled = saved.flags.edns_enabled;
    self.flags.query_mixed = saved.flags.query_mixed;
    assert(self.server_index < self.config.server_count());
}

/// Makes the try at `index` the one the checks of §7 read: its id, its server, its case and its
/// cookie, waiting as it went. The transaction's number stays the current one, so the next
/// transaction the lookup draws is numbered after every try it has sent.
pub fn load(self: *Lookup, index: usize) void {
    const kept = &self.tries.items[index];
    assert(index < self.tries.count);
    assert(kept.position < self.config.server_count());
    self.state = if (kept.marks.stream) .awaiting_tcp else .awaiting_udp;
    self.server_index = kept.position;
    self.transaction.id = kept.id;
    self.transaction.case_seed = kept.case_seed;
    self.sent_at_ns = kept.sent_at_ns;
    self.cookie_form = kept.cookie_form;
    self.cookie_client = kept.cookie_client;
    self.flags.edns_enabled = kept.marks.edns_enabled;
    self.flags.query_mixed = kept.marks.query_mixed;
    self.flags.reply_marked = kept.marks.reply_marked;
}

/// What a try went out over: a datagram, or a stream (docs/design.md §5, Tries kept open).
pub const Carrier = enum { datagram, stream };

/// The newest earlier try open at the configured server `configured`, over `carrier`, or null.
/// What a driver asks to know whether the lookup still waits on a connection or a socket it left
/// at a deadline (docs/design.md §19 step 13, the stream's rule 3, the datagram's rule 4).
pub fn earlier_at(self: *const Lookup, configured: u8, carrier: Carrier) ?u8 {
    assert(configured < self.config.servers.len);
    const stream = carrier == .stream;
    var index: u8 = self.tries.count;
    while (index > 0) {
        index -= 1;
        const kept = &self.tries.items[index];
        if (kept.marks.stream == stream and self.order[kept.position] == configured) return index;
    }
    assert(index == 0);
    return null;
}
