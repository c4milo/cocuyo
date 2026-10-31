//! chapulin's TLS session, through colibri's `tls.record.Client`, behind the session interface of
//! docs/design.md §21. The engine hands it whole records and takes the records it makes; chapulin
//! does the handshake, the ciphers, and the certificate, pin and ticket checks. colibri's `tls`
//! module carries chapulin's objects (§16 decision 32): nothing of chapulin is vendored, and no
//! object is linked beside the module.
//!
//! Every call is a copy between the engine's buffers and colibri's. The handshake writes its
//! records into the session's staged octets, which the engine takes out, and so does every call
//! once the connection is up: a query sealed, what colibri owes after a record it opened (a
//! KeyUpdate's answer, or the alert a refused record raised), and the `close_notify`. chapulin
//! draws every random octet from the engine's seeded stream, which `start` hands colibri
//! (colibri#71), and the image supplies chapulin's one remaining hook, `ch_assert_fail`, through
//! the `chapulin_hooks` module it binds (`io/io_chapulin_hooks.zig`).
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
// The engine's constants, through the engine's module: a file belongs to one module.
const constants = @import("io").constants;
const limits = @import("io").limits;
const hooks = @import("chapulin_hooks");
const tls = @import("tls");
const tls_provider = @import("tls_provider");

// colibri's objects call `ch_assert_fail` whatever of the session a program uses, so the image
// links it whenever it links the session: a module is analysed, and its exports emitted, only when
// something references it.
comptime {
    _ = hooks;
}

comptime {
    if (limits.tls_records_out_bytes_max < Session.out_bytes_max + cocuyo.limits.query_bytes_max + constants.tls_record_overhead_bytes) {
        @compileError("a connection's records cannot hold what the session stages beside a query sealed at its longest");
    }
    if (Session.out_bytes_max < cocuyo.limits.query_bytes_max + constants.tls_record_overhead_bytes) {
        @compileError("the session's staged octets cannot hold a query sealed at its longest");
    }
    if (Session.out_bytes_max < tls.record.alert_record_len) {
        @compileError("the session's staged octets cannot hold an alert or the close_notify of an idle close");
    }
}

pub const Session = struct {
    pub const enabled = true;
    /// What the session stages between two of the engine's calls: what one of colibri's handshake
    /// calls writes at its longest, a ClientHello, which a sealed query is shorter than. An output
    /// that long takes the whole flight in one call, and leaves nothing with chapulin that the
    /// engine would never take.
    pub const out_bytes_max = tls.record.Client.handshake_output_len_min;
    pub const Error = error{Failed};
    pub const Handshake = enum { going, done };
    pub const Opened = union(enum) { data: usize, nothing, closed };
    /// The alert descriptions of RFC 9846 §6, as colibri names them.
    pub const Alert = tls_provider.Alert;
    /// A NewSessionTicket as colibri hands it over, its identity included (RFC 9846 §4.7.1). A
    /// copy holds a resumption secret, and whoever holds one zeroes it.
    pub const Ticket = tls.Ticket;
    /// A root the chain may end at: its subject Name and its SubjectPublicKeyInfo, each a whole
    /// DER TLV (colibri's `values.zig`).
    pub const Anchor = tls.Anchor;
    /// What the consumer states of its CPU: what its probe found, and the timing mode of the thread
    /// that drives the engine (colibri's `values.zig`). It decides the suites of each hello
    /// (docs/design.md §16 decision 48).
    pub const Cpu = tls.Cpu;
    /// The most roots a context holds: what colibri's configuration takes, chapulin's
    /// `CH_WEBPKI_ANCHOR_MAX`.
    pub const anchors_max = tls.record.ClientConfig.anchors_max;

    /// What every session starts from (docs/design.md §21, and §24, the context a session starts
    /// from). It holds the roots a named server's chain may end at, and the consumer's statement
    /// of its CPU. It holds the stream chapulin draws from, and the wall clock at an instant of the
    /// caller's. No field has a default, so a context is built by `init`, with each of them named
    /// (§16 decision 39). The anchors are the caller's and outlive the engine.
    pub const Context = struct {
        anchors: []const Anchor,
        cpu: Cpu,
        stream: std.Random.ChaCha,
        unix_seconds: u64,
        at_ns: u64,

        /// `cpu` is the consumer's probe and its thread's timing mode, which the engine cannot
        /// check (§16 decision 48). Under `data_independent`, with the AES instructions found,
        /// each hello offers AES-GCM first; under any other value, ChaCha20-Poly1305 alone. `seed`
        /// must be 32 octets of a CSPRNG, drawn for this context alone: chapulin draws each
        /// handshake's random and its key shares from the stream they key. `unix_seconds` is the
        /// wall clock at the caller's `now_ns`. `anchors` may be none when every server is known
        /// by its pins.
        pub fn init(anchors: []const Anchor, cpu: Cpu, seed: [std.Random.ChaCha.secret_seed_length]u8, unix_seconds: u64, now_ns: u64) Context {
            assert(anchors.len <= anchors_max);
            return .{ .anchors = anchors, .cpu = cpu, .stream = std.Random.ChaCha.init(seed), .unix_seconds = unix_seconds, .at_ns = now_ns };
        }

        /// The wall clock at `now_ns`, carried forward from the instant the context was made.
        pub fn seconds_at(context: *const Context, now_ns: u64) u64 {
            return context.unix_seconds + (now_ns -| context.at_ns) / constants.ns_per_second;
        }
    };

    client: tls.record.Client = undefined,
    /// What the session starts from, which chapulin reads through pointers into it.
    config: tls.record.ClientConfig = undefined,
    /// colibri's calls on the records once the handshake has completed.
    records: tls_provider.Provider = undefined,
    hostname: [cocuyo.limits.name_text_bytes_max]u8 = undefined,
    /// The ticket this session resumes with: a copy, which `wipe` zeroes.
    resuming: Ticket = undefined,
    staged: [out_bytes_max]u8 = undefined,
    staged_len: usize = 0,
    /// Started: `client` has secrets to wipe. Live: records may be sealed and read.
    started: bool = false,
    live: bool = false,

    pub fn lifetime_ns(ticket: *const Ticket) u64 {
        return @as(u64, ticket.lifetime_s) * constants.ns_per_second;
    }

    /// Stages the hello for `start.tls`'s server, resuming with `start.ticket` when there is
    /// one, and collects it at once.
    pub fn start(self: *Session, start_with: anytype) Error!void {
        const server: *const cocuyo.Tls = start_with.tls;
        const context = start_with.context;
        self.* = .{};
        // What the consumer stated of its CPU decides the suites of the hello (§16 decision 48).
        // A server that requires the hybrid gets a hello that offers it alone (§21, TLS rule 10).
        self.config.init(.{ .trust = trust(server, context, &self.hostname), .cpu = context.cpu, .require_pq = server.require_post_quantum }) catch return self.fail();
        var resumption: ?tls.Resumption = null;
        if (start_with.ticket) |ticket| {
            self.resuming = ticket;
            resumption = .{ .ticket = &self.resuming, .age_ms = start_with.ticket_age_ns / constants.ns_per_millisecond };
        }
        // A refused start leaves colibri's copy of the ticket for `close` to zero, and chapulin's
        // close writes zeros and reads nothing, so a session is started before colibri is called.
        // chapulin draws from the context's stream, which outlives every session of the engine.
        self.started = true;
        self.client.start(&self.config, context.stream.random(), context.seconds_at(start_with.now_ns), resumption) catch return self.fail();
        self.live = true;
        var nothing: [0]u8 = .{};
        const progress = self.client.handshake(&nothing, &self.staged) catch return self.fail();
        self.took(progress.written, self.staged.len);
    }

    /// How chapulin checks the server (RFC 8310 §6.3, docs/design.md §21): a name against the
    /// context's anchors, and pins as they are. A server known by pins alone, "SPKI + IP", is
    /// known by its key and nothing else: it gets no anchors and no clock, however many the
    /// context carries for the servers that have names. chapulin refuses anchors with no name to
    /// check a chain against (its webpki_cfg.c), which would fail such a server at every start. A
    /// named server with no anchors is judged by its pins alone, its name sent and judged against
    /// nothing.
    pub fn trust(server: *const cocuyo.Tls, context: *const Context, hostname: *[cocuyo.limits.name_text_bytes_max]u8) tls.Trust {
        const pins: []const tls.Pin = server.pins;
        const name = server.name orelse return .{ .pins = .{ .pins = pins } };
        var length = name.write_text(hostname);
        // chapulin takes a hostname, which has no root label's dot.
        if (length > 1 and hostname[length - 1] == '.') length -= 1;
        const server_name = hostname[0..length];
        if (context.anchors.len == 0) return .{ .pins = .{ .pins = pins, .server_name = server_name } };
        return .{ .web_pki = .{ .anchors = context.anchors, .server_name = server_name, .pins = pins } };
    }

    /// Counts `written` octets staged, of `room`, which held colibri's longest flight: nothing of
    /// the step's flight stayed with chapulin.
    fn took(self: *Session, written: usize, room: usize) void {
        assert(room >= tls.record.Client.handshake_output_len_min);
        assert(written <= room);
        self.staged_len += written;
        assert(self.staged_len <= self.staged.len);
    }

    pub fn take_out(self: *Session, out: []u8) usize {
        assert(out.len >= self.staged_len);
        const made = self.staged_len;
        @memcpy(out[0..made], self.staged[0..made]);
        self.staged_len = 0;
        return made;
    }

    /// One whole record while the handshake runs. chapulin reads records in place, so `record`
    /// is rewritten.
    pub fn handshake(self: *Session, record: []u8) Error!Handshake {
        assert(self.live);
        // The engine takes what the session staged after every call, so each step has all of it.
        assert(self.staged_len == 0);
        const room = self.staged[self.staged_len..];
        const progress = self.client.handshake(record, room) catch {
            // colibri wrote the fatal alert chapulin chose behind what the call wrote before it
            // (RFC 9846 §6.2): kept, for the engine to send before it closes.
            self.staged_len += self.client.failure_written();
            return self.fail();
        };
        self.took(progress.written, room.len);
        // The engine hands over one whole record, and chapulin takes whole records: less is a
        // programmer's error, the engine's or colibri's, not the peer's.
        assert(progress.consumed == record.len);
        if (!progress.complete) return .going;
        self.records = self.client.provider();
        return .done;
    }

    /// Whether the handshake resumed with the ticket it offered: chapulin completes a declined
    /// ticket as a full handshake in the same connection (its docs/decisions.md 55), so an
    /// offered ticket says nothing of whether it was taken.
    pub fn resumed(self: *const Session) bool {
        return self.started and self.client.resumed();
    }

    /// Seals a query whole into the staged octets, or fails: a query sealed in part could not go.
    pub fn seal(self: *Session, plaintext: []const u8) Error!void {
        assert(self.live);
        assert(plaintext.len <= cocuyo.limits.query_bytes_max);
        const sealed = self.records.vtable.encrypt_record(self.records.context, plaintext, self.staged[self.staged_len..]) catch return self.fail();
        if (sealed.consumed != plaintext.len) return self.fail();
        self.staged_len += sealed.written;
        assert(self.staged_len <= self.staged.len);
    }

    /// One whole record once up: its plaintext, or nothing the engine sees (a ticket, or a
    /// KeyUpdate, whose answer is staged), or the peer's close. colibri opens a record whole, so
    /// plaintext too short for one fails the session rather than drop part of it.
    pub fn open(self: *Session, record: []u8, plaintext: []u8) Error!Opened {
        assert(self.live);
        const opened = self.records.vtable.decrypt_record(self.records.context, record, plaintext) catch {
            // colibri owes the fatal alert chapulin chose (RFC 9846 §6.2): kept, for the engine to
            // send before it closes.
            self.stage_owed() catch {};
            return self.fail();
        };
        // The engine hands over one whole record; one taken in part is one colibri refused.
        if (opened.consumed != record.len) return self.fail();
        // A KeyUpdate's answer that could not go would leave the server reading records under keys
        // it was never told of (RFC 9846 §4.7.3).
        self.stage_owed() catch return self.fail();
        return switch (opened.content) {
            .application_data => .{ .data = opened.plaintext_len },
            // A ticket, a KeyUpdate or an empty record: colibri writes a KeyUpdate's answer in
            // front of the next query's records (RFC 9846 §4.7.3).
            .without_data => .nothing,
            // The peer's close_notify (RFC 9846 §6.1), the one alert a record read leaves unfailed.
            .alert => .closed,
            // RFC 8310 §9 asks no client certificate of DoT, and RFC 9846 §4.7.2 lets a client
            // answer a CertificateRequest it did not offer to take with a failure.
            .certificate_request, .incomplete => self.fail(),
        };
    }

    /// What colibri owes after a record: a KeyUpdate's answer, or the alert a failure raised,
    /// staged behind what the session holds. colibri's record provider reads no clock here.
    fn stage_owed(self: *Session) error{NoSpaceLeft}!void {
        const now_ns = 0;
        const written = self.records.vtable.handshake_write(self.records.context, self.staged[self.staged_len..], now_ns) catch return error.NoSpaceLeft;
        self.staged_len += written;
        assert(self.staged_len <= self.staged.len);
    }

    pub fn take_ticket(self: *Session) ?Ticket {
        if (!self.started) return null;
        return self.client.take_ticket();
    }

    /// The `close_notify` of an idle close (RFC 9846 §6.1), staged, and the keys wiped.
    pub fn close(self: *Session) void {
        assert(self.live);
        // An output that cannot take the alert still closes the session: the close goes unsaid,
        // and the connection closes all the same.
        const written = self.records.vtable.send_close_notify(self.records.context, self.staged[self.staged_len..]) catch 0;
        self.staged_len += written;
        self.live = false;
    }

    /// The fatal alert the engine names, for an error the engine found itself (RFC 9846 §6.2),
    /// staged, and the session failed: chapulin wipes the keys (docs/design.md §16 decision 62).
    pub fn stage_alert(self: *Session, description: Alert) void {
        assert(self.live);
        const written = self.client.fail(description, self.staged[self.staged_len..]) catch |failure| switch (failure) {
            // The engine names an error alert of RFC 9846 §6.2 alone.
            error.NotErrorAlert => unreachable,
            // chapulin's session failed already, the output had no room for the alert, or the key
            // seals no more records (RFC 9846 §5.5): the alert goes unsaid, and the connection
            // closes all the same.
            error.NotConnected, error.NoSpaceLeft, error.KeyExhausted => 0,
        };
        self.staged_len += written;
        assert(self.staged_len <= self.staged.len);
        self.live = false;
    }

    /// Every secret gone: colibri wipes chapulin's session and its copy of the ticket, and the
    /// copy this session resumed with is zeroed.
    pub fn wipe(self: *Session) void {
        if (self.started) self.client.close();
        std.crypto.secureZero(u8, std.mem.asBytes(&self.resuming));
        self.started = false;
        self.live = false;
    }

    fn fail(self: *Session) Error {
        self.wipe();
        return Error.Failed;
    }
};

// Tests.

test {
    _ = @import("io_chapulin_test.zig");
    _ = @import("io_chapulin_alert_test.zig");
}
