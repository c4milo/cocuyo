//! The hot paths `zig build fill-check` reads (`fill_check.zig`): one exported function for each of
//! the library's per-query entry points, compiled ReleaseSafe for each target the library ships
//! to. Each takes what it needs through pointers, so the compiler keeps the whole path, and
//! nothing here ever runs: the check reads the code the compiler wrote for it.
const cocuyo = @import("cocuyo");
const wire = cocuyo.wire;

/// A query's octets written out: every lookup's first send.
export fn probe_query_write(query: *const wire.Query, out: [*]u8, out_bytes: usize) usize {
    return wire.query.write(query, out[0..out_bytes]);
}

/// A response's records read into answers: every answer a lookup takes.
export fn probe_response_collect(message: [*]const u8, message_bytes: usize, chain: *cocuyo.Name, kind: cocuyo.Kind, answers: *wire.Answers) bool {
    _ = wire.response.collect(message[0..message_bytes], chain, kind, 0, answers) catch return false;
    return true;
}

/// A lookup started in the table: its slot taken and the lookup built in it.
export fn probe_table_start(resolver: *cocuyo.Resolver, question: *const cocuyo.Question, handle: *cocuyo.Handle) bool {
    handle.* = resolver.start(question.*) catch return false;
    return true;
}

/// The table asked what to do next: the cache recalled into a lookup, or its query built.
export fn probe_table_poll(resolver: *cocuyo.Resolver, now_ns: u64, out: [*]u8, out_bytes: usize, event: *cocuyo.Event) bool {
    event.* = resolver.poll(now_ns, out[0..out_bytes]) orelse return false;
    return true;
}

/// A datagram matched against the table, and the answer it carries taken.
export fn probe_table_datagram(resolver: *cocuyo.Resolver, message: [*]const u8, message_bytes: usize, from: *const cocuyo.Endpoint, now_ns: u64) bool {
    return resolver.on_datagram(message[0..message_bytes], from.*, now_ns) == .accepted;
}

/// A question looked up in the cache.
export fn probe_cache_get(cache: *cocuyo.Cache, question: *const cocuyo.Question, now_ns: u64) bool {
    return cache.get(question, now_ns) != null;
}

/// An answer kept in the cache.
export fn probe_cache_put(cache: *cocuyo.Cache, question: *const cocuyo.Question, answers: *const wire.Answers, now_ns: u64) void {
    cache.put(question, answers, null, now_ns);
}

/// A question with no answer kept in the cache.
export fn probe_cache_put_negative(cache: *cocuyo.Cache, question: *const cocuyo.Question, ttl_seconds: u32, now_ns: u64) void {
    cache.put_negative(question, .no_data, ttl_seconds, now_ns);
}

/// A lookup built by value, as a caller that holds one outside a table builds it.
export fn probe_lookup_init(config: *const cocuyo.Config, servers: *cocuyo.Servers, question: *const cocuyo.Question, seed: u64, out: *cocuyo.Lookup) void {
    out.* = cocuyo.Lookup.init(config, servers, question.*, seed);
}
