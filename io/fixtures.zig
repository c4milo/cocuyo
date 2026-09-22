//! The sizes the engine's tests build their rig with. Exempt from the magic-numbers rule by
//! name, like every corpus; test-only.

/// A small engine: enough lookups for the many-in-flight scenario, a cache the same size, and
/// a group of a few buffers so the buffers run out under load.
pub const lookups = 64;
pub const cache_slots = 64;
pub const group_buffers = 16;

/// The scripted servers the rig configures: the twin's first two.
pub const servers = 2;

/// The lookups the many-in-flight scenario starts, and the rounds it gives them.
pub const many_lookups = 48;
pub const rounds_max = 4096;
pub const until_rounds_max = 512;

const rotor = @import("rotor");

/// How many events one tick of the rig may hand back.
pub const events_max = 32;

/// The wait a tick is given when the rig runs until a result: long enough for any timeout.
pub const wait_ns = 60 * 1_000_000_000;

/// The many-in-flight scenario's servers: lossy and slow, one of them saying NXDOMAIN now and
/// then, under a short timeout.
pub const lossy_scripts = [servers]rotor.server.Script{
    .{ .drop_per_256 = 64, .delay_ns_min = 1_000_000, .delay_ns_max = 50_000_000 },
    .{ .drop_per_256 = 128, .delay_ns_min = 1_000_000, .delay_ns_max = 20_000_000, .nxdomain_per_256 = 32 },
};
pub const lossy_timeout_ns = 200_000_000;
pub const lossy_step_ns = 1_000_000_000;

/// Room for a scenario's generated names, and how a result folds into the trace: the address's
/// last octet, shifted above the handle's index.
pub const name_text_bytes = 24;
pub const trace_code_shift = 32;

/// A small engine whose group runs dry under its own lookups: more replies at once than buffers.
pub const small_lookups = 6;
pub const small_group_buffers = 2;
