//! core: the types, the limits and the errors more than one module needs. It imports nothing,
//! which is what lets every other module reach it without reaching sideways (docs/design.md §2).
//!
//! Step 1 of §15 fills this module: `Address`, `Endpoint`, `Name`, `Question`, `Config`, `Error`
//! and `constants.zig`.
