//! Session module: unlocks one vault (vaultname + master password), holds its decrypted
//! secrets for the session, reveals them one at a time, and wipes them on lock or auto-lock.
//!
//! Owns the secret model and its JSON serialization. A session only ever sees the vault it
//! unlocked, so no per-secret ownership checks are needed (ADR-0001).
