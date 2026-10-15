//! Storage module: SQL database, schema, and parameterized queries.
//!
//! One SQLite file per user's vault, named after its vaultname: plaintext header +
//! encrypted body. Never handles plaintext.
