//! # argus-core
//!
//! Security-critical core of Argus Vault. This crate contains **no UI code,
//! no network code and no `unsafe` code**. Everything that touches secrets
//! lives here so it can be reviewed, tested and fuzzed in isolation.
//!
//! ## Cryptographic design (v1)
//!
//! ```text
//! pw_hash  = BLAKE2b-512("argus/v1/password" || len || NFC(password))
//! kf_hash  = BLAKE2b-512("argus/v1/keyfile"  || len || keyfile)   (or 64 zero bytes)
//! master   = Argon2id(pw_hash || kf_hash, salt[32], m, t, p) -> 32 bytes
//! enc_key  = BLAKE2b-MAC-256(key = master, "argus/v1/enc")
//! file     = header || XChaCha20-Poly1305(enc_key, nonce[24], aad = header, plaintext)
//! ```
//!
//! See [`format`] for the on-disk layout and [`vault::UnlockedVault`] for the
//! high-level API.

#![forbid(unsafe_code)]

pub mod base32;
pub mod calibrate;
mod codec;
pub mod error;
pub mod format;
mod fs_util;
pub mod generator;
pub mod import;
mod kdf;
pub mod keyfile;
pub mod model;
mod reader;
mod rng;
pub mod search;
mod securebuf;
pub mod strength;
pub mod totp;
pub mod vault;

#[cfg(feature = "fuzzing")]
pub mod fuzzing;

pub use error::{Error, Result};
pub use model::{Entry, EntryId, EntryKind, Settings, Vault};
pub use vault::{Credentials, UnlockedVault};
