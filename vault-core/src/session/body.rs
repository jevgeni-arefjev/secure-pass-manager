//! The decrypted body: `{"version":1,"secrets":[...]}`, the only plaintext crypto seals.
//!
//! Security: the body is parsed straight from crypto's locked [`Plaintext`] and written
//! into a buffer that zeroizes every allocation it outgrows, then moved into locked
//! memory. serde_json's scratch space for escaped strings isn't zeroized; it holds one
//! string at a time and is accepted.

use std::io;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::secret::Secret;
use crate::crypto::Plaintext;

/// Version of the body layout, independent of the header's format version.
const BODY_VERSION: u32 = 1;

/// The body as written: borrows the session's secrets.
#[derive(Serialize)]
struct BodyRef<'a> {
    version: u32,
    secrets: &'a [Secret],
}

/// The body as read.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    version: u32,
    secrets: Vec<Secret>,
}

/// The body of a vault that doesn't parse as any known body version.
///
/// ```ignore
/// body::decode(&plaintext).map_err(|BodyUnreadable| SessionError::VaultUnreadable)?;
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct BodyUnreadable;

/// Parses a decrypted body into secrets. No validation beyond the layout: a body
/// written by an older build must still open.
///
/// ```ignore
/// let secrets = body::decode(&crypto::open_body(&key, &sealed)?)?;
/// ```
pub(super) fn decode(plaintext: &Plaintext) -> Result<Vec<Secret>, BodyUnreadable> {
    let body: Body = serde_json::from_slice(plaintext.as_bytes()).map_err(|_| BodyUnreadable)?;
    if body.version == BODY_VERSION {
        Ok(body.secrets)
    } else {
        Err(BodyUnreadable)
    }
}

/// Serializes `secrets` into a new locked body.
///
/// ```ignore
/// let plaintext = body::encode(&secrets);
/// let sealed = crypto::seal(&key, &header, &plaintext)?;
/// ```
pub(super) fn encode(secrets: &[Secret]) -> Plaintext {
    let mut out = ZeroizingBuffer::default();
    let body = BodyRef {
        version: BODY_VERSION,
        secrets,
    };
    serde_json::to_writer(&mut out, &body).expect("writing to memory can't fail");
    Plaintext::new(std::mem::take(&mut out.0))
}

/// An in-memory writer that never leaves a copy behind: when it grows, the old
/// allocation is zeroized before it is freed, and the rest on drop.
///
/// ```ignore
/// let mut out = ZeroizingBuffer::default();
/// serde_json::to_writer(&mut out, &body)?;
/// ```
#[derive(Default)]
struct ZeroizingBuffer(Vec<u8>);

impl io::Write for ZeroizingBuffer {
    /// Appends `data`, moving to a larger allocation (and wiping the old one) when full.
    ///
    /// ```ignore
    /// out.write_all(b"{")?;
    /// ```
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let needed = self.0.len() + data.len();
        if needed > self.0.capacity() {
            let mut bigger = Vec::with_capacity(needed.max(self.0.capacity() * 2).max(4096));
            bigger.extend_from_slice(&self.0);
            self.0.zeroize();
            self.0 = bigger;
        }
        self.0.extend_from_slice(data);
        Ok(data.len())
    }

    /// Nothing is buffered beyond the vector itself.
    ///
    /// ```ignore
    /// out.flush()?;
    /// ```
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for ZeroizingBuffer {
    /// Zeroizes whatever is still in the buffer.
    ///
    /// ```ignore
    /// drop(out); // wiped
    /// ```
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
