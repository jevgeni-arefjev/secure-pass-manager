//! Behaviour of the encryption module, tested only through its public API.
//!
//! All vaults use the test format (`create_insecure_for_tests`) so each Argon2id
//! derivation stays fast; one ignored test covers the production format.

use vault_core::crypto::{self, CryptoError, Header, MasterPassword, Plaintext};

/// Builds a master password from a literal.
///
/// ```text
/// crypto::unlock(&header, &password("correct horse"))
/// ```
fn password(s: &str) -> MasterPassword {
    MasterPassword::new(s.to_owned())
}

/// Builds a plaintext body from a literal.
///
/// ```text
/// crypto::seal(&key, &header, &body("v1"))
/// ```
fn body(s: &str) -> Plaintext {
    Plaintext::new(s.as_bytes().to_vec())
}

/// Round trip: create, unlock with the right password, open the body.
#[test]
fn unlocked_vault_opens_to_the_plaintext_it_was_created_with() {
    let (_, sealed) = crypto::create_insecure_for_tests(
        &password("correct horse"),
        &body(r#"[{"title":"github"}]"#),
    )
    .unwrap();

    let key = crypto::unlock(&sealed.header, &password("correct horse")).unwrap();
    let opened = crypto::open_body(&key, &sealed).unwrap();

    assert_eq!(opened.as_bytes(), br#"[{"title":"github"}]"#);
}

/// Creates a vault with password "correct horse" and a small body.
///
/// ```text
/// let sealed = sample_vault();
/// ```
fn sample_vault() -> crypto::SealedVault {
    let (_, sealed) = crypto::create_insecure_for_tests(
        &password("correct horse"),
        &body(r#"[{"title":"github"}]"#),
    )
    .unwrap();
    sealed
}

/// Header byte offsets, per the documented layout.
mod offset {
    pub const VERSION: usize = 4;
    pub const SALT: usize = 6;
    pub const WRAP_NONCE: usize = 22;
    pub const WRAPPED_KEY: usize = 46;
    pub const REVISION: usize = 94;
    pub const BODY_NONCE: usize = 102;
    pub const END: usize = 126;
}

/// Re-decodes the vault's header after `edit` changes its encoded bytes.
///
/// ```text
/// let tampered = with_header_bytes(&sealed, |b| b[offset::SALT] ^= 1);
/// ```
fn with_header_bytes(
    sealed: &crypto::SealedVault,
    edit: impl FnOnce(&mut Vec<u8>),
) -> crypto::SealedVault {
    let mut bytes = sealed.header.encode();
    edit(&mut bytes);
    crypto::SealedVault {
        header: Header::decode(&bytes).unwrap(),
        body: sealed.body.clone(),
    }
}

/// Unlocks with the right password and opens the body, returning the first error.
///
/// ```text
/// assert_eq!(unlock_and_open(&tampered).err(), Some(CryptoError::BodyCorrupt));
/// ```
fn unlock_and_open(sealed: &crypto::SealedVault) -> Result<Plaintext, CryptoError> {
    let key = crypto::unlock(&sealed.header, &password("correct horse"))?;
    crypto::open_body(&key, sealed)
}

/// A wrong master password is rejected by the key-wrap tag check (ADR-0002).
#[test]
fn wrong_master_password_fails_to_unlock() {
    let sealed = sample_vault();

    let result = crypto::unlock(&sealed.header, &password("wrong horse"));

    assert_eq!(result.err(), Some(CryptoError::UnlockFailed));
}

/// Any change to a field the key wrap authenticates (salt, wrap nonce, wrapped key)
/// fails unlock, the same way a wrong password does.
#[test]
fn tampering_with_key_wrap_fields_fails_unlock() {
    let sealed = sample_vault();

    for at in [
        offset::SALT,
        offset::SALT + 15,
        offset::WRAP_NONCE,
        offset::WRAPPED_KEY,
        offset::WRAPPED_KEY + 40,
    ] {
        let tampered = with_header_bytes(&sealed, |b| b[at] ^= 1);
        assert_eq!(
            unlock_and_open(&tampered).err(),
            Some(CryptoError::UnlockFailed),
            "byte {at}"
        );
    }
}

/// Changes to header fields only the body authenticates (revision, body nonce), or
/// to the body itself, are reported as a corrupt body.
#[test]
fn tampering_with_body_fields_fails_as_corrupt_body() {
    let sealed = sample_vault();

    for at in [offset::REVISION + 7, offset::BODY_NONCE] {
        let tampered = with_header_bytes(&sealed, |b| b[at] ^= 1);
        assert_eq!(
            unlock_and_open(&tampered).err(),
            Some(CryptoError::BodyCorrupt),
            "byte {at}"
        );
    }

    let mut tampered = sealed.clone();
    tampered.body[0] ^= 1;
    assert_eq!(
        unlock_and_open(&tampered).err(),
        Some(CryptoError::BodyCorrupt)
    );
}

/// A body cut short or extended never decrypts.
#[test]
fn truncated_or_extended_body_is_corrupt() {
    let sealed = sample_vault();

    for len in [0, 15, sealed.body.len() - 1] {
        let mut cut = sealed.clone();
        cut.body.truncate(len);
        assert_eq!(
            unlock_and_open(&cut).err(),
            Some(CryptoError::BodyCorrupt),
            "len {len}"
        );
    }
    let mut longer = sealed.clone();
    longer.body.push(0);
    assert_eq!(
        unlock_and_open(&longer).err(),
        Some(CryptoError::BodyCorrupt)
    );
}

/// The fixed header encoding round-trips and has the documented length.
#[test]
fn header_survives_encode_and_decode() {
    let sealed = sample_vault();

    let bytes = sealed.header.encode();

    assert_eq!(bytes.len(), offset::END);
    assert_eq!(Header::decode(&bytes), Ok(sealed.header));
}

/// A named edit to an encoded header that must make it undecodable.
type HeaderMutation = (&'static str, fn(&mut Vec<u8>));

/// The header parser rejects malformed or unknown input without detail.
#[test]
fn malformed_headers_are_unsupported_format() {
    let good = sample_vault().header.encode();
    let mutations: [HeaderMutation; 7] = [
        ("empty", |b| b.clear()),
        ("truncated", |b| b.truncate(offset::END - 1)),
        ("trailing byte", |b| b.push(0)),
        ("bad magic", |b| b[0] = b'X'),
        ("unknown version", |b| b[offset::VERSION + 1] = 2),
        ("unknown test version", |b| {
            b[offset::VERSION..offset::VERSION + 2].copy_from_slice(&0x8002u16.to_be_bytes())
        }),
        ("version 0", |b| {
            b[offset::VERSION..offset::VERSION + 2].fill(0)
        }),
    ];

    for (what, mutate) in mutations {
        let mut bytes = good.clone();
        mutate(&mut bytes);
        assert_eq!(
            Header::decode(&bytes),
            Err(CryptoError::UnsupportedFormat),
            "{what}"
        );
    }
}

/// Test vaults carry the top format bit (0x8001); relabelling one as production
/// (0x0001) switches it to the production KDF params, so it fails to unlock.
#[test]
fn test_vault_relabelled_as_production_fails_unlock() {
    let sealed = sample_vault();
    assert_eq!(
        sealed.header.encode()[offset::VERSION..offset::SALT],
        0x8001u16.to_be_bytes()
    );

    let relabelled = with_header_bytes(&sealed, |b| b[offset::VERSION] = 0);

    assert_eq!(
        unlock_and_open(&relabelled).err(),
        Some(CryptoError::UnlockFailed)
    );
}

/// The production format round-trips end to end with the real 256 MiB derivation.
/// Ignored by default for speed: `cargo test -- --ignored`.
#[test]
#[ignore = "runs the production Argon2id params (256 MiB, t=3)"]
fn production_format_creates_and_unlocks() {
    let (_, sealed) = crypto::create(&password("correct horse"), &body("prod")).unwrap();

    assert_eq!(
        sealed.header.encode()[offset::VERSION..offset::SALT],
        0x0001u16.to_be_bytes()
    );
    let key = crypto::unlock(&sealed.header, &password("correct horse")).unwrap();
    assert_eq!(
        crypto::open_body(&key, &sealed).unwrap().as_bytes(),
        b"prod"
    );
}

/// Each save increments the revision and never reuses a nonce.
#[test]
fn saving_bumps_the_revision_and_uses_a_fresh_nonce() {
    let (key, first) =
        crypto::create_insecure_for_tests(&password("correct horse"), &body("v0")).unwrap();

    let second = crypto::seal(&key, &first.header, &body("v1")).unwrap();
    let third = crypto::seal(&key, &second.header, &body("v1")).unwrap();

    assert_eq!(
        [
            first.header.revision(),
            second.header.revision(),
            third.header.revision()
        ],
        [0, 1, 2]
    );
    assert_ne!(
        second.body, third.body,
        "same plaintext must not give the same ciphertext"
    );
    assert_eq!(crypto::open_body(&key, &third).unwrap().as_bytes(), b"v1");
}

/// Bodies are padded to 4 KiB steps, hiding how many secrets a vault holds.
#[test]
fn body_size_does_not_reveal_plaintext_size() {
    let (key, small) =
        crypto::create_insecure_for_tests(&password("correct horse"), &body("")).unwrap();

    let medium = crypto::seal(&key, &small.header, &Plaintext::new(vec![b'x'; 3000])).unwrap();
    let large = crypto::seal(&key, &small.header, &Plaintext::new(vec![b'x'; 5000])).unwrap();

    assert_eq!(small.body.len(), medium.body.len());
    assert_eq!(large.body.len(), small.body.len() + 4096);
}

/// After a password change only the new master password unlocks the vault.
#[test]
fn changing_the_master_password_replaces_the_old_one() {
    let sealed = sample_vault();

    let (_, changed) = crypto::change_master_password(
        &sealed.header,
        &password("correct horse"),
        &password("battery staple"),
        &body("after change"),
    )
    .unwrap();

    assert_eq!(
        crypto::unlock(&changed.header, &password("correct horse")).err(),
        Some(CryptoError::UnlockFailed)
    );
    let key = crypto::unlock(&changed.header, &password("battery staple")).unwrap();
    assert_eq!(
        crypto::open_body(&key, &changed).unwrap().as_bytes(),
        b"after change"
    );
    assert_eq!(changed.header.revision(), sealed.header.revision() + 1);
}

/// A password change rotates the vault key, so a key (or old copy) from before the
/// change can't read later versions.
#[test]
fn old_vault_key_cannot_open_the_vault_after_a_password_change() {
    let sealed = sample_vault();
    let old_key = crypto::unlock(&sealed.header, &password("correct horse")).unwrap();

    let (_, changed) = crypto::change_master_password(
        &sealed.header,
        &password("correct horse"),
        &password("battery staple"),
        &body("after change"),
    )
    .unwrap();

    assert_eq!(
        crypto::open_body(&old_key, &changed).err(),
        Some(CryptoError::BodyCorrupt)
    );
}

/// A password change verifies the current master password first.
#[test]
fn password_change_requires_the_current_master_password() {
    let sealed = sample_vault();

    let changed = crypto::change_master_password(
        &sealed.header,
        &password("guess"),
        &password("battery staple"),
        &body("x"),
    );

    assert_eq!(changed.err(), Some(CryptoError::UnlockFailed));
}
