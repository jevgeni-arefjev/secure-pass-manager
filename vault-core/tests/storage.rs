//! Behaviour of the storage module, tested only through its public API.
//!
//! Every test gets its own temporary vault directory. Vaults are sealed in the test
//! format (`create_insecure_for_tests`) so each Argon2id derivation stays fast.

use std::path::{Path, PathBuf};

use tempfile::TempDir;
use vault_core::crypto::{self, MasterPassword, Plaintext, SealedVault, VaultKey};
use vault_core::storage::{SqliteStore, StorageError, VaultStore, Vaultname};

/// A store in a fresh temporary vault directory; keep the `TempDir` alive for the test.
///
/// ```text
/// let (_dir, store) = store();
/// ```
fn store() -> (TempDir, SqliteStore) {
    let dir = TempDir::new().unwrap();
    let store = SqliteStore::new(dir.path().join("vaults")).unwrap();
    (dir, store)
}

/// Parses a vaultname that the test expects to be valid.
///
/// ```text
/// store.load(&name("alice"))
/// ```
fn name(s: &str) -> Vaultname {
    Vaultname::parse(s).unwrap()
}

/// A new test-format vault whose body is `body`, plus its vault key for later saves.
///
/// ```text
/// let (key, v0) = new_vault("[]");
/// ```
fn new_vault(body: &str) -> (VaultKey, SealedVault) {
    crypto::create_insecure_for_tests(
        &MasterPassword::new("correct horse".into()),
        &Plaintext::new(body.as_bytes().to_vec()),
    )
    .unwrap()
}

/// The next revision of `sealed` with `body` as its new contents.
///
/// ```text
/// let v1 = next(&key, &v0, "v1");
/// ```
fn next(key: &VaultKey, sealed: &SealedVault, body: &str) -> SealedVault {
    crypto::seal(
        key,
        &sealed.header,
        &Plaintext::new(body.as_bytes().to_vec()),
    )
    .unwrap()
}

/// Where the store keeps `vaultname`'s vault home inside the temp dir from [`store`].
///
/// ```text
/// let home = vault_home(&dir, "alice");
/// ```
fn vault_home(dir: &TempDir, vaultname: &str) -> PathBuf {
    dir.path().join("vaults").join(vaultname)
}

/// Where the store keeps `vaultname`'s vault file inside the temp dir from [`store`].
///
/// ```text
/// let path = vault_path(&dir, "alice");
/// ```
fn vault_path(dir: &TempDir, vaultname: &str) -> PathBuf {
    vault_home(dir, vaultname).join("secrets.vault")
}

/// Creates `vaultname`'s vault home by hand (panicking if it exists) and returns its
/// vault file path, for tests that plant their own file there.
///
/// ```text
/// std::fs::write(make_vault_home(&dir, "alice"), b"junk")?;
/// ```
fn make_vault_home(dir: &TempDir, vaultname: &str) -> PathBuf {
    std::fs::create_dir(vault_home(dir, vaultname)).unwrap();
    vault_path(dir, vaultname)
}

/// The names of the entries directly inside `path`, sorted.
///
/// ```text
/// assert_eq!(dir_listing(&vault_home(&dir, "alice")), ["secrets.vault"]);
/// ```
fn dir_listing(path: &Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// Whether `needle` occurs anywhere in the file at `path`.
///
/// ```text
/// assert!(!file_contains(&path, &old_body));
/// ```
fn file_contains(path: &Path, needle: &[u8]) -> bool {
    std::fs::read(path)
        .unwrap()
        .windows(needle.len())
        .any(|window| window == needle)
}

// --- Vaultnames ---

#[test]
fn vaultnames_are_lowercased() {
    assert_eq!(name("Alice").as_str(), "alice");
}

#[test]
fn vaultnames_allow_digits_dashes_and_underscores() {
    assert_eq!(name("bob-2_work").as_str(), "bob-2_work");
}

#[test]
fn vaultnames_up_to_32_characters_are_accepted() {
    assert_eq!(name(&"a".repeat(32)).as_str().len(), 32);
}

#[test]
fn unsafe_or_malformed_vaultnames_are_rejected() {
    let too_long = "a".repeat(33);
    for bad in [
        "",
        "../alice",
        "a/b",
        "a\\b",
        ".alice",
        "-alice",
        "_alice",
        "alice.vault",
        "al ice",
        "alice\0",
        "ålice",
        "con",
        "NUL",
        "com1",
        "lpt9",
        &too_long,
    ] {
        assert_eq!(
            Vaultname::parse(bad).err(),
            Some(StorageError::InvalidVaultname),
            "{bad:?} should be rejected"
        );
    }
}

// --- Create, load, save ---

#[test]
fn created_vault_loads_back_unchanged() {
    let (_dir, store) = store();
    let (_, v0) = new_vault("[]");

    store.create(&name("alice"), &v0).unwrap();

    assert_eq!(store.load(&name("alice")).unwrap(), v0);
}

#[test]
fn saved_revision_replaces_the_previous_one() {
    let (_dir, store) = store();
    let (key, v0) = new_vault("v0");
    store.create(&name("alice"), &v0).unwrap();

    let v1 = next(&key, &v0, "v1");
    store.save(&name("alice"), &v1).unwrap();

    let loaded = store.load(&name("alice")).unwrap();
    assert_eq!(loaded, v1);
    assert_eq!(crypto::open_body(&key, &loaded).unwrap().as_bytes(), b"v1");
}

#[test]
fn create_refuses_an_existing_vaultname() {
    let (_dir, store) = store();
    let (_, first) = new_vault("first");
    let (_, second) = new_vault("second");
    store.create(&name("alice"), &first).unwrap();

    assert_eq!(
        store.create(&name("Alice"), &second).err(),
        Some(StorageError::AlreadyExists)
    );
    assert_eq!(store.load(&name("alice")).unwrap(), first);
}

#[test]
fn create_puts_the_vault_file_in_its_vault_home_and_leaves_no_temp_files() {
    let (dir, store) = store();
    store.create(&name("alice"), &new_vault("[]").1).unwrap();

    assert_eq!(dir_listing(&dir.path().join("vaults")), ["alice"]);
    assert_eq!(dir_listing(&vault_home(&dir, "alice")), ["secrets.vault"]);
}

#[test]
fn loading_a_missing_vault_is_not_found() {
    let (_dir, store) = store();
    assert_eq!(
        store.load(&name("nobody")).err(),
        Some(StorageError::NotFound)
    );
}

#[test]
fn saving_a_missing_vault_is_not_found() {
    let (_dir, store) = store();
    let (_, v0) = new_vault("[]");
    assert_eq!(
        store.save(&name("nobody"), &v0).err(),
        Some(StorageError::NotFound)
    );
}

#[test]
fn stale_save_is_a_conflict_and_keeps_the_newer_revision() {
    let (_dir, store) = store();
    let (key, v0) = new_vault("v0");
    store.create(&name("alice"), &v0).unwrap();
    let first_session = next(&key, &v0, "first session");
    let second_session = next(&key, &v0, "second session");

    store.save(&name("alice"), &first_session).unwrap();

    assert_eq!(
        store.save(&name("alice"), &second_session).err(),
        Some(StorageError::Conflict)
    );
    assert_eq!(store.load(&name("alice")).unwrap(), first_session);
}

#[test]
fn saving_the_same_revision_again_is_a_conflict() {
    let (_dir, store) = store();
    let (_, v0) = new_vault("v0");
    store.create(&name("alice"), &v0).unwrap();

    assert_eq!(
        store.save(&name("alice"), &v0).err(),
        Some(StorageError::Conflict)
    );
}

#[test]
fn skipping_a_revision_is_a_conflict() {
    let (_dir, store) = store();
    let (key, v0) = new_vault("v0");
    store.create(&name("alice"), &v0).unwrap();
    let v2 = next(&key, &next(&key, &v0, "v1"), "v2");

    assert_eq!(
        store.save(&name("alice"), &v2).err(),
        Some(StorageError::Conflict)
    );
}

#[test]
fn saved_vault_no_longer_contains_the_old_ciphertext() {
    let (dir, store) = store();
    // A large body followed by a small one, so freed pages are left over instead of
    // being reused (and overwritten) by the new body.
    let (key, v0) = new_vault(&"x".repeat(20_000));
    store.create(&name("alice"), &v0).unwrap();

    store.save(&name("alice"), &next(&key, &v0, "v1")).unwrap();

    let path = vault_path(&dir, "alice");
    for chunk in v0.body.chunks(64) {
        assert!(!file_contains(&path, chunk));
    }
}

#[test]
fn renamed_vault_home_loads_under_its_new_vaultname() {
    let (dir, store) = store();
    let (_, v0) = new_vault("[]");
    store.create(&name("alice"), &v0).unwrap();

    std::fs::rename(vault_home(&dir, "alice"), vault_home(&dir, "bob")).unwrap();

    assert_eq!(store.load(&name("bob")).unwrap(), v0);
}

// --- Files that aren't vaults ---

#[test]
fn random_bytes_are_not_a_vault() {
    let (dir, store) = store();
    std::fs::write(make_vault_home(&dir, "alice"), vec![0x5a; 8192]).unwrap();

    assert_eq!(
        store.load(&name("alice")).err(),
        Some(StorageError::NotAVault)
    );
}

#[test]
fn empty_file_is_not_a_vault() {
    let (dir, store) = store();
    std::fs::write(make_vault_home(&dir, "alice"), []).unwrap();

    assert_eq!(
        store.load(&name("alice")).err(),
        Some(StorageError::NotAVault)
    );
}

#[test]
fn other_sqlite_database_is_not_a_vault() {
    let (dir, store) = store();
    let conn = rusqlite::Connection::open(make_vault_home(&dir, "alice")).unwrap();
    conn.execute_batch(
        "CREATE TABLE vault (id INTEGER, revision INTEGER, header BLOB, body BLOB);",
    )
    .unwrap();
    drop(conn);

    assert_eq!(
        store.load(&name("alice")).err(),
        Some(StorageError::NotAVault)
    );
}

#[test]
fn unknown_storage_schema_version_is_not_a_vault() {
    let (dir, store) = store();
    store.create(&name("alice"), &new_vault("[]").1).unwrap();
    rusqlite::Connection::open(vault_path(&dir, "alice"))
        .unwrap()
        .pragma_update(None, "user_version", 99)
        .unwrap();

    assert_eq!(
        store.load(&name("alice")).err(),
        Some(StorageError::NotAVault)
    );
}

#[test]
fn header_revision_disagreeing_with_the_stored_revision_is_not_a_vault() {
    let (dir, store) = store();
    store.create(&name("alice"), &new_vault("[]").1).unwrap();
    rusqlite::Connection::open(vault_path(&dir, "alice"))
        .unwrap()
        .execute("UPDATE vault SET revision = 7", [])
        .unwrap();

    assert_eq!(
        store.load(&name("alice")).err(),
        Some(StorageError::NotAVault)
    );
}

#[test]
fn malformed_header_is_not_a_vault() {
    let (dir, store) = store();
    store.create(&name("alice"), &new_vault("[]").1).unwrap();
    rusqlite::Connection::open(vault_path(&dir, "alice"))
        .unwrap()
        .execute("UPDATE vault SET header = x'00'", [])
        .unwrap();

    assert_eq!(
        store.load(&name("alice")).err(),
        Some(StorageError::NotAVault)
    );
}

#[test]
fn directory_in_place_of_a_vault_file_is_not_a_vault() {
    let (dir, store) = store();
    std::fs::create_dir_all(vault_path(&dir, "alice")).unwrap();

    assert_eq!(
        store.load(&name("alice")).err(),
        Some(StorageError::NotAVault)
    );
}

#[cfg(unix)]
#[test]
fn symlinked_vault_home_is_not_a_vault() {
    let (dir, store) = store();
    let (_, v0) = new_vault("[]");
    store.create(&name("alice"), &v0).unwrap();
    std::os::unix::fs::symlink(vault_home(&dir, "alice"), vault_home(&dir, "bob")).unwrap();

    assert_eq!(
        store.load(&name("bob")).err(),
        Some(StorageError::NotAVault)
    );
    assert_eq!(
        store.create(&name("bob"), &new_vault("[]").1).err(),
        Some(StorageError::NotAVault)
    );
    assert_eq!(dir_listing(&vault_home(&dir, "alice")), ["secrets.vault"]);
}

#[test]
fn file_in_place_of_a_vault_home_is_not_a_vault() {
    let (dir, store) = store();
    std::fs::write(vault_home(&dir, "alice"), b"not a directory").unwrap();

    assert_eq!(
        store.load(&name("alice")).err(),
        Some(StorageError::NotAVault)
    );
    assert_eq!(
        store.create(&name("alice"), &new_vault("[]").1).err(),
        Some(StorageError::NotAVault)
    );
}

// --- Interrupted init ---

#[test]
fn empty_vault_home_is_not_found_and_create_takes_it_over() {
    let (dir, store) = store();
    std::fs::create_dir(vault_home(&dir, "alice")).unwrap();

    assert_eq!(
        store.load(&name("alice")).err(),
        Some(StorageError::NotFound)
    );

    let (_, v0) = new_vault("[]");
    store.create(&name("alice"), &v0).unwrap();
    assert_eq!(store.load(&name("alice")).unwrap(), v0);
}

// --- Errors ---

#[test]
fn error_messages_are_fixed_strings() {
    assert_eq!(StorageError::NotFound.to_string(), "vault not found");
    assert_eq!(
        StorageError::Conflict.to_string(),
        "vault was changed by another session"
    );
}

// --- Permissions ---

#[cfg(unix)]
mod permissions {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    /// The permission bits of the file or directory at `path`.
    ///
    /// ```text
    /// assert_eq!(mode(&path), 0o600);
    /// ```
    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn vault_directory_is_private_to_its_owner() {
        let (dir, _store) = store();
        assert_eq!(mode(&dir.path().join("vaults")), 0o700);
    }

    #[test]
    fn vault_home_is_private_to_its_owner() {
        let (dir, store) = store();
        store.create(&name("alice"), &new_vault("[]").1).unwrap();

        assert_eq!(mode(&vault_home(&dir, "alice")), 0o700);
    }

    #[test]
    fn vault_file_is_private_to_its_owner() {
        let (dir, store) = store();
        let (key, v0) = new_vault("[]");
        store.create(&name("alice"), &v0).unwrap();
        store.save(&name("alice"), &next(&key, &v0, "v1")).unwrap();

        assert_eq!(mode(&vault_path(&dir, "alice")), 0o600);
    }

    #[test]
    fn loose_permissions_still_open_the_vault() {
        let (dir, store) = store();
        let (_, v0) = new_vault("[]");
        store.create(&name("alice"), &v0).unwrap();
        let path = vault_path(&dir, "alice");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();

        assert_eq!(store.load(&name("alice")).unwrap(), v0);
    }
}
