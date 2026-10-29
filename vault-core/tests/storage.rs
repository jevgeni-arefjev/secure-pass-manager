//! Behaviour of the storage module, tested only through its public API.
//!
//! Every test gets its own temporary vault directory. Vaults are sealed in the test
//! format (`create_insecure_for_tests`) so each Argon2id derivation stays fast.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use tempfile::TempDir;
use vault_core::crypto::{self, MasterPassword, Plaintext, SealedVault, VaultKey};
use vault_core::storage::{FileStore, StorageError, VaultStore, Vaultname};

/// A store in a fresh temporary vault directory; keep the `TempDir` alive for the test.
///
/// ```text
/// let (_dir, store) = store();
/// ```
fn store() -> (TempDir, FileStore) {
    let dir = TempDir::new().unwrap();
    let store = FileStore::new(dir.path().join("vaults")).unwrap();
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

/// Where the store keeps `vaultname`'s lock file inside the temp dir from [`store`].
///
/// ```text
/// let lock = lock_path(&dir, "alice");
/// ```
fn lock_path(dir: &TempDir, vaultname: &str) -> PathBuf {
    vault_home(dir, vaultname).join("secrets.lock")
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
    // A large body followed by a small one, so an in-place write would leave the old
    // body's tail behind.
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

#[test]
fn vault_file_is_the_header_followed_by_the_body() {
    let (dir, store) = store();
    let (key, v0) = new_vault("v0");
    store.create(&name("alice"), &v0).unwrap();
    let v1 = next(&key, &v0, "v1");
    store.save(&name("alice"), &v1).unwrap();

    let mut expected = v1.header.encode();
    expected.extend_from_slice(&v1.body);
    assert_eq!(std::fs::read(vault_path(&dir, "alice")).unwrap(), expected);
}

#[test]
fn save_keeps_a_lock_file_and_leaves_no_temp_files() {
    let (dir, store) = store();
    let (key, v0) = new_vault("v0");
    store.create(&name("alice"), &v0).unwrap();

    store.save(&name("alice"), &next(&key, &v0, "v1")).unwrap();

    assert_eq!(
        dir_listing(&vault_home(&dir, "alice")),
        ["secrets.lock", "secrets.vault"]
    );
}

#[test]
fn save_removes_temp_files_left_by_an_interrupted_save() {
    let (dir, store) = store();
    let (key, v0) = new_vault("v0");
    store.create(&name("alice"), &v0).unwrap();
    let home = vault_home(&dir, "alice");
    std::fs::write(home.join(".interrupted.tmp"), &v0.body).unwrap();
    std::fs::write(home.join("notes.txt"), b"not ours to delete").unwrap();

    store.save(&name("alice"), &next(&key, &v0, "v1")).unwrap();

    assert_eq!(
        dir_listing(&home),
        ["notes.txt", "secrets.lock", "secrets.vault"]
    );
}

// --- Concurrent sessions ---

#[test]
fn stale_save_from_another_store_is_a_conflict() {
    let (dir, first) = store();
    let second = FileStore::new(dir.path().join("vaults")).unwrap();
    let (key, v0) = new_vault("v0");
    first.create(&name("alice"), &v0).unwrap();
    let from_first = next(&key, &v0, "first");
    let from_second = next(&key, &v0, "second");

    first.save(&name("alice"), &from_first).unwrap();

    assert_eq!(
        second.save(&name("alice"), &from_second).err(),
        Some(StorageError::Conflict)
    );
    assert_eq!(second.load(&name("alice")).unwrap(), from_first);
}

#[test]
fn concurrent_saves_of_the_same_revision_let_exactly_one_through() {
    let (dir, creator) = store();
    let (key, v0) = new_vault("v0");
    creator.create(&name("alice"), &v0).unwrap();
    let barrier = Arc::new(Barrier::new(8));

    // Spawn every thread before joining any, or the barrier never fills.
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let store = FileStore::new(dir.path().join("vaults")).unwrap();
            let sealed = next(&key, &v0, &format!("session {i}"));
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                store.save(&name("alice"), &sealed)
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();

    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(
        results
            .iter()
            .all(|r| matches!(r, Ok(()) | Err(StorageError::Conflict)))
    );
    assert_eq!(creator.load(&name("alice")).unwrap().header.revision(), 1);
}

#[test]
fn save_waits_for_a_held_lock() {
    let (dir, store) = store();
    let (key, v0) = new_vault("v0");
    store.create(&name("alice"), &v0).unwrap();
    let lock = std::fs::File::create(lock_path(&dir, "alice")).unwrap();
    lock.lock().unwrap();
    let releaser = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        lock.unlock().unwrap();
    });

    let v1 = next(&key, &v0, "v1");
    store.save(&name("alice"), &v1).unwrap();

    releaser.join().unwrap();
    assert_eq!(store.load(&name("alice")).unwrap(), v1);
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
fn sqlite_database_is_not_a_vault() {
    let (dir, store) = store();
    let mut bytes = b"SQLite format 3\0".to_vec();
    bytes.resize(4096, 0);
    std::fs::write(make_vault_home(&dir, "alice"), bytes).unwrap();

    assert_eq!(
        store.load(&name("alice")).err(),
        Some(StorageError::NotAVault)
    );
}

#[test]
fn file_over_the_size_limit_is_not_a_vault() {
    let (dir, store) = store();
    let (key, v0) = new_vault("v0");
    store.create(&name("alice"), &v0).unwrap();
    // Sparse, so the test doesn't write 64 MiB.
    std::fs::OpenOptions::new()
        .write(true)
        .open(vault_path(&dir, "alice"))
        .unwrap()
        .set_len(64 * 1024 * 1024 + 1)
        .unwrap();

    assert_eq!(
        store.load(&name("alice")).err(),
        Some(StorageError::NotAVault)
    );
    assert_eq!(
        store.save(&name("alice"), &next(&key, &v0, "v1")).err(),
        Some(StorageError::NotAVault)
    );
}

#[test]
fn file_shorter_than_the_header_is_not_a_vault() {
    let (dir, store) = store();
    let header = new_vault("[]").1.header.encode();
    std::fs::write(make_vault_home(&dir, "alice"), &header[..header.len() - 1]).unwrap();

    assert_eq!(
        store.load(&name("alice")).err(),
        Some(StorageError::NotAVault)
    );
}

#[test]
fn wrong_magic_is_not_a_vault() {
    let (dir, store) = store();
    store.create(&name("alice"), &new_vault("[]").1).unwrap();
    let path = vault_path(&dir, "alice");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[0] ^= 0xff;
    std::fs::write(&path, bytes).unwrap();

    assert_eq!(
        store.load(&name("alice")).err(),
        Some(StorageError::NotAVault)
    );
}

#[test]
fn unknown_format_version_is_not_a_vault() {
    let (dir, store) = store();
    store.create(&name("alice"), &new_vault("[]").1).unwrap();
    let path = vault_path(&dir, "alice");
    let mut bytes = std::fs::read(&path).unwrap();
    // Bytes 4..6 are the format version.
    bytes[4..6].copy_from_slice(&0x7fffu16.to_be_bytes());
    std::fs::write(&path, bytes).unwrap();

    assert_eq!(
        store.load(&name("alice")).err(),
        Some(StorageError::NotAVault)
    );
}

#[test]
fn saving_over_a_file_that_is_not_a_vault_is_not_a_vault() {
    let (dir, store) = store();
    let (key, v0) = new_vault("[]");
    std::fs::write(make_vault_home(&dir, "alice"), b"junk").unwrap();

    assert_eq!(
        store.save(&name("alice"), &next(&key, &v0, "v1")).err(),
        Some(StorageError::NotAVault)
    );
    assert_eq!(std::fs::read(vault_path(&dir, "alice")).unwrap(), b"junk");
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
    fn lock_file_is_private_to_its_owner() {
        let (dir, store) = store();
        let (key, v0) = new_vault("[]");
        store.create(&name("alice"), &v0).unwrap();
        store.save(&name("alice"), &next(&key, &v0, "v1")).unwrap();

        assert_eq!(mode(&lock_path(&dir, "alice")), 0o600);
    }

    #[test]
    fn symlinked_lock_file_is_refused_and_its_target_untouched() {
        let (dir, store) = store();
        let (key, v0) = new_vault("[]");
        store.create(&name("alice"), &v0).unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::os::unix::fs::symlink(&elsewhere, lock_path(&dir, "alice")).unwrap();

        assert_eq!(
            store.save(&name("alice"), &next(&key, &v0, "v1")).err(),
            Some(StorageError::Io)
        );
        assert!(!elsewhere.exists());
        assert_eq!(store.load(&name("alice")).unwrap(), v0);
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
