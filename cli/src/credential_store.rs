use std::{
    fs::{self, File},
    io::Write as _,
    path::{Path, PathBuf},
};

use base64ct::{Base64UrlUnpadded, Encoding as _};
use miette::Diagnostic;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    config::{CredentialStore, config_path},
    error::CliConfigError,
};

const FILE_PREFIX: &str = "access-token";
const KEYRING_SERVICE: &str = "s2-cli";

#[derive(Debug, Error, Diagnostic)]
pub enum CredentialStoreError {
    #[error("The OS credential store is unavailable: {0}")]
    #[diagnostic(help(
        "Unlock or enable the OS credential store and retry. To explicitly use a private plaintext file, pass `--insecure-storage`."
    ))]
    SecureStorageUnavailable(String),

    #[error("Failed to access the OS credential store: {0}")]
    CredentialStore(String),

    #[error("Stored access token was not found")]
    #[diagnostic(help(
        "Run `s2 auth access-token set --stdin` to store an S2 access token again."
    ))]
    CredentialNotFound,

    #[error("Failed to {action} the access-token file")]
    CredentialFile {
        action: &'static str,
        #[source]
        source: std::io::Error,
    },

    #[error("Invalid access-token path")]
    InvalidPath,

    #[error("The private access-token file is not safely protected: {0}")]
    #[diagnostic(help(
        "Restrict the credential directory to the current user and the file to mode 0600, or remove it and store the token again."
    ))]
    UnsafeCredentialFile(&'static str),

    #[error(transparent)]
    #[diagnostic(transparent)]
    Config(#[from] CliConfigError),
}

pub fn save(
    credential_id: &str,
    store: CredentialStore,
    bytes: &[u8],
) -> Result<(), CredentialStoreError> {
    match store {
        CredentialStore::Keyring => {
            let value = std::str::from_utf8(bytes)
                .expect("credential JSON serialization always produces valid UTF-8");
            let entry = keyring_entry(credential_id).map_err(|error| {
                CredentialStoreError::SecureStorageUnavailable(error.to_string())
            })?;
            entry
                .set_password(value)
                .map_err(|error| CredentialStoreError::SecureStorageUnavailable(error.to_string()))
        }
        CredentialStore::File => write_private_file(&credential_file_path(credential_id)?, bytes),
    }
}

pub fn load(credential_id: &str, store: CredentialStore) -> Result<Vec<u8>, CredentialStoreError> {
    match store {
        CredentialStore::Keyring => {
            let entry = keyring_entry(credential_id)
                .map_err(|error| CredentialStoreError::CredentialStore(error.to_string()))?;
            entry
                .get_password()
                .map(String::into_bytes)
                .map_err(|error| match error {
                    keyring::Error::NoEntry => CredentialStoreError::CredentialNotFound,
                    error => CredentialStoreError::CredentialStore(error.to_string()),
                })
        }
        CredentialStore::File => {
            let path = credential_file_path(credential_id)?;
            secure_private_file_for_read(&path)?;
            fs::read(path).map_err(|source| {
                if source.kind() == std::io::ErrorKind::NotFound {
                    CredentialStoreError::CredentialNotFound
                } else {
                    CredentialStoreError::CredentialFile {
                        action: "read",
                        source,
                    }
                }
            })
        }
    }
}

pub fn delete(credential_id: &str, store: CredentialStore) -> Result<(), CredentialStoreError> {
    match store {
        CredentialStore::Keyring => {
            let entry = keyring_entry(credential_id)
                .map_err(|error| CredentialStoreError::CredentialStore(error.to_string()))?;
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(error) => Err(CredentialStoreError::CredentialStore(error.to_string())),
            }
        }
        CredentialStore::File => {
            let path = credential_file_path(credential_id)?;
            match fs::remove_file(&path) {
                Ok(()) => {
                    let parent = path.parent().ok_or(CredentialStoreError::InvalidPath)?;
                    // Deletion already committed; a directory-sync failure is not recoverable.
                    let _ = sync_directory(parent);
                    Ok(())
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(source) => Err(CredentialStoreError::CredentialFile {
                    action: "delete",
                    source,
                }),
            }
        }
    }
}

pub fn credential_file_path(credential_id: &str) -> Result<PathBuf, CredentialStoreError> {
    let digest = Sha256::digest(credential_id.as_bytes());
    let filename = format!(
        "{FILE_PREFIX}-{}.json",
        Base64UrlUnpadded::encode_string(digest.as_slice())
    );
    Ok(config_path()?.with_file_name(filename))
}

pub fn credential_location(credential_id: &str, store: CredentialStore) -> String {
    match store {
        CredentialStore::Keyring => format!(
            "OS credential store service `{KEYRING_SERVICE}`, account `{}`",
            keyring_account(credential_id)
        ),
        CredentialStore::File => credential_file_path(credential_id)
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| format!("credential ID `{credential_id}`")),
    }
}

fn keyring_entry(credential_id: &str) -> Result<keyring::Entry, keyring::Error> {
    keyring::Entry::new(KEYRING_SERVICE, &keyring_account(credential_id))
}

fn keyring_account(credential_id: &str) -> String {
    format!("access-token:{credential_id}")
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), CredentialStoreError> {
    let parent = path.parent().ok_or(CredentialStoreError::InvalidPath)?;
    fs::create_dir_all(parent).map_err(|source| CredentialStoreError::CredentialFile {
        action: "create the parent directory for",
        source,
    })?;
    secure_directory(parent)?;

    let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(|source| {
        CredentialStoreError::CredentialFile {
            action: "create",
            source,
        }
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|source| CredentialStoreError::CredentialFile {
                action: "secure",
                source,
            })?;
    }
    temp.write_all(bytes)
        .and_then(|()| temp.as_file_mut().sync_all())
        .map_err(|source| CredentialStoreError::CredentialFile {
            action: "write",
            source,
        })?;
    temp.persist(path)
        .map_err(|error| CredentialStoreError::CredentialFile {
            action: "replace",
            source: error.error,
        })?;
    // Rename committed the credential; a directory-sync failure cannot be rolled back.
    let _ = sync_directory(parent);
    Ok(())
}

#[cfg(unix)]
fn secure_private_file_for_read(path: &Path) -> Result<(), CredentialStoreError> {
    use std::os::unix::fs::PermissionsExt as _;

    let parent = path.parent().ok_or(CredentialStoreError::InvalidPath)?;
    let directory = fs::symlink_metadata(parent).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            CredentialStoreError::CredentialNotFound
        } else {
            CredentialStoreError::CredentialFile {
                action: "inspect the parent directory for",
                source,
            }
        }
    })?;
    if !directory.file_type().is_dir() {
        return Err(CredentialStoreError::UnsafeCredentialFile(
            "the parent path is not a directory",
        ));
    }
    if directory.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|source| {
            CredentialStoreError::CredentialFile {
                action: "secure the parent directory for",
                source,
            }
        })?;
    }

    let file = fs::symlink_metadata(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            CredentialStoreError::CredentialNotFound
        } else {
            CredentialStoreError::CredentialFile {
                action: "inspect",
                source,
            }
        }
    })?;
    if !file.file_type().is_file() {
        return Err(CredentialStoreError::UnsafeCredentialFile(
            "the credential path is not a regular file",
        ));
    }
    if file.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
            CredentialStoreError::CredentialFile {
                action: "secure",
                source,
            }
        })?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn secure_private_file_for_read(_path: &Path) -> Result<(), CredentialStoreError> {
    Ok(())
}

#[cfg(unix)]
fn secure_directory(path: &Path) -> Result<(), CredentialStoreError> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
        CredentialStoreError::CredentialFile {
            action: "secure the parent directory for",
            source,
        }
    })
}

#[cfg(not(unix))]
fn secure_directory(_path: &Path) -> Result<(), CredentialStoreError> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), CredentialStoreError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| CredentialStoreError::CredentialFile {
            action: "sync the parent directory for",
            source,
        })
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), CredentialStoreError> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use super::*;

    #[test]
    fn private_file_is_atomically_replaced_with_user_only_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let credential_directory = directory.path().join("s2");
        let path = credential_directory.join("credential.json");

        write_private_file(&path, b"first").unwrap();
        write_private_file(&path, b"second").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert_eq!(
            fs::metadata(&credential_directory)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read_dir(&credential_directory).unwrap().count(), 1);
    }

    #[test]
    fn private_file_permissions_are_repaired_before_reading() {
        let directory = tempfile::tempdir().unwrap();
        let credential_directory = directory.path().join("s2");
        let path = credential_directory.join("credential.json");
        write_private_file(&path, b"secret").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(&credential_directory, fs::Permissions::from_mode(0o755)).unwrap();

        secure_private_file_for_read(&path).unwrap();

        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&credential_directory)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn private_file_symlinks_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let credential_directory = directory.path().join("s2");
        fs::create_dir(&credential_directory).unwrap();
        fs::set_permissions(&credential_directory, fs::Permissions::from_mode(0o700)).unwrap();
        let target = credential_directory.join("target.json");
        fs::write(&target, b"secret").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let link = credential_directory.join("credential.json");
        symlink(&target, &link).unwrap();

        assert!(matches!(
            secure_private_file_for_read(&link),
            Err(CredentialStoreError::UnsafeCredentialFile(_))
        ));
    }
}
