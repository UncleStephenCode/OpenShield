//! Fixed-path, administrator-owned learning budgets. No environment override.

use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use anyhow::{Context, Result, ensure};
use openshield_core::LearningLimits;
use rustix::fs::{Mode, OFlags, openat};
use serde::Deserialize;

const MAX_CONFIG_BYTES: u64 = 4_096;
const CONFIG_NAME: &str = "learning-limits.json";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    per_uid: usize,
    per_application: usize,
}

pub(crate) fn load() -> Result<LearningLimits> {
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .context("cannot open trusted configuration root")?;
    load_from_root(root, 0).context("cannot load /etc/openshield/learning-limits.json")
}

fn validate_metadata(metadata: &Metadata, expected_uid: u32, directory: bool) -> Result<()> {
    ensure!(
        if directory {
            metadata.is_dir()
        } else {
            metadata.is_file()
        },
        "learning configuration must use only real directories and a regular file"
    );
    ensure!(
        metadata.uid() == expected_uid,
        "learning configuration has an untrusted owner"
    );
    ensure!(
        metadata.mode() & 0o022 == 0,
        "learning configuration is writable by group or other users"
    );
    Ok(())
}

fn load_from_root(mut directory: File, expected_uid: u32) -> Result<LearningLimits> {
    // Walk descriptor-relative components. A renamed ancestor cannot redirect
    // subsequent opens, and NOFOLLOW rejects symlinks at every component.
    validate_metadata(&directory.metadata()?, expected_uid, true)?;
    for name in ["etc", "openshield"] {
        let opened = openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        );
        directory = match opened {
            Ok(fd) => File::from(fd),
            Err(rustix::io::Errno::NOENT) => return Ok(LearningLimits::default()),
            Err(error) => {
                return Err(error).context("cannot open trusted learning configuration directory");
            }
        };
        validate_metadata(&directory.metadata()?, expected_uid, true)?;
    }
    let fd = match openat(
        &directory,
        CONFIG_NAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(LearningLimits::default()),
        Err(error) => return Err(error).context("cannot open trusted learning configuration file"),
    };
    let file = File::from(fd);
    let metadata = file
        .metadata()
        .context("cannot inspect open learning configuration")?;
    validate_metadata(&metadata, expected_uid, false)?;
    ensure!(
        metadata.len() <= MAX_CONFIG_BYTES,
        "learning configuration exceeds 4096 bytes"
    );
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("cannot read learning configuration")?;
    ensure!(
        bytes.len() <= 4_096,
        "learning configuration exceeds 4096 bytes"
    );
    parse(&bytes)
}

fn parse(bytes: &[u8]) -> Result<LearningLimits> {
    // Struct deserialization rejects duplicate fields as well as unknown
    // names; JSON numbers must fit usize and must not be fractional/negative.
    let config: Config =
        serde_json::from_slice(bytes).context("invalid learning configuration JSON")?;
    LearningLimits::new(config.per_uid, config.per_application)
        .context("invalid learning configuration budgets")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Path;

    use super::*;

    fn setup() -> Result<tempfile::TempDir> {
        let root = tempfile::tempdir()?;
        fs::create_dir(root.path().join("etc"))?;
        fs::create_dir(root.path().join("etc/openshield"))?;
        for path in [
            root.path().to_path_buf(),
            root.path().join("etc"),
            root.path().join("etc/openshield"),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        Ok(root)
    }

    fn read(root: &Path) -> Result<LearningLimits> {
        let directory = File::open(root)?;
        let uid = directory.metadata()?.uid();
        load_from_root(directory, uid)
    }

    fn write_config(root: &Path, contents: &[u8]) -> Result<()> {
        let path = root.join("etc/openshield").join(CONFIG_NAME);
        fs::write(&path, contents)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    #[test]
    fn missing_trusted_optional_config_uses_defaults() -> Result<()> {
        let root = setup()?;
        assert_eq!(read(root.path())?, LearningLimits::default());
        fs::remove_dir(root.path().join("etc/openshield"))?;
        assert_eq!(read(root.path())?, LearningLimits::default());
        Ok(())
    }

    #[test]
    fn accepts_root_only_write_modes_and_valid_budgets() -> Result<()> {
        let root = setup()?;
        write_config(root.path(), br#"{"per_uid":2048,"per_application":512}"#)?;
        assert_eq!(read(root.path())?, LearningLimits::new(2048, 512)?);
        fs::set_permissions(
            root.path().join("etc/openshield").join(CONFIG_NAME),
            fs::Permissions::from_mode(0o644),
        )?;
        assert_eq!(read(root.path())?, LearningLimits::new(2048, 512)?);
        Ok(())
    }

    #[test]
    fn rejects_unknown_duplicate_missing_and_invalid_fields() {
        for bytes in [
            r#"{"per_uid":512,"per_application":256,"extra":1}"#,
            r#"{"per_uid":512,"per_uid":1024,"per_application":256}"#,
            r#"{"per_uid":512,"per_application":128,"per_application":256}"#,
            r#"{"per_uid":512}"#,
            "{}",
            "[]",
            r#"{"per_uid":0,"per_application":0}"#,
            r#"{"per_uid":7501,"per_application":1}"#,
            r#"{"per_uid":10,"per_application":11}"#,
            r#"{"per_uid":-1,"per_application":1}"#,
            r#"{"per_uid":10.0,"per_application":1}"#,
            r#"{"per_uid":"512","per_application":1}"#,
            r#"{"per_uid":18446744073709551616,"per_application":1}"#,
            r#"{"per_uid":512,"per_application":256} {}"#,
        ] {
            assert!(
                parse(bytes.as_bytes()).is_err(),
                "accepted invalid input: {bytes}"
            );
        }
    }

    #[test]
    fn rejects_oversize_empty_and_nonregular_files() -> Result<()> {
        let root = setup()?;
        write_config(root.path(), &vec![b' '; 4097])?;
        assert!(read(root.path()).is_err());
        write_config(root.path(), b"")?;
        assert!(read(root.path()).is_err());
        let path = root.path().join("etc/openshield").join(CONFIG_NAME);
        fs::remove_file(&path)?;
        fs::create_dir(&path)?;
        assert!(read(root.path()).is_err());
        fs::remove_dir(&path)?;
        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR)?;
        assert!(read(root.path()).is_err());
        Ok(())
    }

    #[test]
    fn rejects_symlink_file_and_ancestors_including_dangling_links() -> Result<()> {
        let root = setup()?;
        let file = root.path().join("etc/openshield").join(CONFIG_NAME);
        symlink("missing", &file)?;
        assert!(read(root.path()).is_err());
        fs::remove_file(&file)?;
        fs::remove_dir(root.path().join("etc/openshield"))?;
        symlink("missing", root.path().join("etc/openshield"))?;
        assert!(read(root.path()).is_err());
        fs::remove_file(root.path().join("etc/openshield"))?;
        fs::remove_dir(root.path().join("etc"))?;
        symlink("missing", root.path().join("etc"))?;
        assert!(read(root.path()).is_err());
        Ok(())
    }

    #[test]
    fn rejects_untrusted_owner_and_writable_ancestors_even_when_missing() -> Result<()> {
        let root = setup()?;
        let opened = File::open(root.path())?;
        let wrong_uid = opened.metadata()?.uid().wrapping_add(1);
        assert!(load_from_root(opened, wrong_uid).is_err());
        for component in ["etc", "etc/openshield"] {
            let path = root.path().join(component);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o770))?;
            assert!(read(root.path()).is_err());
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        write_config(root.path(), br#"{"per_uid":2048,"per_application":512}"#)?;
        fs::set_permissions(
            root.path().join("etc/openshield").join(CONFIG_NAME),
            fs::Permissions::from_mode(0o666),
        )?;
        assert!(read(root.path()).is_err());
        Ok(())
    }
}
