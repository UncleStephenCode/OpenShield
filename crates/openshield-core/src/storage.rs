use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use thiserror::Error;
use uuid::Uuid;

use crate::{CoreError, MAX_STATE_BYTES, State};

const STATE_FILE_MODE: u32 = 0o600;

pub trait StateStore: std::fmt::Debug + Send + Sync {
    /// Loads and validates persisted state, or reports that no state exists.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] for unsafe metadata, bounded I/O, JSON, or
    /// state-validation failures.
    fn load(&self) -> Result<Option<State>, StorageError>;
    /// Atomically persists validated state with private ownership and mode.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when validation, secure file creation, write,
    /// replacement, or synchronization fails.
    fn save(&self, state: &State) -> Result<(), StorageError>;

    /// Loads state or returns a fresh fail-closed state when it is absent.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] for malformed or insecure existing state.  A
    /// caller must apply its firewall fail-closed policy before aborting.
    fn load_or_fail_closed(&self) -> Result<State, StorageError> {
        self.load().map(Option::unwrap_or_default)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomicStateStore {
    path: PathBuf,
    required_owner: u32,
}

impl AtomicStateStore {
    #[must_use]
    pub fn root_owned(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            required_owner: 0,
        }
    }

    /// Constructs a store for a specific service uid.
    ///
    /// Production system-daemon code should use [`Self::root_owned`].  This
    /// constructor supports an intentionally unprivileged deployment and tests
    /// without weakening the ownership checks.
    #[must_use]
    pub fn for_owner(path: impl Into<PathBuf>, required_owner: u32) -> Self {
        Self {
            path: path.into(),
            required_owner,
        }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn required_owner(&self) -> u32 {
        self.required_owner
    }

    fn validate_parent(&self) -> Result<&Path, StorageError> {
        let parent = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or_else(|| StorageError::MissingParent(self.path.clone()))?;
        let metadata = fs::symlink_metadata(parent)
            .map_err(|source| StorageError::io("inspect state directory", parent, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(StorageError::UnsafeFileType(parent.to_path_buf()));
        }
        validate_owner(parent, &metadata, self.required_owner)?;
        let mode = metadata.mode() & 0o777;
        if mode & 0o022 != 0 {
            return Err(StorageError::InsecureDirectoryMode {
                path: parent.to_path_buf(),
                mode,
            });
        }
        Ok(parent)
    }

    fn validate_existing_file(&self) -> Result<Option<fs::Metadata>, StorageError> {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(StorageError::UnsafeFileType(self.path.clone()));
                }
                validate_owner(&self.path, &metadata, self.required_owner)?;
                let mode = metadata.mode() & 0o777;
                if mode != STATE_FILE_MODE {
                    return Err(StorageError::InsecureFileMode {
                        path: self.path.clone(),
                        mode,
                    });
                }
                Ok(Some(metadata))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(StorageError::io("inspect state file", &self.path, source)),
        }
    }

    fn temporary_path(&self) -> Result<PathBuf, StorageError> {
        let file_name = self
            .path
            .file_name()
            .ok_or_else(|| StorageError::MissingFileName(self.path.clone()))?;
        let mut temporary_name = file_name.to_os_string();
        temporary_name.push(format!(".{}.tmp", Uuid::new_v4()));
        Ok(self.path.with_file_name(temporary_name))
    }
}

impl StateStore for AtomicStateStore {
    fn load(&self) -> Result<Option<State>, StorageError> {
        self.validate_parent()?;
        if self.validate_existing_file()?.is_none() {
            return Ok(None);
        }

        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&self.path)
            .map_err(|source| StorageError::io("open state file", &self.path, source))?;

        // Validate the opened descriptor too.  This closes the metadata/open
        // time-of-check/time-of-use gap even if an unexpectedly mutable parent
        // directory is supplied.
        let metadata = file
            .metadata()
            .map_err(|source| StorageError::io("inspect open state file", &self.path, source))?;
        if !metadata.is_file() {
            return Err(StorageError::UnsafeFileType(self.path.clone()));
        }
        validate_owner(&self.path, &metadata, self.required_owner)?;
        let mode = metadata.mode() & 0o777;
        if mode != STATE_FILE_MODE {
            return Err(StorageError::InsecureFileMode {
                path: self.path.clone(),
                mode,
            });
        }

        let limit = u64::try_from(MAX_STATE_BYTES)
            .map_err(|_| StorageError::StateTooLarge(MAX_STATE_BYTES))?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|source| StorageError::io("read state file", &self.path, source))?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(StorageError::StateTooLarge(bytes.len()));
        }
        let state: State = serde_json::from_slice(&bytes)
            .map_err(|source| StorageError::InvalidJson(source.to_string()))?;
        state.validate()?;
        Ok(Some(state))
    }

    fn save(&self, state: &State) -> Result<(), StorageError> {
        state.validate()?;
        let parent = self.validate_parent()?;
        self.validate_existing_file()?;

        let bytes = serde_json::to_vec(state)
            .map_err(|source| StorageError::InvalidJson(source.to_string()))?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(StorageError::StateTooLarge(bytes.len()));
        }

        let temporary_path = self.temporary_path()?;
        let mut temporary_created = false;
        let result: Result<(), StorageError> = (|| {
            let mut temporary = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(STATE_FILE_MODE)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&temporary_path)
                .map_err(|source| {
                    StorageError::io("create temporary state file", &temporary_path, source)
                })?;
            temporary_created = true;

            let metadata = temporary.metadata().map_err(|source| {
                StorageError::io("inspect temporary state file", &temporary_path, source)
            })?;
            validate_owner(&temporary_path, &metadata, self.required_owner)?;
            if metadata.mode() & 0o777 != STATE_FILE_MODE {
                return Err(StorageError::InsecureFileMode {
                    path: temporary_path.clone(),
                    mode: metadata.mode() & 0o777,
                });
            }

            temporary.write_all(&bytes).map_err(|source| {
                StorageError::io("write temporary state file", &temporary_path, source)
            })?;
            temporary.sync_all().map_err(|source| {
                StorageError::io("sync temporary state file", &temporary_path, source)
            })?;
            fs::rename(&temporary_path, &self.path)
                .map_err(|source| StorageError::io("replace state file", &self.path, source))?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|source| StorageError::io("sync state directory", parent, source))?;
            Ok(())
        })();

        if result.is_err() && temporary_created {
            let _cleanup_result = fs::remove_file(&temporary_path);
        }
        result
    }
}

fn validate_owner(
    path: &Path,
    metadata: &fs::Metadata,
    required_owner: u32,
) -> Result<(), StorageError> {
    if metadata.uid() != required_owner {
        return Err(StorageError::WrongOwner {
            path: path.to_path_buf(),
            expected: required_owner,
            actual: metadata.uid(),
        });
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("{operation} at {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("state path {0} has no parent directory")]
    MissingParent(PathBuf),
    #[error("state path {0} has no file name")]
    MissingFileName(PathBuf),
    #[error("{0} is a symbolic link or has an unexpected file type")]
    UnsafeFileType(PathBuf),
    #[error("{path} is owned by uid {actual}; required uid is {expected}")]
    WrongOwner {
        path: PathBuf,
        expected: u32,
        actual: u32,
    },
    #[error("state directory {path} has insecure mode {mode:#o}")]
    InsecureDirectoryMode { path: PathBuf, mode: u32 },
    #[error("state file {path} must have mode 0o600, not {mode:#o}")]
    InsecureFileMode { path: PathBuf, mode: u32 },
    #[error("serialized state is too large: {0} bytes")]
    StateTooLarge(usize),
    #[error("invalid state JSON: {0}")]
    InvalidJson(String),
    #[error(transparent)]
    InvalidState(#[from] CoreError),
}

impl StorageError {
    fn io(operation: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            operation,
            path: path.to_path_buf(),
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        os::unix::fs::{PermissionsExt, symlink},
    };

    use tempfile::tempdir;

    use super::*;
    use crate::{
        ApplicationPath, ApplicationSelector, CgroupPath, CommandArgument, CommandLineMatch,
        CommandLineSelector, Direction, ExecutableFileId, InterfaceName,
        MAX_APPLICATION_PATH_BYTES, MAX_CGROUP_PATH_BYTES, MAX_COMMAND_ARGUMENT_BYTES,
        MAX_COMMAND_LINE_BYTES, MAX_RULE_NAME_BYTES, MAX_RULES, Mode, PortRange, RuleName,
        RuleOrigin, RuleSpec, TransportProtocol,
    };

    fn owner(path: &Path) -> Result<u32, Box<dyn Error>> {
        Ok(fs::metadata(path)?.uid())
    }

    #[test]
    fn round_trip_is_atomic_and_private() -> Result<(), Box<dyn Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("state.json");
        let store = AtomicStateStore::for_owner(&path, owner(directory.path())?);
        let state = State::new();
        store.save(&state)?;

        assert_eq!(fs::metadata(&path)?.mode() & 0o777, 0o600);
        assert_eq!(store.load()?, Some(state));
        let temporary_count = fs::read_dir(directory.path())?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(temporary_count, 0);
        Ok(())
    }

    #[test]
    fn missing_state_loads_fail_closed() -> Result<(), Box<dyn Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("missing.json");
        let store = AtomicStateStore::for_owner(&path, owner(directory.path())?);
        assert_eq!(store.load_or_fail_closed()?.mode(), Mode::BlockAll);
        Ok(())
    }

    #[test]
    fn refuses_state_symlink() -> Result<(), Box<dyn Error>> {
        let directory = tempdir()?;
        let target = directory.path().join("target");
        fs::write(&target, b"secret")?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
        let path = directory.path().join("state.json");
        symlink(&target, &path)?;
        let store = AtomicStateStore::for_owner(&path, owner(directory.path())?);
        assert!(matches!(
            store.load(),
            Err(StorageError::UnsafeFileType(error_path)) if error_path == path
        ));
        Ok(())
    }

    #[test]
    fn refuses_world_readable_state() -> Result<(), Box<dyn Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("state.json");
        fs::write(&path, b"{}")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        let store = AtomicStateStore::for_owner(&path, owner(directory.path())?);
        assert!(matches!(
            store.load(),
            Err(StorageError::InsecureFileMode { mode: 0o644, .. })
        ));
        Ok(())
    }

    #[test]
    fn refuses_writable_state_directory() -> Result<(), Box<dyn Error>> {
        let directory = tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o777))?;
        let path = directory.path().join("state.json");
        let store = AtomicStateStore::for_owner(&path, owner(directory.path())?);
        assert!(matches!(
            store.load(),
            Err(StorageError::InsecureDirectoryMode { mode: 0o777, .. })
        ));
        Ok(())
    }

    #[test]
    fn maximum_valid_state_fits_the_bounded_store() -> Result<(), Box<dyn Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("state.json");
        let store = AtomicStateStore::for_owner(&path, owner(directory.path())?);
        let specification = RuleSpec::new(
            RuleName::new("x".repeat(MAX_RULE_NAME_BYTES))?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128".parse()?),
            Some(PortRange::new(1, u16::MAX)?),
            Some(InterfaceName::new("abcdefghijklmno")?),
            RuleOrigin::Manual,
            true,
        )?;
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        for _index in 0..MAX_RULES {
            state.create_rule(specification.clone())?;
        }

        let serialized = serde_json::to_vec(&state)?;
        assert!(serialized.len() <= MAX_STATE_BYTES);
        store.save(&state)?;
        assert_eq!(store.load()?, Some(state));
        Ok(())
    }

    #[test]
    fn legacy_accept_state_near_byte_limit_does_not_expand_during_upgrade()
    -> Result<(), Box<dyn Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("state.json");
        let store = AtomicStateStore::for_owner(&path, owner(directory.path())?);
        let executable = format!("/{}", "\"".repeat(MAX_APPLICATION_PATH_BYTES - 1));
        let cgroup = format!("/{}", "\"".repeat(MAX_CGROUP_PATH_BYTES - 1));
        let argument_size = MAX_COMMAND_ARGUMENT_BYTES - 1;
        let argument_count = MAX_COMMAND_LINE_BYTES / (argument_size + 1);
        let arguments = (0..argument_count)
            .map(|_| CommandArgument::new("\"".repeat(argument_size)))
            .collect::<Result<Vec<_>, _>>()?;
        let mut specification = RuleSpec::new(
            RuleName::new("x".repeat(MAX_RULE_NAME_BYTES))?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("203.0.113.1/32".parse()?),
            Some(PortRange::single(443)?),
            Some(InterfaceName::new("abcdefghijklmno")?),
            RuleOrigin::Manual,
            true,
        )?;
        specification.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new(executable)?),
            Some(ExecutableFileId {
                device: 1,
                inode: 1,
                size: 1,
                ctime_seconds: 1,
                ctime_nanoseconds: 1,
            }),
            Some(CommandLineSelector::new(
                CommandLineMatch::Exact,
                arguments,
            )?),
            Some(1_000),
            Some(CgroupPath::new(cgroup)?),
        )?);
        specification.validate()?;

        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        let mut near_limit = Vec::new();
        for index in 0..MAX_RULES {
            state.create_rule(specification.clone())?;
            if index % 4 != 3 {
                continue;
            }
            let candidate = serde_json::to_vec(&state)?;
            if candidate.len() > MAX_STATE_BYTES {
                break;
            }
            near_limit = candidate;
        }
        assert!(
            near_limit.len() > MAX_STATE_BYTES - 512 * 1_024,
            "legacy fixture is not close enough to the state limit: {} bytes",
            near_limit.len()
        );
        assert!(
            !near_limit
                .windows(b"\"action\":".len())
                .any(|window| window == b"\"action\":"),
            "default Accept must retain the compact legacy representation"
        );

        fs::write(&path, &near_limit)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let loaded = store.load()?.ok_or("legacy state did not load")?;
        assert!(
            loaded
                .rules()
                .all(|rule| rule.spec.action == crate::RuleAction::Accept)
        );
        store.save(&loaded)?;
        assert!(fs::metadata(&path)?.len() <= u64::try_from(MAX_STATE_BYTES)?);
        Ok(())
    }

    #[test]
    fn oversized_application_state_is_rejected_by_the_semantic_invariant()
    -> Result<(), Box<dyn Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("state.json");
        let store = AtomicStateStore::for_owner(&path, owner(directory.path())?);
        let executable = format!("/{}", "\"".repeat(MAX_APPLICATION_PATH_BYTES - 1));
        let cgroup = format!("/{}", "\"".repeat(MAX_CGROUP_PATH_BYTES - 1));
        let argument_size = MAX_COMMAND_ARGUMENT_BYTES - 1;
        let argument_count = MAX_COMMAND_LINE_BYTES / (argument_size + 1);
        let arguments = (0..argument_count)
            .map(|_| CommandArgument::new("\"".repeat(argument_size)))
            .collect::<Result<Vec<_>, _>>()?;
        let mut specification = RuleSpec::new(
            RuleName::new("x".repeat(MAX_RULE_NAME_BYTES))?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("203.0.113.1/32".parse()?),
            Some(PortRange::single(443)?),
            Some(InterfaceName::new("abcdefghijklmno")?),
            RuleOrigin::Manual,
            true,
        )?;
        specification.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new(executable)?),
            Some(ExecutableFileId {
                device: 1,
                inode: 1,
                size: 1,
                ctime_seconds: 1,
                ctime_nanoseconds: 1,
            }),
            Some(CommandLineSelector::new(
                CommandLineMatch::Exact,
                arguments,
            )?),
            Some(1_000),
            Some(CgroupPath::new(cgroup)?),
        )?);
        specification.validate()?;

        let mut state = State::new();
        for _index in 0..512 {
            state.create_rule(specification.clone())?;
        }
        assert!(matches!(
            state.validate(),
            Err(CoreError::StateSizeLimitReached(MAX_STATE_BYTES))
        ));
        assert!(matches!(
            store.save(&state),
            Err(StorageError::InvalidState(
                CoreError::StateSizeLimitReached(MAX_STATE_BYTES)
            ))
        ));
        assert!(!path.exists());
        Ok(())
    }
}
