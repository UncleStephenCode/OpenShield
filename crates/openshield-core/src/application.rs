use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;

use crate::LearnedEndpoint;

pub const MAX_APPLICATION_PATH_BYTES: usize = 4_096;
pub const MAX_CGROUP_PATH_BYTES: usize = 1_024;
pub const MAX_COMMAND_ARGUMENTS: usize = 64;
pub const MAX_COMMAND_LINE_BYTES: usize = 8 * 1_024;
/// An argument may use the command-line budget, less its terminating NUL.
pub const MAX_COMMAND_ARGUMENT_BYTES: usize = MAX_COMMAND_LINE_BYTES - 1;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ApplicationPath(String);

impl ApplicationPath {
    /// Constructs a bounded absolute executable path.
    ///
    /// Paths are matched exactly as reported by `/proc/<pid>/exe`. Non-UTF-8,
    /// relative, control-character, traversal, and kernel `" (deleted)"`
    /// representations are rejected so a displayed rule cannot mean something
    /// different from the value used for enforcement.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationValidationError::InvalidExecutablePath`] when the
    /// path is not an absolute, bounded, terminal-safe executable path.
    pub fn new(value: impl Into<String>) -> Result<Self, ApplicationValidationError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_APPLICATION_PATH_BYTES {
            return Err(ApplicationValidationError::InvalidExecutablePath);
        }
        if !value.starts_with('/')
            || value.ends_with(" (deleted)")
            || value.chars().any(is_unsafe_text_character)
            || value
                .split('/')
                .any(|component| component == "." || component == "..")
        {
            return Err(ApplicationValidationError::InvalidExecutablePath);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ApplicationPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ApplicationPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CgroupPath(String);

impl CgroupPath {
    /// Constructs one exact, bounded cgroup membership path.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationValidationError::InvalidCgroupPath`] for a
    /// relative, traversing, oversized, or terminal-unsafe value.
    pub fn new(value: impl Into<String>) -> Result<Self, ApplicationValidationError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_CGROUP_PATH_BYTES
            || !value.starts_with('/')
            || value.chars().any(is_unsafe_text_character)
            || value
                .split('/')
                .any(|component| component == "." || component == "..")
        {
            return Err(ApplicationValidationError::InvalidCgroupPath);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CgroupPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CgroupPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CommandArgument(String);

impl CommandArgument {
    /// Constructs one bounded UTF-8 argument without flattening or rewriting argv.
    ///
    /// Control and formatting characters are valid argument bytes, not an
    /// identity-validation error. Matching and serialization preserve them;
    /// [`fmt::Display`] produces an escaped JSON string for safe presentation.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationValidationError::InvalidCommandArgument`] for an
    /// oversized argument or an embedded NUL, which cannot occur inside argv.
    pub fn new(value: impl Into<String>) -> Result<Self, ApplicationValidationError> {
        let value = value.into();
        if value.len() > MAX_COMMAND_ARGUMENT_BYTES || value.contains('\0') {
            return Err(ApplicationValidationError::InvalidCommandArgument);
        }
        Ok(Self(value))
    }

    /// Returns the unmodified argument for matching, not terminal output.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CommandArgument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // JSON escaping is reversible: a literal backslash followed by `n`
        // must never be displayed like an actual newline argument. Escape
        // formatting characters as well, which ordinary JSON permits verbatim.
        formatter.write_str("\"")?;
        for character in self.0.chars() {
            match character {
                '\\' => formatter.write_str("\\\\")?,
                '"' => formatter.write_str("\\\"")?,
                '\n' => formatter.write_str("\\n")?,
                '\r' => formatter.write_str("\\r")?,
                '\t' => formatter.write_str("\\t")?,
                '\u{08}' => formatter.write_str("\\b")?,
                '\u{0c}' => formatter.write_str("\\f")?,
                character
                    if is_unsafe_text_character(character)
                        || matches!(character, '\u{2028}' | '\u{2029}') =>
                {
                    write!(formatter, "\\u{:04x}", u32::from(character))?;
                }
                character => write!(formatter, "{character}")?,
            }
        }
        formatter.write_str("\"")
    }
}

impl<'de> Deserialize<'de> for CommandArgument {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum CommandLineMatch {
    Exact,
    Prefix,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct CommandLineSelector {
    pub kind: CommandLineMatch,
    pub arguments: Vec<CommandArgument>,
}

impl CommandLineSelector {
    /// Constructs an exact or prefix argv selector.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationValidationError::InvalidCommandLine`] when the
    /// argument vector is empty or exceeds its fixed count or byte bounds.
    pub fn new(
        kind: CommandLineMatch,
        arguments: Vec<CommandArgument>,
    ) -> Result<Self, ApplicationValidationError> {
        let selector = Self { kind, arguments };
        selector.validate()?;
        Ok(selector)
    }

    /// Revalidates the fixed argv count and byte bounds.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationValidationError::InvalidCommandLine`] when a bound
    /// is violated.
    pub fn validate(&self) -> Result<(), ApplicationValidationError> {
        if self.arguments.is_empty() || self.arguments.len() > MAX_COMMAND_ARGUMENTS {
            return Err(ApplicationValidationError::InvalidCommandLine);
        }
        let total = self.arguments.iter().try_fold(0_usize, |total, argument| {
            total
                .checked_add(argument.as_str().len())
                .and_then(|value| value.checked_add(1))
        });
        if total.is_none_or(|total| total > MAX_COMMAND_LINE_BYTES) {
            return Err(ApplicationValidationError::InvalidCommandLine);
        }
        Ok(())
    }

    #[must_use]
    pub fn matches(&self, actual: &[CommandArgument]) -> bool {
        match self.kind {
            CommandLineMatch::Exact => self.arguments == actual,
            CommandLineMatch::Prefix => actual.starts_with(&self.arguments),
        }
    }
}

impl<'de> Deserialize<'de> for CommandLineSelector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireSelector {
            kind: CommandLineMatch,
            arguments: Vec<CommandArgument>,
        }

        let wire = WireSelector::deserialize(deserializer)?;
        Self::new(wire.kind, wire.arguments).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableFileId {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub ctime_seconds: i64,
    pub ctime_nanoseconds: i64,
}

impl ExecutableFileId {
    /// Validates a persistent executable version identity.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationValidationError::InvalidExecutableFileId`] when
    /// the inode is zero or the change-time nanoseconds are outside the
    /// kernel's normalized range.
    pub fn validate(self) -> Result<(), ApplicationValidationError> {
        if self.inode == 0 || !(0..1_000_000_000).contains(&self.ctime_nanoseconds) {
            return Err(ApplicationValidationError::InvalidExecutableFileId);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct ApplicationSelector {
    pub executable: Option<ApplicationPath>,
    pub executable_file: Option<ExecutableFileId>,
    pub command_line: Option<CommandLineSelector>,
    pub uid: Option<u32>,
    pub cgroup: Option<CgroupPath>,
    #[serde(default)]
    pub metadata_redacted: bool,
}

impl ApplicationSelector {
    /// Constructs a conjunction of application identity constraints.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationValidationError`] when the exact executable path
    /// is absent or an embedded selector is invalid.
    pub fn new(
        executable: Option<ApplicationPath>,
        executable_file: Option<ExecutableFileId>,
        command_line: Option<CommandLineSelector>,
        uid: Option<u32>,
        cgroup: Option<CgroupPath>,
    ) -> Result<Self, ApplicationValidationError> {
        let selector = Self {
            executable,
            executable_file,
            command_line,
            uid,
            cgroup,
            metadata_redacted: false,
        };
        selector.validate()?;
        Ok(selector)
    }

    /// Revalidates all application selector invariants.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationValidationError`] for missing executable identity,
    /// malformed nested selectors, or an invalid redaction marker.
    pub fn validate(&self) -> Result<(), ApplicationValidationError> {
        if self.metadata_redacted {
            if self.executable.as_ref().map(ApplicationPath::as_str) == Some("/redacted")
                && self.executable_file.is_none()
                && self.command_line.is_none()
                && self.uid.is_none()
                && self.cgroup.is_none()
            {
                return Ok(());
            }
            return Err(ApplicationValidationError::InvalidRedactedSelector);
        }
        if self.executable.is_none() {
            return Err(ApplicationValidationError::ApplicationSelectorNeedsExecutable);
        }
        if self.executable_file.is_some() && self.executable.is_none() {
            return Err(ApplicationValidationError::FileIdWithoutExecutablePath);
        }
        if let Some(file) = self.executable_file {
            file.validate()?;
        }
        if let Some(command_line) = &self.command_line {
            command_line.validate()?;
        }
        Ok(())
    }

    #[must_use]
    pub fn matches(&self, identity: &ApplicationIdentity) -> bool {
        !self.metadata_redacted
            && self
                .executable
                .as_ref()
                .is_none_or(|expected| expected == &identity.executable)
            && self
                .executable_file
                .is_none_or(|expected| expected == identity.executable_file)
            && self
                .command_line
                .as_ref()
                .is_none_or(|expected| expected.matches(&identity.command_line))
            && self.uid.is_none_or(|expected| expected == identity.uid)
            && self
                .cgroup
                .as_ref()
                .is_none_or(|expected| identity.cgroups.iter().any(|actual| actual == expected))
    }

    #[must_use]
    pub fn redacted() -> Self {
        Self {
            executable: Some(ApplicationPath("/redacted".to_owned())),
            executable_file: None,
            command_line: None,
            uid: None,
            cgroup: None,
            metadata_redacted: true,
        }
    }
}

impl<'de> Deserialize<'de> for ApplicationSelector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireSelector {
            executable: Option<ApplicationPath>,
            executable_file: Option<ExecutableFileId>,
            command_line: Option<CommandLineSelector>,
            uid: Option<u32>,
            cgroup: Option<CgroupPath>,
            #[serde(default)]
            metadata_redacted: bool,
        }

        let wire = WireSelector::deserialize(deserializer)?;
        if wire.metadata_redacted {
            let redacted = Self {
                executable: wire.executable,
                executable_file: wire.executable_file,
                command_line: wire.command_line,
                uid: wire.uid,
                cgroup: wire.cgroup,
                metadata_redacted: true,
            };
            redacted.validate().map_err(de::Error::custom)?;
            return Ok(redacted);
        }
        Self::new(
            wire.executable,
            wire.executable_file,
            wire.command_line,
            wire.uid,
            wire.cgroup,
        )
        .map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationIdentity {
    pub pid: u32,
    pub process_start_time_ticks: u64,
    pub executable: ApplicationPath,
    pub executable_file: ExecutableFileId,
    pub command_line: Vec<CommandArgument>,
    pub uid: u32,
    pub cgroups: Vec<CgroupPath>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct LearnedApplicationEndpoint {
    pub endpoint: LearnedEndpoint,
    pub application: ApplicationSelector,
}

impl LearnedApplicationEndpoint {
    /// Validates the exact network endpoint and its application selector.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationValidationError`] when either half is malformed.
    pub fn validate(&self) -> Result<(), ApplicationValidationError> {
        self.endpoint
            .validate()
            .map_err(|_| ApplicationValidationError::InvalidLearnedEndpoint)?;
        self.application.validate()?;
        if self.application.uid.is_none() || self.application.executable_file.is_none() {
            return Err(ApplicationValidationError::IncompleteLearnedApplicationIdentity);
        }
        Ok(())
    }
}

impl ApplicationIdentity {
    /// Validates a process identity captured by the daemon.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationValidationError`] for a missing process identity,
    /// invalid executable file, or bounded-vector overflow.
    pub fn validate(&self) -> Result<(), ApplicationValidationError> {
        if self.pid == 0 || self.process_start_time_ticks == 0 {
            return Err(ApplicationValidationError::InvalidProcessIdentity);
        }
        self.executable_file.validate()?;
        if self.command_line.len() > MAX_COMMAND_ARGUMENTS
            || self.cgroups.len() > MAX_COMMAND_ARGUMENTS
        {
            return Err(ApplicationValidationError::InvalidProcessIdentity);
        }
        let command_bytes = self
            .command_line
            .iter()
            .try_fold(0_usize, |total, argument| {
                total
                    .checked_add(argument.as_str().len())
                    .and_then(|value| value.checked_add(1))
            });
        if command_bytes.is_none_or(|total| total > MAX_COMMAND_LINE_BYTES) {
            return Err(ApplicationValidationError::InvalidProcessIdentity);
        }
        Ok(())
    }

    /// Builds the exact application selector used by learning.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationValidationError`] if the captured identity cannot
    /// form a valid application selector.
    pub fn learned_selector(&self) -> Result<ApplicationSelector, ApplicationValidationError> {
        self.validate()?;
        let command_line =
            CommandLineSelector::new(CommandLineMatch::Exact, self.command_line.clone())?;
        let cgroup = match self.cgroups.as_slice() {
            [] => None,
            [cgroup] => Some(cgroup.clone()),
            _ => return Err(ApplicationValidationError::InvalidProcessIdentity),
        };
        ApplicationSelector::new(
            Some(self.executable.clone()),
            Some(self.executable_file),
            Some(command_line),
            Some(self.uid),
            cgroup,
        )
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ApplicationValidationError {
    #[error("executable path must be a bounded canonical-looking absolute UTF-8 path")]
    InvalidExecutablePath,
    #[error("cgroup path must be a bounded absolute path without traversal or controls")]
    InvalidCgroupPath,
    #[error("command argument exceeds its byte bound or contains an embedded NUL")]
    InvalidCommandArgument,
    #[error("command-line selector is empty or exceeds its fixed bounds")]
    InvalidCommandLine,
    #[error("application selector requires an exact executable path")]
    ApplicationSelectorNeedsExecutable,
    #[error("executable file identity requires an executable path")]
    FileIdWithoutExecutablePath,
    #[error("executable file version identity is invalid")]
    InvalidExecutableFileId,
    #[error("runtime process identity is incomplete or exceeds its fixed bounds")]
    InvalidProcessIdentity,
    #[error("learned application endpoint is not an exact supported network endpoint")]
    InvalidLearnedEndpoint,
    #[error("learned application identity requires a filesystem UID and pinned executable file")]
    IncompleteLearnedApplicationIdentity,
    #[error("redacted application selector has unexpected metadata")]
    InvalidRedactedSelector,
}

fn is_unsafe_text_character(character: char) -> bool {
    character == '\0'
        || character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{feff}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argument_controls_are_preserved_but_displayed_as_reversible_safe_json()
    -> Result<(), Box<dyn std::error::Error>> {
        let raw = "line\n\t\r\u{08}\u{0c}\u{1b}[31m\u{7f}\u{85}\u{202e}rtl\u{2066}\u{feff}\u{2028}\u{2029}\"\\Русский🙂";
        let argument = CommandArgument::new(raw)?;
        assert_eq!(argument.as_str().as_bytes(), raw.as_bytes());
        let displayed = argument.to_string();
        assert!(!displayed.chars().any(is_unsafe_text_character));
        assert!(!displayed.contains(['\u{2028}', '\u{2029}']));
        assert!(displayed.contains("\\n\\t\\r\\b\\f\\u001b[31m"));
        assert!(displayed.contains("\\u202ertl\\u2066\\ufeff"));
        assert_eq!(
            serde_json::from_str::<CommandArgument>(&displayed)?,
            argument
        );
        assert_eq!(
            serde_json::from_str::<CommandArgument>(&serde_json::to_string(&argument)?)?,
            argument
        );
        assert!(
            !format!("{argument:?}")
                .chars()
                .any(is_unsafe_text_character)
        );
        Ok(())
    }

    #[test]
    fn argument_escapes_do_not_conflate_exact_or_prefix_matching()
    -> Result<(), Box<dyn std::error::Error>> {
        for (raw, literal) in [
            ("\n", "\\n"),
            ("\u{1b}[31m", "\\u001b[31m"),
            ("\u{202e}name", "\\u202ename"),
            ("\t", " "),
            ("", "\"\""),
        ] {
            let raw = CommandArgument::new(raw)?;
            let literal = CommandArgument::new(literal)?;
            assert_ne!(raw, literal);
            assert_ne!(raw.to_string(), literal.to_string());
            for kind in [CommandLineMatch::Exact, CommandLineMatch::Prefix] {
                let selector = CommandLineSelector::new(kind, vec![raw.clone()])?;
                assert!(selector.matches(std::slice::from_ref(&raw)));
                assert!(!selector.matches(std::slice::from_ref(&literal)));
            }
        }
        Ok(())
    }

    #[test]
    fn long_arguments_keep_the_total_nul_terminated_command_line_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        let maximum = CommandArgument::new("x".repeat(MAX_COMMAND_LINE_BYTES - 1))?;
        let selector = CommandLineSelector::new(CommandLineMatch::Exact, vec![maximum.clone()])?;
        assert_eq!(
            selector.arguments[0].as_str().len(),
            MAX_COMMAND_LINE_BYTES - 1
        );
        assert!(CommandArgument::new("x".repeat(MAX_COMMAND_LINE_BYTES)).is_err());
        assert!(CommandArgument::new("я".repeat(MAX_COMMAND_LINE_BYTES / 2)).is_err());
        assert!(
            CommandLineSelector::new(
                CommandLineMatch::Exact,
                vec![maximum, CommandArgument::new("")?],
            )
            .is_err()
        );
        assert!(
            CommandLineSelector::new(
                CommandLineMatch::Exact,
                vec![CommandArgument::new("")?; MAX_COMMAND_ARGUMENTS + 1],
            )
            .is_err()
        );
        assert!(CommandLineSelector::new(CommandLineMatch::Exact, vec![]).is_err());
        assert!(
            CommandLineSelector::new(CommandLineMatch::Exact, vec![CommandArgument::new("")?],)
                .is_ok()
        );
        assert!(CommandArgument::new("embedded\0nul").is_err());
        assert!(serde_json::from_str::<CommandArgument>(r#""embedded\u0000nul""#).is_err());
        Ok(())
    }

    #[test]
    fn learned_selector_preserves_long_multiline_arguments_exactly()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut actual = identity()?;
        let raw = format!("{}\n\u{1b}[31m\\n", "x".repeat(2_048));
        actual.command_line.push(CommandArgument::new(raw.clone())?);
        let learned = actual.learned_selector()?;
        assert!(learned.matches(&actual));
        actual.command_line.pop();
        actual
            .command_line
            .push(CommandArgument::new(raw.replace('\n', "\\n"))?);
        assert!(!learned.matches(&actual));
        Ok(())
    }

    fn identity() -> Result<ApplicationIdentity, ApplicationValidationError> {
        Ok(ApplicationIdentity {
            pid: 42,
            process_start_time_ticks: 100,
            executable: ApplicationPath::new("/usr/bin/curl")?,
            executable_file: ExecutableFileId {
                device: 8,
                inode: 99,
                size: 12_345,
                ctime_seconds: 1_700_000_000,
                ctime_nanoseconds: 123_456_789,
            },
            command_line: vec![
                CommandArgument::new("curl")?,
                CommandArgument::new("https://example.test")?,
            ],
            uid: 1_000,
            cgroups: vec![CgroupPath::new("/user.slice/test.scope")?],
        })
    }

    #[test]
    fn exact_and_prefix_command_lines_are_distinct() -> Result<(), Box<dyn std::error::Error>> {
        let identity = identity()?;
        let prefix = CommandLineSelector::new(
            CommandLineMatch::Prefix,
            vec![CommandArgument::new("curl")?],
        )?;
        let exact =
            CommandLineSelector::new(CommandLineMatch::Exact, vec![CommandArgument::new("curl")?])?;
        assert!(prefix.matches(&identity.command_line));
        assert!(!exact.matches(&identity.command_line));
        Ok(())
    }

    #[test]
    fn selector_matches_all_configured_identity_fields() -> Result<(), Box<dyn std::error::Error>> {
        let identity = identity()?;
        let selector = ApplicationSelector::new(
            Some(ApplicationPath::new("/usr/bin/curl")?),
            Some(ExecutableFileId {
                device: 8,
                inode: 99,
                size: 12_345,
                ctime_seconds: 1_700_000_000,
                ctime_nanoseconds: 123_456_789,
            }),
            Some(CommandLineSelector::new(
                CommandLineMatch::Prefix,
                vec![CommandArgument::new("curl")?],
            )?),
            Some(1_000),
            Some(CgroupPath::new("/user.slice/test.scope")?),
        )?;
        assert!(selector.matches(&identity));

        let wrong_uid = ApplicationSelector::new(
            Some(ApplicationPath::new("/usr/bin/curl")?),
            None,
            None,
            Some(1_001),
            None,
        )?;
        assert!(!wrong_uid.matches(&identity));
        Ok(())
    }

    #[test]
    fn selector_rejects_in_place_executable_version_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        let original = identity()?;
        let selector = ApplicationSelector::new(
            Some(original.executable.clone()),
            Some(original.executable_file),
            None,
            Some(original.uid),
            None,
        )?;
        let rewritten = ApplicationIdentity {
            executable_file: ExecutableFileId {
                device: original.executable_file.device,
                inode: original.executable_file.inode,
                size: original.executable_file.size + 1,
                ctime_seconds: original.executable_file.ctime_seconds + 1,
                ctime_nanoseconds: original.executable_file.ctime_nanoseconds,
            },
            ..original
        };

        assert!(!selector.matches(&rewritten));
        Ok(())
    }

    #[test]
    fn executable_version_rejects_invalid_timestamp_nanoseconds() {
        let invalid = ExecutableFileId {
            device: 8,
            inode: 99,
            size: 1,
            ctime_seconds: 0,
            ctime_nanoseconds: 1_000_000_000,
        };
        assert_eq!(
            invalid.validate(),
            Err(ApplicationValidationError::InvalidExecutableFileId)
        );
    }

    #[test]
    fn executable_version_wire_format_requires_every_known_field() {
        assert!(serde_json::from_str::<ExecutableFileId>(r#"{"device":8,"inode":99}"#).is_err());
        assert!(serde_json::from_str::<ExecutableFileId>(
            r#"{"device":8,"inode":99,"size":1,"ctime_seconds":2,"ctime_nanoseconds":3,"digest":"unexpected"}"#
        )
        .is_err());
    }

    #[test]
    fn rejects_traversal_deleted_and_bidi_paths() {
        assert!(ApplicationPath::new("/usr/../bin/curl").is_err());
        assert!(ApplicationPath::new("/usr/bin/curl (deleted)").is_err());
        assert!(ApplicationPath::new("/usr/bin/\u{202e}lruc").is_err());
    }

    #[test]
    fn learned_selector_pins_exact_captured_identity() -> Result<(), Box<dyn std::error::Error>> {
        let identity = identity()?;
        let selector = identity.learned_selector()?;
        assert_eq!(
            selector.command_line,
            Some(CommandLineSelector::new(
                CommandLineMatch::Exact,
                identity.command_line.clone(),
            )?)
        );
        assert_eq!(selector.uid, Some(1_000));
        assert!(selector.executable_file.is_some());
        assert_eq!(selector.cgroup, identity.cgroups.first().cloned());
        assert!(selector.matches(&identity));
        Ok(())
    }

    #[test]
    fn learned_selector_omits_unavailable_v1_cgroup_but_keeps_exact_argv()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut identity = identity()?;
        identity.cgroups.clear();
        let selector = identity.learned_selector()?;
        assert!(selector.command_line.is_some());
        assert!(selector.cgroup.is_none());
        assert!(selector.matches(&identity));
        Ok(())
    }

    #[test]
    fn learned_selector_rejects_ambiguous_cgroup_identity() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut identity = identity()?;
        identity
            .cgroups
            .push(CgroupPath::new("/user.slice/other.scope")?);
        assert_eq!(
            identity.learned_selector(),
            Err(ApplicationValidationError::InvalidProcessIdentity)
        );
        Ok(())
    }
}
