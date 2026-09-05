use std::collections::HashSet;
use std::fmt::Write as _;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use openshield_core::{
    COUNTER_ACCEPTED_IN, COUNTER_ACCEPTED_OUT, COUNTER_DROPPED_IN, COUNTER_DROPPED_OUT,
    COUNTER_LEARNED_OUT, CounterValue, FirewallCounters, IPTABLES_FORWARD_CHAIN,
    IPTABLES_INPUT_CHAIN, IPTABLES_LEARNING_OBSERVE_CHAIN, IPTABLES_MARK_SANITIZE_CHAIN,
    IPTABLES_OUTPUT_CHAIN, IPTABLES_OWNERSHIP_COMMENT, IptablesCompiler, IptablesPolicy,
    NFT_OWNERSHIP_COUNTER, NftablesCompiler, Snapshot, owned_chains, owned_mangle_chains,
};
#[cfg(test)]
use openshield_core::{
    InterfaceName, LEARNED_ICMP_V4_SET, LEARNED_ICMP_V6_SET, LEARNED_TCP_V4_SET,
    LEARNED_TCP_V6_SET, LEARNED_UDP_V4_SET, LEARNED_UDP_V6_SET, LearnedEndpoint, PortRange,
    TransportProtocol,
};
use openshield_protocol::FirewallBackendKind;
use serde_json::Value;

const NFT_CANDIDATES: [&str; 3] = ["/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft"];
const NFT_TABLE_QUERY: [&str; 4] = ["-j", "list", "tables", "inet"];
const NFT_COUNTER_QUERY: [&str; 4] = ["-j", "list", "counters", "inet"];
const NFT_OBSERVATION_QUERY: [&str; 2] = [
    "-j",
    "list tables inet; list chains inet; list counters inet",
];
#[cfg(test)]
const NFT_SET_QUERY_PREFIX: [&str; 5] = ["-j", "list", "set", "inet", "openshield"];
#[cfg(test)]
const LEARNING_SET_NAMES: [&str; 6] = [
    LEARNED_TCP_V4_SET,
    LEARNED_TCP_V6_SET,
    LEARNED_UDP_V4_SET,
    LEARNED_UDP_V6_SET,
    LEARNED_ICMP_V4_SET,
    LEARNED_ICMP_V6_SET,
];
const NFT_TIMEOUT: Duration = Duration::from_secs(5);
const NFT_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const NFT_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(6);
const WAIT_INTERVAL: Duration = Duration::from_millis(10);
// A maximum-size validated state can expand when rendered as nft syntax.  Keep
// the execution input bounded while leaving headroom for all 10,000 rules.
const MAX_POLICY_BYTES: usize = 8 * 1024 * 1024;
const MAX_NFT_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_FIREWALL_STDERR_BYTES: usize = 64 * 1024;
const XT_WAIT_SECONDS: &str = "5";
const XTABLES_LIST_ARGS: [&str; 6] = ["--wait", XT_WAIT_SECONDS, "-t", "filter", "-n", "-L"];
const LEGACY_BACKEND_UNAVAILABLE_SUFFIXES: [&str; 2] = [
    ": Cannot initialize: iptables who? (do you need to insmod?)",
    ": Cannot initialize: Protocol not supported",
];
// `--test --noflush` validates every xtables extension and control-flow
// primitive used by the compatibility compiler without changing live rules.
// A bundle which merely understands an empty filter table is not sufficient:
// legacy/nft shims can be installed while their kernel backend or one of the
// required modules is unavailable.
const XTABLES_CAPABILITY_POLICY: &str = "*mangle\n\
:OPENSHIELD_PROBE_MARK - [0:0]\n\
-A OPENSHIELD_PROBE_MARK -m mark ! --mark 0x00000000/0xc0000000 -j MARK --set-xmark 0x00000000/0xc0000000\n\
-A OPENSHIELD_PROBE_MARK -m conntrack --ctdir ORIGINAL -j NFQUEUE --queue-num 1338 --queue-bypass\n\
-A OPENSHIELD_PROBE_MARK -p tcp -m tcp --tcp-flags FIN,RST NONE -m conntrack --ctstate ESTABLISHED --ctdir ORIGINAL -m limit --limit 64/sec --limit-burst 32 -j NFQUEUE --queue-num 1338 --queue-bypass\n\
-A OPENSHIELD_PROBE_MARK -j RETURN\n\
COMMIT\n\
*filter\n\
:OPENSHIELD_PROBE - [0:0]\n\
:OPENSHIELD_PROBE_GOTO - [0:0]\n\
-A OPENSHIELD_PROBE -p tcp -m tcp --tcp-flags RST RST -m conntrack --ctstate RELATED --ctdir REPLY -m comment --comment openshield:probe -j RETURN\n\
-A OPENSHIELD_PROBE -p tcp -m conntrack --ctstate ESTABLISHED --ctorigdstport 443 --ctdir ORIGINAL -m connmark --mark 0x40000001/0x7fffffff -m comment --comment openshield:probe -j RETURN\n\
-A OPENSHIELD_PROBE -m conntrack --ctstate UNTRACKED -j RETURN\n\
-A OPENSHIELD_PROBE -m mark ! --mark 0x00000000/0xc0000000 -j MARK --set-xmark 0x00000000/0xc0000000\n\
-A OPENSHIELD_PROBE -m conntrack --ctdir ORIGINAL -j NFQUEUE --queue-num 1337\n\
-A OPENSHIELD_PROBE -m mark --mark 0x40000000/0xc0000000 -j REJECT\n\
-A OPENSHIELD_PROBE -m mark --mark 0x80000000/0xc0000000 -g OPENSHIELD_PROBE_GOTO\n\
-A OPENSHIELD_PROBE_GOTO -j CONNMARK --set-xmark 0x40000001/0x7fffffff\n\
-A OPENSHIELD_PROBE_GOTO -j RETURN\n\
COMMIT\n";
const IP6TABLES_CONTROL_PLANE_CAPABILITY_POLICY: &str = "*filter\n\
:OPENSHIELD_PROBE6 - [0:0]\n\
-A OPENSHIELD_PROBE6 -p ipv6-icmp -m addrtype ! --src-type UNSPEC,MULTICAST -m hl --hl-eq 255 -m icmp6 --icmpv6-type 134 -j RETURN\n\
COMMIT\n";
#[cfg(test)]
const MAX_LEARNED_ENDPOINTS: usize = 6 * 4_096;

pub trait FirewallObserver: Send {
    fn policy_observation(&mut self) -> Result<FirewallCounters>;
}

pub trait FirewallBackend: FirewallObserver {
    /// Identifies the active production firewall implementation.
    ///
    /// Test or third-party backends remain `Unknown` unless they explicitly
    /// provide a trustworthy identity.
    fn kind(&self) -> FirewallBackendKind {
        FirewallBackendKind::Unknown
    }

    fn apply(&mut self, snapshot: &Snapshot) -> Result<()>;
    fn fail_closed(&mut self) -> Result<()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueVerdictStrategy {
    Accept,
    RepeatWithHandoffMark,
}

#[derive(Clone, Debug)]
pub struct NftBackend {
    binary: PathBuf,
}

impl NftBackend {
    pub fn discover() -> Result<Self> {
        for candidate in NFT_CANDIDATES.map(Path::new) {
            if validate_nft_binary(candidate).is_ok() {
                return Ok(Self {
                    binary: candidate.to_path_buf(),
                });
            }
        }
        bail!("no trusted nft executable was found in the fixed allowlist")
    }

    fn checked_apply(&self, policy: &[u8]) -> Result<()> {
        ensure!(
            policy.len() <= MAX_POLICY_BYTES,
            "compiled nftables policy exceeds {MAX_POLICY_BYTES} bytes"
        );

        ensure!(
            !active_xtables_artifacts()?,
            "refusing nftables activation while an OpenShield iptables/ip6tables policy is still active"
        );
        self.ensure_owned_table_or_absent()?;
        self.run_with_input(&["-c", "-f", "-"], policy)
            .context("nftables validation failed")?;
        self.run_with_input(&["-f", "-"], policy)
            .context("atomic nftables transaction failed")
    }

    fn ensure_owned_table_or_absent(&self) -> Result<()> {
        let tables = self.capture(&NFT_TABLE_QUERY)?;
        match openshield_table_count(&tables)? {
            0 => Ok(()),
            1 => {
                let counters = self.capture(&NFT_COUNTER_QUERY)?;
                verify_nft_ownership_counter(&counters).context(
                    "refusing to replace nft table inet openshield without its ownership sentinel",
                )
            }
            _ => bail!("duplicate nft table inet openshield declarations were reported"),
        }
    }

    fn probe(&self) -> Result<()> {
        ensure!(
            !active_xtables_artifacts()?,
            "OpenShield artifacts from an xtables backend are still active"
        );
        self.ensure_owned_table_or_absent()
            .context("nftables ownership preflight failed")?;

        // Runtime integrity monitoring depends on all three bounded JSON
        // queries. Exercise their exact single-process command form before
        // selecting this backend, even when no OpenShield table exists yet.
        // nft 1.0.6 accepts semicolon-separated commands as one literal argv
        // value and emits one JSON document per command.
        let observation = self
            .capture_observation()
            .context("nftables batched observation preflight failed")?;
        parse_nft_observation_documents(&observation)?;

        let mut state = openshield_core::State::new();
        state
            .set_mode(openshield_core::Mode::Learning)
            .context("cannot construct representative nftables Learning probe")?;
        let policy = NftablesCompiler::compile(&state.snapshot())
            .context("failed to compile nftables capability probe")?;
        self.run_with_input(&["-c", "-f", "-"], policy.as_bytes())
            .context("trusted nft executable or kernel nftables support is unusable")
    }

    fn run_with_input(&self, args: &[&str], input: &[u8]) -> Result<()> {
        let mut child = self
            .command(args)
            .stdin(Stdio::piped())
            .spawn()
            .with_context(|| {
                format!(
                    "failed to start allowlisted nft executable {}",
                    self.binary.display()
                )
            })?;
        let Some(mut stdin) = child.stdin.take() else {
            terminate_child(&mut child);
            bail!("nft stdin pipe was not created");
        };
        let policy = input.to_vec();
        let writer = match thread::Builder::new()
            .name("openshield-nft-writer".to_owned())
            .spawn(move || stdin.write_all(&policy))
        {
            Ok(writer) => writer,
            Err(error) => {
                terminate_child(&mut child);
                return Err(error).context("failed to create bounded nft input writer");
            }
        };

        let status_result = wait_with_timeout(&mut child, NFT_TIMEOUT);
        let write_result = writer
            .join()
            .map_err(|_| anyhow!("nft input writer terminated unexpectedly"))?;
        let status = status_result?;
        write_result.context("failed to send policy to nft")?;
        ensure!(status.success(), "nft exited with status {status}");
        Ok(())
    }

    fn capture(&self, args: &[&str]) -> Result<Vec<u8>> {
        self.capture_bounded(args, NFT_QUERY_TIMEOUT, MAX_NFT_OUTPUT_BYTES)
    }

    fn capture_bounded(
        &self,
        args: &[&str],
        timeout: Duration,
        maximum_output: usize,
    ) -> Result<Vec<u8>> {
        let mut child = self
            .command(args)
            .stdout(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to start {}", self.binary.display()))?;
        let Some(mut stdout) = child.stdout.take() else {
            terminate_child(&mut child);
            bail!("nft stdout pipe was not created");
        };

        let reader = match thread::Builder::new()
            .name("openshield-nft-reader".to_owned())
            .spawn(move || -> Result<(Vec<u8>, bool)> {
                let mut captured = Vec::new();
                let mut overflow = false;
                let mut chunk = [0_u8; 8192];
                loop {
                    let read = stdout
                        .read(&mut chunk)
                        .context("failed to read nft output")?;
                    if read == 0 {
                        break;
                    }
                    let remaining = maximum_output.saturating_sub(captured.len());
                    let keep = remaining.min(read);
                    captured.extend_from_slice(&chunk[..keep]);
                    overflow |= keep != read;
                }
                Ok((captured, overflow))
            }) {
            Ok(reader) => reader,
            Err(error) => {
                terminate_child(&mut child);
                return Err(error).context("failed to create bounded nft output reader");
            }
        };

        let status_result = wait_with_timeout(&mut child, timeout);
        let output_result = reader
            .join()
            .map_err(|_| anyhow!("nft output reader terminated unexpectedly"))?;
        let status = status_result?;
        let (output, overflow) = output_result?;
        ensure!(status.success(), "nft exited with status {status}");
        ensure!(!overflow, "nft output exceeded {maximum_output} bytes");
        Ok(output)
    }

    fn capture_observation(&self) -> Result<Vec<u8>> {
        self.capture_bounded(
            &NFT_OBSERVATION_QUERY,
            NFT_OBSERVATION_TIMEOUT,
            MAX_NFT_OUTPUT_BYTES.saturating_mul(3),
        )
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(&self.binary);
        command
            .args(args)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }
}

impl FirewallBackend for NftBackend {
    fn kind(&self) -> FirewallBackendKind {
        FirewallBackendKind::Nftables
    }

    fn apply(&mut self, snapshot: &Snapshot) -> Result<()> {
        let policy = NftablesCompiler::compile(snapshot).context("failed to compile nft policy")?;
        self.checked_apply(policy.as_bytes())
    }

    fn fail_closed(&mut self) -> Result<()> {
        let snapshot = openshield_core::State::new().snapshot();
        let policy = NftablesCompiler::compile(&snapshot)
            .context("failed to compile fail-closed nft policy")?;
        self.checked_apply(policy.as_bytes())
    }
}

impl FirewallObserver for NftBackend {
    fn policy_observation(&mut self) -> Result<FirewallCounters> {
        // Avoid `list table`: a valid 10,000-rule policy makes that operation
        // O(rules) and can exceed the observation bound. These plural queries
        // are O(named objects) on nftables 1.0.6 and still verify every base
        // hook, default-drop policy, and named counter. They deliberately do
        // not authenticate rule bodies: a root process could inject an early
        // verdict while retaining that metadata. Root is trusted by the threat
        // model; detecting such mutation would require listing up to 10,000
        // rules on every observation interval or a different table topology.
        // Preserve the exact table/chain/counter checks and their one-second
        // cadence while avoiding three fork/exec cycles per observation.
        parse_nft_policy_observation(&self.capture_observation()?)
    }
}

/// Deterministic firewall backend selection. A safely preflighted nftables
/// backend is always preferred. The compatibility backend is considered when
/// any read-only nftables ownership, observation, coexistence, or kernel
/// capability check fails.
#[derive(Clone, Debug)]
pub enum AutoBackend {
    Nft(NftBackend),
    Iptables(IptablesBackend),
}

impl AutoBackend {
    pub fn discover() -> Result<Self> {
        Self::discover_with(
            || {
                let backend = NftBackend::discover()?;
                backend.probe()?;
                Ok(backend)
            },
            IptablesBackend::discover,
        )
    }

    fn discover_with<Nft, Iptables>(
        discover_usable_nft: Nft,
        discover_usable_iptables: Iptables,
    ) -> Result<Self>
    where
        Nft: FnOnce() -> Result<NftBackend>,
        Iptables: FnOnce() -> Result<IptablesBackend>,
    {
        let nft_error = match discover_usable_nft() {
            Ok(backend) => return Ok(Self::Nft(backend)),
            Err(error) => error,
        };
        match discover_usable_iptables() {
            Ok(backend) => Ok(Self::Iptables(backend)),
            Err(iptables_error) => Err(anyhow!(
                "neither firewall backend is safely usable: nftables: {nft_error:#}; iptables fallback: {iptables_error:#}"
            )),
        }
    }

    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Nft(_) => "nftables",
            Self::Iptables(_) => "iptables/ip6tables",
        }
    }

    #[must_use]
    pub const fn queue_verdict_strategy(&self) -> QueueVerdictStrategy {
        match self {
            Self::Nft(_) => QueueVerdictStrategy::Accept,
            Self::Iptables(_) => QueueVerdictStrategy::RepeatWithHandoffMark,
        }
    }
}

impl FirewallBackend for AutoBackend {
    fn kind(&self) -> FirewallBackendKind {
        match self {
            Self::Nft(_) => FirewallBackendKind::Nftables,
            Self::Iptables(_) => FirewallBackendKind::Iptables,
        }
    }

    fn apply(&mut self, snapshot: &Snapshot) -> Result<()> {
        match self {
            Self::Nft(backend) => backend.apply(snapshot),
            Self::Iptables(backend) => backend.apply(snapshot),
        }
    }

    fn fail_closed(&mut self) -> Result<()> {
        match self {
            Self::Nft(backend) => backend.fail_closed(),
            Self::Iptables(backend) => backend.fail_closed(),
        }
    }
}

impl FirewallObserver for AutoBackend {
    fn policy_observation(&mut self) -> Result<FirewallCounters> {
        match self {
            Self::Nft(backend) => backend.policy_observation(),
            Self::Iptables(backend) => backend.policy_observation(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct XtablesBundle {
    command: &'static str,
    restore: &'static str,
    save: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum XtablesWorld {
    Legacy,
    Nft,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct XtablesIdentity {
    resolved: PathBuf,
    world: XtablesWorld,
}

const IPV4_XTABLES_BUNDLES: [XtablesBundle; 12] = [
    XtablesBundle {
        command: "/usr/sbin/iptables-legacy",
        restore: "/usr/sbin/iptables-legacy-restore",
        save: "/usr/sbin/iptables-legacy-save",
    },
    XtablesBundle {
        command: "/usr/sbin/iptables-nft",
        restore: "/usr/sbin/iptables-nft-restore",
        save: "/usr/sbin/iptables-nft-save",
    },
    XtablesBundle {
        command: "/usr/sbin/iptables",
        restore: "/usr/sbin/iptables-restore",
        save: "/usr/sbin/iptables-save",
    },
    XtablesBundle {
        command: "/sbin/iptables-legacy",
        restore: "/sbin/iptables-legacy-restore",
        save: "/sbin/iptables-legacy-save",
    },
    XtablesBundle {
        command: "/sbin/iptables-nft",
        restore: "/sbin/iptables-nft-restore",
        save: "/sbin/iptables-nft-save",
    },
    XtablesBundle {
        command: "/sbin/iptables",
        restore: "/sbin/iptables-restore",
        save: "/sbin/iptables-save",
    },
    XtablesBundle {
        command: "/usr/bin/iptables-legacy",
        restore: "/usr/bin/iptables-legacy-restore",
        save: "/usr/bin/iptables-legacy-save",
    },
    XtablesBundle {
        command: "/usr/bin/iptables-nft",
        restore: "/usr/bin/iptables-nft-restore",
        save: "/usr/bin/iptables-nft-save",
    },
    XtablesBundle {
        command: "/usr/bin/iptables",
        restore: "/usr/bin/iptables-restore",
        save: "/usr/bin/iptables-save",
    },
    XtablesBundle {
        command: "/bin/iptables-legacy",
        restore: "/bin/iptables-legacy-restore",
        save: "/bin/iptables-legacy-save",
    },
    XtablesBundle {
        command: "/bin/iptables-nft",
        restore: "/bin/iptables-nft-restore",
        save: "/bin/iptables-nft-save",
    },
    XtablesBundle {
        command: "/bin/iptables",
        restore: "/bin/iptables-restore",
        save: "/bin/iptables-save",
    },
];

const IPV6_XTABLES_BUNDLES: [XtablesBundle; 12] = [
    XtablesBundle {
        command: "/usr/sbin/ip6tables-legacy",
        restore: "/usr/sbin/ip6tables-legacy-restore",
        save: "/usr/sbin/ip6tables-legacy-save",
    },
    XtablesBundle {
        command: "/usr/sbin/ip6tables-nft",
        restore: "/usr/sbin/ip6tables-nft-restore",
        save: "/usr/sbin/ip6tables-nft-save",
    },
    XtablesBundle {
        command: "/usr/sbin/ip6tables",
        restore: "/usr/sbin/ip6tables-restore",
        save: "/usr/sbin/ip6tables-save",
    },
    XtablesBundle {
        command: "/sbin/ip6tables-legacy",
        restore: "/sbin/ip6tables-legacy-restore",
        save: "/sbin/ip6tables-legacy-save",
    },
    XtablesBundle {
        command: "/sbin/ip6tables-nft",
        restore: "/sbin/ip6tables-nft-restore",
        save: "/sbin/ip6tables-nft-save",
    },
    XtablesBundle {
        command: "/sbin/ip6tables",
        restore: "/sbin/ip6tables-restore",
        save: "/sbin/ip6tables-save",
    },
    XtablesBundle {
        command: "/usr/bin/ip6tables-legacy",
        restore: "/usr/bin/ip6tables-legacy-restore",
        save: "/usr/bin/ip6tables-legacy-save",
    },
    XtablesBundle {
        command: "/usr/bin/ip6tables-nft",
        restore: "/usr/bin/ip6tables-nft-restore",
        save: "/usr/bin/ip6tables-nft-save",
    },
    XtablesBundle {
        command: "/usr/bin/ip6tables",
        restore: "/usr/bin/ip6tables-restore",
        save: "/usr/bin/ip6tables-save",
    },
    XtablesBundle {
        command: "/bin/ip6tables-legacy",
        restore: "/bin/ip6tables-legacy-restore",
        save: "/bin/ip6tables-legacy-save",
    },
    XtablesBundle {
        command: "/bin/ip6tables-nft",
        restore: "/bin/ip6tables-nft-restore",
        save: "/bin/ip6tables-nft-save",
    },
    XtablesBundle {
        command: "/bin/ip6tables",
        restore: "/bin/ip6tables-restore",
        save: "/bin/ip6tables-save",
    },
];

#[derive(Clone, Debug)]
struct XtablesTools {
    command: PathBuf,
    restore: PathBuf,
    save: PathBuf,
}

impl XtablesTools {
    fn discover(candidates: &[XtablesBundle]) -> Result<Self> {
        Self::discover_with(
            candidates,
            |path| validate_xtables_binary(path, candidates),
            Self::probe,
        )
    }

    fn discover_with<Validate, Probe>(
        candidates: &[XtablesBundle],
        mut validate: Validate,
        mut probe: Probe,
    ) -> Result<Self>
    where
        Validate: FnMut(&Path) -> Result<()>,
        Probe: FnMut(&Self) -> Result<()>,
    {
        for candidate in candidates {
            if validate(Path::new(candidate.command)).is_err()
                || validate(Path::new(candidate.restore)).is_err()
                || validate(Path::new(candidate.save)).is_err()
            {
                continue;
            }
            let tools = Self {
                command: PathBuf::from(candidate.command),
                restore: PathBuf::from(candidate.restore),
                save: PathBuf::from(candidate.save),
            };
            if probe(&tools).is_ok() {
                return Ok(tools);
            }
        }
        bail!("no complete, trusted, and usable xtables executable bundle was found")
    }

    fn probe(&self) -> Result<()> {
        run_command(&self.command, &XTABLES_LIST_ARGS, NFT_QUERY_TIMEOUT)
            .context("xtables command capability probe failed")?;
        self.capture("filter")
            .context("xtables-save filter capability probe failed")?;
        self.capture("mangle")
            .context("xtables-save mangle capability probe failed")?;
        self.restore(XTABLES_CAPABILITY_POLICY, true)
            .context("xtables-restore capability probe failed")?;
        if self
            .command
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|name| name.starts_with("ip6tables"))
        {
            self.restore(IP6TABLES_CONTROL_PLANE_CAPABILITY_POLICY, true)
                .context("ip6tables host control-plane capability probe failed")?;
        }
        Ok(())
    }

    fn restore(&self, policy: &str, test_only: bool) -> Result<()> {
        ensure!(
            policy.len() <= MAX_POLICY_BYTES,
            "compiled iptables policy exceeds {MAX_POLICY_BYTES} bytes"
        );
        let mut args = vec!["--wait", XT_WAIT_SECONDS, "--noflush"];
        if test_only {
            args.push("--test");
        }
        run_command_with_input(&self.restore, &args, policy.as_bytes(), NFT_TIMEOUT)
            .with_context(|| format!("{} rejected restore transaction", self.restore.display()))
    }

    fn insert_dispatch(&self, table: &str, built_in: &str, target: &str) -> Result<()> {
        run_command(
            &self.command,
            &[
                "--wait",
                XT_WAIT_SECONDS,
                "-t",
                table,
                "-I",
                built_in,
                "1",
                "-j",
                target,
            ],
            NFT_TIMEOUT,
        )
        .with_context(|| format!("cannot install fail-closed {built_in} dispatcher"))
    }

    fn append_dispatch(&self, table: &str, built_in: &str, target: &str) -> Result<()> {
        run_command(
            &self.command,
            &[
                "--wait",
                XT_WAIT_SECONDS,
                "-t",
                table,
                "-A",
                built_in,
                "-j",
                target,
            ],
            NFT_TIMEOUT,
        )
        .with_context(|| format!("cannot append fail-closed {built_in} dispatcher"))
    }

    fn delete_dispatch(&self, table: &str, built_in: &str, target: &str) -> Result<()> {
        run_command(
            &self.command,
            &[
                "--wait",
                XT_WAIT_SECONDS,
                "-t",
                table,
                "-D",
                built_in,
                "-j",
                target,
            ],
            NFT_TIMEOUT,
        )
        .with_context(|| format!("cannot relocate {built_in} dispatcher"))
    }

    fn capture(&self, table: &str) -> Result<Vec<u8>> {
        ensure!(
            matches!(table, "filter" | "mangle"),
            "unsupported xtables inspection table"
        );
        let args = selected_xtables_save_args(table);
        capture_command(&self.save, &args, NFT_QUERY_TIMEOUT, MAX_NFT_OUTPUT_BYTES)
            .with_context(|| format!("cannot inspect policy through {}", self.save.display()))
    }
}

#[derive(Clone, Debug, Default)]
struct ExpectedXtablesPolicy {
    ipv4_rules: Option<Vec<String>>,
    ipv6_rules: Option<Vec<String>>,
}

#[derive(Debug)]
struct CapturedXtablesPolicy {
    rules: Vec<String>,
    counters: FirewallCounters,
}

#[derive(Clone, Debug)]
pub struct IptablesBackend {
    ipv4: XtablesTools,
    ipv6: XtablesTools,
    expected: Arc<Mutex<ExpectedXtablesPolicy>>,
}

impl IptablesBackend {
    pub fn discover() -> Result<Self> {
        Ok(Self {
            ipv4: XtablesTools::discover(&IPV4_XTABLES_BUNDLES)
                .context("IPv4 xtables tools are unavailable")?,
            ipv6: XtablesTools::discover(&IPV6_XTABLES_BUNDLES)
                .context("IPv6 xtables tools are unavailable")?,
            expected: Arc::new(Mutex::new(ExpectedXtablesPolicy::default())),
        })
    }

    fn ensure_owned_chains(
        tools: &XtablesTools,
        table: &str,
        chains: &[&str],
    ) -> Result<XtablesSnapshot> {
        let snapshot = parse_xtables_save(&tools.capture(table)?)?;
        let mut missing = Vec::new();
        for &chain in chains {
            if snapshot.declared_chains.contains(chain) {
                snapshot.verify_chain_ownership(chain)?;
            } else {
                missing.push(chain);
            }
        }

        if !missing.is_empty() {
            tools
                .restore(&ownership_initialization_policy(table, &missing), false)
                .context("cannot atomically create owned iptables chains")?;
        }

        let installed = parse_xtables_save(&tools.capture(table)?)?;
        for &chain in chains {
            ensure!(
                installed.declared_chains.contains(chain),
                "required OpenShield iptables chain {chain} is missing after initialization"
            );
            installed.verify_chain_ownership(chain)?;
        }
        Ok(installed)
    }

    fn install_owned_policy(tools: &XtablesTools, policy: &str) -> Result<()> {
        Self::ensure_owned_chains(tools, "mangle", &owned_mangle_chains())?;
        Self::ensure_owned_chains(tools, "filter", &owned_chains())?;
        tools.restore(policy, false)
    }

    fn ensure_no_alternate_xtables_artifacts(&self) -> Result<()> {
        let ipv4 = active_alternate_xtables_world(&IPV4_XTABLES_BUNDLES, &self.ipv4.save);
        let ipv6 = active_alternate_xtables_world(&IPV6_XTABLES_BUNDLES, &self.ipv6.save);
        match (ipv4, ipv6) {
            (Ok(false), Ok(false)) => Ok(()),
            (ipv4, ipv6) => bail!(
                "refusing activation while the alternate xtables backend may contain OpenShield artifacts: IPv4: {}; IPv6: {}",
                bool_result_summary(&ipv4),
                bool_result_summary(&ipv6)
            ),
        }
    }

    fn ensure_topology(tools: &XtablesTools, block_policy: &str) -> Result<()> {
        Self::ensure_owned_chains(tools, "mangle", &owned_mangle_chains())?;
        Self::ensure_owned_chains(tools, "filter", &owned_chains())?;
        // Populate every owned chain with terminal drops before exposing any
        // new dispatcher from a built-in chain.
        tools.restore(block_policy, false)?;
        let filter = parse_xtables_save(&tools.capture("filter")?)?;
        for (built_in, target) in filter_dispatcher_pairs() {
            if filter.first_rule(built_in) != Some(dispatch_rule(built_in, target).as_str()) {
                tools.insert_dispatch("filter", built_in, target)?;
            }
        }
        let mangle = parse_xtables_save(&tools.capture("mangle")?)?;
        for (built_in, target) in mangle_first_dispatcher_pairs() {
            if mangle.first_rule(built_in) != Some(dispatch_rule(built_in, target).as_str()) {
                tools.insert_dispatch("mangle", built_in, target)?;
            }
        }
        for (built_in, target) in mangle_last_dispatcher_pairs() {
            let expected = dispatch_rule(built_in, target);
            let target_dispatchers: Vec<&str> = mangle
                .rules_for_chain(built_in)
                .filter(|rule| rule_jumps_to(rule, target))
                .collect();
            ensure!(
                target_dispatchers
                    .iter()
                    .all(|rule| *rule == expected.as_str()),
                "refusing to relocate a noncanonical mangle {built_in} dispatcher to {target}"
            );
            if target_dispatchers.len() != 1
                || mangle.last_rule(built_in) != Some(expected.as_str())
            {
                // append-then-delete keeps one observer reachable throughout
                // relocation. BlockAll is already installed in the first
                // filter dispatcher, so even a command failure stays closed.
                tools.append_dispatch("mangle", built_in, target)?;
                for _ in 0..target_dispatchers.len() {
                    tools.delete_dispatch("mangle", built_in, target)?;
                }
            }
        }
        Self::capture_verified_policy(tools).map(|_captured| ())
    }

    fn capture_verified_policy(tools: &XtablesTools) -> Result<CapturedXtablesPolicy> {
        let filter = parse_xtables_save(&tools.capture("filter")?)?;
        let mangle = parse_xtables_save(&tools.capture("mangle")?)?;
        filter.verify_filter_topology()?;
        mangle.verify_mangle_topology()?;
        let mut rules = mangle.owned_rules;
        rules.extend(filter.owned_rules);
        // The observational q1338 rule is intentionally in mangle/OUTPUT so
        // its NF_ACCEPT/bypass cannot skip another host mangle rule. Only its
        // exact learned_out comment contributes a counter there; filter keeps
        // the remaining policy counters.
        let counters = add_firewall_counters(&filter.counters, &mangle.counters)?;
        Ok(CapturedXtablesPolicy { rules, counters })
    }

    fn prepare(&self, block_policy: &IptablesPolicy) -> Result<()> {
        attempt_both_families(
            "fail-closed topology preparation",
            || {
                Self::ensure_topology(&self.ipv4, block_policy.ipv4())
                    .context("cannot establish IPv4 fail-closed topology")
            },
            || {
                Self::ensure_topology(&self.ipv6, block_policy.ipv6())
                    .context("cannot establish IPv6 fail-closed topology")
            },
        )
    }

    fn validate_pair(&self, policy: &IptablesPolicy) -> Result<()> {
        self.ipv4
            .restore(policy.ipv4(), true)
            .context("IPv4 policy validation failed")?;
        self.ipv6
            .restore(policy.ipv6(), true)
            .context("IPv6 policy validation failed")
    }

    fn apply_pair(&self, policy: &IptablesPolicy) -> Result<()> {
        Self::install_owned_policy(&self.ipv4, policy.ipv4())
            .context("IPv4 policy transaction failed")?;
        Self::install_owned_policy(&self.ipv6, policy.ipv6())
            .context("IPv6 policy transaction failed")
    }

    fn record_expected(&self, policy: &IptablesPolicy) -> Result<()> {
        let expected_ipv4 = compiled_owned_rules(policy.ipv4())?;
        let expected_ipv6 = compiled_owned_rules(policy.ipv6())?;
        let ipv4 = Self::capture_verified_policy(&self.ipv4)?;
        let ipv6 = Self::capture_verified_policy(&self.ipv6)?;
        ensure!(
            ipv4.rules == expected_ipv4,
            "installed IPv4 iptables rules differ from the compiled policy: {}",
            describe_rule_mismatch(&expected_ipv4, &ipv4.rules)
        );
        ensure!(
            ipv6.rules == expected_ipv6,
            "installed IPv6 iptables rules differ from the compiled policy: {}",
            describe_rule_mismatch(&expected_ipv6, &ipv6.rules)
        );
        let mut expected = self
            .expected
            .lock()
            .map_err(|_| anyhow!("iptables expected-policy mutex is poisoned"))?;
        expected.ipv4_rules = Some(expected_ipv4);
        expected.ipv6_rules = Some(expected_ipv6);
        Ok(())
    }

    fn emergency_block_all(&self, policy: &IptablesPolicy) -> Result<()> {
        attempt_both_families(
            "emergency BlockAll installation",
            || Self::install_owned_policy(&self.ipv4, policy.ipv4()),
            || Self::install_owned_policy(&self.ipv6, policy.ipv6()),
        )?;
        self.record_expected(policy)
    }

    fn checked_apply(&self, policy: &IptablesPolicy, block_policy: &IptablesPolicy) -> Result<()> {
        ensure!(
            !active_nft_artifacts()?,
            "refusing iptables activation while nft table inet openshield is still active"
        );
        self.ensure_no_alternate_xtables_artifacts()?;
        if let Err(preparation_error) = self.prepare(block_policy) {
            let emergency = self.emergency_block_all(block_policy);
            return match emergency {
                Ok(()) => Err(preparation_error).context(
                    "iptables preparation failed; emergency IPv4/IPv6 BlockAll was restored",
                ),
                Err(emergency_error) => Err(anyhow!(
                    "iptables preparation failed ({preparation_error:#}); emergency BlockAll also failed ({emergency_error:#})"
                )),
            };
        }
        self.validate_pair(policy)?;

        // xtables has no atomic transaction spanning IPv4 and IPv6. Close
        // both families first so a cross-family transition can only cause a
        // temporary denial, never a transient authorization.
        self.emergency_block_all(block_policy)
            .context("cannot enter cross-family BlockAll quarantine")?;
        if let Err(apply_error) = self.apply_pair(policy) {
            let emergency = self.emergency_block_all(block_policy);
            return match emergency {
                Ok(()) => Err(apply_error)
                    .context("iptables apply failed; emergency IPv4/IPv6 BlockAll was restored"),
                Err(emergency_error) => Err(anyhow!(
                    "iptables apply failed ({apply_error:#}); emergency BlockAll also failed ({emergency_error:#})"
                )),
            };
        }
        if let Err(observation_error) = self.record_expected(policy) {
            let emergency = self.emergency_block_all(block_policy);
            return match emergency {
                Ok(()) => Err(observation_error).context(
                    "applied iptables policy could not be verified; emergency BlockAll was restored",
                ),
                Err(emergency_error) => Err(anyhow!(
                    "iptables verification failed ({observation_error:#}); emergency BlockAll also failed ({emergency_error:#})"
                )),
            };
        }
        Ok(())
    }
}

impl FirewallBackend for IptablesBackend {
    fn kind(&self) -> FirewallBackendKind {
        FirewallBackendKind::Iptables
    }

    fn apply(&mut self, snapshot: &Snapshot) -> Result<()> {
        let policy = IptablesCompiler::compile(snapshot)
            .context("failed to compile iptables compatibility policy")?;
        let block = IptablesCompiler::compile(&openshield_core::State::new().snapshot())
            .context("failed to compile iptables BlockAll policy")?;
        self.checked_apply(&policy, &block)
    }

    fn fail_closed(&mut self) -> Result<()> {
        ensure!(
            !active_nft_artifacts()?,
            "refusing iptables activation while nft table inet openshield is still active"
        );
        self.ensure_no_alternate_xtables_artifacts()?;
        let block = IptablesCompiler::compile(&openshield_core::State::new().snapshot())
            .context("failed to compile iptables BlockAll policy")?;
        let preparation = self.prepare(&block);
        let emergency = self.emergency_block_all(&block);
        match (preparation, emergency) {
            (_, Ok(())) => Ok(()),
            (Ok(()), Err(emergency_error)) => Err(emergency_error),
            (Err(preparation_error), Err(emergency_error)) => Err(anyhow!(
                "fail-closed topology preparation failed ({preparation_error:#}); emergency BlockAll also failed ({emergency_error:#})"
            )),
        }
    }
}

impl FirewallObserver for IptablesBackend {
    fn policy_observation(&mut self) -> Result<FirewallCounters> {
        let ipv4 = Self::capture_verified_policy(&self.ipv4)?;
        let ipv6 = Self::capture_verified_policy(&self.ipv6)?;
        let expected = self
            .expected
            .lock()
            .map_err(|_| anyhow!("iptables expected-policy mutex is poisoned"))?;
        ensure!(
            expected.ipv4_rules.as_ref() == Some(&ipv4.rules)
                && expected.ipv6_rules.as_ref() == Some(&ipv6.rules),
            "OpenShield iptables policy differs from the last verified transaction"
        );
        add_firewall_counters(&ipv4.counters, &ipv6.counters)
    }
}

fn result_summary(result: &Result<()>) -> String {
    match result {
        Ok(()) => "installed".to_owned(),
        Err(error) => format!("failed ({error:#})"),
    }
}

fn attempt_both_families<Ipv4Action, Ipv6Action>(
    action: &str,
    ipv4: Ipv4Action,
    ipv6: Ipv6Action,
) -> Result<()>
where
    Ipv4Action: FnOnce() -> Result<()>,
    Ipv6Action: FnOnce() -> Result<()>,
{
    let ipv4_result = ipv4();
    let ipv6_result = ipv6();
    match (ipv4_result, ipv6_result) {
        (Ok(()), Ok(())) => Ok(()),
        (ipv4_result, ipv6_result) => bail!(
            "{action} outcome: IPv4: {}; IPv6: {}",
            result_summary(&ipv4_result),
            result_summary(&ipv6_result)
        ),
    }
}

fn active_xtables_artifacts() -> Result<bool> {
    let ipv4 = active_xtables_family(&IPV4_XTABLES_BUNDLES);
    let ipv6 = active_xtables_family(&IPV6_XTABLES_BUNDLES);
    match (ipv4, ipv6) {
        (Ok(ipv4), Ok(ipv6)) => Ok(ipv4 || ipv6),
        (ipv4, ipv6) => bail!(
            "cannot safely inspect the previous xtables backend: IPv4: {}; IPv6: {}",
            bool_result_summary(&ipv4),
            bool_result_summary(&ipv6)
        ),
    }
}

fn active_xtables_family(candidates: &[XtablesBundle]) -> Result<bool> {
    active_xtables_worlds(candidates, None)
}

fn active_alternate_xtables_world(
    candidates: &[XtablesBundle],
    selected_save: &Path,
) -> Result<bool> {
    let selected = identify_xtables_world(selected_save).with_context(|| {
        format!(
            "cannot identify selected xtables backend through {}",
            selected_save.display()
        )
    })?;
    let inspection = active_xtables_worlds(candidates, Some(&selected));
    let selected_after = identify_xtables_world(selected_save).with_context(|| {
        format!(
            "cannot re-identify selected xtables backend through {}",
            selected_save.display()
        )
    })?;
    ensure_xtables_identity_unchanged(&selected, &selected_after)
        .context("selected xtables backend changed during alternate-backend inspection")?;
    inspection
}

fn ensure_xtables_identity_unchanged(
    before: &XtablesIdentity,
    after: &XtablesIdentity,
) -> Result<()> {
    ensure!(before == after, "xtables executable identity changed");
    Ok(())
}

fn xtables_world_is_covered(
    world: XtablesWorld,
    excluded: Option<&XtablesIdentity>,
    inspected: &HashSet<XtablesWorld>,
) -> bool {
    excluded.is_some_and(|excluded| excluded.world == world) || inspected.contains(&world)
}

fn active_xtables_worlds(
    candidates: &[XtablesBundle],
    excluded: Option<&XtablesIdentity>,
) -> Result<bool> {
    let mut inspected_paths = HashSet::new();
    let mut inspected_worlds = HashSet::new();
    let mut failures = Vec::new();
    for candidate in candidates {
        let save = Path::new(candidate.save);
        if validate_xtables_binary(save, candidates).is_err() {
            continue;
        }
        let identity_before = match identify_xtables_world(save) {
            Ok(identity) => identity,
            Err(error) => {
                failures.push(format!(
                    "{}: cannot identify xtables backend: {error:#}",
                    save.display()
                ));
                continue;
            }
        };
        if excluded.is_some_and(|excluded| excluded.resolved == identity_before.resolved)
            || !inspected_paths.insert(identity_before.resolved.clone())
        {
            continue;
        }

        let duplicate_world =
            xtables_world_is_covered(identity_before.world, excluded, &inspected_worlds);
        let legacy_world_is_covered =
            xtables_world_is_covered(XtablesWorld::Legacy, excluded, &inspected_worlds);
        let inspection = if duplicate_world {
            None
        } else {
            Some(inspect_xtables_world(|| {
                inspect_xtables_save_world(
                    save,
                    &identity_before.resolved,
                    identity_before.world,
                    legacy_world_is_covered,
                )
            }))
        };
        let identity_after = identify_xtables_world(save);
        match identity_after {
            Ok(identity_after)
                if ensure_xtables_identity_unchanged(&identity_before, &identity_after).is_ok() => {
            }
            Ok(_) => {
                failures.push(format!(
                    "{}: xtables executable identity changed during inspection",
                    save.display()
                ));
                continue;
            }
            Err(error) => {
                failures.push(format!(
                    "{}: cannot re-identify xtables backend: {error:#}",
                    save.display()
                ));
                continue;
            }
        }
        if duplicate_world {
            continue;
        }
        inspected_worlds.insert(identity_before.world);
        let Some(inspection) = inspection else {
            failures.push(format!(
                "{}: internal xtables inspection state is inconsistent",
                save.display()
            ));
            continue;
        };
        match inspection {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(error) => failures.push(format!("{}: {error:#}", save.display())),
        }
    }
    ensure!(
        failures.is_empty(),
        "one or more trusted xtables-save worlds could not be inspected: {}",
        failures.join("; ")
    );
    Ok(false)
}

fn identify_xtables_world(save: &Path) -> Result<XtablesIdentity> {
    let resolved_before = fs::canonicalize(save)
        .with_context(|| format!("cannot resolve xtables-save path {}", save.display()))?;
    let captured = capture_command_output(
        save,
        &["--version"],
        NFT_QUERY_TIMEOUT,
        MAX_FIREWALL_STDERR_BYTES,
    )?;
    ensure!(
        captured.status.success(),
        "{} --version exited with status {}",
        save.display(),
        captured.status
    );
    ensure!(
        captured.stderr.is_empty(),
        "{} --version wrote an unexpected diagnostic",
        save.display()
    );
    let world = parse_xtables_world_version(save, &resolved_before, &captured.stdout)?;
    let resolved_after = fs::canonicalize(save)
        .with_context(|| format!("cannot re-resolve xtables-save path {}", save.display()))?;
    ensure!(
        resolved_after == resolved_before,
        "xtables-save executable changed while its backend was identified"
    );
    Ok(XtablesIdentity {
        resolved: resolved_before,
        world,
    })
}

fn parse_xtables_world_version(
    save: &Path,
    resolved: &Path,
    output: &[u8],
) -> Result<XtablesWorld> {
    let output = std::str::from_utf8(output).context("xtables version output is not UTF-8")?;
    let output = output.strip_suffix('\n').unwrap_or(output);
    let output = output.strip_suffix('\r').unwrap_or(output);
    ensure!(
        !output.contains(['\n', '\r']),
        "xtables version output contains multiple lines"
    );
    let (versioned_program, explicit_world) = if let Some(prefix) = output.strip_suffix(" (legacy)")
    {
        (prefix, Some(XtablesWorld::Legacy))
    } else if let Some(prefix) = output.strip_suffix(" (nf_tables)") {
        (prefix, Some(XtablesWorld::Nft))
    } else {
        (output, None)
    };
    let (program, version) = versioned_program
        .rsplit_once(" v")
        .ok_or_else(|| anyhow!("xtables version output has no version separator"))?;
    let save_name = save
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("xtables-save path has no UTF-8 file name"))?;
    let valid_program = if save_name.starts_with("ip6tables") {
        matches!(program, "ip6tables-save" | "ip6tables-nft-save")
    } else if save_name.starts_with("iptables") {
        matches!(program, "iptables-save" | "iptables-nft-save")
    } else {
        false
    };
    ensure!(valid_program, "unexpected xtables version program name");
    let version_components = version
        .split('.')
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("invalid xtables version")?;
    ensure!(
        version_components.len() >= 2,
        "xtables version must contain at least major and minor components"
    );
    let resolved_world = resolved
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| match name {
            "xtables-multi"
            | "xtables-legacy-multi"
            | "iptables-legacy-save"
            | "ip6tables-legacy-save" => Some(XtablesWorld::Legacy),
            "xtables-compat-multi"
            | "xtables-nft-multi"
            | "iptables-compat-save"
            | "ip6tables-compat-save"
            | "iptables-nft-save"
            | "ip6tables-nft-save" => Some(XtablesWorld::Nft),
            _ => None,
        });
    if let Some(world) = explicit_world {
        ensure!(
            resolved_world.is_none_or(|resolved_world| resolved_world == world),
            "xtables backend marker conflicts with the resolved executable"
        );
        return Ok(world);
    }

    // Pre-1.8 releases did not print a backend marker, but nft-compatible
    // `xtables-compat-multi` already existed. Accept markerless output only
    // when the trusted canonical executable itself proves the world. Unknown
    // alternatives dispatchers and all markerless 1.8+ output fail closed.
    let predates_explicit_marker = (version_components[0], version_components[1]) < (1, 8);
    ensure!(
        predates_explicit_marker,
        "iptables 1.8 or newer must report an explicit backend marker"
    );
    resolved_world
        .ok_or_else(|| anyhow!("markerless xtables version has an unknown resolved executable"))
}

#[derive(Debug)]
enum XtablesWorldInspection {
    Captured(Vec<u8>),
    BackendAbsent,
}

fn inspect_xtables_world<Capture>(capture: Capture) -> Result<bool>
where
    Capture: FnOnce() -> Result<XtablesWorldInspection>,
{
    match capture()? {
        XtablesWorldInspection::Captured(captured) => parse_xtables_world_save(&captured),
        // A backend absence accepted by the exact bounded classifier cannot
        // retain live rules and is therefore equivalent to a clean capture.
        XtablesWorldInspection::BackendAbsent => Ok(false),
    }
}

fn inspect_xtables_save_world(
    save: &Path,
    resolved: &Path,
    world: XtablesWorld,
    legacy_world_is_covered: bool,
) -> Result<XtablesWorldInspection> {
    let args = xtables_save_inspection_args();
    let captured = capture_command_output(save, &args, NFT_QUERY_TIMEOUT, MAX_NFT_OUTPUT_BYTES)?;
    if captured.status.success() {
        ensure!(
            captured.stderr.is_empty()
                || is_expected_covered_legacy_warning(
                    save,
                    world,
                    legacy_world_is_covered,
                    &captured.stderr,
                ),
            "{} wrote an unexpected diagnostic while inspecting its xtables world",
            save.display()
        );
        return Ok(XtablesWorldInspection::Captured(captured.stdout));
    }
    if is_proven_absent_legacy_backend(
        save,
        resolved,
        captured.status.code(),
        &captured.stdout,
        &captured.stderr,
    ) {
        return Ok(XtablesWorldInspection::BackendAbsent);
    }
    bail!(
        "{save} exited with status {status}",
        save = save.display(),
        status = captured.status
    )
}

fn selected_xtables_save_args(table: &str) -> [&str; 3] {
    ["-c", "-t", table]
}

fn xtables_save_inspection_args() -> [&'static str; 1] {
    // With no `-t`, legacy iptables-save enumerates only tables that are already
    // registered in procfs. It therefore observes an alternate world without
    // asking modprobe to load a missing table module. Selected-backend capture
    // deliberately retains `-t` so a usable selected backend can initialize.
    ["-c"]
}

fn is_expected_covered_legacy_warning(
    save: &Path,
    world: XtablesWorld,
    legacy_world_is_covered: bool,
    stderr: &[u8],
) -> bool {
    if world != XtablesWorld::Nft || !legacy_world_is_covered {
        return false;
    }
    let Some(save_name) = save.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let program = if save_name.starts_with("ip6tables") {
        "ip6tables"
    } else if save_name.starts_with("iptables") {
        "iptables"
    } else {
        return false;
    };
    let expected = format!(
        "# Warning: {program}-legacy tables present, use {program}-legacy-save to see them"
    );
    let Ok(stderr) = std::str::from_utf8(stderr) else {
        return false;
    };
    let stderr = stderr
        .strip_suffix("\r\n")
        .or_else(|| stderr.strip_suffix('\n'))
        .unwrap_or(stderr);
    stderr == expected
}

fn is_proven_absent_legacy_backend(
    save: &Path,
    resolved: &Path,
    status_code: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
) -> bool {
    if status_code != Some(1) || !stdout.is_empty() {
        return false;
    }
    let Some(save_name) = save.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let resolved_is_legacy = resolved
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                "xtables-multi"
                    | "xtables-legacy-multi"
                    | "iptables-legacy-save"
                    | "ip6tables-legacy-save"
            )
        });
    let program_prefix = if save_name.starts_with("ip6tables") {
        "ip6tables-save v"
    } else if save_name.starts_with("iptables") {
        "iptables-save v"
    } else {
        return false;
    };
    let Ok(diagnostic) = std::str::from_utf8(stderr) else {
        return false;
    };
    // libxtables releases in supported distributions terminate this fatal
    // diagnostic with either one line ending or a line ending plus one empty
    // line. Accept only those exact encodings; any third or interior line
    // remains below and is rejected as ambiguous output.
    let diagnostic = ["\r\n\r\n", "\n\n", "\r\n", "\n", "\r"]
        .into_iter()
        .find_map(|ending| diagnostic.strip_suffix(ending))
        .unwrap_or(diagnostic);
    if diagnostic.contains(['\n', '\r']) {
        return false;
    }
    let Some(version_line) = LEGACY_BACKEND_UNAVAILABLE_SUFFIXES
        .iter()
        .find_map(|suffix| diagnostic.strip_suffix(suffix))
    else {
        return false;
    };
    if !version_line.starts_with(program_prefix)
        || !matches!(
            parse_xtables_world_version(save, resolved, version_line.as_bytes()),
            Ok(XtablesWorld::Legacy)
        )
    {
        return false;
    }
    // The parser requires a known legacy executable for markerless output. For
    // 1.8+ output, retain the explicit resolved-path check so a generic
    // alternatives dispatcher cannot spoof backend absence.
    !version_line.ends_with(" (legacy)") || resolved_is_legacy
}

fn active_nft_artifacts() -> Result<bool> {
    let mut failures = Vec::new();
    let mut validated = false;
    for candidate in NFT_CANDIDATES.map(Path::new) {
        if validate_nft_binary(candidate).is_err() {
            continue;
        }
        validated = true;
        let backend = NftBackend {
            binary: candidate.to_path_buf(),
        };
        match backend.capture(&NFT_TABLE_QUERY) {
            Ok(tables) => return Ok(openshield_table_count(&tables)? != 0),
            Err(error) => failures.push(format!("{}: {error:#}", candidate.display())),
        }
    }
    if validated {
        bail!(
            "cannot safely inspect the previous nftables backend: {}",
            failures.join("; ")
        );
    }
    Ok(false)
}

fn bool_result_summary(result: &Result<bool>) -> String {
    match result {
        Ok(true) => "OpenShield artifacts present".to_owned(),
        Ok(false) => "no OpenShield artifacts".to_owned(),
        Err(error) => format!("inspection failed ({error:#})"),
    }
}

fn filter_dispatcher_pairs() -> [(&'static str, &'static str); 3] {
    [
        ("INPUT", IPTABLES_INPUT_CHAIN),
        ("OUTPUT", IPTABLES_OUTPUT_CHAIN),
        ("FORWARD", IPTABLES_FORWARD_CHAIN),
    ]
}

fn mangle_first_dispatcher_pairs() -> [(&'static str, &'static str); 1] {
    [("OUTPUT", IPTABLES_MARK_SANITIZE_CHAIN)]
}

fn mangle_last_dispatcher_pairs() -> [(&'static str, &'static str); 1] {
    [("OUTPUT", IPTABLES_LEARNING_OBSERVE_CHAIN)]
}

fn ownership_initialization_policy(table: &str, chains: &[&str]) -> String {
    let mut policy = format!("*{table}\n");
    for chain in chains {
        let _infallible = writeln!(policy, ":{chain} - [0:0]");
    }
    for chain in chains {
        let _infallible = writeln!(
            policy,
            "-A {chain} -m comment --comment {IPTABLES_OWNERSHIP_COMMENT}"
        );
    }
    policy.push_str("COMMIT\n");
    policy
}

fn dispatch_rule(built_in: &str, target: &str) -> String {
    format!("-A {built_in} -j {target}")
}

fn validate_xtables_binary(path: &Path, bundles: &[XtablesBundle]) -> Result<()> {
    ensure!(
        bundles.iter().any(|bundle| {
            [bundle.command, bundle.restore, bundle.save]
                .into_iter()
                .any(|candidate| path == Path::new(candidate))
        }),
        "xtables path is outside the fixed allowlist"
    );
    validate_trusted_executable(path, "xtables")
}

fn run_command(path: &Path, args: &[&str], timeout: Duration) -> Result<()> {
    let mut child = trusted_command(path, args)
        .spawn()
        .with_context(|| format!("failed to start trusted executable {}", path.display()))?;
    let status = wait_with_timeout(&mut child, timeout)?;
    ensure!(
        status.success(),
        "{} exited with status {status}",
        path.display()
    );
    Ok(())
}

fn run_command_with_input(
    path: &Path,
    args: &[&str],
    input: &[u8],
    timeout: Duration,
) -> Result<()> {
    let mut child = trusted_command(path, args)
        .stdin(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to start trusted executable {}", path.display()))?;
    let Some(mut stdin) = child.stdin.take() else {
        terminate_child(&mut child);
        bail!("trusted executable stdin pipe was not created");
    };
    let bounded_input = input.to_vec();
    let writer = match thread::Builder::new()
        .name("openshield-xtables-writer".to_owned())
        .spawn(move || stdin.write_all(&bounded_input))
    {
        Ok(writer) => writer,
        Err(error) => {
            terminate_child(&mut child);
            return Err(error).context("failed to create bounded xtables input writer");
        }
    };
    let status_result = wait_with_timeout(&mut child, timeout);
    let write_result = writer
        .join()
        .map_err(|_| anyhow!("xtables input writer terminated unexpectedly"))?;
    let status = status_result?;
    write_result.context("failed to send policy to xtables restore")?;
    ensure!(
        status.success(),
        "{} exited with status {status}",
        path.display()
    );
    Ok(())
}

#[derive(Debug)]
struct CapturedCommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug)]
struct BoundedCommandStream {
    bytes: Vec<u8>,
    overflow: bool,
}

fn capture_command(
    path: &Path,
    args: &[&str],
    timeout: Duration,
    maximum: usize,
) -> Result<Vec<u8>> {
    let mut child = trusted_command(path, args)
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to start trusted executable {}", path.display()))?;
    let Some(stdout) = child.stdout.take() else {
        terminate_child(&mut child);
        bail!("trusted executable stdout pipe was not created");
    };
    let reader = match spawn_bounded_command_reader(stdout, maximum, "openshield-firewall-stdout") {
        Ok(reader) => reader,
        Err(error) => {
            terminate_child(&mut child);
            return Err(error).context("failed to create bounded firewall stdout reader");
        }
    };
    let status_result = wait_with_timeout(&mut child, timeout);
    let stdout_result = reader
        .join()
        .map_err(|_| anyhow!("firewall stdout reader terminated unexpectedly"));
    let status = status_result?;
    let stdout = stdout_result??;
    ensure!(
        status.success(),
        "{} exited with status {}",
        path.display(),
        status
    );
    ensure!(
        !stdout.overflow,
        "{} stdout exceeded {maximum} bytes",
        path.display(),
    );
    Ok(stdout.bytes)
}

fn capture_command_output(
    path: &Path,
    args: &[&str],
    timeout: Duration,
    maximum_stdout: usize,
) -> Result<CapturedCommandOutput> {
    let mut child = trusted_command(path, args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to start trusted executable {}", path.display()))?;
    let Some(stdout) = child.stdout.take() else {
        terminate_child(&mut child);
        bail!("trusted executable stdout pipe was not created");
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_child(&mut child);
        bail!("trusted executable stderr pipe was not created");
    };
    let stdout_reader =
        match spawn_bounded_command_reader(stdout, maximum_stdout, "openshield-firewall-stdout") {
            Ok(reader) => reader,
            Err(error) => {
                terminate_child(&mut child);
                return Err(error).context("failed to create bounded firewall stdout reader");
            }
        };
    let stderr_reader = match spawn_bounded_command_reader(
        stderr,
        MAX_FIREWALL_STDERR_BYTES,
        "openshield-firewall-stderr",
    ) {
        Ok(reader) => reader,
        Err(error) => {
            terminate_child(&mut child);
            let _ignored = stdout_reader.join();
            return Err(error).context("failed to create bounded firewall stderr reader");
        }
    };
    let status_result = wait_with_timeout(&mut child, timeout);
    let stdout_result = stdout_reader
        .join()
        .map_err(|_| anyhow!("firewall stdout reader terminated unexpectedly"));
    let stderr_result = stderr_reader
        .join()
        .map_err(|_| anyhow!("firewall stderr reader terminated unexpectedly"));
    let status = status_result?;
    let stdout = stdout_result??;
    let stderr = stderr_result??;
    ensure!(
        !stdout.overflow,
        "{} stdout exceeded {maximum_stdout} bytes",
        path.display(),
    );
    ensure!(
        !stderr.overflow,
        "{} stderr exceeded {MAX_FIREWALL_STDERR_BYTES} bytes",
        path.display(),
    );
    Ok(CapturedCommandOutput {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
    })
}

fn spawn_bounded_command_reader<Reader>(
    mut reader: Reader,
    maximum: usize,
    thread_name: &str,
) -> Result<thread::JoinHandle<Result<BoundedCommandStream>>>
where
    Reader: Read + Send + 'static,
{
    thread::Builder::new()
        .name(thread_name.to_owned())
        .spawn(move || {
            let mut bytes = Vec::new();
            let mut overflow = false;
            let mut chunk = [0_u8; 8192];
            loop {
                let read = reader
                    .read(&mut chunk)
                    .context("failed to read firewall subprocess output")?;
                if read == 0 {
                    break;
                }
                let remaining = maximum.saturating_sub(bytes.len());
                let keep = remaining.min(read);
                bytes.extend_from_slice(&chunk[..keep]);
                overflow |= keep != read;
            }
            Ok(BoundedCommandStream { bytes, overflow })
        })
        .context("cannot spawn bounded firewall output reader")
}

fn trusted_command(path: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(path);
    command
        .args(args)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

#[derive(Debug)]
struct XtablesSnapshot {
    declared_chains: HashSet<String>,
    ordered_rules: Vec<String>,
    owned_rules: Vec<String>,
    counters: FirewallCounters,
}

impl XtablesSnapshot {
    fn rules_for_chain<'a>(&'a self, chain: &str) -> impl DoubleEndedIterator<Item = &'a str> + 'a {
        let prefix = format!("-A {chain} ");
        self.ordered_rules
            .iter()
            .filter(move |rule| rule.starts_with(&prefix))
            .map(String::as_str)
    }

    fn first_rule(&self, chain: &str) -> Option<&str> {
        self.rules_for_chain(chain).next()
    }

    fn last_rule(&self, chain: &str) -> Option<&str> {
        self.rules_for_chain(chain).next_back()
    }

    fn verify_filter_topology(&self) -> Result<()> {
        for chain in owned_chains() {
            ensure!(
                self.declared_chains.contains(chain),
                "required OpenShield iptables chain {chain} is missing"
            );
            self.verify_chain_ownership(chain)?;
        }
        for (built_in, target) in filter_dispatcher_pairs() {
            ensure!(
                self.first_rule(built_in) == Some(dispatch_rule(built_in, target).as_str()),
                "OpenShield dispatcher is not first in built-in {built_in}"
            );
            let prefix = format!("-A {built_in} ");
            let owned_dispatchers = self
                .ordered_rules
                .iter()
                .filter(|rule| {
                    rule.starts_with(&prefix)
                        && owned_chains()
                            .iter()
                            .any(|chain| rule_jumps_to(rule, chain))
                })
                .count();
            ensure!(
                owned_dispatchers == 1,
                "built-in {built_in} must contain exactly one OpenShield dispatcher"
            );
        }
        Ok(())
    }

    fn verify_mangle_topology(&self) -> Result<()> {
        for chain in owned_mangle_chains() {
            ensure!(
                self.declared_chains.contains(chain),
                "required OpenShield iptables mangle chain {chain} is missing"
            );
            self.verify_chain_ownership(chain)?;
        }
        for (built_in, target) in mangle_first_dispatcher_pairs() {
            ensure!(
                self.first_rule(built_in) == Some(dispatch_rule(built_in, target).as_str()),
                "OpenShield mark sanitizer is not first in mangle {built_in}"
            );
            let owned_dispatchers = self
                .rules_for_chain(built_in)
                .filter(|rule| rule_jumps_to(rule, target))
                .count();
            ensure!(
                owned_dispatchers == 1,
                "mangle {built_in} must contain exactly one OpenShield mark sanitizer"
            );
        }
        for (built_in, target) in mangle_last_dispatcher_pairs() {
            ensure!(
                self.last_rule(built_in) == Some(dispatch_rule(built_in, target).as_str()),
                "OpenShield Learning observer is not last in mangle {built_in}"
            );
            let observer_dispatchers = self
                .rules_for_chain(built_in)
                .filter(|rule| rule_jumps_to(rule, target))
                .count();
            ensure!(
                observer_dispatchers == 1,
                "mangle {built_in} must contain exactly one OpenShield Learning observer"
            );
        }

        for (built_in, _) in mangle_first_dispatcher_pairs() {
            let owned_dispatchers = self
                .rules_for_chain(built_in)
                .filter(|rule| {
                    owned_mangle_chains()
                        .iter()
                        .any(|chain| rule_jumps_to(rule, chain))
                })
                .count();
            ensure!(
                owned_dispatchers == 2,
                "mangle {built_in} must contain exactly two OpenShield dispatchers"
            );
        }
        Ok(())
    }

    fn has_openshield_artifacts(&self) -> bool {
        all_owned_xtables_chains().any(|chain| self.declared_chains.contains(chain))
            || self
                .ordered_rules
                .iter()
                .any(|rule| all_owned_xtables_chains().any(|chain| rule_jumps_to(rule, chain)))
    }

    fn verify_chain_ownership(&self, chain: &str) -> Result<()> {
        let first = self.first_rule(chain).ok_or_else(|| {
            anyhow!("OpenShield iptables chain {chain} has no ownership sentinel")
        })?;
        ensure!(
            is_exact_ownership_rule(first, chain)?,
            "refusing to manage iptables chain {chain}: ownership sentinel is missing or not first"
        );
        Ok(())
    }
}

fn all_owned_xtables_chains() -> impl Iterator<Item = &'static str> {
    owned_chains().into_iter().chain(owned_mangle_chains())
}

fn is_exact_ownership_rule(rule: &str, chain: &str) -> Result<bool> {
    let tokens = tokenize_xtables_rule(rule)?;
    Ok(tokens
        == [
            "-A",
            chain,
            "-m",
            "comment",
            "--comment",
            IPTABLES_OWNERSHIP_COMMENT,
        ])
}

fn rule_jumps_to(rule: &str, target: &str) -> bool {
    rule.ends_with(&format!(" -j {target}")) || rule.ends_with(&format!(" -g {target}"))
}

fn parse_xtables_save(input: &[u8]) -> Result<XtablesSnapshot> {
    let text = std::str::from_utf8(input).context("xtables-save output is not UTF-8")?;
    let tables = text
        .lines()
        .filter(|line| matches!(*line, "*filter" | "*mangle"))
        .count();
    ensure!(tables == 1, "missing or duplicated supported xtables table");
    ensure!(
        text.lines().any(|line| line == "COMMIT"),
        "unterminated filter table"
    );
    let mut declared_chains = HashSet::new();
    let mut ordered_rules = Vec::new();
    let mut owned_rules = Vec::new();
    let mut counters = FirewallCounters::default();

    for line in text.lines() {
        if let Some(declaration) = line.strip_prefix(':')
            && let Some((chain, _remainder)) = declaration.split_once(' ')
        {
            ensure!(
                declared_chains.insert(chain.to_owned()),
                "duplicate chain declaration in xtables-save output"
            );
            continue;
        }
        let Some((packets, bytes, rule)) = parse_saved_rule(line)? else {
            continue;
        };
        ordered_rules.push(rule.to_owned());
        if all_owned_xtables_chains().any(|chain| rule.starts_with(&format!("-A {chain} "))) {
            accumulate_comment_counter(&mut counters, rule, packets, bytes)?;
            owned_rules.push(normalize_owned_xtables_rule(rule)?);
        }
    }

    let owned_rules = order_owned_xtables_rules(owned_rules);

    Ok(XtablesSnapshot {
        declared_chains,
        ordered_rules,
        owned_rules,
        counters,
    })
}

fn parse_xtables_world_save(input: &[u8]) -> Result<bool> {
    let text = std::str::from_utf8(input).context("xtables-save output is not UTF-8")?;
    let mut tables = HashSet::new();
    let mut current_table = None;
    let mut supported_table = String::new();
    let mut has_openshield_artifacts = false;

    for line in text.lines() {
        if let Some(table) = line.strip_prefix('*') {
            ensure!(
                current_table.is_none(),
                "nested table in combined xtables-save output"
            );
            ensure!(
                !table.is_empty()
                    && table.len() <= 32
                    && table.bytes().all(|byte| byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || byte == b'_'),
                "invalid table name in combined xtables-save output"
            );
            ensure!(
                tables.insert(table),
                "duplicate table in combined xtables-save output"
            );
            current_table = Some(table);
            if matches!(table, "filter" | "mangle") {
                supported_table.push_str(line);
                supported_table.push('\n');
            }
            continue;
        }

        if line == "COMMIT" {
            let table = current_table
                .take()
                .ok_or_else(|| anyhow!("xtables COMMIT has no table"))?;
            if matches!(table, "filter" | "mangle") {
                supported_table.push_str("COMMIT\n");
                has_openshield_artifacts |=
                    parse_xtables_save(supported_table.as_bytes())?.has_openshield_artifacts();
                supported_table.clear();
            }
            continue;
        }

        match current_table {
            Some("filter" | "mangle") => {
                supported_table.push_str(line);
                supported_table.push('\n');
            }
            Some(_) => {}
            None => ensure!(
                line.is_empty() || line.starts_with('#'),
                "unexpected data outside a table in combined xtables-save output"
            ),
        }
    }

    ensure!(
        current_table.is_none(),
        "unterminated table in combined xtables-save output"
    );
    ensure!(
        supported_table.is_empty(),
        "incomplete supported table in combined xtables-save output"
    );
    Ok(has_openshield_artifacts)
}

fn compiled_owned_rules(policy: &str) -> Result<Vec<String>> {
    let mut table = None;
    let mut filter = Vec::new();
    let mut mangle = Vec::new();
    let mut committed = 0_u8;
    for line in policy.lines() {
        match line {
            "*filter" => {
                ensure!(table.replace("filter").is_none(), "nested xtables table");
            }
            "*mangle" => {
                ensure!(table.replace("mangle").is_none(), "nested xtables table");
            }
            "COMMIT" => {
                ensure!(table.take().is_some(), "xtables COMMIT has no table");
                committed = committed.saturating_add(1);
            }
            line if line.starts_with("-A ") => {
                let table = table.ok_or_else(|| anyhow!("xtables rule is outside a table"))?;
                let normalized = normalize_owned_xtables_rule(line)?;
                let valid_chain = if table == "mangle" {
                    owned_mangle_chains().contains(&normalized.0.as_str())
                } else {
                    owned_chains().contains(&normalized.0.as_str())
                };
                ensure!(
                    valid_chain,
                    "compiled iptables rule uses chain {} in the wrong table",
                    normalized.0
                );
                if table == "mangle" {
                    mangle.push(normalized);
                } else {
                    filter.push(normalized);
                }
            }
            _ => {}
        }
    }
    ensure!(
        table.is_none() && committed == 2,
        "compiled iptables policy is not a complete mangle/filter transaction"
    );
    let mut rules = order_owned_xtables_rules(mangle);
    rules.extend(order_owned_xtables_rules(filter));
    Ok(rules)
}

fn describe_rule_mismatch(expected: &[String], installed: &[String]) -> String {
    let common = expected.len().min(installed.len());
    for index in 0..common {
        if expected[index] != installed[index] {
            return format!(
                "rule {index}: expected {:?}, installed {:?}",
                expected[index], installed[index]
            );
        }
    }
    format!(
        "rule counts differ: expected {}, installed {}",
        expected.len(),
        installed.len()
    )
}

fn parse_saved_rule(line: &str) -> Result<Option<(u64, u64, &str)>> {
    if !line.starts_with('[') {
        ensure!(
            !line.starts_with("-A "),
            "xtables-save omitted counters despite the mandatory -c query"
        );
        return Ok(None);
    }
    let (counter, rule) = line
        .split_once("] ")
        .ok_or_else(|| anyhow!("malformed xtables rule counter prefix"))?;
    let counter = counter
        .strip_prefix('[')
        .ok_or_else(|| anyhow!("malformed xtables rule counter"))?;
    let (packets, bytes) = counter
        .split_once(':')
        .ok_or_else(|| anyhow!("malformed xtables packet/byte counter"))?;
    let packets = packets
        .parse::<u64>()
        .context("invalid xtables packet counter")?;
    let bytes = bytes
        .parse::<u64>()
        .context("invalid xtables byte counter")?;
    Ok(rule.starts_with("-A ").then_some((packets, bytes, rule)))
}

fn accumulate_comment_counter(
    counters: &mut FirewallCounters,
    rule: &str,
    packets: u64,
    bytes: u64,
) -> Result<()> {
    match xtables_rule_comment(rule)?.as_deref() {
        Some("openshield:accepted_in") => {
            add_xtables_counter(&mut counters.accepted_in, packets, bytes, "accepted_in")?;
        }
        Some("openshield:accepted_out") => {
            add_xtables_counter(&mut counters.accepted_out, packets, bytes, "accepted_out")?;
        }
        Some("openshield:dropped_in") => {
            add_xtables_counter(&mut counters.dropped_in, packets, bytes, "dropped_in")?;
        }
        Some("openshield:dropped_out") => {
            add_xtables_counter(&mut counters.dropped_out, packets, bytes, "dropped_out")?;
        }
        Some("openshield:accepted_out+learned_out") => {
            add_xtables_counter(&mut counters.accepted_out, packets, bytes, "accepted_out")?;
            add_xtables_counter(&mut counters.learned_out, packets, bytes, "learned_out")?;
        }
        Some("openshield:learned_out") => {
            add_xtables_counter(&mut counters.learned_out, packets, bytes, "learned_out")?;
        }
        Some(_) | None => {}
    }
    Ok(())
}

fn add_xtables_counter(
    destination: &mut CounterValue,
    packets: u64,
    bytes: u64,
    name: &str,
) -> Result<()> {
    destination.packets = destination
        .packets
        .checked_add(packets)
        .ok_or_else(|| anyhow!("iptables {name} packet counter overflow"))?;
    destination.bytes = destination
        .bytes
        .checked_add(bytes)
        .ok_or_else(|| anyhow!("iptables {name} byte counter overflow"))?;
    Ok(())
}

fn xtables_rule_comment(rule: &str) -> Result<Option<String>> {
    let tokens = tokenize_xtables_rule(rule)?;
    let mut comment = None;
    let mut index = 0;
    while index < tokens.len() {
        if tokens[index] == "--comment" {
            let value = tokens
                .get(index + 1)
                .ok_or_else(|| anyhow!("xtables rule has --comment without a value"))?;
            ensure!(
                comment.replace(value.clone()).is_none(),
                "xtables rule contains more than one --comment option"
            );
            index += 2;
        } else {
            index += 1;
        }
    }
    Ok(comment)
}

fn tokenize_xtables_rule(rule: &str) -> Result<Vec<String>> {
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Quote {
        Single,
        Double,
    }

    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut in_token = false;
    let mut quote = None;
    let mut characters = rule.chars();

    while let Some(character) = characters.next() {
        match quote {
            Some(Quote::Single) => {
                if character == '\'' {
                    quote = None;
                } else {
                    token.push(character);
                }
            }
            Some(Quote::Double) => match character {
                '"' => quote = None,
                '\\' => token.push(
                    characters
                        .next()
                        .ok_or_else(|| anyhow!("dangling escape in quoted xtables rule"))?,
                ),
                _ => token.push(character),
            },
            None => match character {
                character if character.is_ascii_whitespace() => {
                    if in_token {
                        tokens.push(std::mem::take(&mut token));
                        in_token = false;
                    }
                }
                '\'' => {
                    quote = Some(Quote::Single);
                    in_token = true;
                }
                '"' => {
                    quote = Some(Quote::Double);
                    in_token = true;
                }
                '\\' => {
                    token.push(
                        characters
                            .next()
                            .ok_or_else(|| anyhow!("dangling escape in xtables rule"))?,
                    );
                    in_token = true;
                }
                _ => {
                    token.push(character);
                    in_token = true;
                }
            },
        }
    }

    ensure!(quote.is_none(), "unterminated quote in xtables rule");
    if in_token {
        tokens.push(token);
    }
    Ok(tokens)
}

#[cfg(test)]
fn normalize_xtables_rule(rule: &str) -> Result<String> {
    normalize_xtables_tokens(tokenize_xtables_rule(rule)?)
}

fn normalize_owned_xtables_rule(rule: &str) -> Result<(String, String)> {
    let tokens = tokenize_xtables_rule(rule)?;
    let chain = tokens
        .get(1)
        .ok_or_else(|| anyhow!("iptables append rule has no chain"))?;
    ensure!(
        tokens.first().map(String::as_str) == Some("-A")
            && all_owned_xtables_chains().any(|owned| owned == chain),
        "iptables policy appends to non-owned chain {chain}"
    );
    Ok((chain.clone(), normalize_xtables_tokens(tokens)?))
}

fn order_owned_xtables_rules(mut rules: Vec<(String, String)>) -> Vec<String> {
    // Rule order is significant within a chain, but iptables-save is free to
    // emit user-defined chains in a different order from the restore program.
    // Stable sorting by chain removes only that semantically irrelevant
    // cross-chain ordering difference.
    rules.sort_by(|left, right| left.0.cmp(&right.0));
    rules.into_iter().map(|(_chain, rule)| rule).collect()
}

fn normalize_xtables_tokens(mut tokens: Vec<String>) -> Result<String> {
    ensure!(!tokens.is_empty(), "empty xtables rule");

    // `--syn` is an exact shorthand for this flag mask, but
    // iptables-save always expands it. Canonicalize the shorthand before
    // comparing an installed owned rule with the compiled transaction.
    let mut index = 0;
    while index < tokens.len() {
        if tokens[index] == "--syn" {
            tokens.splice(
                index..=index,
                [
                    "--tcp-flags".to_owned(),
                    "FIN,SYN,RST,ACK".to_owned(),
                    "SYN".to_owned(),
                ],
            );
            index += 3;
        } else {
            index += 1;
        }
    }

    // iptables-save inserts the protocol's match module when a port option is
    // present (`-p tcp -m tcp --dport ...`), while iptables-restore accepts the
    // compiler's shorter spelling.  It is the same rule, so remove only that
    // redundant, protocol-identical module from both representations.
    let protocol = tokens
        .windows(2)
        .find(|window| window[0] == "-p")
        .map(|window| window[1].clone());
    if matches!(protocol.as_deref(), Some("tcp" | "udp")) {
        let protocol = protocol.as_deref().unwrap_or_default();
        let mut index = 0;
        while index + 1 < tokens.len() {
            if tokens[index] == "-m" && tokens[index + 1] == protocol {
                tokens.drain(index..=index + 1);
            } else {
                index += 1;
            }
        }
    }

    for index in 0..tokens.len().saturating_sub(1) {
        if matches!(tokens[index].as_str(), "--mark" | "--set-xmark") {
            tokens[index + 1] = normalize_mark_argument(&tokens[index + 1])?;
        }
    }

    // Length-prefix each token so distinct token vectors cannot collide even
    // if an inspected rule contains whitespace or delimiter characters.
    let mut normalized = String::new();
    for token in tokens {
        normalized.push_str(&token.len().to_string());
        normalized.push(':');
        normalized.push_str(&token);
    }
    Ok(normalized)
}

fn normalize_mark_argument(argument: &str) -> Result<String> {
    let (value, mask) = argument
        .split_once('/')
        .map_or((argument, None), |(value, mask)| (value, Some(mask)));
    let value = parse_u32_argument(value)?;
    if let Some(mask) = mask {
        Ok(format!("0x{value:x}/0x{:x}", parse_u32_argument(mask)?))
    } else {
        Ok(format!("0x{value:x}"))
    }
}

fn parse_u32_argument(argument: &str) -> Result<u32> {
    if let Some(hexadecimal) = argument
        .strip_prefix("0x")
        .or_else(|| argument.strip_prefix("0X"))
    {
        u32::from_str_radix(hexadecimal, 16)
            .with_context(|| format!("invalid hexadecimal xtables mark {argument}"))
    } else {
        argument
            .parse::<u32>()
            .with_context(|| format!("invalid decimal xtables mark {argument}"))
    }
}

fn add_firewall_counters(
    left: &FirewallCounters,
    right: &FirewallCounters,
) -> Result<FirewallCounters> {
    Ok(FirewallCounters {
        accepted_in: add_counter(left.accepted_in, right.accepted_in, "accepted_in")?,
        accepted_out: add_counter(left.accepted_out, right.accepted_out, "accepted_out")?,
        dropped_in: add_counter(left.dropped_in, right.dropped_in, "dropped_in")?,
        dropped_out: add_counter(left.dropped_out, right.dropped_out, "dropped_out")?,
        learned_out: add_counter(left.learned_out, right.learned_out, "learned_out")?,
    })
}

fn add_counter(left: CounterValue, right: CounterValue, name: &str) -> Result<CounterValue> {
    Ok(CounterValue {
        packets: left
            .packets
            .checked_add(right.packets)
            .ok_or_else(|| anyhow!("combined {name} packet counter overflow"))?,
        bytes: left
            .bytes
            .checked_add(right.bytes)
            .ok_or_else(|| anyhow!("combined {name} byte counter overflow"))?,
    })
}

#[cfg(test)]
#[derive(Clone, Debug, Default)]
pub struct MemoryBackend {
    applied: Option<Snapshot>,
    fail_next_apply: bool,
}

#[cfg(test)]
impl MemoryBackend {
    pub fn fail_next_apply(&mut self) {
        self.fail_next_apply = true;
    }
}

#[cfg(test)]
impl FirewallBackend for MemoryBackend {
    fn apply(&mut self, snapshot: &Snapshot) -> Result<()> {
        if self.fail_next_apply {
            self.fail_next_apply = false;
            bail!("injected memory backend failure");
        }
        self.applied = Some(snapshot.clone());
        Ok(())
    }

    fn fail_closed(&mut self) -> Result<()> {
        self.applied = Some(openshield_core::State::new().snapshot());
        Ok(())
    }
}

#[cfg(test)]
impl FirewallObserver for MemoryBackend {
    fn policy_observation(&mut self) -> Result<FirewallCounters> {
        Ok(FirewallCounters::default())
    }
}

fn validate_nft_binary(path: &Path) -> Result<()> {
    ensure!(
        NFT_CANDIDATES
            .iter()
            .any(|candidate| path == Path::new(candidate)),
        "nft path is outside the fixed allowlist"
    );
    validate_trusted_executable(path, "nft")
}

fn validate_trusted_executable(path: &Path, kind: &str) -> Result<()> {
    let link_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect {kind} executable {}", path.display()))?;
    ensure!(
        link_metadata.uid() == 0,
        "{kind} executable path is not owned by root"
    );
    validate_trusted_lookup_parent_chain(path, kind)?;
    let resolved = fs::canonicalize(path)
        .with_context(|| format!("cannot resolve {kind} executable {}", path.display()))?;
    ensure!(
        resolved.is_absolute(),
        "resolved {kind} path is not absolute"
    );
    let metadata = fs::metadata(&resolved).with_context(|| {
        format!(
            "cannot inspect resolved {kind} executable {}",
            resolved.display()
        )
    })?;
    ensure!(
        metadata.is_file(),
        "{kind} executable is not a regular file"
    );
    ensure!(
        metadata.uid() == 0,
        "{kind} executable target is not owned by root"
    );
    ensure!(
        metadata.mode() & 0o022 == 0,
        "{kind} executable is writable by group or other users"
    );
    ensure!(
        metadata.permissions().mode() & 0o111 != 0,
        "{kind} executable is not executable"
    );
    validate_trusted_parent_chain(&resolved, kind)
}

fn validate_trusted_lookup_parent_chain(path: &Path, kind: &str) -> Result<()> {
    let mut parent = path
        .parent()
        .ok_or_else(|| anyhow!("{kind} executable path has no parent directory"))?;
    loop {
        let metadata = fs::symlink_metadata(parent).with_context(|| {
            format!(
                "cannot inspect {kind} executable lookup parent {}",
                parent.display()
            )
        })?;
        ensure!(
            metadata.uid() == 0,
            "{kind} executable lookup parent {} is not owned by root",
            parent.display()
        );
        if !metadata.file_type().is_symlink() {
            ensure!(
                metadata.is_dir(),
                "{kind} executable lookup parent {} is not a directory or symlink",
                parent.display()
            );
            ensure!(
                metadata.mode() & 0o022 == 0,
                "{kind} executable lookup parent {} is writable by group or other users",
                parent.display()
            );
        }
        let Some(next) = parent.parent() else {
            break;
        };
        parent = next;
    }
    Ok(())
}

fn validate_trusted_parent_chain(path: &Path, kind: &str) -> Result<()> {
    let mut parent = path
        .parent()
        .ok_or_else(|| anyhow!("resolved {kind} executable has no parent directory"))?;
    loop {
        let metadata = fs::symlink_metadata(parent).with_context(|| {
            format!(
                "cannot inspect {kind} executable parent {}",
                parent.display()
            )
        })?;
        ensure!(
            metadata.is_dir(),
            "{kind} executable parent {} is not a directory",
            parent.display()
        );
        ensure!(
            metadata.uid() == 0,
            "{kind} executable parent {} is not owned by root",
            parent.display()
        );
        ensure!(
            metadata.mode() & 0o022 == 0,
            "{kind} executable parent {} is writable by group or other users",
            parent.display()
        );
        let Some(next) = parent.parent() else {
            break;
        };
        parent = next;
    }
    Ok(())
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(error) => {
                terminate_child(child);
                return Err(error).context("failed to query firewall subprocess");
            }
        }
        if Instant::now() >= deadline {
            terminate_child(child);
            bail!("firewall subprocess exceeded its {timeout:?} deadline");
        }
        thread::sleep(WAIT_INTERVAL);
    }
}

fn terminate_child(child: &mut Child) {
    let _ignored = child.kill();
    let _ignored = child.wait();
}

#[cfg(test)]
fn parse_learned_endpoints(input: &[u8]) -> Result<Vec<LearnedEndpoint>> {
    let document: Value = serde_json::from_slice(input).context("invalid nft JSON output")?;
    parse_learned_endpoints_document(&document)
}

#[cfg(test)]
fn parse_learned_endpoints_document(document: &Value) -> Result<Vec<LearnedEndpoint>> {
    let objects = nft_objects(document)?;
    let mut endpoints = Vec::new();
    let mut seen = HashSet::new();
    let mut seen_sets = HashSet::new();

    for object in objects {
        let Some(set) = object.get("set") else {
            continue;
        };
        if set.get("family").and_then(Value::as_str) != Some("inet")
            || set.get("table").and_then(Value::as_str) != Some("openshield")
        {
            continue;
        }
        let Some(name) = set.get("name").and_then(Value::as_str) else {
            continue;
        };
        let kind = learned_set_kind(name)
            .ok_or_else(|| anyhow!("unexpected set in the OpenShield learning table"))?;
        ensure!(seen_sets.insert(name), "duplicate OpenShield learning set");
        validate_learning_set_metadata(set, kind)?;
        let Some(elements_value) = set.get("elem") else {
            continue;
        };
        let elements = elements_value
            .as_array()
            .ok_or_else(|| anyhow!("OpenShield learning-set elements are not an array"))?;
        for element in elements {
            if let Some(endpoint) = parse_set_element(element, kind) {
                let key = learned_endpoint_key(&endpoint);
                if seen.insert(key) {
                    ensure!(
                        endpoints.len() < MAX_LEARNED_ENDPOINTS,
                        "nft learning sets exceed their aggregate endpoint bound"
                    );
                    endpoints.push(endpoint);
                }
            }
        }
    }
    let required_sets: HashSet<&str> = LEARNING_SET_NAMES.into_iter().collect();
    ensure!(
        seen_sets == required_sets,
        "one or more OpenShield learning sets are missing"
    );
    Ok(endpoints)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
struct LearnedSetKind {
    protocol: TransportProtocol,
    requires_port: bool,
    expects_ipv6: bool,
    data_types: &'static [&'static str],
}

#[cfg(test)]
fn learned_set_kind(name: &str) -> Option<LearnedSetKind> {
    match name {
        LEARNED_TCP_V4_SET => Some(LearnedSetKind {
            protocol: TransportProtocol::Tcp,
            requires_port: true,
            expects_ipv6: false,
            data_types: &["ifname", "ipv4_addr", "inet_service"],
        }),
        LEARNED_TCP_V6_SET => Some(LearnedSetKind {
            protocol: TransportProtocol::Tcp,
            requires_port: true,
            expects_ipv6: true,
            data_types: &["ifname", "ipv6_addr", "inet_service"],
        }),
        LEARNED_UDP_V4_SET => Some(LearnedSetKind {
            protocol: TransportProtocol::Udp,
            requires_port: true,
            expects_ipv6: false,
            data_types: &["ifname", "ipv4_addr", "inet_service"],
        }),
        LEARNED_UDP_V6_SET => Some(LearnedSetKind {
            protocol: TransportProtocol::Udp,
            requires_port: true,
            expects_ipv6: true,
            data_types: &["ifname", "ipv6_addr", "inet_service"],
        }),
        LEARNED_ICMP_V4_SET => Some(LearnedSetKind {
            protocol: TransportProtocol::Icmp,
            requires_port: false,
            expects_ipv6: false,
            data_types: &["ifname", "ipv4_addr"],
        }),
        LEARNED_ICMP_V6_SET => Some(LearnedSetKind {
            protocol: TransportProtocol::IcmpV6,
            requires_port: false,
            expects_ipv6: true,
            data_types: &["ifname", "ipv6_addr"],
        }),
        _ => None,
    }
}

#[cfg(test)]
fn validate_learning_set_metadata(set: &Value, kind: LearnedSetKind) -> Result<()> {
    let data_types = set
        .get("type")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("OpenShield learning set has an invalid type"))?;
    ensure!(
        data_types.len() == kind.data_types.len()
            && data_types
                .iter()
                .zip(kind.data_types)
                .all(|(actual, expected)| actual.as_str() == Some(*expected)),
        "OpenShield learning-set type does not match its name"
    );
    let flags = set
        .get("flags")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("OpenShield learning set has invalid flags"))?;
    ensure!(
        flags.len() == 1 && flags.first().and_then(Value::as_str) == Some("timeout"),
        "OpenShield learning set must have the normalized timeout flag"
    );
    ensure!(
        set.get("size").and_then(Value::as_u64) == Some(4_096)
            && set.get("timeout").and_then(Value::as_u64) == Some(300),
        "OpenShield learning-set bounds do not match the compiled policy"
    );
    Ok(())
}

#[cfg(test)]
fn parse_set_element(element: &Value, kind: LearnedSetKind) -> Option<LearnedEndpoint> {
    let value = element
        .get("elem")
        .and_then(|inner| inner.get("val"))
        .or_else(|| element.get("val"))
        .unwrap_or(element);
    let components = value.get("concat").and_then(Value::as_array)?;
    let expected_components = if kind.requires_port { 3 } else { 2 };
    if components.len() != expected_components {
        return None;
    }
    let interface = components
        .first()
        .and_then(Value::as_str)
        .and_then(|name| InterfaceName::new(name).ok())?;
    let address: std::net::IpAddr = components.get(1)?.as_str()?.parse().ok()?;
    if address.is_ipv6() != kind.expects_ipv6 {
        return None;
    }
    let port = components
        .get(2)
        .and_then(json_port)
        .and_then(|port| PortRange::single(port).ok());
    if kind.requires_port && port.is_none() {
        return None;
    }

    Some(LearnedEndpoint {
        address,
        protocol: kind.protocol,
        port,
        interface: Some(interface),
    })
}

#[cfg(test)]
fn learned_endpoint_key(endpoint: &LearnedEndpoint) -> (std::net::IpAddr, u8, u16, u16, String) {
    let protocol = match endpoint.protocol {
        TransportProtocol::Any => 0,
        TransportProtocol::Tcp => 1,
        TransportProtocol::Udp => 2,
        TransportProtocol::Icmp => 3,
        TransportProtocol::IcmpV6 => 4,
    };
    let (port_start, port_end) = endpoint
        .port
        .map_or((0, 0), |port| (port.start(), port.end()));
    let interface = endpoint
        .interface
        .as_ref()
        .map_or_else(String::new, |name| name.as_str().to_owned());
    (endpoint.address, protocol, port_start, port_end, interface)
}

#[cfg(test)]
fn parse_counters(input: &[u8]) -> Result<FirewallCounters> {
    let document: Value = serde_json::from_slice(input).context("invalid nft counter JSON")?;
    parse_counters_document(&document)
}

fn nft_objects(document: &Value) -> Result<&[Value]> {
    document
        .get("nftables")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| anyhow!("nft JSON has no nftables array"))
}

fn parse_nft_observation_documents(input: &[u8]) -> Result<()> {
    visit_nft_observation_documents_bounded(input, MAX_NFT_OUTPUT_BYTES, |_, _| Ok(()))
}

fn visit_nft_observation_documents_bounded(
    input: &[u8],
    maximum_document_bytes: usize,
    mut visitor: impl FnMut(&Value, &str) -> Result<()>,
) -> Result<()> {
    ensure!(
        maximum_document_bytes > 0,
        "batched nft observation document bound is zero"
    );
    let maximum_batch_bytes = maximum_document_bytes
        .checked_mul(3)
        .ok_or_else(|| anyhow!("batched nft observation byte bound overflowed"))?;
    ensure!(
        input.len() <= maximum_batch_bytes,
        "batched nft observation exceeded {maximum_batch_bytes} bytes"
    );

    let mut offset = 0_usize;
    for kind in ["table", "chain", "counter"] {
        let bounded_end = offset
            .saturating_add(maximum_document_bytes)
            .min(input.len());
        let mut stream =
            serde_json::Deserializer::from_slice(&input[offset..bounded_end]).into_iter::<Value>();
        let document = stream
            .next()
            .ok_or_else(|| anyhow!("batched nft observation omitted the {kind} document"))?
            .with_context(|| format!("invalid nft {kind} document in observation batch"))?;
        let document_bytes = stream.byte_offset();
        ensure!(
            document_bytes > 0 && document_bytes <= maximum_document_bytes,
            "nft {kind} observation document exceeded {maximum_document_bytes} bytes"
        );
        let _objects = nft_objects(&document)
            .with_context(|| format!("invalid nft {kind} document in observation batch"))?;
        visitor(&document, kind)?;
        offset = offset
            .checked_add(document_bytes)
            .ok_or_else(|| anyhow!("batched nft observation offset overflowed"))?;
    }
    ensure!(
        input[offset..]
            .iter()
            .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n')),
        "batched nft observation returned more than 3 JSON documents"
    );
    Ok(())
}

fn parse_nft_policy_observation(input: &[u8]) -> Result<FirewallCounters> {
    let mut counters = None;
    visit_nft_observation_documents_bounded(
        input,
        MAX_NFT_OUTPUT_BYTES,
        |document, kind| match kind {
            "table" => verify_table_document(document),
            "chain" => verify_base_chains_document(document),
            "counter" => {
                counters = Some(parse_counters_document(document)?);
                Ok(())
            }
            _ => bail!("unexpected nft observation document kind"),
        },
    )?;
    counters.ok_or_else(|| anyhow!("batched nft observation omitted parsed counters"))
}

#[cfg(test)]
fn verify_table(input: &[u8]) -> Result<()> {
    let document: Value = serde_json::from_slice(input).context("invalid nft table JSON")?;
    verify_table_document(&document)
}

fn verify_table_document(document: &Value) -> Result<()> {
    ensure!(
        openshield_table_count_document(document)? == 1,
        "OpenShield table declaration is missing or duplicated"
    );
    Ok(())
}

fn openshield_table_count(input: &[u8]) -> Result<usize> {
    let document: Value = serde_json::from_slice(input).context("invalid nft table JSON")?;
    openshield_table_count_document(&document)
}

fn openshield_table_count_document(document: &Value) -> Result<usize> {
    let objects = nft_objects(document)?;
    Ok(objects
        .iter()
        .filter_map(|object| object.get("table"))
        .filter(|table| {
            table.get("family").and_then(Value::as_str) == Some("inet")
                && table.get("name").and_then(Value::as_str) == Some("openshield")
        })
        .count())
}

fn verify_nft_ownership_counter(input: &[u8]) -> Result<()> {
    let document: Value = serde_json::from_slice(input).context("invalid nft counter JSON")?;
    let objects = nft_objects(&document)?;
    let mut ownership = 0_usize;
    for counter in objects.iter().filter_map(|object| object.get("counter")) {
        if counter.get("family").and_then(Value::as_str) == Some("inet")
            && counter.get("table").and_then(Value::as_str) == Some("openshield")
            && counter.get("name").and_then(Value::as_str) == Some(NFT_OWNERSHIP_COUNTER)
        {
            ensure!(
                counter.get("packets").and_then(Value::as_u64) == Some(0)
                    && counter.get("bytes").and_then(Value::as_u64) == Some(0),
                "nft ownership sentinel must remain an unreferenced zero counter"
            );
            ownership += 1;
        }
    }
    ensure!(
        ownership == 1,
        "nft ownership sentinel is missing or duplicated"
    );
    Ok(())
}

#[cfg(test)]
fn verify_base_chains(input: &[u8]) -> Result<()> {
    let document: Value = serde_json::from_slice(input).context("invalid nft chain JSON")?;
    verify_base_chains_document(&document)
}

fn verify_base_chains_document(document: &Value) -> Result<()> {
    let objects = nft_objects(document)?;
    let required_chains = [
        ("input", "input", 0, "drop"),
        ("output_sanitize", "output", -1, "accept"),
        ("output", "output", 0, "drop"),
        ("output_authorize", "output", 1, "drop"),
        ("forward", "forward", 0, "drop"),
    ];
    let mut chains = HashSet::new();

    for object in objects {
        if let Some(chain) = object.get("chain")
            && chain.get("family").and_then(Value::as_str) == Some("inet")
            && chain.get("table").and_then(Value::as_str) == Some("openshield")
        {
            let name = chain
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("OpenShield chain has no name"))?;
            let (hook, priority, policy) = required_chains
                .iter()
                .find_map(|(required_name, hook, priority, policy)| {
                    (*required_name == name).then_some((*hook, *priority, *policy))
                })
                .ok_or_else(|| anyhow!("unexpected chain in the OpenShield table"))?;
            ensure!(
                chain.get("type").and_then(Value::as_str) == Some("filter")
                    && chain.get("hook").and_then(Value::as_str) == Some(hook)
                    && chain.get("prio").and_then(Value::as_i64) == Some(priority)
                    && chain.get("policy").and_then(Value::as_str) == Some(policy),
                "OpenShield base chain metadata does not match the compiled policy"
            );
            ensure!(chains.insert(name), "duplicate OpenShield base chain");
        }
    }

    ensure!(
        chains.len() == required_chains.len(),
        "one or more required OpenShield base chains are missing"
    );
    Ok(())
}

fn parse_counters_document(document: &Value) -> Result<FirewallCounters> {
    let objects = nft_objects(document)?;

    let mut accepted_in = None;
    let mut accepted_out = None;
    let mut dropped_in = None;
    let mut dropped_out = None;
    let mut learned_out = None;
    let mut ownership = false;

    for object in objects {
        let Some(counter) = object.get("counter") else {
            continue;
        };
        if counter.get("family").and_then(Value::as_str) != Some("inet")
            || counter.get("table").and_then(Value::as_str) != Some("openshield")
        {
            continue;
        }
        let Some(name) = counter.get("name").and_then(Value::as_str) else {
            continue;
        };
        let value = CounterValue {
            packets: counter
                .get("packets")
                .and_then(Value::as_u64)
                .ok_or_else(|| anyhow!("counter {name} has an invalid packet count"))?,
            bytes: counter
                .get("bytes")
                .and_then(Value::as_u64)
                .ok_or_else(|| anyhow!("counter {name} has an invalid byte count"))?,
        };
        if name == NFT_OWNERSHIP_COUNTER {
            ensure!(
                value == CounterValue::default(),
                "nft ownership sentinel must remain an unreferenced zero counter"
            );
            ensure!(!ownership, "duplicate nft ownership sentinel");
            ownership = true;
            continue;
        }
        let destination = match name {
            COUNTER_ACCEPTED_IN => &mut accepted_in,
            COUNTER_ACCEPTED_OUT => &mut accepted_out,
            COUNTER_DROPPED_IN => &mut dropped_in,
            COUNTER_DROPPED_OUT => &mut dropped_out,
            COUNTER_LEARNED_OUT => &mut learned_out,
            _ => bail!("unexpected named counter in the OpenShield table"),
        };
        ensure!(
            destination.replace(value).is_none(),
            "duplicate nft counter {name}"
        );
    }

    ensure!(ownership, "missing nft ownership sentinel");

    Ok(FirewallCounters {
        accepted_in: accepted_in.ok_or_else(|| anyhow!("missing {COUNTER_ACCEPTED_IN} counter"))?,
        accepted_out: accepted_out
            .ok_or_else(|| anyhow!("missing {COUNTER_ACCEPTED_OUT} counter"))?,
        dropped_in: dropped_in.ok_or_else(|| anyhow!("missing {COUNTER_DROPPED_IN} counter"))?,
        dropped_out: dropped_out.ok_or_else(|| anyhow!("missing {COUNTER_DROPPED_OUT} counter"))?,
        learned_out: learned_out.ok_or_else(|| anyhow!("missing {COUNTER_LEARNED_OUT} counter"))?,
    })
}

#[cfg(test)]
fn json_port(value: &Value) -> Option<u16> {
    value
        .as_u64()
        .and_then(|port| u16::try_from(port).ok())
        .or_else(|| value.as_str().and_then(|port| port.parse().ok()))
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::{
        AutoBackend, FirewallBackend, FirewallCounters, InterfaceName, IptablesBackend,
        LearnedEndpoint, MemoryBackend, NftBackend, PortRange, TransportProtocol, XtablesBundle,
        XtablesIdentity, XtablesTools, XtablesWorld, XtablesWorldInspection, add_firewall_counters,
        attempt_both_families, ensure_xtables_identity_unchanged, inspect_xtables_world,
        is_expected_covered_legacy_warning, is_proven_absent_legacy_backend, parse_counters,
        parse_learned_endpoints, parse_xtables_save, parse_xtables_world_save,
        parse_xtables_world_version, selected_xtables_save_args, verify_base_chains, verify_table,
        xtables_save_inspection_args, xtables_world_is_covered,
    };
    use anyhow::Result;
    use openshield_protocol::FirewallBackendKind;
    use serde_json::{Value, json};
    use std::{
        cell::RefCell,
        collections::HashSet,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        path::PathBuf as TestPathBuf,
        sync::{Arc, Mutex},
    };

    fn inert_xtables_tools(family: &str) -> XtablesTools {
        XtablesTools {
            command: TestPathBuf::from(format!("/{family}tables")),
            restore: TestPathBuf::from(format!("/{family}tables-restore")),
            save: TestPathBuf::from(format!("/{family}tables-save")),
        }
    }

    #[test]
    fn production_backends_report_explicit_kinds_and_test_backend_defaults_unknown() {
        let nft = NftBackend {
            binary: TestPathBuf::from("/nft"),
        };
        let iptables = IptablesBackend {
            ipv4: inert_xtables_tools("ip"),
            ipv6: inert_xtables_tools("ip6"),
            expected: Arc::new(Mutex::new(super::ExpectedXtablesPolicy::default())),
        };

        assert_eq!(nft.kind(), FirewallBackendKind::Nftables);
        assert_eq!(iptables.kind(), FirewallBackendKind::Iptables);
        assert_eq!(AutoBackend::Nft(nft).kind(), FirewallBackendKind::Nftables);
        assert_eq!(
            AutoBackend::Iptables(iptables).kind(),
            FirewallBackendKind::Iptables
        );
        assert_eq!(
            MemoryBackend::default().kind(),
            FirewallBackendKind::Unknown
        );
    }

    #[test]
    fn automatic_backend_discovery_prefers_nft_and_falls_back_in_order() -> Result<()> {
        let calls = RefCell::new(Vec::new());
        let selected = AutoBackend::discover_with(
            || {
                calls.borrow_mut().push("nftables");
                Ok(NftBackend {
                    binary: TestPathBuf::from("/nft"),
                })
            },
            || -> Result<IptablesBackend> {
                calls.borrow_mut().push("iptables");
                anyhow::bail!("iptables must not be probed after nftables succeeds")
            },
        )?;
        assert!(matches!(selected, AutoBackend::Nft(_)));
        assert_eq!(*calls.borrow(), ["nftables"]);

        let calls = RefCell::new(Vec::new());
        let selected = AutoBackend::discover_with(
            || {
                calls.borrow_mut().push("nftables");
                anyhow::bail!("nft probe failed")
            },
            || {
                calls.borrow_mut().push("iptables");
                Ok(IptablesBackend {
                    ipv4: inert_xtables_tools("ip"),
                    ipv6: inert_xtables_tools("ip6"),
                    expected: Arc::new(Mutex::new(super::ExpectedXtablesPolicy::default())),
                })
            },
        )?;
        assert!(matches!(selected, AutoBackend::Iptables(_)));
        assert_eq!(*calls.borrow(), ["nftables", "iptables"]);
        Ok(())
    }

    #[test]
    fn automatic_backend_discovery_reports_both_probe_failures() -> Result<()> {
        let result = AutoBackend::discover_with(
            || anyhow::bail!("nft capability rejected"),
            || anyhow::bail!("xtables capability rejected"),
        );
        let error = result
            .err()
            .ok_or_else(|| anyhow::anyhow!("both rejected backends must fail discovery"))?;
        let message = format!("{error:#}");
        assert!(message.contains("nft capability rejected"), "{message}");
        assert!(message.contains("xtables capability rejected"), "{message}");
        Ok(())
    }

    fn learning_set(name: &str, data_types: &[&str], elements: Option<Value>) -> Value {
        let mut object = json!({"set": {
            "family": "inet",
            "table": "openshield",
            "name": name,
            "type": data_types,
            "size": 4096,
            "flags": ["timeout"],
            "timeout": 300
        }});
        if let Some(elements) = elements {
            object["set"]["elem"] = elements;
        }
        object
    }

    fn learning_document(
        tcp_v4: Option<Value>,
        udp_v4: Option<Value>,
        icmp_v6: Option<Value>,
    ) -> Result<Vec<u8>> {
        let document = json!({"nftables": [
            {"set":{"family":"inet","table":"other","name":"learned_tcp_v4"}},
            learning_set(
                "learned_tcp_v4",
                &["ifname", "ipv4_addr", "inet_service"],
                tcp_v4,
            ),
            learning_set(
                "learned_tcp_v6",
                &["ifname", "ipv6_addr", "inet_service"],
                None,
            ),
            learning_set(
                "learned_udp_v4",
                &["ifname", "ipv4_addr", "inet_service"],
                udp_v4,
            ),
            learning_set(
                "learned_udp_v6",
                &["ifname", "ipv6_addr", "inet_service"],
                None,
            ),
            learning_set(
                "learned_icmp_v4",
                &["ifname", "ipv4_addr"],
                None,
            ),
            learning_set(
                "learned_icmp_v6",
                &["ifname", "ipv6_addr"],
                icmp_v6,
            )
        ]});
        Ok(serde_json::to_vec(&document)?)
    }

    #[test]
    fn parses_only_allowlisted_learning_sets_and_deduplicates() -> Result<()> {
        let input = learning_document(
            Some(json!([
                {"concat":["eth0","192.0.2.5",443]},
                {"elem":{"val":{"concat":["eth0","192.0.2.5",443]}}}
            ])),
            None,
            Some(json!([{"concat":["tun0","2001:db8::7"]}])),
        )?;
        let endpoints = parse_learned_endpoints(&input)?;
        assert_eq!(
            endpoints,
            vec![
                LearnedEndpoint {
                    address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
                    protocol: TransportProtocol::Tcp,
                    port: Some(PortRange::single(443)?),
                    interface: Some(InterfaceName::new("eth0")?),
                },
                LearnedEndpoint {
                    address: IpAddr::V6("2001:db8::7".parse::<Ipv6Addr>()?),
                    protocol: TransportProtocol::IcmpV6,
                    port: None,
                    interface: Some(InterfaceName::new("tun0")?),
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn rejects_oversized_or_invalid_ports() -> Result<()> {
        let input = learning_document(
            None,
            Some(json!([
                {"concat":["eth0","192.0.2.1",65536]},
                {"concat":["bad;name","192.0.2.2",53]},
                {"concat":["192.0.2.3",53]},
                {"concat":["eth1","192.0.2.2","53"]}
            ])),
            None,
        )?;
        let endpoints = parse_learned_endpoints(&input)?;
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].port, Some(PortRange::single(53)?));
        assert_eq!(endpoints[0].interface, Some(InterfaceName::new("eth1")?));
        Ok(())
    }

    #[test]
    fn rejects_missing_or_unbounded_learning_set_metadata() -> Result<()> {
        let incomplete = serde_json::to_vec(&json!({"nftables": [learning_set(
            "learned_tcp_v4",
            &["ifname", "ipv4_addr", "inet_service"],
            None,
        )]}))?;
        assert!(parse_learned_endpoints(&incomplete).is_err());

        let mut invalid = serde_json::from_slice::<Value>(&learning_document(None, None, None)?)?;
        invalid["nftables"][1]["set"]["size"] = json!(8192);
        assert!(parse_learned_endpoints(&serde_json::to_vec(&invalid)?).is_err());
        Ok(())
    }

    #[test]
    fn nft_query_preflight_requires_three_well_formed_json_documents() -> Result<()> {
        let empty = r#"{"nftables":[]}"#;
        super::parse_nft_observation_documents(format!("{empty}\n{empty}\n{empty}\n").as_bytes())?;
        assert!(
            super::parse_nft_observation_documents(format!("{empty}\n{empty}\n").as_bytes())
                .is_err()
        );
        assert!(super::parse_nft_observation_documents(b"{}\n{}\n{}\n").is_err());
        assert!(
            super::parse_nft_observation_documents(
                format!("{empty}\nnot-json\n{empty}\n").as_bytes()
            )
            .is_err()
        );
        assert!(
            super::parse_nft_observation_documents(
                format!("{empty}\n{empty}\n{empty}\n{empty}\n").as_bytes()
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn nft_observation_preserves_the_original_per_document_byte_bound() -> Result<()> {
        const TEST_DOCUMENT_BOUND: usize = 64;
        let bounded = r#"{"nftables":[],"padding":"12345678"}"#;
        super::visit_nft_observation_documents_bounded(
            format!("{bounded}\n{bounded}\n{bounded}\n").as_bytes(),
            TEST_DOCUMENT_BOUND,
            |_, _| Ok(()),
        )?;

        let oversized = format!(
            "{{\"nftables\":[],\"padding\":\"{}\"}}\n{bounded}\n{bounded}\n",
            "x".repeat(48)
        );
        assert!(oversized.len() <= TEST_DOCUMENT_BOUND * 3);
        assert!(
            super::visit_nft_observation_documents_bounded(
                oversized.as_bytes(),
                TEST_DOCUMENT_BOUND,
                |_, _| Ok(())
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn parses_only_fixed_table_counters() -> Result<()> {
        let input = br#"{"nftables":[
          {"metainfo":{"json_schema_version":1}},
          {"counter":{"family":"inet","table":"openshield","name":"openshield_owner_v1","packets":0,"bytes":0}},
          {"counter":{"family":"inet","table":"openshield","name":"accepted_in","packets":1,"bytes":10}},
          {"counter":{"family":"inet","table":"openshield","name":"accepted_out","packets":2,"bytes":20}},
          {"counter":{"family":"inet","table":"openshield","name":"dropped_in","packets":3,"bytes":30}},
          {"counter":{"family":"inet","table":"openshield","name":"dropped_out","packets":4,"bytes":40}},
          {"counter":{"family":"inet","table":"openshield","name":"learned_out","packets":5,"bytes":50}},
          {"counter":{"family":"inet","table":"other","name":"accepted_in","packets":99,"bytes":99}}
        ]}"#;
        let counters = parse_counters(input)?;
        assert_eq!(
            counters,
            FirewallCounters {
                accepted_in: openshield_core::CounterValue {
                    packets: 1,
                    bytes: 10
                },
                accepted_out: openshield_core::CounterValue {
                    packets: 2,
                    bytes: 20
                },
                dropped_in: openshield_core::CounterValue {
                    packets: 3,
                    bytes: 30
                },
                dropped_out: openshield_core::CounterValue {
                    packets: 4,
                    bytes: 40
                },
                learned_out: openshield_core::CounterValue {
                    packets: 5,
                    bytes: 50
                },
            }
        );
        Ok(())
    }

    #[test]
    fn rejects_incomplete_counter_snapshot() {
        let input = br#"{"nftables":[]}"#;
        assert!(parse_counters(input).is_err());
    }

    #[test]
    fn nft_replacement_requires_an_exact_unreferenced_ownership_sentinel() -> Result<()> {
        let owned = br#"{"nftables":[
          {"counter":{"family":"inet","table":"openshield","name":"openshield_owner_v1","packets":0,"bytes":0}},
          {"counter":{"family":"inet","table":"other","name":"openshield_owner_v1","packets":0,"bytes":0}}
        ]}"#;
        super::verify_nft_ownership_counter(owned)?;

        let missing = br#"{"nftables":[
          {"counter":{"family":"inet","table":"openshield","name":"accepted_in","packets":0,"bytes":0}}
        ]}"#;
        assert!(super::verify_nft_ownership_counter(missing).is_err());

        let referenced = br#"{"nftables":[
          {"counter":{"family":"inet","table":"openshield","name":"openshield_owner_v1","packets":1,"bytes":64}}
        ]}"#;
        assert!(super::verify_nft_ownership_counter(referenced).is_err());
        Ok(())
    }

    #[test]
    fn observation_queries_use_nft_1_0_6_compatible_grammar() {
        assert_eq!(super::NFT_TABLE_QUERY, ["-j", "list", "tables", "inet"]);
        assert_eq!(super::NFT_COUNTER_QUERY, ["-j", "list", "counters", "inet"]);
        assert_eq!(
            super::NFT_OBSERVATION_QUERY,
            [
                "-j",
                "list tables inet; list chains inet; list counters inet"
            ]
        );
        assert_eq!(
            super::NFT_SET_QUERY_PREFIX,
            ["-j", "list", "set", "inet", "openshield"]
        );
        assert_eq!(
            super::LEARNING_SET_NAMES,
            [
                "learned_tcp_v4",
                "learned_tcp_v6",
                "learned_udp_v4",
                "learned_udp_v6",
                "learned_icmp_v4",
                "learned_icmp_v6"
            ]
        );
    }

    #[test]
    fn policy_observation_requires_fixed_table_and_all_fail_closed_hooks() -> Result<()> {
        let complete = br#"{"nftables":[
          {"table":{"family":"inet","name":"openshield"}},
          {"chain":{"family":"inet","table":"openshield","name":"input","type":"filter","hook":"input","prio":0,"policy":"drop"}},
          {"chain":{"family":"inet","table":"openshield","name":"output_sanitize","type":"filter","hook":"output","prio":-1,"policy":"accept"}},
          {"chain":{"family":"inet","table":"openshield","name":"output","type":"filter","hook":"output","prio":0,"policy":"drop"}},
          {"chain":{"family":"inet","table":"openshield","name":"output_authorize","type":"filter","hook":"output","prio":1,"policy":"drop"}},
          {"chain":{"family":"inet","table":"openshield","name":"forward","type":"filter","hook":"forward","prio":0,"policy":"drop"}},
          {"counter":{"family":"inet","table":"openshield","name":"openshield_owner_v1","packets":0,"bytes":0}},
          {"counter":{"family":"inet","table":"openshield","name":"accepted_in","packets":1,"bytes":10}},
          {"counter":{"family":"inet","table":"openshield","name":"accepted_out","packets":2,"bytes":20}},
          {"counter":{"family":"inet","table":"openshield","name":"dropped_in","packets":3,"bytes":30}},
          {"counter":{"family":"inet","table":"openshield","name":"dropped_out","packets":4,"bytes":40}},
          {"counter":{"family":"inet","table":"openshield","name":"learned_out","packets":5,"bytes":50}},
          {"rule":{"family":"inet","table":"openshield","chain":"input"}},
          {"rule":{"family":"inet","table":"openshield","chain":"output_sanitize"}},
          {"rule":{"family":"inet","table":"openshield","chain":"output"}},
          {"rule":{"family":"inet","table":"openshield","chain":"output_authorize"}},
          {"rule":{"family":"inet","table":"openshield","chain":"forward"}}
        ]}"#;
        verify_table(complete)?;
        verify_base_chains(complete)?;

        let document: Value = serde_json::from_slice(complete)?;
        let objects = super::nft_objects(&document)?;
        let select = |kind: &str| {
            json!({
                "nftables": objects
                    .iter()
                    .filter(|object| object.get(kind).is_some())
                    .collect::<Vec<_>>()
            })
        };
        let tables = select("table");
        let chains = select("chain");
        let counters = select("counter");
        let observation = format!("{tables}\n{chains}\n{counters}\n");
        assert_eq!(
            super::parse_nft_policy_observation(observation.as_bytes())?,
            parse_counters(complete)?
        );
        assert!(
            super::parse_nft_policy_observation(
                format!("{chains}\n{tables}\n{counters}\n").as_bytes()
            )
            .is_err()
        );
        assert!(
            super::parse_nft_policy_observation(format!("{tables}\n{chains}\n").as_bytes())
                .is_err()
        );

        let missing_forward_hook = br#"{"nftables":[
          {"table":{"family":"inet","name":"openshield"}},
          {"chain":{"family":"inet","table":"openshield","name":"input","type":"filter","hook":"input","prio":0,"policy":"drop"}},
          {"chain":{"family":"inet","table":"openshield","name":"output","type":"filter","hook":"output","prio":0,"policy":"drop"}},
          {"chain":{"family":"inet","table":"other","name":"forward","type":"filter","hook":"forward","prio":0,"policy":"drop"}}
        ]}"#;
        assert!(verify_base_chains(missing_forward_hook).is_err());
        Ok(())
    }

    #[test]
    fn memory_backend_supports_bounded_test_observation() -> Result<()> {
        use super::{FirewallBackend, FirewallObserver, MemoryBackend};

        let mut backend = MemoryBackend::default();
        backend.apply(&openshield_core::State::new().snapshot())?;
        backend.fail_next_apply();
        assert!(
            backend
                .apply(&openshield_core::State::new().snapshot())
                .is_err()
        );
        assert_eq!(backend.policy_observation()?, FirewallCounters::default());
        Ok(())
    }

    #[test]
    fn maximum_rule_policy_fits_the_bounded_nft_input() -> Result<()> {
        use openshield_core::{
            Direction, InterfaceName, IptablesCompiler, MAX_RULES, Mode, NftablesCompiler,
            RuleName, RuleOrigin, RuleSpec, State,
        };

        let specification = RuleSpec::new(
            RuleName::new("maximum compiled selector")?,
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

        let policy = NftablesCompiler::compile(&state.snapshot())?;
        assert!(policy.as_bytes().len() > 1024 * 1024);
        assert!(policy.as_bytes().len() <= super::MAX_POLICY_BYTES);
        let compatibility = IptablesCompiler::compile(&state.snapshot())?;
        assert!(compatibility.ipv6().len() > 1024 * 1024);
        assert!(compatibility.ipv4().len() <= super::MAX_POLICY_BYTES);
        assert!(compatibility.ipv6().len() <= super::MAX_POLICY_BYTES);
        Ok(())
    }

    #[test]
    fn xtables_observation_requires_first_dispatchers_and_exact_owned_chains() -> Result<()> {
        let complete = br#"# Generated by iptables-save
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:OPENSHIELD_IN - [0:0]
:OPENSHIELD_OUT - [0:0]
:OPENSHIELD_FWD - [0:0]
:OPENSHIELD_APP_TCP - [0:0]
:OPENSHIELD_APP_PKT - [0:0]
[0:0] -A INPUT -j OPENSHIELD_IN
[0:0] -A FORWARD -j OPENSHIELD_FWD
[0:0] -A OUTPUT -j OPENSHIELD_OUT
[0:0] -A OPENSHIELD_IN -m comment --comment "openshield:owner:v1"
[1:10] -A OPENSHIELD_IN -m comment --comment "openshield:accepted_in" -j RETURN
[2:20] -A OPENSHIELD_IN -m comment --comment "openshield:dropped_in" -j DROP
[0:0] -A OPENSHIELD_OUT -m comment --comment "openshield:owner:v1"
[3:30] -A OPENSHIELD_OUT -m comment --comment "openshield:accepted_out" -j RETURN
[4:40] -A OPENSHIELD_OUT -m comment --comment "openshield:dropped_out" -j DROP
[0:0] -A OPENSHIELD_FWD -m comment --comment "openshield:owner:v1"
[5:50] -A OPENSHIELD_FWD -m comment --comment "openshield:dropped_out" -j DROP
[0:0] -A OPENSHIELD_APP_TCP -m comment --comment "openshield:owner:v1"
[6:60] -A OPENSHIELD_APP_TCP -m comment --comment "openshield:accepted_out+learned_out" -j RETURN
[0:0] -A OPENSHIELD_APP_TCP -m comment --comment "openshield:dropped_out" -j DROP
[0:0] -A OPENSHIELD_APP_PKT -m comment --comment "openshield:owner:v1"
[0:0] -A OPENSHIELD_APP_PKT -m comment --comment "openshield:dropped_out" -j DROP
COMMIT
"#;
        let snapshot = parse_xtables_save(complete)?;
        snapshot.verify_filter_topology()?;
        assert_eq!(snapshot.owned_rules.len(), 13);
        assert_eq!(snapshot.counters.accepted_in.packets, 1);
        assert_eq!(snapshot.counters.accepted_out.packets, 9);
        assert_eq!(snapshot.counters.learned_out.packets, 6);
        assert_eq!(snapshot.counters.dropped_out.packets, 9);

        let tampered = String::from_utf8(complete.to_vec())?.replace(
            "[0:0] -A INPUT -j OPENSHIELD_IN\n",
            "[0:0] -A INPUT -j UNTRUSTED\n[0:0] -A INPUT -j OPENSHIELD_IN\n",
        );
        assert!(
            parse_xtables_save(tampered.as_bytes())?
                .verify_filter_topology()
                .is_err()
        );

        let duplicate = String::from_utf8(complete.to_vec())?.replace(
            "[0:0] -A OUTPUT -j OPENSHIELD_OUT\n",
            "[0:0] -A OUTPUT -j OPENSHIELD_OUT\n[0:0] -A OUTPUT -j OPENSHIELD_OUT\n",
        );
        assert!(
            parse_xtables_save(duplicate.as_bytes())?
                .verify_filter_topology()
                .is_err()
        );

        let foreign_chain = String::from_utf8(complete.to_vec())?.replace(
            "[0:0] -A OPENSHIELD_OUT -m comment --comment \"openshield:owner:v1\"\n",
            "",
        );
        assert!(
            parse_xtables_save(foreign_chain.as_bytes())?
                .verify_filter_topology()
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn xtables_observation_requires_first_sanitizer_and_last_learning_observer() -> Result<()> {
        let complete = br#"*mangle
:OUTPUT ACCEPT [0:0]
:OPENSHIELD_MARK - [0:0]
:OPENSHIELD_OBSERVE - [0:0]
[0:0] -A OUTPUT -j OPENSHIELD_MARK
[0:0] -A OUTPUT -j OPENSHIELD_OBSERVE
[0:0] -A OPENSHIELD_MARK -m comment --comment "openshield:owner:v1"
[0:0] -A OPENSHIELD_MARK -m mark ! --mark 0x0/0xc0000000 -j MARK --set-xmark 0x0/0xc0000000
[0:0] -A OPENSHIELD_MARK -j RETURN
[0:0] -A OPENSHIELD_OBSERVE -m comment --comment "openshield:owner:v1"
[0:0] -A OPENSHIELD_OBSERVE -m mark ! --mark 0x0/0xc0000000 -j MARK --set-xmark 0x0/0xc0000000
[0:0] -A OPENSHIELD_OBSERVE -j RETURN
COMMIT
"#;
        let snapshot = parse_xtables_save(complete)?;
        snapshot.verify_mangle_topology()?;
        assert_eq!(snapshot.owned_rules.len(), 6);

        let bypassed = String::from_utf8(complete.to_vec())?.replace(
            "[0:0] -A OUTPUT -j OPENSHIELD_MARK\n",
            "[0:0] -A OUTPUT -j UNTRUSTED\n[0:0] -A OUTPUT -j OPENSHIELD_MARK\n",
        );
        assert!(
            parse_xtables_save(bypassed.as_bytes())?
                .verify_mangle_topology()
                .is_err()
        );

        let foreign_between = String::from_utf8(complete.to_vec())?.replace(
            "[0:0] -A OUTPUT -j OPENSHIELD_OBSERVE\n",
            "[0:0] -A OUTPUT -j FOREIGN_MANGLE\n[0:0] -A OUTPUT -j OPENSHIELD_OBSERVE\n",
        );
        parse_xtables_save(foreign_between.as_bytes())?.verify_mangle_topology()?;

        let observer_not_last = String::from_utf8(complete.to_vec())?.replace(
            "[0:0] -A OUTPUT -j OPENSHIELD_OBSERVE\n",
            "[0:0] -A OUTPUT -j OPENSHIELD_OBSERVE\n[0:0] -A OUTPUT -j FOREIGN_MANGLE\n",
        );
        assert!(
            parse_xtables_save(observer_not_last.as_bytes())?
                .verify_mangle_topology()
                .is_err()
        );

        let duplicate = String::from_utf8(complete.to_vec())?.replace(
            "[0:0] -A OUTPUT -j OPENSHIELD_OBSERVE\n",
            "[0:0] -A OUTPUT -j OPENSHIELD_OBSERVE\n[0:0] -A OUTPUT -j OPENSHIELD_OBSERVE\n",
        );
        assert!(
            parse_xtables_save(duplicate.as_bytes())?
                .verify_mangle_topology()
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn xtables_counter_aggregation_is_checked() {
        let left = FirewallCounters {
            accepted_in: openshield_core::CounterValue {
                packets: u64::MAX,
                bytes: 0,
            },
            ..FirewallCounters::default()
        };
        let right = FirewallCounters {
            accepted_in: openshield_core::CounterValue {
                packets: 1,
                bytes: 0,
            },
            ..FirewallCounters::default()
        };
        assert!(add_firewall_counters(&left, &right).is_err());
    }

    #[test]
    fn fail_closed_attempts_both_families_and_reports_both_failures() -> Result<()> {
        let attempts = RefCell::new(Vec::new());
        let result = attempt_both_families(
            "test quarantine",
            || {
                attempts.borrow_mut().push("IPv4");
                Err(anyhow::anyhow!("IPv4 injected failure"))
            },
            || {
                attempts.borrow_mut().push("IPv6");
                Err(anyhow::anyhow!("IPv6 injected failure"))
            },
        );

        assert_eq!(*attempts.borrow(), ["IPv4", "IPv6"]);
        let error = result
            .err()
            .ok_or_else(|| anyhow::anyhow!("both injected failures must be reported"))?;
        let message = format!("{error:#}");
        assert!(message.contains("IPv4 injected failure"));
        assert!(message.contains("IPv6 injected failure"));
        Ok(())
    }

    #[test]
    fn xtables_discovery_skips_an_unusable_legacy_bundle() -> Result<()> {
        let candidates = [
            XtablesBundle {
                command: "/test/iptables-legacy",
                restore: "/test/iptables-legacy-restore",
                save: "/test/iptables-legacy-save",
            },
            XtablesBundle {
                command: "/test/iptables",
                restore: "/test/iptables-restore",
                save: "/test/iptables-save",
            },
        ];
        let probes = RefCell::new(Vec::new());
        let tools = XtablesTools::discover_with(
            &candidates,
            |_path| Ok(()),
            |tools| {
                let command = tools.command.to_string_lossy().into_owned();
                probes.borrow_mut().push(command.clone());
                if command.ends_with("-legacy") {
                    Err(anyhow::anyhow!("legacy kernel backend is unavailable"))
                } else {
                    Ok(())
                }
            },
        )?;

        assert_eq!(
            *probes.borrow(),
            ["/test/iptables-legacy", "/test/iptables"]
        );
        assert_eq!(tools.command, std::path::Path::new("/test/iptables"));
        Ok(())
    }

    #[test]
    fn xtables_probe_is_numeric_and_exercises_every_required_extension() {
        assert_eq!(
            super::XTABLES_LIST_ARGS,
            ["--wait", "5", "-t", "filter", "-n", "-L"]
        );
        let policy = super::XTABLES_CAPABILITY_POLICY;
        for required in [
            "-m conntrack",
            "--ctstate RELATED",
            "--tcp-flags RST RST",
            "--ctdir ORIGINAL",
            "-m connmark --mark",
            "-m comment --comment openshield:probe",
            "-m mark ! --mark",
            "-j MARK --set-xmark",
            "-j CONNMARK --set-xmark",
            "-j NFQUEUE --queue-num 1338 --queue-bypass",
            "-j NFQUEUE --queue-num 1337",
            "-j REJECT",
            "-g OPENSHIELD_PROBE_GOTO",
        ] {
            assert!(policy.contains(required), "probe omitted {required}");
        }
    }

    #[test]
    fn ownership_initializer_is_atomic_and_does_not_flush() {
        let policy = super::ownership_initialization_policy(
            "filter",
            &["OPENSHIELD_IN", "OPENSHIELD_APP_TCP"],
        );
        assert!(policy.starts_with("*filter\n:OPENSHIELD_IN - [0:0]\n"));
        assert!(policy.contains(":OPENSHIELD_APP_TCP - [0:0]\n"));
        assert!(policy.contains("-A OPENSHIELD_IN -m comment --comment openshield:owner:v1\n"));
        assert!(
            policy.contains("-A OPENSHIELD_APP_TCP -m comment --comment openshield:owner:v1\n")
        );
        assert!(!policy.contains("-F "));
        assert!(policy.ends_with("COMMIT\n"));
    }

    #[test]
    fn backend_switch_detection_recognizes_partial_xtables_artifacts() -> Result<()> {
        let empty = parse_xtables_save(
            b"*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\nCOMMIT\n",
        )?;
        assert!(!empty.has_openshield_artifacts());

        let partial =
            parse_xtables_save(b"*filter\n:INPUT ACCEPT [0:0]\n:OPENSHIELD_IN - [0:0]\nCOMMIT\n")?;
        assert!(partial.has_openshield_artifacts());

        let dispatcher = parse_xtables_save(
            b"*filter\n:INPUT ACCEPT [0:0]\n[0:0] -A INPUT -j OPENSHIELD_IN\nCOMMIT\n",
        )?;
        assert!(dispatcher.has_openshield_artifacts());
        Ok(())
    }

    #[test]
    fn legacy_enoprotoopt_diagnostic_proves_backend_absence() {
        let legacy_save = std::path::Path::new("/usr/sbin/ip6tables-legacy-save");
        let legacy_binary = std::path::Path::new("/usr/sbin/xtables-legacy-multi");
        let diagnostic = b"ip6tables-save v1.8.9 (legacy): Cannot initialize: iptables who? (do you need to insmod?)\n";
        assert!(is_proven_absent_legacy_backend(
            legacy_save,
            legacy_binary,
            Some(1),
            b"",
            diagnostic,
        ));

        // Ubuntu 22.04's libxtables 1.8.7 appends an additional empty line to
        // this fatal diagnostic when the legacy IPv6 module is unavailable.
        let ubuntu_double_lf = b"ip6tables-save v1.8.7 (legacy): Cannot initialize: iptables who? (do you need to insmod?)\n\n";
        assert!(is_proven_absent_legacy_backend(
            legacy_save,
            legacy_binary,
            Some(1),
            b"",
            ubuntu_double_lf,
        ));

        for crlf_diagnostic in [
            &b"ip6tables-save v1.8.7 (legacy): Cannot initialize: iptables who? (do you need to insmod?)\r\n"[..],
            &b"ip6tables-save v1.8.7 (legacy): Cannot initialize: iptables who? (do you need to insmod?)\r\n\r\n"[..],
        ] {
            assert!(is_proven_absent_legacy_backend(
                legacy_save,
                legacy_binary,
                Some(1),
                b"",
                crlf_diagnostic,
            ));
        }

        let unsupported_protocol =
            b"ip6tables-save v1.8.7 (legacy): Cannot initialize: Protocol not supported\n";
        assert!(is_proven_absent_legacy_backend(
            legacy_save,
            legacy_binary,
            Some(1),
            b"",
            unsupported_protocol,
        ));

        let ipv4_save = std::path::Path::new("/usr/sbin/iptables-save");
        let old_legacy_binary = std::path::Path::new("/usr/sbin/xtables-multi");
        let ipv4_diagnostic =
            b"iptables-save v1.4.21: Cannot initialize: iptables who? (do you need to insmod?)\n";
        assert!(is_proven_absent_legacy_backend(
            ipv4_save,
            old_legacy_binary,
            Some(1),
            b"",
            ipv4_diagnostic,
        ));
    }

    #[test]
    fn xtables_world_version_recognizes_legacy_and_nft_aliases() -> Result<()> {
        assert_eq!(
            parse_xtables_world_version(
                std::path::Path::new("/usr/sbin/iptables-save"),
                std::path::Path::new("/usr/bin/alts"),
                b"iptables-save v1.8.13 (legacy)\n",
            )?,
            XtablesWorld::Legacy
        );
        assert_eq!(
            parse_xtables_world_version(
                std::path::Path::new("/usr/sbin/iptables-nft-save"),
                std::path::Path::new("/usr/sbin/xtables-nft-multi"),
                b"iptables-nft-save v1.8.13 (nf_tables)\n",
            )?,
            XtablesWorld::Nft
        );
        assert_eq!(
            parse_xtables_world_version(
                std::path::Path::new("/usr/sbin/ip6tables-save"),
                std::path::Path::new("/usr/sbin/xtables-nft-multi"),
                b"ip6tables-save v1.8.9 (nf_tables)\n",
            )?,
            XtablesWorld::Nft
        );
        assert_eq!(
            parse_xtables_world_version(
                std::path::Path::new("/usr/sbin/iptables-save"),
                std::path::Path::new("/usr/sbin/xtables-multi"),
                b"iptables-save v1.4.21\n",
            )?,
            XtablesWorld::Legacy
        );
        assert_eq!(
            parse_xtables_world_version(
                std::path::Path::new("/usr/sbin/iptables-save"),
                std::path::Path::new("/usr/sbin/xtables-compat-multi"),
                b"iptables-save v1.6.2\n",
            )?,
            XtablesWorld::Nft
        );
        Ok(())
    }

    #[test]
    fn xtables_world_version_rejects_unknown_or_ambiguous_output() {
        let save = std::path::Path::new("/usr/sbin/iptables-save");
        let unknown_dispatcher = std::path::Path::new("/usr/bin/alts");
        for output in [
            b"iptables-save v1.8.13\n".as_slice(),
            b"iptables-save v1.8.13 (unknown)\n".as_slice(),
            b"iptables-save v1.8.13 (legacy)\nwarning\n".as_slice(),
            b"ip6tables-save v1.8.13 (legacy)\n".as_slice(),
            b"iptables-save v1.8.x (legacy)\n".as_slice(),
        ] {
            assert!(parse_xtables_world_version(save, unknown_dispatcher, output).is_err());
        }
        assert!(
            parse_xtables_world_version(
                save,
                std::path::Path::new("/usr/sbin/xtables-multi"),
                b"iptables-save v1.8.0\n"
            )
            .is_err()
        );
        assert!(
            parse_xtables_world_version(
                save,
                std::path::Path::new("/usr/sbin/xtables-nft-multi"),
                b"iptables-save v1.8.13 (legacy)\n"
            )
            .is_err()
        );
    }

    #[test]
    fn xtables_world_deduplication_distinguishes_selected_and_alternate_backends() {
        let selected_path = std::path::Path::new("/usr/sbin/iptables-legacy-save");
        let selected = XtablesIdentity {
            resolved: selected_path.to_path_buf(),
            world: XtablesWorld::Legacy,
        };
        let mut inspected = HashSet::new();

        assert!(xtables_world_is_covered(
            XtablesWorld::Legacy,
            Some(&selected),
            &inspected
        ));
        assert!(!xtables_world_is_covered(
            XtablesWorld::Nft,
            Some(&selected),
            &inspected
        ));
        inspected.insert(XtablesWorld::Nft);
        assert!(xtables_world_is_covered(
            XtablesWorld::Nft,
            Some(&selected),
            &inspected
        ));
    }

    #[test]
    fn xtables_identity_stability_rejects_path_and_backend_switches() {
        let legacy = XtablesIdentity {
            resolved: std::path::PathBuf::from("/usr/sbin/xtables-legacy-multi"),
            world: XtablesWorld::Legacy,
        };
        assert!(ensure_xtables_identity_unchanged(&legacy, &legacy).is_ok());

        let changed_world = XtablesIdentity {
            resolved: legacy.resolved.clone(),
            world: XtablesWorld::Nft,
        };
        assert!(ensure_xtables_identity_unchanged(&legacy, &changed_world).is_err());

        let changed_path = XtablesIdentity {
            resolved: std::path::PathBuf::from("/usr/bin/alts"),
            world: XtablesWorld::Legacy,
        };
        assert!(ensure_xtables_identity_unchanged(&legacy, &changed_path).is_err());

        let changed_both = XtablesIdentity {
            resolved: std::path::PathBuf::from("/usr/sbin/xtables-nft-multi"),
            world: XtablesWorld::Nft,
        };
        assert!(ensure_xtables_identity_unchanged(&legacy, &changed_both).is_err());
    }

    #[test]
    fn legacy_backend_absence_classifier_rejects_ambiguous_failures() {
        struct AmbiguousCase<'a> {
            status: Option<i32>,
            stdout: &'a [u8],
            stderr: &'a [u8],
            resolved: &'a std::path::Path,
        }

        let legacy_save = std::path::Path::new("/usr/sbin/ip6tables-legacy-save");
        let legacy_binary = std::path::Path::new("/usr/sbin/xtables-legacy-multi");
        let nft_binary = std::path::Path::new("/usr/sbin/xtables-nft-multi");
        let diagnostic = b"ip6tables-save v1.8.9 (legacy): Cannot initialize: iptables who? (do you need to insmod?)\n";
        let unsupported_protocol =
            b"ip6tables-save v1.8.9 (legacy): Cannot initialize: Protocol not supported\n";
        let ambiguous = [
            AmbiguousCase { status: Some(0), stdout: b"", stderr: diagnostic, resolved: legacy_binary },
            AmbiguousCase { status: Some(2), stdout: b"", stderr: diagnostic, resolved: legacy_binary },
            AmbiguousCase { status: None, stdout: b"", stderr: diagnostic, resolved: legacy_binary },
            AmbiguousCase { status: Some(1), stdout: b"unexpected", stderr: diagnostic, resolved: legacy_binary },
            AmbiguousCase { status: Some(1), stdout: b"", stderr: b"", resolved: legacy_binary },
            AmbiguousCase {
                status: Some(1),
                stdout: b"",
                stderr: b"warning\nip6tables-save v1.8.9 (legacy): Cannot initialize: iptables who? (do you need to insmod?)\n",
                resolved: legacy_binary,
            },
            AmbiguousCase {
                status: Some(1),
                stdout: b"",
                stderr: b"modprobe: FATAL: Module ip6_tables not found in directory /lib/modules/6.17.0-1022-azure\nip6tables-save v1.8.13 (legacy): Cannot initialize: iptables who? (do you need to insmod?)\n\n",
                resolved: legacy_binary,
            },
            AmbiguousCase {
                status: Some(1),
                stdout: b"",
                stderr: b"ip6tables-save v1.8.13 (legacy): Cannot initialize: iptables who? (do you need to insmod?)\n\n\n",
                resolved: legacy_binary,
            },
            AmbiguousCase {
                status: Some(1),
                stdout: b"",
                stderr: b"ip6tables-save v1.8.9 (nf_tables): Cannot initialize: iptables who? (do you need to insmod?)\n",
                resolved: legacy_binary,
            },
            AmbiguousCase {
                status: Some(1),
                stdout: b"",
                stderr: b"ip6tables-save v1.8.9: Cannot initialize: iptables who? (do you need to insmod?)\n",
                resolved: legacy_binary,
            },
            AmbiguousCase {
                status: Some(1),
                stdout: b"",
                stderr: b"ip6tables-save v1.8.9 (legacy): Permission denied\n",
                resolved: legacy_binary,
            },
            AmbiguousCase {
                status: Some(1),
                stdout: b"",
                stderr: b"ip6tables-save v1.8.13 (legacy): Cannot initialize: Permission denied (you must be root)\n",
                resolved: legacy_binary,
            },
            AmbiguousCase { status: Some(1), stdout: b"", stderr: diagnostic, resolved: nft_binary },
            AmbiguousCase {
                status: Some(1),
                stdout: b"",
                stderr: unsupported_protocol,
                resolved: nft_binary,
            },
        ];
        for case in ambiguous {
            assert!(!is_proven_absent_legacy_backend(
                legacy_save,
                case.resolved,
                case.status,
                case.stdout,
                case.stderr,
            ));
        }
    }

    #[test]
    fn alternate_xtables_save_inspection_enumerates_only_loaded_tables() {
        assert_eq!(selected_xtables_save_args("filter"), ["-c", "-t", "filter"]);
        assert_eq!(selected_xtables_save_args("mangle"), ["-c", "-t", "mangle"]);
        assert_eq!(xtables_save_inspection_args(), ["-c"]);

        let ipv4_save = std::path::Path::new("/usr/sbin/iptables-nft-save");
        let ipv6_save = std::path::Path::new("/usr/sbin/ip6tables-nft-save");
        let ipv4_warning =
            b"# Warning: iptables-legacy tables present, use iptables-legacy-save to see them\n";
        let ipv6_warning = b"# Warning: ip6tables-legacy tables present, use ip6tables-legacy-save to see them\r\n";
        assert!(is_expected_covered_legacy_warning(
            ipv4_save,
            XtablesWorld::Nft,
            true,
            ipv4_warning,
        ));
        assert!(is_expected_covered_legacy_warning(
            ipv6_save,
            XtablesWorld::Nft,
            true,
            ipv6_warning,
        ));
        assert!(!is_expected_covered_legacy_warning(
            ipv4_save,
            XtablesWorld::Nft,
            false,
            ipv4_warning,
        ));
        assert!(!is_expected_covered_legacy_warning(
            ipv4_save,
            XtablesWorld::Legacy,
            true,
            ipv4_warning,
        ));
        assert!(!is_expected_covered_legacy_warning(
            ipv4_save,
            XtablesWorld::Nft,
            true,
            b"warning\n",
        ));
    }

    #[test]
    fn alternate_xtables_world_accepts_absent_and_clean_loaded_tables() -> Result<()> {
        assert!(!inspect_xtables_world(|| {
            Ok(XtablesWorldInspection::BackendAbsent)
        })?);
        assert!(!inspect_xtables_world(|| {
            Ok(XtablesWorldInspection::Captured(Vec::new()))
        })?);
        for captured in [
            &b"*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"[..],
            &b"*mangle\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"[..],
            &b"# Generated by iptables-save\n*raw\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n\
               *filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n\
               *mangle\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n# Completed\n"[..],
        ] {
            assert!(!inspect_xtables_world(|| {
                Ok(XtablesWorldInspection::Captured(captured.to_vec()))
            })?);
        }
        assert!(
            inspect_xtables_world(|| { Err(anyhow::anyhow!("injected permission failure")) })
                .is_err()
        );
        for captured in [
            &b"unexpected\n"[..],
            &b"COMMIT\n"[..],
            &b"*filter\n:INPUT ACCEPT [0:0]\n"[..],
            &b"*filter\n*mangle\nCOMMIT\n"[..],
            &b"*filter\nCOMMIT\n*filter\nCOMMIT\n"[..],
            &b"*FILTER\nCOMMIT\n"[..],
            &b"*filter name\nCOMMIT\n"[..],
        ] {
            assert!(parse_xtables_world_save(captured).is_err());
        }
        Ok(())
    }

    #[test]
    fn alternate_xtables_world_detects_artifacts_in_each_owned_table() -> Result<()> {
        for captured in [
            &b"*filter\n:INPUT ACCEPT [0:0]\n:OPENSHIELD_IN - [0:0]\nCOMMIT\n"[..],
            &b"*mangle\n:OUTPUT ACCEPT [0:0]\n:OPENSHIELD_MARK - [0:0]\nCOMMIT\n"[..],
            &b"*raw\n:OPENSHIELD_IN - [0:0]\nCOMMIT\n\
               *filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n\
               *mangle\n:OUTPUT ACCEPT [0:0]\n:OPENSHIELD_MARK - [0:0]\nCOMMIT\n"[..],
        ] {
            assert!(inspect_xtables_world(|| {
                Ok(XtablesWorldInspection::Captured(captured.to_vec()))
            })?);
        }
        Ok(())
    }

    #[test]
    fn executable_validation_accepts_trusted_symlinks_and_rejects_writable_ancestry() -> Result<()>
    {
        use std::os::unix::fs::PermissionsExt as _;

        super::validate_trusted_executable(std::path::Path::new("/bin/sh"), "test shell")?;
        super::validate_trusted_lookup_parent_chain(std::path::Path::new("/bin/sh"), "test shell")?;

        let temporary = tempfile::tempdir()?;
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o777))?;
        let pretend_executable = temporary.path().join("bin/tool");
        assert!(
            super::validate_trusted_lookup_parent_chain(&pretend_executable, "test executable")
                .is_err()
        );
        assert!(
            super::validate_trusted_parent_chain(&pretend_executable, "test executable").is_err()
        );
        Ok(())
    }

    #[test]
    fn xtables_comments_are_tokenized_and_matched_exactly() -> Result<()> {
        let mut counters = FirewallCounters::default();
        super::accumulate_comment_counter(
            &mut counters,
            r#"-A OPENSHIELD_OUT -m comment --comment "openshield:accepted_out" -j RETURN"#,
            2,
            20,
        )?;
        super::accumulate_comment_counter(
            &mut counters,
            r#"-A OPENSHIELD_OUT -m comment --comment "prefix-openshield:accepted_out" -j RETURN"#,
            100,
            1_000,
        )?;
        super::accumulate_comment_counter(
            &mut counters,
            r"-A OPENSHIELD_APP_TCP -m comment --comment 'openshield:accepted_out+learned_out' -j RETURN",
            3,
            30,
        )?;
        super::accumulate_comment_counter(
            &mut counters,
            r#"-A OPENSHIELD_OBSERVE -m comment --comment "openshield:learned_out" -j NFQUEUE --queue-num 1338 --queue-bypass"#,
            4,
            40,
        )?;
        assert_eq!(counters.accepted_out.packets, 5);
        assert_eq!(counters.accepted_out.bytes, 50);
        assert_eq!(counters.learned_out.packets, 7);
        assert_eq!(counters.learned_out.bytes, 70);

        assert!(
            super::accumulate_comment_counter(
                &mut counters,
                r"-A OPENSHIELD_OUT --comment one --comment openshield:accepted_out -j RETURN",
                1,
                1,
            )
            .is_err()
        );
        assert!(
            super::accumulate_comment_counter(
                &mut counters,
                r#"-A OPENSHIELD_OUT --comment "openshield:accepted_out -j RETURN"#,
                1,
                1,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn xtables_rule_normalization_handles_save_canonicalization() -> Result<()> {
        let compiled = "-A OPENSHIELD_OUT -p tcp --dport 443 -m connmark --mark 0x40000001/0x7fffffff -m comment --comment openshield:accepted_out -j RETURN";
        let captured = "-A OPENSHIELD_OUT -p tcp -m tcp --dport 443 -m connmark --mark 1073741825/2147483647 -m comment --comment \"openshield:accepted_out\" -j RETURN";
        assert_eq!(
            super::normalize_xtables_rule(compiled)?,
            super::normalize_xtables_rule(captured)?
        );
        let compiled_syn = "-A OPENSHIELD_OBSERVE -p tcp --syn -m conntrack --ctstate NEW --ctdir ORIGINAL -j NFQUEUE --queue-num 1338 --queue-bypass";
        let captured_syn = "-A OPENSHIELD_OBSERVE -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW --ctdir ORIGINAL -j NFQUEUE --queue-num 1338 --queue-bypass";
        assert_eq!(
            super::normalize_xtables_rule(compiled_syn)?,
            super::normalize_xtables_rule(captured_syn)?
        );
        Ok(())
    }

    #[test]
    fn compiled_policy_comparison_rejects_an_injected_owned_rule() -> Result<()> {
        let policy =
            openshield_core::IptablesCompiler::compile(&openshield_core::State::new().snapshot())?;
        let expected = super::compiled_owned_rules(policy.ipv4())?;
        let mut filter_saved = String::from(
            "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n",
        );
        for chain in openshield_core::owned_chains() {
            let _infallible = writeln!(filter_saved, ":{chain} - [0:0]");
        }
        filter_saved.push_str("[0:0] -A INPUT -j OPENSHIELD_IN\n");
        filter_saved.push_str("[0:0] -A OUTPUT -j OPENSHIELD_OUT\n");
        filter_saved.push_str("[0:0] -A FORWARD -j OPENSHIELD_FWD\n");
        let mut current_table = "";
        let mut mangle_rules = Vec::new();
        for line in policy.ipv4().lines() {
            match line {
                "*mangle" => current_table = "mangle",
                "*filter" => current_table = "filter",
                "COMMIT" => current_table = "",
                rule if rule.starts_with("-A ") && current_table == "mangle" => {
                    mangle_rules.push(rule);
                }
                rule if rule.starts_with("-A ") && current_table == "filter" => {
                    let _infallible = writeln!(filter_saved, "[0:0] {rule}");
                }
                _ => {}
            }
        }
        filter_saved.push_str("COMMIT\n");

        let mut mangle_saved = String::from(
            "*mangle\n:OUTPUT ACCEPT [0:0]\n:OPENSHIELD_MARK - [0:0]\n:OPENSHIELD_OBSERVE - [0:0]\n[0:0] -A OUTPUT -j OPENSHIELD_MARK\n[0:0] -A OUTPUT -j OPENSHIELD_OBSERVE\n",
        );
        for rule in mangle_rules {
            let _infallible = writeln!(mangle_saved, "[0:0] {rule}");
        }
        mangle_saved.push_str("COMMIT\n");

        let filter = parse_xtables_save(filter_saved.as_bytes())?;
        filter.verify_filter_topology()?;
        let mangle = parse_xtables_save(mangle_saved.as_bytes())?;
        mangle.verify_mangle_topology()?;
        let mut installed = mangle.owned_rules;
        installed.extend(filter.owned_rules);
        assert_eq!(installed, expected);

        let injected = filter_saved.replace(
            "[0:0] -A OPENSHIELD_OUT -m comment --comment openshield:owner:v1\n",
            "[0:0] -A OPENSHIELD_OUT -m comment --comment openshield:owner:v1\n[0:0] -A OPENSHIELD_OUT -j ACCEPT\n",
        );
        let filter = parse_xtables_save(injected.as_bytes())?;
        filter.verify_filter_topology()?;
        let mangle = parse_xtables_save(mangle_saved.as_bytes())?;
        let mut installed = mangle.owned_rules;
        installed.extend(filter.owned_rules);
        assert_ne!(installed, expected);
        Ok(())
    }

    #[test]
    fn xtables_parser_rejects_duplicate_or_unterminated_state() {
        let duplicate = br"*filter
:INPUT ACCEPT [0:0]
:INPUT ACCEPT [0:0]
COMMIT
";
        assert!(parse_xtables_save(duplicate).is_err());
        assert!(parse_xtables_save(b"*filter\n:INPUT ACCEPT [0:0]\n").is_err());
        assert!(parse_xtables_save(b"*filter\n[bad] -A INPUT -j DROP\nCOMMIT\n").is_err());
        assert!(parse_xtables_save(b"*filter\n-A INPUT -j DROP\nCOMMIT\n").is_err());
    }
}
