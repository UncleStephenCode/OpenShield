//! Bounded explanations of policy misses, never inputs to authorization.
//!
//! In particular, do not log argv, cgroup paths, rule names, or executable
//! paths here: those fields can contain credentials and private information.

use openshield_core::{ApplicationIdentity, ApplicationSelector};

use crate::application::{
    ApplicationDecisionPolicy, OutboundConnection, application_rule_network_and_uid_matches,
};

const MAX_DIAGNOSTIC_RULES: usize = 256;
const REDACTED: u8 = 1 << 5;
const EXECUTABLE_PATH: u8 = 1 << 4;
const EXECUTABLE_VERSION: u8 = 1 << 3;
const UID: u8 = 1 << 2;
const COMMAND_LINE: u8 = 1 << 1;
const CGROUP: u8 = 1;

/// Describe the closest sampled endpoint candidate using field names only.
/// The sample is explicitly bounded even during a sustained denied-packet
/// stream. A missing candidate in the sample never means the policy has none.
pub(crate) fn rule_mismatch_summary(
    policy: &ApplicationDecisionPolicy,
    connection: &OutboundConnection,
    identity: &ApplicationIdentity,
) -> String {
    let closest = policy
        .rules
        .iter()
        .take(MAX_DIAGNOSTIC_RULES)
        .filter(|rule| application_rule_network_and_uid_matches(rule, connection))
        .filter_map(|rule| rule.spec.application.as_ref())
        .map(|selector| mismatch_fields(selector, identity))
        .min();
    let explanation = closest.map_or_else(
        || "no endpoint candidate in diagnostic sample".to_owned(),
        describe_fields,
    );
    format!(
        "pid={}, socket_uid={}, protocol={}, {}; inspected_rules={}/{}",
        identity.pid,
        connection.socket_uid,
        connection.protocol,
        explanation,
        policy.rules.len().min(MAX_DIAGNOSTIC_RULES),
        policy.rules.len(),
    )
}

fn mismatch_fields(selector: &ApplicationSelector, identity: &ApplicationIdentity) -> u8 {
    let mut fields = 0;
    if selector.metadata_redacted {
        fields |= REDACTED;
    }
    if selector
        .executable
        .as_ref()
        .is_some_and(|path| path != &identity.executable)
    {
        fields |= EXECUTABLE_PATH;
    }
    if selector
        .executable_file
        .is_some_and(|file| file != identity.executable_file)
    {
        fields |= EXECUTABLE_VERSION;
    }
    if selector.uid.is_some_and(|uid| uid != identity.uid) {
        fields |= UID;
    }
    if selector
        .command_line
        .as_ref()
        .is_some_and(|line| !line.matches(&identity.command_line))
    {
        fields |= COMMAND_LINE;
    }
    if selector
        .cgroup
        .as_ref()
        .is_some_and(|group| !identity.cgroups.contains(group))
    {
        fields |= CGROUP;
    }
    fields
}

fn describe_fields(fields: u8) -> String {
    if fields == 0 {
        return "sampled selector matches; check policy eligibility".to_owned();
    }
    let names = [
        (REDACTED, "redacted_metadata"),
        (EXECUTABLE_PATH, "executable_path"),
        (EXECUTABLE_VERSION, "executable_version"),
        (UID, "uid"),
        (COMMAND_LINE, "command_line"),
        (CGROUP, "cgroup"),
    ]
    .into_iter()
    .filter_map(|(flag, name)| (fields & flag != 0).then_some(name))
    .collect::<Vec<_>>();
    format!("closest sampled selector differs in {}", names.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use openshield_core::{
        ApplicationPath, CgroupPath, CommandArgument, Direction, ExecutableFileId, InterfaceName,
        Mode, PortRange, Rule, RuleName, RuleOrigin, RuleSpec, Snapshot, TransportProtocol,
    };

    fn identity() -> Result<ApplicationIdentity> {
        Ok(ApplicationIdentity {
            pid: 42,
            process_start_time_ticks: 100,
            executable: ApplicationPath::new("/usr/bin/private-application")?,
            executable_file: ExecutableFileId {
                device: 1,
                inode: 123,
                size: 4096,
                ctime_seconds: 100,
                ctime_nanoseconds: 0,
            },
            command_line: vec![CommandArgument::new("private-token")?],
            uid: 1000,
            cgroups: vec![CgroupPath::new("/private-cgroup")?],
        })
    }

    #[test]
    fn unchanged_identity_has_no_mismatches() -> Result<()> {
        let identity = identity()?;
        assert_eq!(mismatch_fields(&identity.learned_selector()?, &identity), 0);
        Ok(())
    }

    #[test]
    fn diagnostic_names_changed_fields_without_disclosing_values() -> Result<()> {
        let original = identity()?;
        let selector = original.learned_selector()?;
        let mut changed = original.clone();
        changed.command_line = vec![CommandArgument::new("new-secret")?];
        changed.cgroups = vec![CgroupPath::new("/new-private-group")?];
        changed.executable_file.inode += 1;
        let fields = mismatch_fields(&selector, &changed);
        assert_eq!(fields, EXECUTABLE_VERSION | COMMAND_LINE | CGROUP);
        let explanation = describe_fields(fields);
        assert_eq!(
            explanation,
            "closest sampled selector differs in executable_version,command_line,cgroup"
        );
        for private in [
            "private-token",
            "new-secret",
            "/private-cgroup",
            "/new-private-group",
        ] {
            assert!(!explanation.contains(private));
        }
        // Diagnostics do not relax the actual selector.
        assert!(!selector.matches(&changed));
        Ok(())
    }

    #[test]
    fn path_and_uid_mismatches_remain_distinct_from_argument_changes() -> Result<()> {
        let identity = identity()?;
        let mut selector = identity.learned_selector()?;
        selector.executable = Some(ApplicationPath::new("/usr/bin/another-application")?);
        selector.uid = Some(1001);
        assert_eq!(mismatch_fields(&selector, &identity), EXECUTABLE_PATH | UID);
        assert!(!selector.matches(&identity));
        Ok(())
    }

    #[test]
    fn truncated_diagnostics_do_not_truncate_authorization() -> Result<()> {
        let identity = identity()?;
        let connection = OutboundConnection {
            source_address: "192.0.2.1".parse()?,
            source_port: Some(40000),
            destination_address: "192.0.2.2".parse()?,
            destination_port: Some(443),
            protocol: TransportProtocol::Tcp,
            output_interface: InterfaceName::new("eth0")?,
            socket_uid: identity.uid,
        };
        let mut spec = RuleSpec::new(
            RuleName::new("private-rule-name")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("192.0.2.2/32".parse()?),
            Some(PortRange::single(443)?),
            None,
            RuleOrigin::Manual,
            false,
        )?;
        spec.application = Some(identity.learned_selector()?);
        let mut rules = (0..MAX_DIAGNOSTIC_RULES)
            .map(|_| Rule::new(spec.clone()))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        spec.enabled = true;
        rules.push(Rule::new(spec)?);
        let policy = ApplicationDecisionPolicy::new(Snapshot {
            revision: 1,
            flow_generation: 1,
            mode: Mode::Enforcing,
            rules,
        });
        policy.validate()?;
        let explanation = rule_mismatch_summary(&policy, &connection, &identity);
        assert!(explanation.contains("no endpoint candidate in diagnostic sample"));
        assert!(explanation.contains("inspected_rules=256/257"));
        assert!(!explanation.contains("private-rule-name"));
        assert!(policy.matching_rule(&connection, &identity).is_some());
        Ok(())
    }
}
