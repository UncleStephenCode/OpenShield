#!/usr/bin/env bash
set -euo pipefail

umask 077
export LC_ALL=C.UTF-8
export PYTHONDONTWRITEBYTECODE=1

readonly MAX_TIMEOUT_SECONDS=1800
readonly MAX_JSON_BYTES=$((20 * 1024 * 1024))
readonly MAX_CSV_BYTES=$((16 * 1024 * 1024))
readonly MAX_MARKDOWN_BYTES=$((512 * 1024))
readonly MAX_LOG_BYTES=$((16 * 1024 * 1024))
readonly RUN_LABEL_KEY='org.openshield.perf.run'
output_directory_owned=false
run_cleanup_started=false
run_token=''

cleanup_current_run() {
    local exact_label
    local identifier
    local -a identifiers=()

    [[ "$run_cleanup_started" == false ]] || return 0
    run_cleanup_started=true
    [[ "$run_token" =~ ^[0-9a-f]{32}$ ]] || return 0
    command -v docker >/dev/null 2>&1 || return 0
    command -v timeout >/dev/null 2>&1 || return 0

    # The filter is only a first pass. Re-inspect every immutable Docker ID
    # and require the exact cryptographic token before deleting anything.
    mapfile -t identifiers < <(
        timeout --signal=TERM --kill-after=2s 10s \
            docker ps --all --quiet \
                --filter "label=${RUN_LABEL_KEY}=${run_token}" 2>/dev/null
    )
    for identifier in "${identifiers[@]}"; do
        [[ "$identifier" =~ ^[0-9a-f]{12,64}$ ]] || continue
        exact_label=$(
            timeout --signal=TERM --kill-after=2s 10s \
                docker inspect --type container \
                    --format '{{ index .Config.Labels "org.openshield.perf.run" }}' \
                    "$identifier" 2>/dev/null
        ) || continue
        [[ "$exact_label" == "$run_token" ]] || continue
        timeout --signal=TERM --kill-after=2s 20s \
            docker rm --force "$identifier" >/dev/null 2>&1 || true
    done

    identifiers=()
    mapfile -t identifiers < <(
        timeout --signal=TERM --kill-after=2s 10s \
            docker network ls --quiet \
                --filter "label=${RUN_LABEL_KEY}=${run_token}" 2>/dev/null
    )
    for identifier in "${identifiers[@]}"; do
        [[ "$identifier" =~ ^[0-9a-f]{12,64}$ ]] || continue
        exact_label=$(
            timeout --signal=TERM --kill-after=2s 10s \
                docker network inspect \
                    --format '{{ index .Labels "org.openshield.perf.run" }}' \
                    "$identifier" 2>/dev/null
        ) || continue
        [[ "$exact_label" == "$run_token" ]] || continue
        timeout --signal=TERM --kill-after=2s 20s \
            docker network rm "$identifier" >/dev/null 2>&1 || true
    done
}

on_exit() {
    local status=$?
    trap - EXIT TERM INT
    set +e
    cleanup_current_run
    exit "$status"
}

trap on_exit EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

preserve_failure_diagnostics() {
    local message=$1
    local base=${output_directory:-}
    local diagnostics_directory
    local entry
    local maximum_size
    local name
    local path
    local size
    [[ "$output_directory_owned" == true \
        && -n "$base" && -d "$base" && ! -L "$base" ]] || return 0
    diagnostics_directory="$base/failure-diagnostics"
    [[ ! -e "$diagnostics_directory" && ! -L "$diagnostics_directory" ]] || return 0
    install -d -m 0700 -- "$diagnostics_directory" || return 0
    printf '%s\n' "${message:0:4096}" \
        > "$diagnostics_directory/wrapper-error.txt"
    for entry in \
        "run.log:$MAX_LOG_BYTES" \
        "report.json:$MAX_JSON_BYTES" \
        "report.csv:$MAX_CSV_BYTES" \
        "overload.csv:$MAX_CSV_BYTES" \
        "report.md:$MAX_MARKDOWN_BYTES"; do
        name=${entry%%:*}
        maximum_size=${entry#*:}
        path="$base/$name"
        [[ -f "$path" && ! -L "$path" ]] || continue
        size=$(stat -c '%s' -- "$path" 2>/dev/null) || continue
        [[ "$size" =~ ^[0-9]+$ ]] || continue
        (( size > 0 && size <= maximum_size )) || continue
        install -m 0600 -- "$path" "$diagnostics_directory/$name" || return 0
    done
}

fail() {
    local message=$*
    printf 'performance CI smoke: %s\n' "$message" >&2
    preserve_failure_diagnostics "$message"
    exit 1
}

usage() {
    printf 'usage: %s ABSOLUTE_NEW_OUTPUT_DIRECTORY\n' "$0" >&2
}

[[ "$#" -eq 1 ]] || {
    usage
    exit 2
}

output_directory=$1
[[ "$output_directory" == /* ]] || fail 'output directory must be absolute'
[[ ! -e "$output_directory" && ! -L "$output_directory" ]] \
    || fail 'output directory must not already exist'

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repository_root=$(CDPATH='' cd -- "$script_directory/../.." && pwd -P)
runner="$repository_root/tests/perf/run.py"
config="$repository_root/tests/perf/config/ci-smoke.json"
release_validator="$script_directory/validate_report.py"
output_filter="$script_directory/bounded_output.py"

for required_command in awk docker grep install jq python3 sha256sum stat tee timeout; do
    command -v "$required_command" >/dev/null 2>&1 \
        || fail "required command is unavailable: $required_command"
done

for source_file in \
    "$runner" \
    "$script_directory/environment.py" \
    "$release_validator" \
    "$output_filter" \
    "$config"; do
    [[ -f "$source_file" && ! -L "$source_file" && -r "$source_file" ]] \
        || fail "required input is not a readable regular non-symlink file: $source_file"
done
jq -e 'type == "object"' "$config" >/dev/null \
    || fail 'ci-smoke configuration is not a JSON object'
jq -e '
    .criteria.maximum_throughput_reduction_vs_baseline_percent == 10
    and .criteria.maximum_dut_pps_reduction_vs_baseline_percent == 10
    and .criteria.maximum_latency_increase_vs_baseline_percent == 10
    and .criteria.maximum_cgroup_cpu_increase_vs_baseline_percent == 10
    and .criteria.cpu_latency_relative_regressions_are_advisory == true
    and .criteria.maximum_comparison_gap_seconds == 15
    and .criteria.require_burst_capacity == true
    and .capacity_certification == false
' "$config" >/dev/null \
    || fail 'ci-smoke must retain 10-percent observations, advisory CPU/latency, and required burst capacity'

daemon=${OPENSHIELD_DAEMON:-}
[[ "$daemon" == /* ]] || fail 'OPENSHIELD_DAEMON must be an absolute path'
[[ -f "$daemon" && ! -L "$daemon" && -x "$daemon" ]] \
    || fail 'OPENSHIELD_DAEMON must be an executable regular non-symlink file'

install -d -m 0700 -- "$output_directory"
output_directory_owned=true
run_log="$output_directory/run.log"
report_json="$output_directory/report.json"
report_csv="$output_directory/report.csv"
overload_csv="$output_directory/overload.csv"
report_markdown="$output_directory/report.md"

docker_host=$(timeout --signal=TERM --kill-after=5s 15s \
    docker context inspect --format '{{(index .Endpoints "docker").Host}}' 2>/dev/null) \
    || fail 'cannot inspect the active Docker context'
if [[ -n "${DOCKER_HOST:-}" && "$DOCKER_HOST" != unix:///* ]]; then
    fail "refusing DOCKER_HOST override: $DOCKER_HOST"
fi
case "$docker_host" in
    unix:///*) ;;
    *) fail "refusing non-local Docker endpoint: $docker_host" ;;
esac
docker_socket=${docker_host#unix://}
[[ "$docker_socket" == /* && -S "$docker_socket" ]] \
    || fail "Docker endpoint is not a local Unix socket: $docker_host"
timeout --signal=TERM --kill-after=5s 30s docker info >/dev/null 2>&1 \
    || fail 'the local Docker engine is unavailable'

run_token=$(python3 -I -B -S -c 'import secrets; print(secrets.token_hex(16))') \
    || fail 'cannot generate a private performance run token'
[[ "$run_token" =~ ^[0-9a-f]{32}$ ]] \
    || fail 'generated performance run token has an invalid format'
readonly run_token

timeout_seconds=${PERF_TIMEOUT_SECONDS:-$MAX_TIMEOUT_SECONDS}
[[ "$timeout_seconds" =~ ^[1-9][0-9]{1,3}$ ]] \
    || fail 'PERF_TIMEOUT_SECONDS must be a decimal integer without leading zeroes'
(( timeout_seconds >= 30 && timeout_seconds <= MAX_TIMEOUT_SECONDS )) \
    || fail "PERF_TIMEOUT_SECONDS must be between 30 and $MAX_TIMEOUT_SECONDS"

printf 'performance CI smoke: daemon sha256 %s\n' \
    "$(sha256sum -- "$daemon" | awk '{print $1}')"
printf 'performance CI smoke: hard timeout %s seconds\n' "$timeout_seconds"

set +e
{
    # Keep GNU timeout's separate process group.  It must terminate the runner
    # and every docker CLI child together; --foreground would only signal
    # run.py and a child retaining stdout could keep the pipeline alive.
    timeout --signal=TERM --kill-after=15s "${timeout_seconds}s" \
        python3 -I -B -S "$runner" \
            --config "$config" \
            --output-dir "$output_directory" \
            --run-token "$run_token"
    runner_status=$?
    if (( runner_status != 0 )); then
        printf 'performance CI smoke: runner status %s\n' "$runner_status"
        if [[ -f "$report_json" && ! -L "$report_json" ]]; then
            report_size=$(stat -c '%s' -- "$report_json" 2>/dev/null)
            if [[ "$report_size" =~ ^[0-9]+$ ]] \
                && (( report_size > 0 && report_size <= MAX_JSON_BYTES )); then
                printf 'performance CI smoke: bounded failure summary: '
                jq -c '
                    def short: if type == "string" then .[0:2048] else . end;
                    def reasons:
                        if type == "array"
                        then [.[0:16][] | short]
                        else []
                        end;
                    {
                        schema,
                        valid,
                        passed,
                        fatal_error: ((.fatal_error // null) | short),
                        backends: ([.backends[]? | {
                            name,
                            status,
                            reason: ((.reason // null) | short)
                        }] | .[0:8]),
                        environment_consistency: {
                            valid: (.environment_consistency.valid // null),
                            failure_reasons: (
                                (.environment_consistency.failure_reasons // [])
                                | reasons
                            )
                        },
                        baseline_pairing: {
                            valid: (.baseline_pairing.valid // null),
                            strategy: (.baseline_pairing.strategy // null),
                            failure_reasons: (
                                (.baseline_pairing.failure_reasons // [])
                                | reasons
                            ),
                            baseline_sample_count: (
                                .baseline_pairing.baseline_sample_count // null
                            ),
                            comparison_count: (
                                .baseline_pairing.comparison_count // null
                            ),
                            orders: (.baseline_pairing.orders // null),
                            maximum_gap_seconds: (
                                .baseline_pairing.maximum_gap_seconds // null
                            )
                        },
                        invalid_results: ([.results[]?
                            | select(.valid != true)
                            | {
                                backend,
                                policy,
                                mode,
                                profile,
                                phase,
                                baseline_sample_id,
                                comparison_order,
                                execution_sequence,
                                topology_role,
                                valid,
                                passed,
                                unreliable_reasons: (
                                    (.unreliable_reasons // []) | reasons
                                ),
                                failure_reasons: (
                                    (.failure_reasons // []) | reasons
                                ),
                                safety_failure_reasons: (
                                    (.safety_failure_reasons // []) | reasons
                                )
                            }
                        ] | .[0:20]),
                        failed_overload: ([.overload_results[]?
                            | select(.valid != true or .passed != true)
                            | {
                                backend,
                                transport,
                                valid,
                                passed,
                                saturation: {
                                    # Preserve explicit false: jq `//` treats
                                    # false like a missing/null value.
                                    proven: .saturation.proven,
                                    minimum_nfqueue_drops: (
                                        .saturation.minimum_nfqueue_drops // null
                                    ),
                                    stall_drop_delta: (
                                        .saturation.stall_drop_delta // null
                                    ),
                                    nfqueue_depth_peak: (
                                        .saturation.nfqueue_depth_peak // null
                                    )
                                },
                                resource_validity,
                                validity_failure_reasons: (
                                    (.validity_failure_reasons // []) | reasons
                                ),
                                safety_failure_reasons: (
                                    (.safety_failure_reasons // []) | reasons
                                ),
                                recovery_failure_reasons: (
                                    (.recovery_failure_reasons // []) | reasons
                                )
                            }
                        ] | .[0:8]),
                        relative_failure_counts: (
                            [.results[]?
                                | .relative_performance_failure_reasons[]?]
                            | sort
                            | group_by(.)
                            | map({reason: .[0], count: length})
                        ),
                        relative_observation_counts: (
                            [.results[]?
                                | .relative_performance_observation_reasons[]?]
                            | sort
                            | group_by(.)
                            | map({reason: .[0], count: length})
                        ),
                        failed_results: ([.results[]?
                            | select(.valid == true and .passed != true)
                            | {
                                backend,
                                policy,
                                mode,
                                profile,
                                phase,
                                baseline_sample_id,
                                comparison_order,
                                execution_sequence,
                                topology_role,
                                failure_reasons: (
                                    (.failure_reasons // []) | reasons
                                ),
                                safety_failure_reasons: (
                                    (.safety_failure_reasons // []) | reasons
                                ),
                                relative_performance_failure_reasons: (
                                    (.relative_performance_failure_reasons // [])
                                    | reasons
                                ),
                                relative_performance_observation_reasons: (
                                    (.relative_performance_observation_reasons // [])
                                    | reasons
                                )
                            }
                        ] | .[0:12])
                    }
                ' "$report_json" || printf '%s\n' 'report.json is malformed'
            else
                printf 'performance CI smoke: report.json is empty or exceeds its size bound\n'
            fi
        else
            printf 'performance CI smoke: no safe report.json was produced\n'
        fi
    fi
    exit "$runner_status"
} 2>&1 \
    | python3 -I -B -S "$output_filter" --limit-bytes "$MAX_LOG_BYTES" \
    | tee "$run_log"
pipeline_status=("${PIPESTATUS[@]}")
set -e

[[ "${pipeline_status[1]}" -eq 0 && "${pipeline_status[2]}" -eq 0 ]] \
    || fail 'could not capture the performance runner output'
if [[ "${pipeline_status[0]}" -ne 0 ]]; then
    if [[ "${pipeline_status[0]}" -eq 124 ]]; then
        fail "performance runner exceeded the ${timeout_seconds}-second limit"
    fi
    fail "performance runner exited with status ${pipeline_status[0]}"
fi

validate_output_file() {
    local path=$1
    local maximum_size=$2
    local size
    [[ -f "$path" && ! -L "$path" ]] \
        || fail "missing regular non-symlink report: $path"
    size=$(stat -c '%s' -- "$path")
    [[ "$size" =~ ^[0-9]+$ ]] || fail "cannot determine report size: $path"
    (( size > 0 && size <= maximum_size )) \
        || fail "report has an invalid size ($size bytes): $path"
}

validate_output_file "$report_json" "$MAX_JSON_BYTES"
validate_output_file "$report_csv" "$MAX_CSV_BYTES"
validate_output_file "$overload_csv" "$MAX_CSV_BYTES"
validate_output_file "$report_markdown" "$MAX_MARKDOWN_BYTES"

allow_unsupported_iptables=$(jq -r '
    if has("allow_unsupported_iptables")
    then .allow_unsupported_iptables
    else false
    end
' "$config")
case "$allow_unsupported_iptables" in
    true|false) ;;
    *) fail 'allow_unsupported_iptables must be a JSON boolean' ;;
esac

jq -e --argjson allow_unsupported_iptables "$allow_unsupported_iptables" '
    def nonnegative_integer:
        type == "number" and . >= 0 and floor == .;
    def zero_network_errors:
        ([
            .network.rx_dropped,
            .network.tx_dropped,
            .network.rx_errors,
            .network.tx_errors
        ] | all(.[]; nonnegative_integer and . == 0));
    def zero_udp_errors:
        ([
            .udp_errors.in_errors,
            .udp_errors.rcvbuf_errors,
            .udp_errors.sndbuf_errors
        ] | all(.[]; nonnegative_integer and . == 0));
    def zero_tcp_listen_errors:
        ([
            .tcp_listen.listen_drops,
            .tcp_listen.listen_overflows
        ] | all(.[]; nonnegative_integer and . == 0));
    def collector_excluded_cgroup_cpu($elapsed):
        type == "object"
        and ($elapsed | type == "number" and . > 0)
        and .accounting == "container_cgroup_minus_metric_collector"
        and (.raw_cpu_seconds | type == "number" and . >= 0)
        and (.collector_cpu_seconds_excluded | type == "number" and . >= 0)
        and (.cpu_seconds | type == "number" and . >= 0)
        and (.cpu_percent_one_core | type == "number" and . >= 0)
        and .collector_cpu_seconds_excluded <= .raw_cpu_seconds + 0.000001
        and ((.cpu_seconds
              - ([0, (.raw_cpu_seconds - .collector_cpu_seconds_excluded)] | max))
             | abs < 0.000001)
        and ((.cpu_percent_one_core - (.cpu_seconds * 100 / $elapsed))
             | abs < 0.000001);
    def workload_normalized_network_rates($collector_elapsed; $workload_wall):
        type == "object"
        and ($collector_elapsed | type == "number" and . > 0)
        and ($workload_wall | type == "number" and . > 0)
        and (.collector_elapsed_seconds | type == "number" and . > 0)
        and (.rate_denominator_seconds | type == "number" and . > 0)
        and ((.collector_elapsed_seconds - $collector_elapsed)
             | abs < 0.000001)
        and ((.rate_denominator_seconds - $workload_wall)
             | abs < 0.000001)
        and ([.rx_packets, .tx_packets, .rx_bytes, .tx_bytes]
             | all(.[]; nonnegative_integer))
        and ([.rx_pps, .tx_pps, .rx_mbps, .tx_mbps]
             | all(.[]; type == "number" and . >= 0))
        and ((.rx_pps - (.rx_packets / $workload_wall)) | abs < 0.000001)
        and ((.tx_pps - (.tx_packets / $workload_wall)) | abs < 0.000001)
        and ((.rx_mbps - (.rx_bytes * 8 / $workload_wall / 1000000))
             | abs < 0.000001)
        and ((.tx_mbps - (.tx_bytes * 8 / $workload_wall / 1000000))
             | abs < 0.000001);
    def ordered_positive_timestamps:
        . as $values
        | (all(.[]; nonnegative_integer and . > 0))
        and all(range(0; length - 1);
            . as $index | $values[$index] <= $values[$index + 1]);
    def u32_counter_delta($before; $after):
        if (($before | nonnegative_integer and . < 4294967296)
            and ($after | nonnegative_integer and . < 4294967296))
        then (if $after >= $before
              then $after - $before
              else 4294967296 - $before + $after
              end)
        else null
        end;
    def metric_start:
        type == "object"
        and keys == ["boundary_monotonic_ns", "event", "schema"]
        and .schema == "openshield.perf.metrics.control.v2"
        and .event == "start"
        and (.boundary_monotonic_ns | nonnegative_integer and . > 0);
    def pinned_process($uid):
        (.pid | nonnegative_integer and . > 0)
        and (.starttime | nonnegative_integer and . > 0)
        and (.uid | nonnegative_integer and . == $uid)
        and (.executable | type == "string" and startswith("/") and length <= 4096);
    def same_process($left; $right):
        $left.pid == $right.pid
        and $left.starttime == $right.starttime
        and $left.executable == $right.executable
        and $left.uid == $right.uid;
    . as $report
    | type == "object"
    and .schema == "openshield.perf.report.v2"
    and .valid == true
    and .passed == true
    and .configuration.schema == "openshield.perf.config.v2"
    and .criteria == .configuration.criteria
    and .criteria.maximum_throughput_reduction_vs_baseline_percent == 10
    and .criteria.maximum_dut_pps_reduction_vs_baseline_percent == 10
    and .criteria.maximum_latency_increase_vs_baseline_percent == 10
    and .criteria.maximum_cgroup_cpu_increase_vs_baseline_percent == 10
    and .criteria.cpu_latency_relative_regressions_are_advisory == true
    and .criteria.require_burst_capacity == true
    and .configuration.criteria.require_burst_capacity == true
    and .configuration.capacity_certification == false
    and .relative_performance_methodology == {
        pairing: "independent_order_balanced_adjacent_ab_ba",
        gate_phase: "steady",
        burst_relative_role: "single_sample_threshold_gate",
        minimum_paired_samples: 3,
        confidence_level: 0.95,
        method: "arithmetic_mean_of_independent_paired_deltas",
        confirmation_method: "one_sided_paired_student_t_mean_lower_bound",
        thresholds_unchanged: true,
        cpu_latency_release_action: "observe"
    }
    and .harness.schema == "openshield.perf.harness-evidence.v1"
    and (.harness.manifest_sha256
        | type == "string" and test("^[0-9a-f]{64}$"))
    and (.harness.components | type == "array" and length == 12)
    and all(.harness.components[];
        (.path | type == "string" and length > 0)
        and (.size | type == "number" and . > 0 and . <= 4194304)
        and (.sha256 | type == "string" and test("^[0-9a-f]{64}$")))
    and (.environments | type == "array" and length == 2)
    and (([.environments[].backend] | sort) == ["iptables", "nftables"])
    and all(.environments[];
        .schema == "openshield.perf.environment.v1"
        and (.backend == "iptables" or .backend == "nftables")
        and .image_reference == $report.configuration.images.dut
        and (.image_id | type == "string" and test("^sha256:[0-9a-f]{64}$"))
        and (.os_release | type == "object" and .ID == "opensuse-tumbleweed")
        and (.uname | type == "string" and startswith("Linux "))
        and .machine == "x86_64"
        and (.repo_oss_repomd_sha256
            | type == "string" and test("^[0-9a-f]{64}$"))
        and (.rpm_manifest_sha256
            | type == "string" and test("^[0-9a-f]{64}$"))
        and (.rpm_nevra | type == "array" and length > 0)
        and .reproducibility.image_content_pinned == true
        and .reproducibility.repository_metadata_recorded == true
        and .reproducibility.cross_run_package_set_immutable == false)
    and (([.environments[].image_id] | unique | length) == 1)
    and (([.environments[].os_release] | unique | length) == 1)
    and (([.environments[].uname] | unique | length) == 1)
    and (([.environments[].repo_oss_repomd_sha256] | unique | length) == 1)
    and .environment_consistency.schema
        == "openshield.perf.environment-consistency.v1"
    and .environment_consistency.valid == true
    and (.environment_consistency.failure_reasons
        | type == "array" and length == 0)
    and .environment_consistency.package_delta.expected_nftables_delta_observed
        == true
    and .environment_consistency.package_delta.expected_nftables_only_package_names
        == ["libedit0", "libjansson4", "libnftables1", "nftables"]
    and .environment_consistency.package_delta.observed_nftables_only_package_names
        == ["libedit0", "libjansson4", "libnftables1", "nftables"]
    and (.environment_consistency.package_delta.nftables_only_nevra
        | type == "array" and length == 4)
    and (.environment_consistency.package_delta.iptables_only_nevra
        | type == "array" and length == 0)
    and .environment_consistency.package_delta.full_manifest_equality_required
        == false
    and (.baseline_pairing | type == "object")
    and .baseline_pairing.schema
        == "openshield.perf.baseline-pairing.v2"
        and .baseline_pairing.strategy == "independent_order_balanced_ab_ba"
    and .baseline_pairing.valid == true
    and (.baseline_pairing.failure_reasons
        | type == "array" and length == 0)
    and (.baseline_pairing.baseline_environments
        | type == "array" and length == 2)
    and (([.baseline_pairing.baseline_environments[].backend] | sort)
        == ["iptables", "nftables"])
    and all(.baseline_pairing.baseline_environments[];
        . as $baseline_environment
        | any($report.environments[]; . == $baseline_environment))
    and (.baseline_pairing.environment_pairs
        | type == "array" and length == 2)
    and (([.baseline_pairing.environment_pairs[].backend] | sort)
        == ["iptables", "nftables"])
    and all(.baseline_pairing.environment_pairs[];
        .valid == true
        and (.failure_reasons | type == "array" and length == 0)
        and (.baseline_client_id
            | type == "string" and test("^[0-9a-f]{64}$"))
        and (.protected_client_id
            | type == "string" and test("^[0-9a-f]{64}$"))
        and .baseline_client_id != .protected_client_id
        and .baseline_daemon_started == false)
    and (.baseline_pairing.baseline_sample_count
        | nonnegative_integer and . > 0)
    and (.baseline_pairing.comparison_count
        | nonnegative_integer and . > 0)
    and (.baseline_pairing.orders | type == "object")
    and (.baseline_pairing.orders | keys) == ["ab", "ba"]
    and (.baseline_pairing.orders.ab | nonnegative_integer and . > 0)
    and (.baseline_pairing.orders.ba | nonnegative_integer and . > 0)
    and (.baseline_pairing.maximum_gap_seconds
        | type == "number" and . >= 0)
    and .baseline_pairing.maximum_gap_seconds
        <= .criteria.maximum_comparison_gap_seconds
    and (.backends | type == "array")
    and (([.backends[].name] | sort) == ["iptables", "nftables"])
    and all(.backends[];
        type == "object"
        and (.name == "iptables" or .name == "nftables")
        and (.status == "passed" or .status == "failed" or .status == "unsupported")
        and (.reason == null or (.reason | type == "string")))
    and any(.backends[]; .name == "nftables" and .status == "passed")
    and any(.backends[];
        .name == "iptables"
        and (.status == "passed"
            or ($allow_unsupported_iptables and .status == "unsupported")))
    and (.results | type == "array" and length > 0)
    and (.overload_results | type == "array")
    and all(.overload_results[];
        . as $overload
        | .resource_validity.controlled_udp_send_backpressure as $backpressure
        | .pressure_workload.metrics as $pressure
        | .metric_starts as $metric_starts
        | ([
            ([$metric_starts.dut.boundary_monotonic_ns,
              $metric_starts.peer.boundary_monotonic_ns,
              $metric_starts.canary.boundary_monotonic_ns] | max),
            .saturation.snapshot_before_stop.observed_at_monotonic_ns,
            .saturation.stopped_at_monotonic_ns,
            .saturation.snapshot_at_barrier.observed_at_monotonic_ns
        ] + ([.identity_probe_during_stall.attempts[]? | [
            .liveness_before.started_at_monotonic_ns,
            .liveness_before.completed_at_monotonic_ns,
            .nfqueue_before.observed_at_monotonic_ns,
            .started_at_monotonic_ns,
            .completed_at_monotonic_ns,
            .nfqueue_after.observed_at_monotonic_ns,
            .liveness_after.started_at_monotonic_ns,
            .liveness_after.completed_at_monotonic_ns
        ]] | add // []) + [
            .saturation.pressure_reaped_at_monotonic_ns,
            .saturation.snapshot_before_continue.observed_at_monotonic_ns,
            .saturation.continued_at_monotonic_ns,
            .saturation.metric_boundary_monotonic_ns
        ]) as $overload_timeline
        | type == "object"
        and .schema == "openshield.perf.overload.v2"
        and (.backend == "iptables" or .backend == "nftables")
        and (.transport == "tcp" or .transport == "udp")
        and .mode == "enforcing"
        and .valid == true
        and .passed == true
        and .safety_pass == true
        and .resource_validity.valid == true
        and (.resource_validity.failure_reasons | type == "array" and length == 0)
        and ($backpressure | type == "object")
        and ($backpressure.applicable == ($overload.transport == "udp"))
        and ($backpressure.dut_sndbuf_errors
            == $overload.dut_metrics.udp_errors.sndbuf_errors)
        and ($backpressure.dut_sndbuf_errors | nonnegative_integer)
        and ($backpressure.stall_kernel_drop_delta
            == $overload.saturation.stall_drop_delta.kernel_dropped)
        and ($backpressure.stall_kernel_drop_delta | nonnegative_integer)
        and ($backpressure.scope | type == "string" and length > 0)
        and (if $overload.transport == "udp"
             then (
                 ([
                     $pressure.data_send_failures,
                     $pressure.data_send_timeouts,
                     $pressure.data_send_enobufs,
                     $pressure.data_send_would_block,
                     $pressure.data_send_other_os_errors,
                     $pressure.barrier_send_failures,
                     $pressure.barrier_send_timeouts,
                     $pressure.barrier_send_enobufs,
                     $pressure.barrier_send_would_block,
                     $pressure.barrier_send_other_os_errors
                 ] | all(.[]; nonnegative_integer))
                 and $backpressure.workload_send_counters == {
                     data_send_failures: $pressure.data_send_failures,
                     data_send_timeouts: $pressure.data_send_timeouts,
                     data_send_enobufs: $pressure.data_send_enobufs,
                     data_send_would_block: $pressure.data_send_would_block,
                     data_send_other_os_errors: $pressure.data_send_other_os_errors,
                     barrier_send_failures: $pressure.barrier_send_failures,
                     barrier_send_timeouts: $pressure.barrier_send_timeouts,
                     barrier_send_enobufs: $pressure.barrier_send_enobufs,
                     barrier_send_would_block: $pressure.barrier_send_would_block,
                     barrier_send_other_os_errors: $pressure.barrier_send_other_os_errors
                 }
                 and $pressure.data_send_failures == (
                     $pressure.data_send_timeouts
                     + $pressure.data_send_enobufs
                     + $pressure.data_send_would_block
                     + $pressure.data_send_other_os_errors)
                 and $pressure.barrier_send_failures == (
                     $pressure.barrier_send_timeouts
                     + $pressure.barrier_send_enobufs
                     + $pressure.barrier_send_would_block
                     + $pressure.barrier_send_other_os_errors)
                 and $pressure.data_send_other_os_errors == 0
                 and $pressure.barrier_send_other_os_errors == 0
                 and $backpressure.total_send_failures == (
                     $pressure.data_send_failures
                     + $pressure.barrier_send_failures)
                 and $backpressure.total_send_failures
                     == $backpressure.dut_sndbuf_errors
                 and $backpressure.total_send_failures
                     <= $backpressure.stall_kernel_drop_delta
                 and $backpressure.classification_exact == true
                 and $backpressure.only_backpressure_classes == true
                 and $backpressure.exact_kernel_workload_match == true
                 and $backpressure.within_direct_drop_bound == true
                 and ($backpressure.exception_eligible
                     == ($backpressure.dut_sndbuf_errors > 0))
                 and ($backpressure.exception_applied
                     == ($backpressure.dut_sndbuf_errors > 0))
                 and (if $backpressure.dut_sndbuf_errors > 0
                      then $backpressure.stall_kernel_drop_delta
                          >= $overload.saturation.minimum_nfqueue_drops
                      else true
                      end)
             )
             else (
                 $backpressure.dut_sndbuf_errors == 0
                 and
                 ($backpressure.workload_send_counters
                     | type == "object" and all(.[]; . == null))
                 and $backpressure.total_send_failures == null
                 and $backpressure.classification_exact == false
                 and $backpressure.only_backpressure_classes == false
                 and $backpressure.exact_kernel_workload_match == false
                 and $backpressure.within_direct_drop_bound == false
                 and $backpressure.exception_eligible == false
                 and $backpressure.exception_applied == false
             )
             end)
        and ($metric_starts | type == "object")
        and ($metric_starts | keys) == ["canary", "dut", "peer"]
        and ($metric_starts.dut | metric_start)
        and ($metric_starts.peer | metric_start)
        and ($metric_starts.canary | metric_start)
        and (.metric_collectors | type == "object")
        and (.metric_collectors | keys) == ["canary", "dut", "peer"]
        and (.metric_collectors.dut | pinned_process(0))
        and (.metric_collectors.peer | pinned_process(0))
        and (.metric_collectors.canary | pinned_process(0))
        and .dut_metrics.schema == "openshield.perf.metrics.v3"
        and .dut_metrics.nfqueue.queue_number == 1337
        and (.dut_metrics as $metrics
             | $metrics.cgroup
             | collector_excluded_cgroup_cpu($metrics.elapsed_seconds))
        and .dut_metrics.stop_reason == "split_boundary"
        and (.dut_metrics.elapsed_seconds | type == "number" and . > 0)
        and .dut_metrics.started_at_monotonic_ns
            == $metric_starts.dut.boundary_monotonic_ns
        and (.dut_metric_boundary | type == "object")
        and (.dut_metric_boundary | keys)
            == ["boundary_monotonic_ns", "event", "schema"]
        and .dut_metric_boundary.schema
            == "openshield.perf.metrics.control.v2"
        and .dut_metric_boundary.event == "split"
        and (.dut_metric_boundary.boundary_monotonic_ns
            | nonnegative_integer and . > 0)
        and .dut_metrics.finished_at_monotonic_ns
            == .dut_metric_boundary.boundary_monotonic_ns
        and .post_resume_dut_metrics.schema == "openshield.perf.metrics.v3"
        and .post_resume_dut_metrics.nfqueue.queue_number == 1337
        and (.post_resume_dut_metrics as $metrics
             | $metrics.cgroup
             | collector_excluded_cgroup_cpu($metrics.elapsed_seconds))
        and .post_resume_dut_metrics.stop_reason == "requested"
        and (.post_resume_dut_metrics.elapsed_seconds
            | type == "number" and . > 0)
        and .post_resume_dut_metrics.started_at_monotonic_ns
            == .dut_metric_boundary.boundary_monotonic_ns
        and .peer_metrics.schema == "openshield.perf.metrics.v3"
        and (.peer_metrics as $metrics
             | $metrics.cgroup
             | collector_excluded_cgroup_cpu($metrics.elapsed_seconds))
        and .peer_metrics.started_at_monotonic_ns
            == $metric_starts.peer.boundary_monotonic_ns
        and .canary_metrics.schema == "openshield.perf.metrics.v3"
        and (.canary_metrics as $metrics
             | $metrics.cgroup
             | collector_excluded_cgroup_cpu($metrics.elapsed_seconds))
        and .canary_metrics.started_at_monotonic_ns
            == $metric_starts.canary.boundary_monotonic_ns
        and .saturation.metric_boundary_monotonic_ns
            == .dut_metric_boundary.boundary_monotonic_ns
        and ($overload_timeline | ordered_positive_timestamps)
        and (.saturation.stopped_at_monotonic_ns
            | nonnegative_integer and . > 0)
        and (.saturation.pressure_reaped_at_monotonic_ns
            | nonnegative_integer and . > 0)
        and (.saturation.continued_at_monotonic_ns
            | nonnegative_integer and . > 0)
        and (.dut_metrics | zero_network_errors)
        and (.dut_metrics | zero_tcp_listen_errors)
        and ([
            .dut_metrics.udp_errors.in_errors,
            .dut_metrics.udp_errors.rcvbuf_errors
        ] | all(.[]; nonnegative_integer and . == 0))
        and all([
            .post_resume_dut_metrics,
            .peer_metrics,
            .canary_metrics
        ][]; zero_network_errors and zero_udp_errors and zero_tcp_listen_errors)
        and ([
            .post_resume_dut_metrics.nfqueue.kernel_dropped,
            .post_resume_dut_metrics.nfqueue.user_dropped,
            .post_resume_dut_metrics.nfqueue.depth_end,
            .post_resume_dut_metrics.tcp_retransmits
        ] | all(.[]; nonnegative_integer and . == 0))
        and .post_resume_dut_metrics.daemon.alive_end == true
        and .post_resume_dut_metrics.daemon.pid == .daemon_identity.pid
        and .pressure_start_gate.schema == "openshield.perf.workload.v1"
        and .pressure_start_gate.event == "ready"
        and .pressure_start_gate.role == "client"
        and .pressure_start_gate.transport == .transport
        and .pressure_start_gate.control_protocol
            == "stdin_start_finish_release_v2"
        and (.pressure_start_gate | pinned_process(65532))
        and (.pressure_start_gate.spawned | pinned_process(65532))
        and same_process(.pressure_start_gate; .pressure_start_gate.spawned)
        and .pressure_started.schema == "openshield.perf.workload.v1"
        and .pressure_started.event == "started"
        and .pressure_started.transport == .transport
        and .pressure_started.control_protocol
            == "stdin_start_finish_release_v2"
        and same_process(.pressure_start_gate; .pressure_started)
        and .pressure_finished.schema == "openshield.perf.workload.v1"
        and .pressure_finished.event == "finished"
        and .pressure_finished.transport == .transport
        and .pressure_finished.control_protocol
            == "stdin_start_finish_release_v2"
        and .pressure_finished.hold == "awaiting_release"
        and (.pressure_finished.summary_sha256
            | type == "string" and test("^[0-9a-f]{64}$"))
        and .pressure_finished.exit_code == .pressure_exit_code
        and same_process(.pressure_start_gate; .pressure_finished)
        and .pressure_released.schema == "openshield.perf.workload.v1"
        and .pressure_released.event == "released"
        and .pressure_released.transport == .transport
        and .pressure_released.control_protocol
            == "stdin_start_finish_release_v2"
        and same_process(.pressure_start_gate; .pressure_released)
        and .metric_starts.dut.boundary_monotonic_ns
            <= .pressure_started.boundary_monotonic_ns
        and .metric_starts.peer.boundary_monotonic_ns
            <= .pressure_started.boundary_monotonic_ns
        and .metric_starts.canary.boundary_monotonic_ns
            <= .pressure_started.boundary_monotonic_ns
        and .pressure_started.boundary_monotonic_ns
            <= .pressure_finished.boundary_monotonic_ns
        and .pressure_finished.boundary_monotonic_ns
            <= .pressure_released.boundary_monotonic_ns
        and .pressure_released.boundary_monotonic_ns
            <= .saturation.pressure_reaped_at_monotonic_ns
        and .pressure_workload.schema == "openshield.perf.workload.v1"
        and .pressure_workload.event == "summary"
        and .pressure_workload.role == "client"
        and .pressure_workload.transport == .transport
        and (.pressure_workload.metrics | type == "object")
        and (.pressure_exit_code
            | nonnegative_integer and . <= 255)
        and .network_liveness_preflight.passed == true
        and .saturation.proven == true
        and .saturation.timestamps_ordered == true
        and (.saturation.minimum_nfqueue_drops | type == "number" and . >= 1)
        and (.config.minimum_nfqueue_drops == .saturation.minimum_nfqueue_drops)
        and .saturation.threshold_drop_delta.kernel_dropped
            == u32_counter_delta(
                .saturation.snapshot_before_stop.kernel_dropped;
                .saturation.snapshot_at_barrier.kernel_dropped)
        and .saturation.threshold_drop_delta.user_dropped
            == u32_counter_delta(
                .saturation.snapshot_before_stop.user_dropped;
                .saturation.snapshot_at_barrier.user_dropped)
        and .saturation.threshold_drop_delta.total == (
            .saturation.threshold_drop_delta.kernel_dropped
            + .saturation.threshold_drop_delta.user_dropped)
        and (.saturation.threshold_drop_delta.total | nonnegative_integer)
        and (.saturation.threshold_drop_delta.total
            >= .saturation.minimum_nfqueue_drops)
        and .saturation.stall_drop_delta.kernel_dropped
            == u32_counter_delta(
                .saturation.snapshot_before_stop.kernel_dropped;
                .saturation.snapshot_before_continue.kernel_dropped)
        and .saturation.stall_drop_delta.user_dropped
            == u32_counter_delta(
                .saturation.snapshot_before_stop.user_dropped;
                .saturation.snapshot_before_continue.user_dropped)
        and .saturation.stall_drop_delta.total == (
            .saturation.stall_drop_delta.kernel_dropped
            + .saturation.stall_drop_delta.user_dropped)
        and (.saturation.stall_drop_delta.total | type == "number")
        and (.saturation.stall_drop_delta.total >= .saturation.minimum_nfqueue_drops)
        and (.saturation.stall_drop_delta.total
            >= .saturation.threshold_drop_delta.total)
        and .identity_probe_during_stall.blocked_all == true
        and .identity_probe_during_stall.fail_open == false
        and .identity_probe_during_stall.liveness_passed == true
        and (.identity_probe_during_stall.attempts | type == "array")
        and (($overload.identity_probe_during_stall.attempts | length)
            == $overload.config.probe_attempts)
        and all(.identity_probe_during_stall.attempts[];
            .schema == "openshield.perf.workload.v1"
            and .event == "probe"
            and .role == "identity_probe"
            and .transport == $overload.transport
            and .probe_event_valid == true
            and .timeout_observed == true
            and .success == false
            and .exit_code == 2
            and .indeterminate == false
            and .blocked == true
            and .fail_open == false
            and .isolated_canary_server_alive == true
            and .liveness_before.passed == true
            and .liveness_before.server_alive == true
            and .liveness_after.passed == true
            and .liveness_after.server_alive == true)
        and (
            if .quarantine.reported == true
            then (
                .recovery_pass == null
                and .quarantine.occurred == true
                and .quarantine.kernel_block_all == true
                and .quarantine.black_box.valid == true
                and .quarantine.black_box.passed == true
                and .quarantine.black_box.structural_passed == true
                and .quarantine.black_box.timestamps_ordered == true
                and .quarantine.black_box.ipv4.passed == true
                and ((.quarantine.black_box.ipv4.probes | keys | sort)
                    == ["tcp", "udp"])
                and .quarantine.black_box.ipv4.probes.tcp.transport == "tcp"
                and .quarantine.black_box.ipv4.probes.udp.transport == "udp"
                and .quarantine.black_box.ipv6.available == false
                and .quarantine.black_box.ipv6.valid == false
                and .quarantine.black_box.ipv6.passed == false
                and .quarantine.black_box.status_before.mode == "block_all"
                and .quarantine.black_box.status_after.mode == "block_all"
                and .quarantine.black_box.kernel_before.inspected == true
                and .quarantine.black_box.kernel_before.block_all == true
                and .quarantine.black_box.kernel_after.inspected == true
                and .quarantine.black_box.kernel_after.block_all == true
                and all(.quarantine.black_box.ipv4.probes[];
                    .schema == "openshield.perf.workload.v1"
                    and .event == "probe"
                    and .role == "identity_probe"
                    and .probe_event_valid == true
                    and .timeout_observed == true
                    and .success == false
                    and .exit_code == 2
                    and .indeterminate == false
                    and .preflight_reachable == true
                    and .server_alive == true
                    and .peer_health_before.path == "canary-container-loopback"
                    and .peer_health_before.passed == true
                    and .peer_health_before.server_alive == true
                    and .peer_health_after.path == "canary-container-loopback"
                    and .peer_health_after.passed == true
                    and .peer_health_after.server_alive == true
                    and .blocked == true
                    and .fail_open == false)
                and .identity_probe_after_resume.skipped_due_to_reported_quarantine == true
            )
            else (
                .quarantine.reported == false
                and .recovery_pass == true
                and .network_liveness_after_resume.passed == true
                and .network_liveness_after_resume.before.server_alive == true
                and .network_liveness_after_resume.after.server_alive == true
                and .identity_probe_after_resume.schema
                    == "openshield.perf.workload.v1"
                and .identity_probe_after_resume.event == "probe"
                and .identity_probe_after_resume.role == "identity_probe"
                and .identity_probe_after_resume.transport == $overload.transport
                and .identity_probe_after_resume.probe_event_valid == true
                and .identity_probe_after_resume.timeout_observed == true
                and .identity_probe_after_resume.success == false
                and .identity_probe_after_resume.exit_code == 2
                and .identity_probe_after_resume.indeterminate == false
                and .identity_probe_after_resume.blocked == true
                and .identity_probe_after_resume.fail_open == false
            )
            end
        ))
    and all(.results[];
        .workload.metrics.wall_seconds as $workload_wall
        | type == "object"
        and (.backend == "iptables" or .backend == "nftables")
        and (.policy == "baseline"
            or .policy == "network_only"
            or .policy == "application_tcp"
            or .policy == "application_udp")
        and (.mode == null or .mode == "enforcing" or .mode == "learning")
        and (.profile | type == "string" and length > 0)
        and (.phase | type == "string" and length > 0)
        and (.phase_role == "warmup"
            or .phase_role == "ramp"
            or .phase_role == "steady"
            or .phase_role == "burst")
        and .workload_start_gate.schema == "openshield.perf.workload.v1"
        and .workload_start_gate.event == "ready"
        and .workload_start_gate.role == "client"
        and .workload_start_gate.transport == .transport
        and .workload_start_gate.control_protocol
            == "stdin_start_finish_release_v2"
        and (.workload_start_gate | pinned_process(65532))
        and (.workload_start_gate | keys) == [
            "control_protocol", "event", "executable", "pid", "role",
            "schema", "spawned", "starttime", "transport", "uid"
        ]
        and .workload_start_gate.spawned.schema
            == "openshield.perf.workload.v1"
        and .workload_start_gate.spawned.event == "spawned"
        and .workload_start_gate.spawned.role == "client"
        and .workload_start_gate.spawned.transport == .transport
        and .workload_start_gate.spawned.control_protocol
            == "stdin_start_finish_release_v2"
        and (.workload_start_gate.spawned | pinned_process(65532))
        and (.workload_start_gate.spawned | keys) == [
            "boundary_monotonic_ns", "control_protocol", "event", "executable",
            "pid", "role", "schema", "starttime", "transport", "uid"
        ]
        and same_process(.workload_start_gate; .workload_start_gate.spawned)
        and .workload_started.schema == "openshield.perf.workload.v1"
        and .workload_started.event == "started"
        and .workload_started.role == "client"
        and .workload_started.transport == .transport
        and .workload_started.control_protocol
            == "stdin_start_finish_release_v2"
        and (.workload_started | pinned_process(65532))
        and (.workload_started | keys) == [
            "boundary_monotonic_ns", "control_protocol", "event", "executable",
            "pid", "role", "schema", "starttime", "transport", "uid"
        ]
        and same_process(.workload_start_gate; .workload_started)
        and .workload_finished.schema == "openshield.perf.workload.v1"
        and .workload_finished.event == "finished"
        and .workload_finished.role == "client"
        and .workload_finished.transport == .transport
        and .workload_finished.control_protocol
            == "stdin_start_finish_release_v2"
        and .workload_finished.hold == "awaiting_release"
        and (.workload_finished.summary_sha256
            | type == "string" and test("^[0-9a-f]{64}$"))
        and (.workload_finished.exit_code | nonnegative_integer and . <= 255)
        and .workload_finished.exit_code == 0
        and (.workload_finished | pinned_process(65532))
        and (.workload_finished | keys) == [
            "boundary_monotonic_ns", "control_protocol", "event", "executable",
            "exit_code", "hold", "pid", "role", "schema", "starttime",
            "summary_sha256", "transport", "uid"
        ]
        and same_process(.workload_start_gate; .workload_finished)
        and .workload_released.schema == "openshield.perf.workload.v1"
        and .workload_released.event == "released"
        and .workload_released.role == "client"
        and .workload_released.transport == .transport
        and .workload_released.control_protocol
            == "stdin_start_finish_release_v2"
        and (.workload_released | pinned_process(65532))
        and (.workload_released | keys) == [
            "boundary_monotonic_ns", "control_protocol", "event", "executable",
            "pid", "role", "schema", "starttime", "transport", "uid"
        ]
        and same_process(.workload_start_gate; .workload_released)
        and (.metric_starts | type == "object")
        and (.metric_starts | keys) == ["dut", "peer"]
        and (.metric_starts.dut | metric_start)
        and (.metric_starts.peer | metric_start)
        and (.metric_collectors | type == "object")
        and (.metric_collectors | keys) == ["dut", "peer"]
        and (.metric_collectors.dut | pinned_process(0))
        and (.metric_collectors.peer | pinned_process(0))
        and .dut_metrics.started_at_monotonic_ns
            == .metric_starts.dut.boundary_monotonic_ns
        and .peer_metrics.started_at_monotonic_ns
            == .metric_starts.peer.boundary_monotonic_ns
        and .metric_starts.dut.boundary_monotonic_ns
            <= .workload_started.boundary_monotonic_ns
        and .metric_starts.peer.boundary_monotonic_ns
            <= .workload_started.boundary_monotonic_ns
        and .workload_started.boundary_monotonic_ns
            <= .workload_finished.boundary_monotonic_ns
        and .workload_finished.boundary_monotonic_ns
            <= .dut_metrics.finished_at_monotonic_ns
        and .workload_finished.boundary_monotonic_ns
            <= .peer_metrics.finished_at_monotonic_ns
        and .dut_metrics.finished_at_monotonic_ns
            <= .workload_released.boundary_monotonic_ns
        and .peer_metrics.finished_at_monotonic_ns
            <= .workload_released.boundary_monotonic_ns
        and (if .direction == "outbound"
             then .dut_metrics.workload_process.pid == .workload_start_gate.pid
                  and .dut_metrics.workload_process.alive_end == true
                  and (.dut_metrics.workload_process.cpu_seconds
                      | type == "number" and . >= 0)
                  and (.dut_metrics.workload_process.rss_bytes_peak
                      | type == "number" and . > 0)
             else .peer_metrics.workload_process.pid == .workload_start_gate.pid
                  and .peer_metrics.workload_process.alive_end == true
                  and (.peer_metrics.workload_process.cpu_seconds
                      | type == "number" and . >= 0)
                  and (.peer_metrics.workload_process.rss_bytes_peak
                      | type == "number" and . > 0)
             end)
        and (.baseline_sample_id
            | type == "string" and test("^b[0-9]{5}$"))
        and (.comparison_pair_id
            | type == "string" and test("^p[0-9]{5}$"))
        and (.comparison_repetition
            | nonnegative_integer and . >= 1 and . <= 20)
        and (.execution_sequence | nonnegative_integer)
        and (.block_started_monotonic_ns
            | nonnegative_integer and . > 0)
        and (.block_finished_monotonic_ns
            | nonnegative_integer and . > 0)
        and .block_finished_monotonic_ns > .block_started_monotonic_ns
        and (if .policy == "baseline"
             then .topology_role == "baseline"
                 and .comparison_order == null
                 and .comparison_gap_seconds == null
             else .topology_role == "protected"
                 and (.comparison_order == "ab" or .comparison_order == "ba")
                 and (.comparison_gap_seconds
                     | type == "number" and . >= 0
                       and . <= $report.criteria.maximum_comparison_gap_seconds)
             end)
        and .valid == true
        and .passed == true
        and .safety_pass == true
        and .dut_metrics.schema == "openshield.perf.metrics.v3"
        and .dut_metrics.nfqueue.queue_number
            == (if .mode == "learning" then 1338 else 1337 end)
        and (.dut_metrics as $metrics
             | $metrics.cgroup
             | collector_excluded_cgroup_cpu($metrics.elapsed_seconds))
        and (.dut_metrics as $metrics
             | $metrics.network
             | workload_normalized_network_rates(
                 $metrics.elapsed_seconds; $workload_wall))
        and .peer_metrics.schema == "openshield.perf.metrics.v3"
        and (.peer_metrics as $metrics
             | $metrics.cgroup
             | collector_excluded_cgroup_cpu($metrics.elapsed_seconds))
        and (.peer_metrics as $metrics
             | $metrics.network
             | workload_normalized_network_rates(
                 $metrics.elapsed_seconds; $workload_wall))
        and (if (.phase_role == "steady" or .phase_role == "burst")
             then .workload.config.target_application_ops_per_second as $target
                  | .derived.actual_application_ops_per_second as $actual
                  | ($target | type == "number" and . > 0)
                  and ($actual | type == "number" and . >= 0)
                  and .capacity_pass == true
                  and ((.derived.expected_application_ops_per_second - $target)
                       | abs < 0.000001)
                  and ((.derived.target_attainment_ratio - ($actual / $target))
                       | abs < 0.000001)
                  and .derived.target_attainment_ratio
                      >= $report.criteria.minimum_target_ratio
                  and (.derived.latency_p99_ms
                       | type == "number"
                         and . <= $report.criteria.maximum_latency_p99_ms)
                  and (if .policy == "baseline"
                       then true
                       else (.dut_metrics.daemon.cpu_percent_one_core
                             | type == "number" and . >= 0
                               and . <= $report.criteria.maximum_daemon_cpu_percent_one_core)
                            and (.dut_metrics.daemon.rss_bytes_peak
                                 | type == "number" and . >= 0
                                   and . <= $report.criteria.maximum_daemon_rss_bytes)
                       end)
             else (.capacity_pass | type == "boolean")
             end)
        and (.workload.metrics.errors | type == "number" and . == 0)
        and ([
            .dut_metrics.network.rx_pps,
            .dut_metrics.network.tx_pps,
            .dut_metrics.network.rx_mbps,
            .dut_metrics.network.tx_mbps,
            .peer_metrics.network.rx_pps,
            .peer_metrics.network.tx_pps,
            .peer_metrics.network.rx_mbps,
            .peer_metrics.network.tx_mbps,
            .dut_metrics.softirq.net_rx,
            .dut_metrics.softirq.net_tx,
            .peer_metrics.softirq.net_rx,
            .peer_metrics.softirq.net_tx,
            .dut_metrics.conntrack_count_start,
            .dut_metrics.conntrack_count_peak,
            .peer_metrics.conntrack_count_start,
            .peer_metrics.conntrack_count_peak
        ] | all(.[]; type == "number" and . >= 0))
        and (.dut_metrics.conntrack_count_peak
             >= .dut_metrics.conntrack_count_start)
        and (.peer_metrics.conntrack_count_peak
             >= .peer_metrics.conntrack_count_start)
        and ([
            .dut_metrics.network.rx_dropped,
            .dut_metrics.network.tx_dropped,
            .dut_metrics.network.rx_errors,
            .dut_metrics.network.tx_errors,
            .peer_metrics.network.rx_dropped,
            .peer_metrics.network.tx_dropped,
            .peer_metrics.network.rx_errors,
            .peer_metrics.network.tx_errors
        ] | all(.[]; type == "number" and . == 0))
        and (if .transport == "tcp"
             then ([.dut_metrics.tcp_retransmits, .peer_metrics.tcp_retransmits]
                   | all(.[]; type == "number" and . == 0))
             else ((.workload.metrics.reply_loss_ratio
                    | type == "number" and . == 0)
                   and .udp_scenario_accounting.valid == true
                   and .udp_scenario_accounting.matched == true
                   and .udp_scenario_accounting.packet_matched == true
                   and .udp_scenario_accounting.barrier_evidence_valid == true
                   and .udp_scenario_accounting.barriers_matched == true
                   and (.udp_scenario_accounting.client_barrier_errors
                        | type == "number" and . == 0)
                   and (.udp_scenario_accounting.packet_loss
                        | type == "number" and . == 0)
                   and (.udp_scenario_accounting.unexpected_packets
                        | type == "number" and . == 0))
             end)
        and (if .policy == "baseline"
             then true
             else ([
                 .dut_metrics.nfqueue.kernel_dropped,
                 .dut_metrics.nfqueue.user_dropped,
                 .daemon_log_events.terminal_queue_error_lower_bound,
                 .daemon_log_events.queue_overflow_lower_bound,
                 .daemon_log_events.attribution_timeout_lower_bound
             ] | all(.[]; type == "number" and . == 0))
             and .nfqueue_runtime_counters.valid == true
             and ([
                 .nfqueue_runtime_counters.before.queue_overflow,
                 .nfqueue_runtime_counters.before.attribution_timeout,
                 .nfqueue_runtime_counters.before.terminal_queue_error,
                 .nfqueue_runtime_counters.before.denied,
                 .nfqueue_runtime_counters.after.queue_overflow,
                 .nfqueue_runtime_counters.after.attribution_timeout,
                 .nfqueue_runtime_counters.after.terminal_queue_error,
                 .nfqueue_runtime_counters.after.denied,
                 .nfqueue_runtime_counters.delta.queue_overflow,
                 .nfqueue_runtime_counters.delta.attribution_timeout,
                 .nfqueue_runtime_counters.delta.terminal_queue_error
             ] | all(.[]; type == "number" and . == 0))
             and (.nfqueue_runtime_counters.delta.denied
                  | type == "number" and . == 0)
             end)
        and (.identity_probe == null or .identity_probe.fail_open == false))
    and all(.results[];
        . as $result
        | any($report.backends[];
              .name == $result.backend
              and (
                  .status == "passed"
                  or ($allow_unsupported_iptables
                      and .name == "iptables"
                      and .status == "unsupported"
                      and $result.policy == "baseline")
              )))
    and all(.backends[];
        . as $backend
        | if .status == "passed"
          then any($report.results[];
                   .backend == $backend.name and .phase_role == "steady")
               and any($report.results[];
                       .backend == $backend.name and .phase_role == "burst")
          else true
          end)
    and all(.results[];
        if .policy == "baseline" or (.phase_role != "steady" and .phase_role != "burst")
        then true
        elif .phase_role == "steady"
        then (.relative_performance_evidence | type == "array" and length > 0)
             and all(.relative_performance_evidence[];
                 .method == "arithmetic_mean_of_independent_paired_deltas"
                 and .confirmation_method
                     == "one_sided_paired_student_t_mean_lower_bound"
                 and .minimum_sample_count == 3
                 and .confidence_level == 0.95
                 and (.sample_count | type == "number" and . >= 3)
                 and .independent_pairs_valid == true
                 and (.independent_pair_ids | type == "array" and length >= 3)
                 and ((.independent_pair_ids | unique | length)
                      == (.independent_pair_ids | length))
                 and (.baseline_sample_ids | type == "array" and length >= 3)
                 and ((.baseline_sample_ids | unique | length)
                      == (.baseline_sample_ids | length))
                 and ((.comparison_orders | unique | sort) == ["ab", "ba"])
                 and (
                     if (.metric == "cgroup_cpu_increase_percent"
                         or (.metric | startswith("latency_"))
                         or (.metric | startswith("connect_latency_")))
                     then .release_action == "observe"
                          and (.mean_exceeded_threshold | type == "boolean")
                          and (.confirmed_regression | type == "boolean")
                     else .release_action == "fail"
                          and .mean_exceeded_threshold == false
                          and .confirmed_regression == false
                     end))
        else (.relative_performance_evidence | type == "array" and length > 0)
             and all(.relative_performance_evidence[];
                 .method == "single_paired_burst_threshold_gate"
                 and .minimum_sample_count == 3
                 and .confidence_level == 0.95
                 and (.sample_count == 0 or .sample_count == 1)
                 and (
                     if (.metric == "cgroup_cpu_increase_percent"
                         or (.metric | startswith("latency_"))
                         or (.metric | startswith("connect_latency_")))
                     then .release_action == "observe"
                          and (.mean_exceeded_threshold | type == "boolean")
                     else .release_action == "fail"
                          and .mean_exceeded_threshold == false
                     end)
                 and .confirmed_regression == false)
        end)
' "$report_json" >/dev/null \
    || fail 'report.json does not satisfy the release performance gate'

if ! python3 -I -B -S - "$config" "$report_json" "$repository_root" <<'PY'
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys


config = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
report = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
repository = Path(sys.argv[3])
status_by_backend = {
    backend["name"]: backend["status"] for backend in report["backends"]
}

harness_paths = (
    "tests/perf/bounded_output.py",
    "tests/perf/ci-smoke.sh",
    "tests/perf/control.py",
    "tests/perf/environment.py",
    "tests/perf/metrics.py",
    "tests/perf/run.py",
    "tests/perf/runtime_launcher.py",
    "tests/perf/validate_report.py",
    "tests/perf/workloads/common.py",
    "tests/perf/workloads/identity_probe.c",
    "tests/perf/workloads/tcp.py",
    "tests/perf/workloads/udp.py",
)
harness_components = report["harness"]["components"]
if [component.get("path") for component in harness_components] != list(harness_paths):
    print("performance CI smoke: harness component plan mismatch", file=sys.stderr)
    raise SystemExit(1)
harness_manifest = hashlib.sha256()
for relative, component in zip(harness_paths, harness_components, strict=True):
    path = repository / relative
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as error:
        print(
            f"performance CI smoke: cannot open harness component {relative}: {error}",
            file=sys.stderr,
        )
        raise SystemExit(1) from error
    payload_chunks = []
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > 4 * 1024 * 1024
        ):
            print(
                f"performance CI smoke: unsafe harness component: {relative}",
                file=sys.stderr,
            )
            raise SystemExit(1)
        observed = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            observed += len(chunk)
            if observed > 4 * 1024 * 1024:
                print(
                    f"performance CI smoke: oversized harness component: {relative}",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            payload_chunks.append(chunk)
        metadata_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
        != (
            metadata_after.st_dev,
            metadata_after.st_ino,
            metadata_after.st_size,
            metadata_after.st_mtime_ns,
        )
    ):
        print(f"performance CI smoke: harness component changed: {relative}", file=sys.stderr)
        raise SystemExit(1)
    payload = b"".join(payload_chunks)
    digest = hashlib.sha256(payload).hexdigest()
    if len(payload) != metadata.st_size or component != {
        "path": relative,
        "size": len(payload),
        "sha256": digest,
    }:
        print(f"performance CI smoke: harness component digest mismatch: {relative}", file=sys.stderr)
        raise SystemExit(1)
    harness_manifest.update(relative.encode("ascii"))
    harness_manifest.update(b"\0")
    harness_manifest.update(str(len(payload)).encode("ascii"))
    harness_manifest.update(b"\0")
    harness_manifest.update(digest.encode("ascii"))
    harness_manifest.update(b"\n")
if harness_manifest.hexdigest() != report["harness"]["manifest_sha256"]:
    print("performance CI smoke: harness manifest digest mismatch", file=sys.stderr)
    raise SystemExit(1)

runtime_plan = (
    ("tests/perf/runtime_launcher.py", "runtime_launcher.py"),
    ("tests/perf/control.py", "control.py"),
    ("tests/perf/metrics.py", "metrics.py"),
    ("tests/perf/workloads/common.py", "workloads/common.py"),
    ("tests/perf/workloads/identity_probe.c", "workloads/identity_probe.c"),
    ("tests/perf/workloads/tcp.py", "workloads/tcp.py"),
    ("tests/perf/workloads/udp.py", "workloads/udp.py"),
)
runtime = report["harness"].get("runtime_bundle")
if not isinstance(runtime, dict) or (
    runtime.get("schema") != "openshield.perf.runtime-bundle.v1"
    or runtime.get("container_root") != "/opt/openshield-perf"
    or runtime.get("python_flags") != ["-I", "-B", "-S"]
    or runtime.get("source_only") is not True
    or runtime.get("entrypoints")
    != ["control.py", "metrics.py", "workloads/tcp.py", "workloads/udp.py"]
    or runtime.get("manifest_path") != ".manifest.json"
):
    print("performance CI smoke: runtime bundle policy mismatch", file=sys.stderr)
    raise SystemExit(1)
runtime_components = runtime.get("components")
if (
    not isinstance(runtime_components, list)
    or [
        (component.get("source_path"), component.get("path"))
        if isinstance(component, dict)
        else None
        for component in runtime_components
    ]
    != list(runtime_plan)
):
    print("performance CI smoke: runtime bundle component plan mismatch", file=sys.stderr)
    raise SystemExit(1)
harness_by_path = {component["path"]: component for component in harness_components}
for (source_relative, runtime_relative), component in zip(
    runtime_plan, runtime_components, strict=True
):
    expected = harness_by_path[source_relative]
    if component != {
        "path": runtime_relative,
        "source_path": source_relative,
        "size": expected["size"],
        "sha256": expected["sha256"],
    }:
        print(
            f"performance CI smoke: runtime component evidence mismatch: {runtime_relative}",
            file=sys.stderr,
        )
        raise SystemExit(1)
runtime_manifest_document = {
    key: runtime[key]
    for key in (
        "schema",
        "container_root",
        "python_flags",
        "source_only",
        "entrypoints",
        "components",
    )
}
runtime_manifest_payload = json.dumps(
    runtime_manifest_document,
    sort_keys=True,
    separators=(",", ":"),
    allow_nan=False,
).encode("utf-8")
if hashlib.sha256(runtime_manifest_payload).hexdigest() != runtime.get(
    "manifest_sha256"
):
    print("performance CI smoke: runtime manifest evidence mismatch", file=sys.stderr)
    raise SystemExit(1)
runtime_root = Path(sys.argv[2]).parent / "runtime-bundle"
expected_runtime_files = {path for _, path in runtime_plan} | {".manifest.json"}
observed_runtime_files = set()
observed_runtime_directories = set()
if runtime_root.is_symlink() or not runtime_root.is_dir():
    print("performance CI smoke: runtime bundle directory is unavailable", file=sys.stderr)
    raise SystemExit(1)
for current, directories, files in os.walk(runtime_root, followlinks=False):
    current_path = Path(current)
    relative_directory = current_path.relative_to(runtime_root).as_posix()
    observed_runtime_directories.add(
        "" if relative_directory == "." else relative_directory
    )
    for name in directories:
        target = current_path / name
        metadata = target.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o022:
            print("performance CI smoke: unsafe runtime directory", file=sys.stderr)
            raise SystemExit(1)
    for name in files:
        target = current_path / name
        metadata = target.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o022:
            print("performance CI smoke: unsafe runtime file", file=sys.stderr)
            raise SystemExit(1)
        observed_runtime_files.add(target.relative_to(runtime_root).as_posix())
if observed_runtime_directories != {"", "workloads"} or observed_runtime_files != expected_runtime_files:
    print("performance CI smoke: runtime bundle has missing or extra entries", file=sys.stderr)
    raise SystemExit(1)
if (runtime_root / ".manifest.json").read_bytes() != runtime_manifest_payload:
    print("performance CI smoke: staged runtime manifest mismatch", file=sys.stderr)
    raise SystemExit(1)
for component in runtime_components:
    payload = (runtime_root / component["path"]).read_bytes()
    if len(payload) != component["size"] or hashlib.sha256(payload).hexdigest() != component["sha256"]:
        print(
            f"performance CI smoke: staged runtime component mismatch: {component['path']}",
            file=sys.stderr,
        )
        raise SystemExit(1)

ordinary_rpm_record = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9+._-]*\|[0-9]+\|"
    r"[A-Za-z0-9][A-Za-z0-9+._~^-]*\|"
    r"[A-Za-z0-9][A-Za-z0-9+._~^-]*\|"
    r"[A-Za-z0-9][A-Za-z0-9_+-]*\Z"
)
signing_key_record = re.compile(
    r"gpg-pubkey\|[0-9]+\|"
    r"[A-Za-z0-9][A-Za-z0-9+._~^-]*\|"
    r"[A-Za-z0-9][A-Za-z0-9+._~^-]*\|\(none\)\Z"
)
for environment in report["environments"]:
    records = environment["rpm_nevra"]
    if records != sorted(set(records)) or not all(
        isinstance(record, str)
        and (
            ordinary_rpm_record.fullmatch(record)
            or signing_key_record.fullmatch(record)
        )
        for record in records
    ):
        print("performance CI smoke: RPM inventory is not canonical", file=sys.stderr)
        raise SystemExit(1)
    manifest = ("\n".join(records) + "\n").encode("ascii")
    if hashlib.sha256(manifest).hexdigest() != environment["rpm_manifest_sha256"]:
        print("performance CI smoke: RPM inventory digest mismatch", file=sys.stderr)
        raise SystemExit(1)

pairing = report["baseline_pairing"]
protected_environment_by_backend = {
    environment["backend"]: environment for environment in report["environments"]
}
baseline_environment_by_backend = {
    environment["backend"]: environment
    for environment in pairing["baseline_environments"]
}
if (
    set(protected_environment_by_backend) != set(config["backends"])
    or len(protected_environment_by_backend) != len(report["environments"])
    or set(baseline_environment_by_backend) != set(config["backends"])
    or len(baseline_environment_by_backend)
    != len(pairing["baseline_environments"])
):
    print(
        "performance CI smoke: baseline/protected environment coverage mismatch",
        file=sys.stderr,
    )
    raise SystemExit(1)
for backend in config["backends"]:
    if baseline_environment_by_backend[backend] != protected_environment_by_backend[backend]:
        print(
            f"performance CI smoke: pristine and protected environments differ: {backend}",
            file=sys.stderr,
        )
        raise SystemExit(1)

environment_pairs = pairing["environment_pairs"]
if (
    len(environment_pairs) != len(config["backends"])
    or [item["backend"] for item in environment_pairs] != config["backends"]
):
    print("performance CI smoke: environment pair plan mismatch", file=sys.stderr)
    raise SystemExit(1)
for item in environment_pairs:
    if (
        item["valid"] is not True
        or item["failure_reasons"]
        or item["baseline_daemon_started"] is not False
        or item["baseline_client_id"] == item["protected_client_id"]
    ):
        print(
            f"performance CI smoke: unsafe environment pair: {item['backend']}",
            file=sys.stderr,
        )
        raise SystemExit(1)

phases = [("warmup", "warmup", config["phases"]["warmup"]["scale"], None)]
phases.extend(
    (f"ramp_{index}", "ramp", scale, None)
    for index, scale in enumerate(config["phases"]["ramp"]["scales"], 1)
)
phases.extend(
    (f"steady_{repetition}", "steady", 1.0, repetition)
    for repetition in range(1, config["phases"]["steady"]["repetitions"] + 1)
)
phases.append(("burst", "burst", config["phases"]["burst"]["scale"], None))


def comparison_phases(repetition):
    repetitions = config["phases"]["steady"]["repetitions"]
    selected = []
    for phase in phases:
        _name, role, _scale, phase_repetition = phase
        if role == "steady":
            if phase_repetition == repetition:
                selected.append(phase)
        elif role == "ramp":
            if repetition == 1:
                selected.append(phase)
        elif role == "burst":
            if repetition == repetitions:
                selected.append(phase)
        else:
            selected.append(phase)
    return selected


def protected_scenarios(profile):
    policies = profile["policy_cases"]
    if "network_only" in policies:
        for mode in config["modes"]:
            yield "network_only", mode, None
    application_policy = f"application_{profile['transport']}"
    if application_policy in policies:
        yield application_policy, "enforcing", None
        for variant in config["learning_variants"]:
            yield application_policy, "learning", variant


def expected_backend_blocks(backend):
    sequence = 0
    sample_index = 0
    pair_index = 0
    group_index = 0
    expected_blocks = []
    repetitions = config["phases"]["steady"]["repetitions"]
    for profile in config["profiles"]:
        scenarios = list(protected_scenarios(profile))
        for load_level in config["load_levels"]:
            for policy, mode, variant in scenarios:
                for repetition in range(1, repetitions + 1):
                    sample_slot = (backend, sample_index)
                    pair_slot = (backend, pair_index)
                    sample_index += 1
                    pair_index += 1
                    order = (
                        "ab"
                        if (group_index + repetition - 1) % 2 == 0
                        else "ba"
                    )
                    common = {
                        "sample_slot": sample_slot,
                        "pair_slot": pair_slot,
                        "comparison_repetition": repetition,
                        "phases": comparison_phases(repetition),
                        "profile": profile,
                        "load_level": load_level,
                    }
                    baseline = {
                        **common,
                        "topology_role": "baseline",
                        "policy": "baseline",
                        "mode": None,
                        "learning_variant": None,
                        "comparison_order": None,
                    }
                    protected = {
                        **common,
                        "topology_role": "protected",
                        "policy": policy,
                        "mode": mode,
                        "learning_variant": variant,
                        "comparison_order": order,
                    }
                    first, second = (
                        (baseline, protected)
                        if order == "ab"
                        else (protected, baseline)
                    )
                    first["sequence"] = sequence
                    expected_blocks.append(first)
                    sequence += 1
                    second["sequence"] = sequence
                    expected_blocks.append(second)
                    sequence += 1
                group_index += 1
    return expected_blocks


def reject(message):
    print(f"performance CI smoke: {message}", file=sys.stderr)
    raise SystemExit(1)


block_constant_fields = (
    "backend",
    "policy",
    "mode",
    "learning_variant",
    "profile",
    "direction",
    "transport",
    "load_level",
    "baseline_sample_id",
    "comparison_pair_id",
    "comparison_repetition",
    "comparison_order",
    "execution_sequence",
    "topology_role",
    "block_started_monotonic_ns",
    "block_finished_monotonic_ns",
    "comparison_gap_seconds",
)
sample_slot_to_id = {}
sample_id_to_slot = {}
pair_slot_to_id = {}
pair_id_to_slot = {}
sample_references = Counter()
observed_gaps = []
observed_comparison_count = 0
observed_order_counts = Counter()
expected_row_count = 0


def process_identity(document):
    return tuple(
        document.get(field)
        for field in ("pid", "starttime", "executable", "uid")
    )


def canonical_digest(document):
    return hashlib.sha256(
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def steady_measurement_intervals(row):
    if row.get("phase_role") != "steady":
        return None
    dut_metrics = row.get("dut_metrics")
    peer_metrics = row.get("peer_metrics")
    if not isinstance(dut_metrics, dict) or not isinstance(peer_metrics, dict):
        return None
    dut_started = dut_metrics.get("started_at_monotonic_ns")
    dut_finished = dut_metrics.get("finished_at_monotonic_ns")
    peer_started = peer_metrics.get("started_at_monotonic_ns")
    peer_finished = peer_metrics.get("finished_at_monotonic_ns")
    workload_started = (row.get("workload_started") or {}).get(
        "boundary_monotonic_ns"
    )
    workload_finished = (row.get("workload_finished") or {}).get(
        "boundary_monotonic_ns"
    )
    block_started = row.get("block_started_monotonic_ns")
    block_finished = row.get("block_finished_monotonic_ns")
    values = (
        dut_started,
        peer_started,
        workload_started,
        workload_finished,
        dut_finished,
        peer_finished,
        block_started,
        block_finished,
    )
    if not all(
        isinstance(value, int) and not isinstance(value, bool) and value > 0
        for value in values
    ):
        return None
    dut_bounded = (
        block_started
        <= dut_started
        <= workload_started
        < workload_finished
        <= dut_finished
        <= block_finished
    )
    peer_bounded = (
        block_started
        <= peer_started
        <= workload_started
        < workload_finished
        <= peer_finished
        <= block_finished
    )
    if not dut_bounded or not peer_bounded:
        return None
    return (
        (dut_started, dut_finished),
        (peer_started, peer_finished),
        (workload_started, workload_finished),
    )


def paired_steady_measurement_gap_seconds(baseline, protected, order):
    baseline_intervals = steady_measurement_intervals(baseline)
    protected_intervals = steady_measurement_intervals(protected)
    if baseline_intervals is None or protected_intervals is None:
        return None
    gaps = []
    for baseline_interval, protected_interval in zip(
        baseline_intervals, protected_intervals, strict=True
    ):
        baseline_started, baseline_finished = baseline_interval
        protected_started, protected_finished = protected_interval
        if order == "ab" and baseline_finished <= protected_started:
            gaps.append(protected_started - baseline_finished)
        elif order == "ba" and protected_finished <= baseline_started:
            gaps.append(baseline_started - protected_finished)
        else:
            return None
    return max(gaps) / 1_000_000_000.0


def validate_workload_lifecycle(row, prefix="workload"):
    ready_key = f"{prefix}_start_gate" if prefix != "workload" else "workload_start_gate"
    started_key = f"{prefix}_started" if prefix != "workload" else "workload_started"
    finished_key = f"{prefix}_finished" if prefix != "workload" else "workload_finished"
    released_key = f"{prefix}_released" if prefix != "workload" else "workload_released"
    summary_key = f"{prefix}_workload" if prefix != "workload" else "workload"
    try:
        ready = row[ready_key]
        spawned = ready["spawned"]
        started = row[started_key]
        finished = row[finished_key]
        released = row[released_key]
        summary = row[summary_key]
        identity = process_identity(ready)
        timestamps = [
            spawned["boundary_monotonic_ns"],
            started["boundary_monotonic_ns"],
            finished["boundary_monotonic_ns"],
            released["boundary_monotonic_ns"],
        ]
    except (KeyError, TypeError) as error:
        reject(f"{prefix} lifecycle evidence is incomplete: {error}")
    if any(
        process_identity(document) != identity
        for document in (spawned, started, finished, released)
    ):
        reject(f"{prefix} lifecycle changed pinned process identity")
    if any(
        document.get("control_protocol") != "stdin_start_finish_release_v2"
        for document in (spawned, ready, started, finished, released)
    ):
        reject(f"{prefix} lifecycle protocol is not authenticated")
    if not all(
        isinstance(value, int) and not isinstance(value, bool) and value > 0
        for value in timestamps
    ) or timestamps != sorted(timestamps):
        reject(f"{prefix} lifecycle timestamps are not ordered")
    if finished.get("summary_sha256") != canonical_digest(summary):
        reject(f"{prefix} finished event does not authenticate its summary")


for result in report["results"]:
    validate_workload_lifecycle(result)
for overload in report["overload_results"]:
    validate_workload_lifecycle(overload, "pressure")

for backend in config["backends"]:
    backend_rows = [
        result for result in report["results"] if result.get("backend") == backend
    ]
    if status_by_backend[backend] == "unsupported":
        if backend_rows:
            reject(f"unsupported backend emitted normal results: {backend}")
        continue
    if status_by_backend[backend] != "passed":
        reject(f"non-passing backend appears in a passing report: {backend}")

    expected_blocks = expected_backend_blocks(backend)
    expected_row_count += sum(len(block["phases"]) for block in expected_blocks)
    rows_by_sequence = {}
    observed_block_order = []
    previous_sequence = None
    closed_sequences = set()
    try:
        for row in backend_rows:
            sequence = row["execution_sequence"]
            if sequence != previous_sequence:
                if sequence in closed_sequences:
                    reject(
                        f"result block is not contiguous: {backend} sequence {sequence}"
                    )
                if previous_sequence is not None:
                    closed_sequences.add(previous_sequence)
                observed_block_order.append(sequence)
                previous_sequence = sequence
            rows_by_sequence.setdefault(sequence, []).append(row)
    except (KeyError, TypeError) as error:
        reject(f"incomplete AB/BA result identity: {error}")

    expected_sequences = list(range(len(expected_blocks)))
    if observed_block_order != expected_sequences or sorted(rows_by_sequence) != expected_sequences:
        reject(
            f"execution sequence mismatch for {backend}: "
            f"expected={expected_sequences!r}, observed={observed_block_order!r}"
        )

    for expected_block, sequence in zip(
        expected_blocks, expected_sequences, strict=True
    ):
        rows = rows_by_sequence[sequence]
        expected_phases = expected_block["phases"]
        if len(rows) != len(expected_phases):
            reject(
                f"wrong phase count for {backend} sequence {sequence}: {len(rows)}"
            )
        first = rows[0]
        for row in rows[1:]:
            if any(row.get(field) != first.get(field) for field in block_constant_fields):
                reject(f"block metadata differs between phases: {backend} sequence {sequence}")
        actual_phases = Counter(
            (
                row.get("phase"),
                row.get("phase_role"),
                row.get("phase_scale"),
                row.get("repetition"),
            )
            for row in rows
        )
        if actual_phases != Counter(expected_phases):
            reject(f"phase plan mismatch: {backend} sequence {sequence}")

        profile = expected_block["profile"]
        expected_identity = {
            "backend": backend,
            "policy": expected_block["policy"],
            "mode": expected_block["mode"],
            "learning_variant": expected_block["learning_variant"],
            "profile": profile["name"],
            "direction": profile["direction"],
            "transport": profile["transport"],
            "load_level": expected_block["load_level"],
            "comparison_repetition": expected_block["comparison_repetition"],
            "comparison_order": expected_block["comparison_order"],
            "execution_sequence": sequence,
            "topology_role": expected_block["topology_role"],
        }
        if any(first.get(field) != value for field, value in expected_identity.items()):
            reject(
                f"AB/BA block identity mismatch: {backend} sequence {sequence}"
            )
        started = first.get("block_started_monotonic_ns")
        finished = first.get("block_finished_monotonic_ns")
        if (
            not isinstance(started, int)
            or isinstance(started, bool)
            or not isinstance(finished, int)
            or isinstance(finished, bool)
            or started <= 0
            or finished <= started
        ):
            reject(f"invalid block interval: {backend} sequence {sequence}")
        sample_id = first.get("baseline_sample_id")
        if not isinstance(sample_id, str) or re.fullmatch(r"b[0-9]{5}", sample_id) is None:
            reject(f"invalid baseline sample id: {backend} sequence {sequence}")
        qualified_sample_id = (backend, sample_id)
        sample_slot = expected_block["sample_slot"]
        expected_sample_id = (backend, f"b{sample_slot[1]:05d}")
        if qualified_sample_id != expected_sample_id:
            reject(
                f"non-canonical baseline sample id: {backend} sequence {sequence}"
            )
        pair_id = first.get("comparison_pair_id")
        if not isinstance(pair_id, str) or re.fullmatch(r"p[0-9]{5}", pair_id) is None:
            reject(f"invalid comparison pair id: {backend} sequence {sequence}")
        qualified_pair_id = (backend, pair_id)
        pair_slot = expected_block["pair_slot"]
        expected_pair_id = (backend, f"p{pair_slot[1]:05d}")
        if qualified_pair_id != expected_pair_id:
            reject(
                f"non-canonical comparison pair id: {backend} sequence {sequence}"
            )
        if expected_block["topology_role"] == "baseline":
            if first.get("comparison_gap_seconds") is not None:
                reject(f"baseline carries a comparison gap: {backend} sequence {sequence}")
            prior_id = sample_slot_to_id.setdefault(sample_slot, qualified_sample_id)
            prior_slot = sample_id_to_slot.setdefault(qualified_sample_id, sample_slot)
            if prior_id != qualified_sample_id or prior_slot != sample_slot:
                reject(f"baseline sample id is ambiguous: {backend}/{sample_id}")
            prior_pair_id = pair_slot_to_id.setdefault(pair_slot, qualified_pair_id)
            prior_pair_slot = pair_id_to_slot.setdefault(qualified_pair_id, pair_slot)
            if prior_pair_id != qualified_pair_id or prior_pair_slot != pair_slot:
                reject(f"comparison pair id is ambiguous: {backend}/{pair_id}")
        else:
            gap = first.get("comparison_gap_seconds")
            if (
                not isinstance(gap, (int, float))
                or isinstance(gap, bool)
                or not math.isfinite(gap)
                or gap < 0
                or gap > config["criteria"]["maximum_comparison_gap_seconds"]
            ):
                reject(f"invalid comparison gap: {backend} sequence {sequence}")
            observed_gaps.append(float(gap))
            observed_comparison_count += 1
            observed_order_counts[first["comparison_order"]] += 1
            sample_references[sample_slot] += 1

    for expected_block in expected_blocks:
        sequence = expected_block["sequence"]
        if expected_block["topology_role"] != "protected":
            continue
        protected = rows_by_sequence[sequence][0]
        sample_slot = expected_block["sample_slot"]
        pair_slot = expected_block["pair_slot"]
        qualified_sample_id = (backend, protected["baseline_sample_id"])
        qualified_pair_id = (backend, protected["comparison_pair_id"])
        if sample_slot_to_id.get(sample_slot) != qualified_sample_id:
            reject(f"protected block references wrong baseline: {backend} sequence {sequence}")
        if pair_slot_to_id.get(pair_slot) != qualified_pair_id:
            reject(f"protected block references wrong pair: {backend} sequence {sequence}")
        baseline_sequence = sequence - 1 if protected["comparison_order"] == "ab" else sequence + 1
        if baseline_sequence not in rows_by_sequence:
            reject(f"comparison has no adjacent baseline: {backend} sequence {sequence}")
        baseline = rows_by_sequence[baseline_sequence][0]
        if (
            baseline["topology_role"] != "baseline"
            or baseline["baseline_sample_id"] != protected["baseline_sample_id"]
            or baseline["comparison_pair_id"] != protected["comparison_pair_id"]
            or baseline["comparison_repetition"]
            != protected["comparison_repetition"]
        ):
            reject(f"comparison baseline is not adjacent: {backend} sequence {sequence}")
        if protected["comparison_order"] == "ab":
            blocks_adjacent = (
                baseline["block_finished_monotonic_ns"]
                <= protected["block_started_monotonic_ns"]
            )
        else:
            blocks_adjacent = (
                protected["block_finished_monotonic_ns"]
                <= baseline["block_started_monotonic_ns"]
            )
        if not blocks_adjacent:
            reject(f"comparison blocks overlap or are out of order: {backend} sequence {sequence}")
        baseline_steady = [
            row
            for row in rows_by_sequence[baseline_sequence]
            if row.get("phase_role") == "steady"
        ]
        protected_steady = [
            row
            for row in rows_by_sequence[sequence]
            if row.get("phase_role") == "steady"
        ]
        expected_gap = (
            paired_steady_measurement_gap_seconds(
                baseline_steady[0],
                protected_steady[0],
                protected["comparison_order"],
            )
            if len(baseline_steady) == 1 and len(protected_steady) == 1
            else None
        )
        if expected_gap is None or not math.isclose(
            protected["comparison_gap_seconds"],
            expected_gap if expected_gap is not None else -1.0,
            rel_tol=0.0,
            abs_tol=1e-9,
        ):
            reject(
                f"comparison gap does not match steady measurement timestamps: "
                f"{backend} sequence {sequence}"
            )
        baseline_rows_by_phase = {row["phase"]: row for row in rows_by_sequence[baseline_sequence]}
        for protected_row in rows_by_sequence[sequence]:
            baseline_row = baseline_rows_by_phase[protected_row["phase"]]
            baseline_derived = baseline_row["derived"]
            gated_phase = protected_row["phase_role"] in {"steady", "burst"}
            expected_baseline_evidence = {
                "sample_id": baseline_row["baseline_sample_id"],
                "comparison_pair_id": baseline_row["comparison_pair_id"],
                "comparison_repetition": baseline_row["comparison_repetition"],
                "comparison_order": protected_row["comparison_order"],
                "execution_sequence": baseline_row["execution_sequence"],
                "comparison_gap_seconds": protected_row["comparison_gap_seconds"],
                "valid": baseline_row["valid"],
                "capacity_pass": baseline_row["capacity_pass"],
                "safety_pass": baseline_row["safety_pass"],
                "eligible": baseline_row["valid"] is True
                and (
                    not gated_phase
                    or (
                        baseline_row["capacity_pass"] is True
                        and baseline_row["safety_pass"] is True
                    )
                ),
                "actual_application_ops_per_second": baseline_derived[
                    "actual_application_ops_per_second"
                ],
                "actual_application_mbps": baseline_derived[
                    "actual_application_mbps"
                ],
                "aggregate_dut_pps": baseline_derived["aggregate_dut_pps"],
                "cgroup_cpu_percent_one_core": baseline_derived[
                    "cgroup_cpu_percent_one_core"
                ],
                "latency_p50_ms": baseline_derived["latency_p50_ms"],
                "latency_p95_ms": baseline_derived["latency_p95_ms"],
                "latency_p99_ms": baseline_derived["latency_p99_ms"],
                "connect_latency_p50_ms": baseline_derived[
                    "connect_latency_p50_ms"
                ],
                "connect_latency_p95_ms": baseline_derived[
                    "connect_latency_p95_ms"
                ],
                "connect_latency_p99_ms": baseline_derived[
                    "connect_latency_p99_ms"
                ],
            }
            if protected_row.get("baseline") != expected_baseline_evidence:
                reject(
                    f"embedded baseline evidence mismatch: {backend} "
                    f"sequence {sequence} phase {protected_row['phase']}"
                )

for sample_slot, qualified_sample_id in sample_slot_to_id.items():
    reference_count = sample_references[sample_slot]
    if reference_count != 1:
        reject(f"baseline sample has invalid use count: {qualified_sample_id!r}")

if len(pair_slot_to_id) != len(sample_slot_to_id):
    reject("comparison pair and baseline sample counts differ")

if len(report["results"]) != expected_row_count:
    reject(
        f"result plan mismatch: expected={expected_row_count}, "
        f"actual={len(report['results'])}"
    )
if all(status == "passed" for status in status_by_backend.values()) and expected_row_count != 576:
    reject(f"ci-smoke independent AB/BA row contract drifted from 576 to {expected_row_count}")
if pairing["baseline_sample_count"] != len(sample_slot_to_id):
    reject("baseline_pairing baseline_sample_count mismatch")
if pairing["comparison_count"] != observed_comparison_count:
    reject("baseline_pairing comparison_count mismatch")
if pairing["orders"] != {
    "ab": observed_order_counts["ab"],
    "ba": observed_order_counts["ba"],
}:
    reject("baseline_pairing order counts mismatch")
maximum_gap = max(observed_gaps, default=0.0)
if not math.isclose(
    pairing["maximum_gap_seconds"],
    maximum_gap,
    rel_tol=0.0,
    abs_tol=1e-9,
):
    reject("baseline_pairing maximum_gap_seconds mismatch")

if config.get("overload", {}).get("enabled"):
    expected_overload = {
        (backend, transport)
        for backend, status in status_by_backend.items()
        if status == "passed"
        for transport in ("tcp", "udp")
    }
    try:
        actual_overload = {
            (result["backend"], result["transport"])
            for result in report["overload_results"]
        }
    except (KeyError, TypeError) as error:
        print(f"performance CI smoke: malformed overload identity: {error}", file=sys.stderr)
        raise SystemExit(1)
    if actual_overload != expected_overload or len(report["overload_results"]) != len(expected_overload):
        print(
            "performance CI smoke: controlled overload plan mismatch: "
            f"expected={sorted(expected_overload)!r}, actual={sorted(actual_overload)!r}",
            file=sys.stderr,
        )
        raise SystemExit(1)
PY
then
    fail 'report.json does not cover the exact configured result plan'
fi

python3 -I -B -S "$release_validator" \
    "$config" \
    "$report_json" \
    || fail 'report.json failed independent configuration and relative-performance recomputation'

readonly EXPECTED_CSV_HEADER='backend,policy,mode,learning_variant,profile,direction,transport,load_level,phase,phase_role,phase_scale,baseline_sample_id,comparison_pair_id,comparison_repetition,comparison_order,execution_sequence,topology_role,block_started_monotonic_ns,block_finished_monotonic_ns,comparison_gap_seconds,valid,passed,safety_pass,capacity_pass,relative_performance_pass,unreliable_reasons,failure_reasons,safety_failure_reasons,relative_performance_failure_reasons,target_ops_per_second,actual_application_ops_per_second,actual_application_mbps,target_attainment_ratio,actual_cps,active_flows_peak,latency_p50_ms,latency_p95_ms,latency_p99_ms,connect_latency_p50_ms,connect_latency_p95_ms,connect_latency_p99_ms,error_ratio,udp_reply_loss_ratio,udp_scenario_accounting_valid,udp_scenario_packets_sent,udp_scenario_packets_received,udp_scenario_packet_loss,udp_scenario_packet_loss_ratio,udp_scenario_unexpected_packets,udp_scenario_packet_matched,udp_barriers_expected,udp_barriers_sent,udp_server_barriers_received,udp_server_barrier_acks_sent,udp_barrier_acks_received,udp_barrier_errors,udp_barriers_matched,tcp_retransmits,tcp_retransmits_per_tx_packet,dut_rx_pps,dut_tx_pps,dut_rx_mbps,dut_tx_mbps,aggregate_dut_pps,daemon_cpu_percent_one_core,cgroup_cpu_percent_one_core,daemon_rss_bytes_peak,softirq_net_rx,softirq_net_tx,conntrack_count_peak,nfqueue_hits,nfqueue_depth_peak,nfqueue_kernel_dropped,nfqueue_user_dropped,nfqueue_runtime_counters_valid,nfqueue_queue_overflow_delta,nfqueue_attribution_timeout_delta,nfqueue_terminal_queue_error_delta,nfqueue_denied_delta,nfqueue_hits_per_connection,nfqueue_hits_per_datagram,identity_probe_fail_open,quarantine_occurred,application_ops_reduction_percent,throughput_reduction_percent,aggregate_dut_pps_reduction_percent,latency_p50_increase_percent,latency_p95_increase_percent,latency_p99_increase_percent,connect_latency_p50_increase_percent,connect_latency_p95_increase_percent,connect_latency_p99_increase_percent,cgroup_cpu_increase_percent'
IFS= read -r csv_header < "$report_csv" \
    || fail 'report.csv does not contain a header'
csv_header=${csv_header%$'\r'}
[[ "$csv_header" == "$EXPECTED_CSV_HEADER" ]] \
    || fail 'report.csv does not contain the expected schema header'
json_result_count=$(jq -r '.results | length' "$report_json")
csv_line_count=$(awk 'END { print NR }' "$report_csv")
(( csv_line_count == json_result_count + 1 )) \
    || fail 'report.csv row count does not match report.json'

readonly EXPECTED_OVERLOAD_CSV_HEADER='backend,policy,mode,profile,canary_profile,transport,probe_transport,valid,passed,safety_pass,recovery_pass,pressure_start_gate_ready,resource_valid,allowed_preflight_pass,network_liveness_preflight_pass,wrong_executable_preflight_blocked,saturation_proven,stall_kernel_drops,stall_user_drops,stall_total_drops,timestamps_ordered,during_stall_blocked_all,during_stall_fail_open,during_stall_liveness_pass,after_resume_blocked,after_resume_liveness_pass,quarantine_reported,quarantine_occurred,kernel_block_all,quarantine_black_box_pass,validity_failure_reasons,safety_failure_reasons,recovery_failure_reasons'
IFS= read -r overload_csv_header < "$overload_csv" \
    || fail 'overload.csv does not contain a header'
overload_csv_header=${overload_csv_header%$'\r'}
[[ "$overload_csv_header" == "$EXPECTED_OVERLOAD_CSV_HEADER" ]] \
    || fail 'overload.csv does not contain the expected schema header'
json_overload_count=$(jq -r '.overload_results | length' "$report_json")
overload_csv_line_count=$(awk 'END { print NR }' "$overload_csv")
(( overload_csv_line_count == json_overload_count + 1 )) \
    || fail 'overload.csv row count does not match report.json'

IFS= read -r markdown_title < "$report_markdown" \
    || fail 'report.md does not contain a title'
[[ "$markdown_title" == '# OpenShield performance report' ]] \
    || fail 'report.md does not contain the expected title'
grep -Fqx 'Overall result: **PASS**' "$report_markdown" \
    || fail 'report.md does not record a passing result'

printf 'performance CI smoke: PASS (%s)\n' "$output_directory"
